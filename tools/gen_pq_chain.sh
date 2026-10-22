#!/usr/bin/env bash
# ------------------------------------------------------------------
# gen_pq_chain.sh
# Generates a 3-level ML-DSA-44 cert chain for the TLS_X9 demo:
#   Root CA  (ML-DSA-44, self-signed)
#       |
#       +-- Intermediate CA (ML-DSA-44, signed by Root)
#               |
#               +-- Leaf  (ML-DSA-44, signed by Intermediate,
#                          CN=192.168.0.100, SAN=IP:192.168.0.100)
#
# Produces:
#   out/root_key.pem, root_cert.pem
#   out/int_key.pem,  int_cert.pem
#   out/leaf_key.pem, leaf_cert.pem
#   out/*.der copies
#   out/certs_pqc.h   <-- copy this into TLS_X9/Core/Inc/
#   out/root_cert.pem <-- use this on the MSYS2 client side (-A)
#
# Requirements:
#   - OpenSSL 3.5 or newer (has native ML-DSA support)
#     In MSYS2:  pacman -S mingw-w64-x86_64-openssl   (check version >= 3.5)
#   - od + awk (shipped with MSYS2 coreutils, already installed).
# ------------------------------------------------------------------
set -euo pipefail

# xxd-like C-array emitter using od+awk (so we don't depend on xxd/vim).
# Writes to stdout in the same form `xxd -i -n NAME FILE` produces:
#   unsigned char NAME[] = { 0xXX, ... };
#   unsigned int  NAME_len = N;
emit_c_array() {
    local name="$1" file="$2"
    local sz
    sz=$(wc -c < "$file")
    printf 'unsigned char %s[] = {\n' "$name"
    od -An -v -tx1 "$file" | awk '
        BEGIN { n = 0 }
        {
            for (i = 1; i <= NF; i++) {
                if (n > 0 && n % 12 == 0) printf "\n"
                if (n % 12 == 0) printf "  "
                else             printf " "
                printf "0x%s,", $i
                n++
            }
        }
        END { if (n > 0) printf "\n" }
    '
    printf '};\nunsigned int %s_len = %d;\n' "$name" "$sz"
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
mkdir -p "${OUT_DIR}"
cd "${OUT_DIR}"

# ---- sanity: OpenSSL with ML-DSA -----------------------------------
echo "[*] OpenSSL version:"
openssl version
if ! openssl list -public-key-algorithms | grep -qi 'ml-dsa-44\|mldsa44'; then
    echo "ERROR: this openssl does not support ML-DSA-44."
    echo "       Need OpenSSL >= 3.5. Check 'pacman -Syu mingw-w64-x86_64-openssl'."
    exit 1
fi
echo "[*] ML-DSA-44 supported: OK"

# ---- 1) Root CA ----------------------------------------------------
# Note: OpenSSL 3.5+ defaults to the "seed-priv" PKCS#8 form
# (SEQUENCE { seed, expandedKey }) for ML-DSA keys. wolfSSL 5.8.0 only
# accepts the raw 2560-byte expanded-key form. We handle that by
# surgically rewrapping the leaf key DER further down, not via
# -pkeyopt (which isn't accepted in OpenSSL 3.6.0's ctrl layer).
echo "[*] (1/3) Generating Root CA..."
openssl genpkey -algorithm ml-dsa-44 -out root_key.pem

cat > root.cnf <<EOF
[req]
distinguished_name = dn
prompt             = no
[dn]
C  = GB
O  = TLS_X9 Demo
CN = PQ Root CA
[v3_ca]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

openssl req -new -x509 -key root_key.pem \
    -days 3650 \
    -config root.cnf -extensions v3_ca \
    -out root_cert.pem

# ---- 2) Intermediate CA (signed by Root) ---------------------------
echo "[*] (2/3) Generating Intermediate CA..."
openssl genpkey -algorithm ml-dsa-44 -out int_key.pem

cat > int.cnf <<EOF
[req]
distinguished_name = dn
prompt             = no
[dn]
C  = GB
O  = TLS_X9 Demo
CN = PQ Intermediate CA
[v3_int]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

openssl req -new -key int_key.pem \
    -config int.cnf \
    -out int_csr.pem

openssl x509 -req -in int_csr.pem \
    -CA root_cert.pem -CAkey root_key.pem -CAcreateserial \
    -days 1825 \
    -extfile int.cnf -extensions v3_int \
    -out int_cert.pem

# ---- 3) Leaf (signed by Intermediate) ------------------------------
echo "[*] (3/3) Generating Leaf (CN=192.168.0.100)..."
openssl genpkey -algorithm ml-dsa-44 -out leaf_key.pem

cat > leaf.cnf <<EOF
[req]
distinguished_name = dn
prompt             = no
[dn]
C  = GB
O  = TLS_X9 Demo
CN = 192.168.0.100
[v3_leaf]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
subjectAltName         = IP:192.168.0.100
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

openssl req -new -key leaf_key.pem \
    -config leaf.cnf \
    -out leaf_csr.pem

openssl x509 -req -in leaf_csr.pem \
    -CA int_cert.pem -CAkey int_key.pem -CAcreateserial \
    -days 825 \
    -extfile leaf.cnf -extensions v3_leaf \
    -out leaf_cert.pem

# ---- Verify chain --------------------------------------------------
echo "[*] Verifying chain..."
cat int_cert.pem root_cert.pem > ca_bundle.pem
openssl verify -CAfile root_cert.pem -untrusted int_cert.pem leaf_cert.pem

# ---- Build chain PEM blob (leaf + intermediate) --------------------
# Order matters: leaf FIRST, then intermediate. wolfSSL parses sequentially.
cat leaf_cert.pem int_cert.pem > chain_cert.pem

# ---- Leaf private key as DER, rewrapped for wolfSSL ----------------
# Emit DER first (will be "seed-priv" form under OpenSSL 3.5+ defaults).
openssl pkey -in leaf_key.pem -outform DER -out leaf_key_raw.der

# wolfSSL 5.8.0's DecodeAsymKey_Assign uses the RFC 8410 "CurvePrivateKey"
# template (edKeyASN[] in asn.c): the PKCS#8 privateKey OCTET STRING must
# itself contain an INNER OCTET STRING whose content is the raw 2560-byte
# expanded ML-DSA-44 secret key. OpenSSL 3.5+ defaults to the IETF ML-DSA
# draft "seed-priv" form (SEQUENCE { seed, expandedKey } inside the
# privateKey OCTET STRING -- 2626 B total), which wolfSSL rejects with
# WOLFSSL_BAD_FILE (-463). We extract the 2560 expanded bytes and build
# a double-wrapped PKCS#8 that matches edKeyASN[].
RAW_SZ=$(wc -c < leaf_key_raw.der)
echo "[*] leaf_key_raw.der size = ${RAW_SZ} bytes (expect 2626 for seed-priv)"

if [ "${RAW_SZ}" -eq 2626 ]; then
    # Seed-priv form. The 2560-byte expanded key sits at fixed offset 66.
    # Layout: 4(outer SEQ hdr) + 3(ver) + 2+11(AlgId) + 4(privKey OS hdr)
    #       + 4(inner SEQ hdr) + 2+32(seed) + 4(priv OS hdr) = 66.
    dd if=leaf_key_raw.der of=leaf_expanded.bin \
        bs=1 skip=66 count=2560 status=none
    EXP_SZ=$(wc -c < leaf_expanded.bin)
    if [ "${EXP_SZ}" -ne 2560 ]; then
        echo "ERROR: extracted expanded key is ${EXP_SZ} bytes, expected 2560."
        exit 1
    fi
elif [ "${RAW_SZ}" -eq 2594 ]; then
    # Some OpenSSL builds already emit priv-only form (single OCTET STRING
    # with 2560 bytes); inner payload starts at fixed offset 24.
    dd if=leaf_key_raw.der of=leaf_expanded.bin \
        bs=1 skip=24 count=2560 status=none
else
    echo "ERROR: unexpected leaf_key DER size ${RAW_SZ}."
    echo "       Expected 2626 (seed-priv) or 2594 (priv-only) for ML-DSA-44."
    echo "       Inspect with: openssl asn1parse -inform DER -in leaf_key_raw.der"
    exit 1
fi

# Build wolfSSL-compatible double-OCTET-STRING PKCS#8 for ML-DSA-44:
#   30 82 0A 18                SEQUENCE, content=2584
#   02 01 00                   INTEGER 0
#   30 0B                      AlgId SEQUENCE, 11
#     06 09 60 86 48 01 65 03 04 03 11   OID 2.16.840.1.101.3.4.3.17
#   04 82 0A 04                OCTET STRING (outer), content=2564
#     04 82 0A 00              OCTET STRING (inner CurvePrivateKey), 2560
#     <2560 expanded key bytes>
# Total = 4 + 2584 = 2588 bytes.
printf '\x30\x82\x0a\x18\x02\x01\x00\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x11\x04\x82\x0a\x04\x04\x82\x0a\x00' \
    > leaf_key.der
cat leaf_expanded.bin >> leaf_key.der
rm -f leaf_key_raw.der leaf_expanded.bin

NEW_SZ=$(wc -c < leaf_key.der)
if [ "${NEW_SZ}" -ne 2588 ]; then
    echo "ERROR: rewrapped DER is ${NEW_SZ} bytes, expected 2588."
    exit 1
fi
echo "[*] rewrapped leaf_key.der (${NEW_SZ} B, RFC 8410 double-OCTET-STRING)"

# ---- Emit C header -------------------------------------------------
echo "[*] Writing certs_pqc.h..."
{
  echo "/* AUTO-GENERATED by tools/gen_pq_chain.sh --- DO NOT EDIT */"
  echo "/* 3-level ML-DSA-44 cert chain for TLS_X9 demo.            */"
  echo "#ifndef CERTS_PQC_H"
  echo "#define CERTS_PQC_H"
  echo ""
  echo "#include <stdint.h>"
  echo "#include <stddef.h>"
  echo ""

  # Leaf + Intermediate, concatenated PEM (fed to
  # wolfSSL_CTX_use_certificate_chain_buffer).
  emit_c_array chain_cert_pem chain_cert.pem
  echo ""
  # Leaf private key (DER, PKCS#8).
  emit_c_array leaf_key_der   leaf_key.der
  echo ""

  echo "#endif /* CERTS_PQC_H */"
} > certs_pqc.h

echo ""
echo "-----------------------------------------------------------------"
echo " OK."
echo " Artifacts in: ${OUT_DIR}"
echo "   - certs_pqc.h   ->  copy to TLS_X9/Core/Inc/"
echo "   - root_cert.pem ->  use on MSYS2 client side: client.exe -A root_cert.pem"
echo "-----------------------------------------------------------------"
ls -la
