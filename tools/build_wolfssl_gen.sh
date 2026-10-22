#!/usr/bin/env bash
# Build the wolfSSL-native cert-chain generator against ~/wolfssl.
set -euo pipefail
cd "$(dirname "$0")"

WOLFSSL_DIR="${WOLFSSL_DIR:-$HOME/wolfssl}"
LIBDIR="${WOLFSSL_DIR}/src/.libs"

if [ ! -d "${LIBDIR}" ]; then
    echo "ERROR: ${LIBDIR} doesn't exist. Build wolfSSL first (see README)."
    exit 1
fi

# Find whichever artifact libtool produced.
STATIC_LIB="${LIBDIR}/libwolfssl.a"
IMPLIB="${LIBDIR}/libwolfssl.dll.a"

if [ -f "${STATIC_LIB}" ]; then
    LINK_ARG="${STATIC_LIB}"
    echo "[*] Linking against static: ${STATIC_LIB}"
elif [ -f "${IMPLIB}" ]; then
    LINK_ARG="-L${LIBDIR} -lwolfssl"
    echo "[*] Linking against DLL import lib: ${IMPLIB}"
else
    echo "ERROR: no libwolfssl.a or libwolfssl.dll.a under ${LIBDIR}."
    echo "       Contents:"
    ls -la "${LIBDIR}" || true
    echo
    echo "Rebuild wolfSSL with static lib + X9.146 dual-alg cert support:"
    echo "  cd ${WOLFSSL_DIR}"
    echo "  make clean"
    echo "  ./configure --enable-static --disable-shared \\"
    echo "      --enable-tls13 --enable-dilithium --enable-mlkem \\"
    echo "      --enable-ecc --enable-dual-alg-certs \\"
    echo "      --enable-certgen --enable-certreq --enable-certext \\"
    echo "      --enable-sha3 --enable-shake128 --enable-shake256 \\"
    echo "      --enable-experimental \\"
    echo "      CFLAGS=\"-DWOLFSSL_DILITHIUM_SMALL -DWOLFSSL_WC_DILITHIUM -DWOLFSSL_DUAL_ALG_CERTS\""
    echo "  make -j\$(nproc)"
    exit 1
fi

# PQ_LEVEL selects the ML-DSA parameter set baked into the chain:
#   2 -> ML-DSA-44  (default, matches paper baseline)
#   3 -> ML-DSA-65
#   5 -> ML-DSA-87
# Override on the command line:  PQ_LEVEL=3 ./build_wolfssl_gen.sh
PQ_LEVEL="${PQ_LEVEL:-2}"
echo "[*] PQ_LEVEL = ${PQ_LEVEL}"

echo "[*] Compiling gen_pq_chain_wolfssl..."
gcc -O2 -Wall -Wextra \
    -DPQ_LEVEL=${PQ_LEVEL} \
    -I"${WOLFSSL_DIR}" \
    gen_pq_chain_wolfssl.c \
    ${LINK_ARG} \
    -o gen_pq_chain_wolfssl.exe \
    -lws2_32 -lbcrypt -lcrypt32 -ladvapi32

# If we linked against the DLL, copy it next to the .exe so loader finds it.
if [ -z "${STATIC_LIB}" ] || [ ! -f "${STATIC_LIB}" ]; then
    DLL=$(ls "${LIBDIR}"/libwolfssl-*.dll 2>/dev/null | head -1 || true)
    if [ -n "${DLL}" ]; then
        cp -f "${DLL}" ./
        echo "[*] Copied $(basename "${DLL}") next to the .exe"
    fi
fi

echo "[*] Built ./gen_pq_chain_wolfssl.exe"
echo "[*] Running..."
./gen_pq_chain_wolfssl.exe
