#!/usr/bin/env python3
"""
corrupt_altsig.py  --  flip one byte in the leaf cert's ECDSA altSignatureValue
                       then rebuild Core/Inc/certs_pqc.h in place.

Usage:  python tools/corrupt_altsig.py          <- corrupt (for handshake test)
        python tools/corrupt_altsig.py --restore <- put original back

After running the corrupt path:
  1. Rebuild firmware in STM32CubeIDE (full clean build)
  2. Flash the board
  3. Run:  N=1 ./tools/run_bench.sh
  4. If the handshake fails with a verify error -> both alt-sigs were checked  PASS
     If the handshake succeeds               -> alt-sig was NOT checked       FAIL
Then run --restore and rebuild for normal operation.
"""

import sys
import base64
import re
import os

TOOLS_OUT   = os.path.join(os.path.dirname(__file__), "out")
CHAIN_PEM   = os.path.join(TOOLS_OUT, "chain_cert.pem")
ORIG_CHAIN  = os.path.join(TOOLS_OUT, "chain_cert_orig.pem")   # backup
CERTS_H     = os.path.join(os.path.dirname(__file__), "..", "Core", "Inc", "certs_pqc.h")

# OID 2.5.29.74 (altSignatureValue) as it appears inside a DER OID TLV: 06 03 55 1d 4a
ALT_SIG_OID_TLV = bytes([0x06, 0x03, 0x55, 0x1d, 0x4a])


def read_len(der, pos):
    """Return (length_value, new_pos) after consuming a DER length at der[pos]."""
    if der[pos] & 0x80 == 0:
        return der[pos], pos + 1
    n = der[pos] & 0x7f
    val = int.from_bytes(der[pos+1:pos+1+n], 'big')
    return val, pos + 1 + n


def find_altsig_sig_offset(der: bytearray) -> int:
    """
    Locate the first byte of the ECDSA signature payload inside
    the leaf certificate's altSignatureValue extension.
    Returns the byte offset to flip (inside the r INTEGER value).
    """
    idx = der.find(ALT_SIG_OID_TLV)
    if idx == -1:
        raise ValueError("altSignatureValue OID (2.5.29.74) not found in certificate DER")

    pos = idx + len(ALT_SIG_OID_TLV)   # just after the OID TLV

    # Optional: BOOLEAN (critical flag) — skip if present
    if der[pos] == 0x01:                # BOOLEAN tag
        _, pos = read_len(der, pos + 1)

    # OCTET STRING (extnValue wrapper)
    if der[pos] != 0x04:
        raise ValueError(f"Expected OCTET STRING (0x04) at {pos}, got {hex(der[pos])}")
    _, pos = read_len(der, pos + 1)

    # BIT STRING (altSignatureValue is encoded as a BIT STRING)
    if der[pos] != 0x03:
        raise ValueError(f"Expected BIT STRING (0x03) at {pos}, got {hex(der[pos])}")
    _, pos = read_len(der, pos + 1)

    # Skip unused-bits octet (always 0x00 for DER)
    if der[pos] != 0x00:
        raise ValueError(f"Expected 0x00 unused-bits byte at {pos}, got {hex(der[pos])}")
    pos += 1

    # SEQUENCE  (ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER })
    if der[pos] != 0x30:
        raise ValueError(f"Expected SEQUENCE (0x30) at {pos}, got {hex(der[pos])}")
    _, pos = read_len(der, pos + 1)

    # INTEGER r — tag + length, then flip the first data byte
    if der[pos] != 0x02:
        raise ValueError(f"Expected INTEGER (0x02) at {pos}, got {hex(der[pos])}")
    pos += 1
    r_len, pos = read_len(der, pos)
    # If r has a leading 0x00 padding byte (positive sign), skip it
    if der[pos] == 0x00:
        pos += 1

    return pos   # byte to flip


def pem_to_der(pem_block: str) -> bytearray:
    b64 = re.sub(r'-----[^-]+-----|\s', '', pem_block)
    return bytearray(base64.b64decode(b64))


def der_to_pem(der: bytearray, label: str = "CERTIFICATE") -> str:
    b64 = base64.b64encode(bytes(der)).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def split_pem_certs(pem_text: str) -> list:
    """Return list of individual PEM certificate blocks."""
    return re.findall(
        r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
        pem_text, re.DOTALL
    )


def pem_to_c_array(name: str, pem_text: str) -> str:
    data = pem_text.encode('ascii')
    items = [f'0x{b:02x}' for b in data]
    lines = ['  ' + ', '.join(items[i:i+16]) for i in range(0, len(items), 16)]
    body = ',\n'.join(lines)
    return (
        f"unsigned char {name}[] = {{\n{body}\n}};\n"
        f"unsigned int {name}_len = {len(data)};\n"
    )


def corrupt():
    # Back up original chain if not already done
    if not os.path.exists(ORIG_CHAIN):
        import shutil
        shutil.copy(CHAIN_PEM, ORIG_CHAIN)
        print(f"[*] Backed up original chain to {ORIG_CHAIN}")

    with open(CHAIN_PEM, 'r') as f:
        chain_pem_text = f.read()

    certs = split_pem_certs(chain_pem_text)
    if len(certs) < 2:
        raise ValueError(f"Expected at least 2 certs in chain, found {len(certs)}")

    leaf_pem  = certs[0]
    rest_pems = certs[1:]

    leaf_der = pem_to_der(leaf_pem)
    offset   = find_altsig_sig_offset(leaf_der)
    original = leaf_der[offset]
    leaf_der[offset] ^= 0xff
    print(f"[*] Flipped byte at DER offset {offset}: 0x{original:02x} -> 0x{leaf_der[offset]:02x}")

    corrupted_leaf_pem   = der_to_pem(leaf_der)
    corrupted_chain_text = corrupted_leaf_pem + "\n".join(rest_pems) + "\n"

    with open(CHAIN_PEM, 'w') as f:
        f.write(corrupted_chain_text)
    print(f"[*] Wrote corrupted chain to {CHAIN_PEM}")

    rebuild_certs_h(corrupted_chain_text)
    print("[*] Done. Rebuild firmware (full clean build), flash, then run: N=1 ./tools/run_bench.sh")
    print("    Handshake fail -> PASS (both sigs verified)")
    print("    Handshake ok   -> FAIL (alt sig not checked)")


def restore():
    if not os.path.exists(ORIG_CHAIN):
        print("[!] No backup found — nothing to restore.")
        return

    with open(ORIG_CHAIN, 'r') as f:
        orig = f.read()
    with open(CHAIN_PEM, 'w') as f:
        f.write(orig)
    os.remove(ORIG_CHAIN)
    print(f"[*] Restored original {CHAIN_PEM}")

    rebuild_certs_h(orig)
    print("[*] Done. Rebuild firmware to return to normal operation.")


def rebuild_certs_h(chain_pem_text: str):
    """Replace only the chain_cert_pem[] array in certs_pqc.h."""
    with open(CERTS_H, 'r') as f:
        header = f.read()

    new_array = pem_to_c_array("chain_cert_pem", chain_pem_text)

    # Replace from 'unsigned char chain_cert_pem' up to and including 'chain_cert_pem_len = N;'
    header = re.sub(
        r'unsigned char chain_cert_pem\[\].*?unsigned int chain_cert_pem_len = \d+;',
        new_array.rstrip(),
        header, flags=re.DOTALL
    )

    with open(CERTS_H, 'w') as f:
        f.write(header)
    print(f"[*] Rebuilt {CERTS_H}")


if __name__ == "__main__":
    if "--restore" in sys.argv:
        restore()
    else:
        corrupt()
