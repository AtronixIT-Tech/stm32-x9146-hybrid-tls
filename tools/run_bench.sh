#!/usr/bin/env bash
# Run a single X9.146 handshake then a 100-handshake benchmark against
# the STM32 server at 192.168.0.100:443.  Safe to paste-fail into:
# every check is scoped to this script, so your shell stays alive.

WOLFSSL="${WOLFSSL:-$HOME/wolfssl}"
TOOLS="${TOOLS:-/d/STM32CubeIDE/workspace_1.19.0/TLS_X9/tools}"
CLIENT="$WOLFSSL/examples/client/client.exe"
ROOT="$TOOLS/out/root_cert.pem"
HOST="${HOST:-192.168.0.100}"
PORT="${PORT:-443}"
N="${N:-100}"

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "[*] client      = $CLIENT"
echo "[*] trust root  = $ROOT"
echo "[*] server      = $HOST:$PORT"
echo "[*] N           = $N"
echo

[ -x "$CLIENT" ] || fail "client not built at $CLIENT"
[ -f "$ROOT"   ] || fail "trust anchor not found at $ROOT"

# The wolfSSL example client opens "./certs/client-cert.pem" etc. relative
# to the CWD, even when -A overrides the trust anchor.  Run it from the
# wolfSSL source tree so those default paths resolve.
cd "$WOLFSSL" || fail "cannot cd to $WOLFSSL"
[ -d ./certs ] || fail "no ./certs dir under $WOLFSSL (is this a wolfSSL source tree?)"

echo "[*] ping $HOST ..."
ping -n 1 "$HOST" >/dev/null 2>&1 || fail "$HOST not pingable (check ETH cable / board power)"
echo "    OK"
echo

echo "=== single handshake ==="
"$CLIENT" -h "$HOST" -p "$PORT" -v 4 -A "$ROOT" -g
rc=$?
if [ $rc -ne 0 ]; then
  fail "single handshake failed (rc=$rc)"
fi
echo "=== single handshake OK ==="
echo

echo "=== $N-handshake benchmark ==="
t0=$(date +%s)
for i in $(seq 1 "$N"); do
  "$CLIENT" -h "$HOST" -p "$PORT" -v 4 -A "$ROOT" -g >/dev/null 2>&1
  rc=$?
  if [ $rc -ne 0 ]; then
    fail "handshake $i failed (rc=$rc)"
  fi
  if [ $((i % 10)) -eq 0 ]; then
    printf "  %d/%d\n" "$i" "$N"
  fi
done
t1=$(date +%s)
echo "=== $N handshakes done in $((t1 - t0)) s (wall-clock, client-side) ==="
echo "    Read the STM32 UART for HANDSHAKE BENCHMARK SUMMARY."
