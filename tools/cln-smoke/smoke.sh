#!/bin/bash
# smoke.sh — the 9452 crash-window demo against a BUILT image, run
# INSIDE a container on the regtest-lab network (see README.md).
# Verdicts: CRASH-REPRODUCED (unfixed) | TYPED-ERROR (fixed) | other.
# NOTE: pyln regression tests are the authoritative harness; this is
# the docker/demo leg.
set -u
LD=/tmp/ld
rm -rf "$LD"; mkdir -p "$LD"
BC="bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass -rpcwallet=labwallet"
CLI="lightning-cli --network=regtest --lightning-dir=$LD"

lightningd --network=regtest --lightning-dir="$LD" \
  --bitcoin-rpcconnect=bitcoind --bitcoin-rpcuser=user --bitcoin-rpcpassword=pass \
  --min-emergency-msat=25000sat --log-level=info --daemon --log-file=/tmp/ld.log
for i in $(seq 1 30); do $CLI getinfo >/dev/null 2>&1 && break; sleep 1; done
$CLI getinfo >/dev/null 2>&1 || { echo "UNEXPECTED: node never came up"; exit 2; }

# funding via listfunds discovery (gettransaction-details parsing is a
# shape trap; the node's own view of its UTXOs is the robust source)
$BC sendtoaddress "$($CLI newaddr bech32 | python3 -c 'import json,sys; print(json.load(sys.stdin)["bech32"])')" 0.0006 >/dev/null
$BC generatetoaddress 1 "$($BC getnewaddress)" >/dev/null
for i in $(seq 1 30); do [ "$($CLI listfunds | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["outputs"]))')" = "1" ] && break; sleep 1; done
SELECTED=$($CLI listfunds | python3 -c 'import json,sys; o=json.load(sys.stdin)["outputs"][0]; print(f"{o[\"txid\"]}:{o[\"output\"]}")')
# the window opener: a SECOND output, 100 sat under the 25k reserve,
# left UNSELECTED (the explicit-utxo call below never passes it)
$BC sendtoaddress "$($CLI newaddr bech32 | python3 -c 'import json,sys; print(json.load(sys.stdin)["bech32"])')" 0.00024900 >/dev/null
$BC generatetoaddress 1 "$($BC getnewaddress)" >/dev/null
for i in $(seq 1 30); do [ "$($CLI listfunds | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["outputs"]))')" = "2" ] && break; sleep 1; done

echo "--- the kill call: utxopsbt 59500sat (no excess_as_change), shortfall 100 < dust"
OUT=$(timeout 40 $CLI utxopsbt 59500sat 253perkw 100 "$SELECTED" \
  reserve=0 excess_as_change=false opening_anchor_channel=true 2>&1)
RC=$?
echo "rc=$RC out=$(echo "$OUT" | head -c 300)"
sleep 2
if ! $CLI getinfo >/dev/null 2>&1; then
  echo "VERDICT: CRASH-REPRODUCED (daemon died on the call)"
  exit 1
fi
if [ $RC -ne 0 ]; then
  echo "VERDICT: TYPED-ERROR (daemon alive, rpc refused cleanly)"
  exit 0
fi
echo "VERDICT: FUNDED (unexpected in the window — inspect)"
exit 3
