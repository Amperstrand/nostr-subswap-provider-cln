#!/usr/bin/env bash
# mine-nonce.sh — mine the electrum announcement PoW nonce for a nostr
# pubkey using the nostr-pow-bench toolbox (rust miner: ~90 s/core at 30
# bits; cuda exists but the GPU is a co-tenant). The plugin's config
# fail-louds if ANN_POW_NONCE doesn't reach ANN_POW_TARGET_BITS, so a
# wrong/nonmatching nonce is caught at startup, not on the wire.
#
# Usage: scripts/mine-nonce.sh <nostr_pubkey_xonly_64hex> [target_bits]
#   → prints ANN_POW_* env assignments (decimal + hex nonce forms)
set -euo pipefail

PUBKEY="${1:?usage: mine-nonce.sh <pubkey_xonly_64hex> [target_bits]}"
TARGET="${2:-30}"
MINER="$(dirname "$0")/../../nostr-pow-bench/rust/target/release/powminer"

[[ "$PUBKEY" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "pubkey must be 64 hex chars (x-only)" >&2; exit 1; }
[ -x "$MINER" ] || { echo "miner missing at $MINER — build ../nostr-pow-bench (cd rust && cargo build --release)" >&2; exit 1; }

echo "mining ${TARGET} bits for ${PUBKEY} (rust miner; ≈90 s/core at 30 bits)…" >&2
RESULT="$("$MINER" --mine --pubkey "$PUBKEY" --target "$TARGET" --start 00)"
NONCE_HEX="$(echo "$RESULT" | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["found"], r; print(r["nonce"])')"
"$MINER" --verify --pubkey "$PUBKEY" --nonce "$NONCE_HEX" >/dev/null \
  || { echo "mined nonce failed verification — toolbox bug, aborting" >&2; exit 1; }
NONCE_DEC="$((16#${NONCE_HEX}))"

echo "ANN_POW_NONCE=$NONCE_DEC"
echo "ANN_POW_NONCE=0x${NONCE_HEX}"
echo "ANN_POW_TARGET_BITS=$TARGET"
