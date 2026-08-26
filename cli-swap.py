#!/usr/bin/env python3
"""cli-swap -- the educational swap walker (design 13, NOSTR-SWAP.md).

Walks a user through an onchain->offchain swap step by step, mirroring
the website's flow while printing the actual state machine as it runs:
every state says what to watch for and what an attacker would try
here.  DRY: it drives the SAME client-mode implementation the plugin
runs (via the swapclient-* RPCs over clnrest), so the walkthrough can
never drift from the executable truth.

Default is DRY-RUN: discovers providers, quotes, prints the full
state-machine diagram with the path highlighted -- and stops before
any payment.  --execute moves real (testnet/signet) sats.

Usage:
  python3 cli-swap.py --port 3025 --rune <rune> --amount 50000
  python3 cli-swap.py ... --dry-run          (default)
  python3 cli-swap.py ... --execute
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time

STEPS = [
    ("discover", "Discover providers over nostr (kind 30315 + PoW gate)"),
    ("quote", "Quote the swap from the provider's live offer"),
    ("request", "Send the createswap DM (NIP-04, kind 25582)"),
    ("validate", "Validate the reply (script, keys, locktime, amounts)"),
    ("pay", "Pay prepay + main invoices (HTLCs park at the provider)"),
    ("lockup", "Wait for the provider's onchain lockup to confirm"),
    ("claim", "Claim onchain -- this reveals the preimage (atomic!)"),
    ("done", "Claim confirmed; parked HTLCs settle; swap complete"),
]

DIAGRAM = """
                 +-----------+
                 |   Idle    |
                 +-----+-----+
                       | NodeBalanceSwapper proposes (or you, here)
                       v
                 +-----------+     no eligible offer
                 | Solicit   +------------------------+
                 +-----+-----+                        |
                       | offers found                 v
                       v                        +-----------+
                 +-----------+                  |  Refused  |
                 |  Quoted   |                  | (retry)   |
                 +-----+-----+                  +-----------+
                       | createswap DM
                       v
                 +-----------+  timeout/error   +-----------+
                 | SwapSent  +----------------->|  Refused  |
                 +-----+-----+                  +-----------+
                       | reply arrives
                       v
                 +-----------+  script/keys/     +-----------+
                 |Validating +---locktime/amt--->|  Refused  |
                 +-----+-----+   gate fails      +-----------+
                       | all gates pass
                       v
                 +-----------+  payment fails    +-----------+
                 |  Paying   +------------------>| Reduced / |
                 +-----+-----+                  |  Refused  |
                       | both invoices parked    +-----------+
                       v
                 +-----------+  provider stalls  +-----------+
                 | LockupWait+------------------>| CLTV fail |
                 +-----+-----+                  | (funds ok)|
                       | lockup confirmed        +-----------+
                       v
                 +-----------+  broadcast fails  +-----------+
                 | Claiming  +------------------>|  Stuck    |
                 +-----+-----+                  | (manual)  |
                       | claim confirmed         +-----------+
                       v
                 +-----------+
                 |  Claimed  |  onchain sats ours; preimage public
                 +-----------+  -> parked HTLCs settle atomically
"""


def rpc(port, rune, method, params):
    r = subprocess.run(
        ["curl", "-sS", "-m", "420", "-X", "POST",
         f"http://127.0.0.1:{port}/v1/{method}",
         "-H", "Rune: " + rune,
         "-H", "Content-Type: application/json",
         "-d", json.dumps(params)],
        capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"raw": r.stdout[:300]}


def say(step_i, msg):
    tag = f"[{step_i + 1}/{len(STEPS)}]" if step_i is not None else "     "
    print(f"{tag} {msg}", flush=True)


def explain(step_key):
    """What this state means + what an attacker tries here (the
    user-facing mirror of the hard-requirements list)."""
    return {
        "discover": "attacker tries: publishing fake offers with 0 proof-of-work;\n"
                    "     the PoW gate makes spam expensive",
        "quote": "attacker tries: bait-and-switch pricing; we re-quote from\n"
                 "     the LIVE offer at swap time, not a cached one",
        "request": "the DM is NIP-04 encrypted to the provider's key and\n"
                   "     signed with ours -- relays can't tamper silently",
        "validate": "THE safety gate: the script must pay OUR hash + OUR claim\n"
                    "     key, locktime (little-endian!) must equal the declared\n"
                    "     timeout, address must match the script. A forged refund\n"
                    "     window here = the advisory-14 attack",
        "pay": "your HTLCs park at the provider's HOLD invoice -- they cannot\n"
               "     settle until the preimage is public (atomic), and they\n"
               "     return to you at their own CLTV if the swap stalls",
        "lockup": "wait for >=1 confirmation: spending an unconfirmed lockup\n"
                  "     hands the provider a free double-spend race",
        "claim": "the claim tx reveals the preimage in its witness -- this is\n"
                 "     the point of no return; the onchain+LN legs settle together",
        "done": "swap complete; only the prepay was ever at risk",
    }.get(step_key, "")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, required=True, help="clnrest port")
    ap.add_argument("--rune", required=True, help="clnrest rune")
    ap.add_argument("--amount", type=int, required=True,
                    help="Lightning sats to pay")
    ap.add_argument("--provider", default=None,
                    help="pin a provider pubkey (default: best quote)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", default=True,
                   help="walk through without paying (default)")
    g.add_argument("--execute", action="store_true",
                   help="move real sats")
    args = ap.parse_args()

    print(DIAGRAM)
    print(f"amount: {args.amount} sats   mode: "
          f"{'EXECUTE' if args.execute else 'DRY-RUN'}\n")

    # [1] discover
    say(0, STEPS[0][1])
    print(f"     {explain('discover')}")
    offers = rpc(args.port, args.rune, "swapclient-offers", {})
    if "error" in offers:
        print(f"     plugin said: {offers['error']}")
        print("     (is the plugin running with SWAP_MODE=client, and has")
        print("      it polled offers yet? first poll lands ~60s after start)")
        sys.exit(1)
    found = offers.get("offers", [])
    if not found:
        print("     no providers discovered yet -- retry in a minute")
        sys.exit(1)
    for o in found:
        mark = " <== best quote" if o == max(
            found, key=lambda x: x['max_reverse']) else ""
        print(f"     {o['pubkey'][:16]}... fee {o['fee_pct']}% + "
              f"{o['mining_fee']} sat, window [{o['min']}, "
              f"{o['max_reverse']}]{mark}")

    # [2] quote
    say(1, STEPS[1][1])
    print(f"     {explain('quote')}")
    best = max(found, key=lambda x: x['max_reverse'])
    est = best['fee_pct'] / 100 * args.amount + best['mining_fee']
    print(f"     estimated fee ~{int(est)} sat -> expect "
          f"~{args.amount - int(est)} sat onchain")

    if not args.execute:
        say(None, "DRY-RUN stops here -- rerun with --execute to swap.")
        for i in range(2, len(STEPS)):
            say(i, STEPS[i][1])
            print(f"     {explain(STEPS[i][0])}")
        sys.exit(0)

    # [3..7] execute via the plugin's gated client
    say(2, STEPS[2][1])
    print(f"     {explain('request')}")
    say(3, STEPS[3][1])
    print(f"     {explain('validate')}")
    say(4, STEPS[4][1])
    print(f"     {explain('pay')}")
    say(5, STEPS[5][1])
    print(f"     {explain('lockup')}")
    say(6, STEPS[6][1])
    print(f"     {explain('claim')}")
    params = {"amount_sat": args.amount}
    if args.provider:
        params["provider"] = args.provider
    res = rpc(args.port, args.rune, "swapclient", params)
    if "error" in res:
        print(f"     swap refused: {res['error']}")
        sys.exit(1)
    print(f"     swap live: hash {res['payment_hash'][:16]}...")
    print(f"     lockup address: {res['lockup_address']}")
    print(f"     onchain amount: {res['onchain_amount']} sat "
          f"(timeout block {res['timeout']})")

    # [8] monitor to completion
    say(7, STEPS[7][1])
    print(f"     {explain('done')}")
    deadline = time.time() + 1800
    while time.time() < deadline:
        st = rpc(args.port, args.rune, "swapclient-status", {})
        for s in st.get("swaps", []):
            if s["payment_hash"].startswith(res['payment_hash'][:16]):
                if s["state"] == "claimed":
                    print(f"     CLAIMED: {s['spending_txid']}")
                    print("     your parked HTLCs settled with the revealed"
                          " preimage.")
                    sys.exit(0)
        time.sleep(10)
    print("     not yet claimed -- keep watching swapclient-status")
    sys.exit(1)


if __name__ == "__main__":
    main()
