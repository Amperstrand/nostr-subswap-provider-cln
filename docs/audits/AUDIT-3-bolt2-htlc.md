# AUDIT-3: BOLT #2 HTLC / Hold-Invoice Semantics

## ROLE
You are a Lightning protocol auditor. You audit THIS repo's server-side
HTLC handling (hold invoices, MPP accumulation, expiry) against BOLT #2
and against the reference implementation.

## OBJECTIVE
Verdicts with file:line evidence for every HTLC-side MUST/SHOULD that
applies to a payment-RECEIVING node, plus port-divergence findings.

## INPUTS (read all)
- Spec: `/home/ubuntu/src/bolts/02-peer-protocol.md` (sections: Adding an
  HTLC, HTLC timeouts, Requirements around cltv_expiry, accepting/
  failing HTLCs) and `/home/ubuntu/src/bolts/04-onion-routing.md`
  (Payload Format: `payment_secret`, `total_msat`, MPP requirements)
- Impl:
  `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/invoices.py`
  (HoldInvoice, Htlc, HtlcState, is_fully_funded, cancel_expired_htlcs,
  settle) and
  `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/cln_lightning.py`
  (hold-invoice registration, callback dispatch, `monitor_expiries`,
  HTLC acceptance path, `check_invoice_expiry`, `bundle_payments`,
  `_htlc_accepted`-style hooks if present) and
  `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/submarine_swaps.py`
  (`hold_invoice_callback` ~line 459, `pay_pending_ln_invoice`)
- Reference: `/home/ubuntu/src/electrum/electrum/lnworker.py` (hold
  invoice machinery: get_hold_invoice, hold_invoice_callback,
  bundle_payments, check_invoice_expiry) and
  `/home/ubuntu/src/electrum/electrum/submarine_swaps.py` — the port
  source; divergences here are the #1 historical bug class in this repo
  (5 of today's 8 bugs were port divergences)

## METHOD
1. Enumerate the receiving-node requirements: multiple HTLCs same hash
   (MUST allow), cltv_expiry bounds (<500000000), amount vs
   htlc_minimum_msat, timeout deadline discipline (a receiving node
   MUST settle/fail before cltv_expiry — how close to expiry do we
   cancel? `MIN_LOCKTIME_DELTA` handling), MPP partial-set semantics
   (payment_secret + total_msat matching).
2. For each: verdict + evidence in OUR code.
3. Port-divergence sweep: for each function in our invoices.py /
   cln_lightning.py hold-invoice section, diff the LOGIC against
   electrum's counterpart (not line-by-line — semantic). Flag anything
   electrum does that we dropped (e.g. prepay bundling coupling,
   expiry checks, retry caps).
4. Crash-safety: what happens on plugin restart mid-payment? Are HTLC
   states persisted (json_db) and re-registered? A restart that parks
   payer funds violates R5 in this repo's AGENTS.md.
5. The prepay bundle: electrum couples prepay+main MPP sets so the hold
   callback fires only when BOTH complete (FINDINGS.md F8). Verify our
   `bundle_payments` + callback preserve that coupling.

## VERDICT FORMAT
Same as AUDIT-1 (H-<n> numbering).

## OUTPUT
Write to `/home/ubuntu/src/nostr-subswap-provider-cln/docs/audits/results/AUDIT-3-bolt2-htlc.md`
(header, table, PORT DIVERGENCES section, COVERAGE GAPS, FINDINGS
SUMMARY, `VERDICT:` line).
