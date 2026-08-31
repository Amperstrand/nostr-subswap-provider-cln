# DESIGN-D2-PREPAYMENT: Anti-Jamming Prepayment for Reverse Swaps

**Status:** Design draft. Not implemented.
**Grounded in:** security-analysis-2026-08-30.md, hold-invoice-analysis.md,
AGENTS.md R1-R9, submarine_swaps.py d1/d2 flows.

## Problem

D2 (reverse swaps, `is_reverse=True`) has **zero attacker-cost coverage**.
Per security-analysis-2026-08-30.md: d2 prepayment is absent; the prepay
mechanism exists only for d1. An attacker can register fake invoices or
create swaps they never fund, causing our node to:
- Park payment attempts in `invoices_to_pay` (serial 15-attempt retries,
  O5), consuming outbound LN liquidity slots.
- Occupy monitoring state per swap until locktime expiry.
- Cost to attacker: zero (no onchain funds committed until lockup).

D1 avoids this via R4: a prepay hold invoice (`claim_fee * 2`) bundled
with the main hold invoice via `bundle_payments`. The hold-invoice
callback fires only when BOTH are fully paid (submarine_swaps.py:459),
so partial-sets never trigger funding (verified the hard way: FINDINGS.md
F8, 10 dead swaps).

## What D2 Prepay Binds Against

In d2, the client's cost is already onchain (they must fund the lockup).
The jam is *before* funding: registering invoices / creating swaps that
park our LN payment machinery. The prepay binds against:
1. **Monitoring slots** — each fake swap occupies expiry-monitor state
   until locktime + cleanup.
2. **`invoices_to_pay` parking** — a registered invoice triggers serial
   pay attempts (pay_pending_ln_invoices, 15-attempt cap, O5).
3. **Hold-invoice creation cost** — we generate preimage+payment_hash;
   registering their invoice against our hash is free for the attacker.

## Mechanism Options

### (1) Prepay LN hold invoice (RECOMMENDED)
Client pays a prepay hold invoice (hash we know preimage of — settles
only if we claim their lockup; cancelled at refund-time) BEFORE we
accept `server_add_swap_invoice`.

**Amount:** `max(claim_fee * 2, MIN_D2_PREPAY)` where `claim_fee` is the
onchain claim tx fee estimate and `MIN_D2_PREPAY` is a floor (e.g.
500 sats). Rationale: d1 uses `claim_fee * 2` (covers our claim-fee
risk if client vanishes after paying d1 invoices); d2 prepay covers
monitoring + pay-attempt slot cost, which is lower but nonzero.

**Lifecycle:**
- `create_reverse_swap`: return prepay bolt11 alongside redeem
  script + onchain amount. Prepay uses a separate preimage we generate.
- `server_add_swap_invoice`: reject if prepay is unpaid. Park prepay
  payment_hash in swap state.
- On claim (`_claim_swap`, submarine_swaps.py:434-444): settle prepay
  hold invoice (we know preimage). This refunds the client's prepay
  atomically with the swap completing.
- On expiry/refund (locktime approaching, time-based fallback #37):
  `cancelholdinvoice` on the prepay. Client's HTLCs return; prepay
  funds return to client.
- Prepay expiry: 300s (matches d1). CLN auto-expires hold invoices
  at CLTV deadline; the expiry monitor (#37) fires cleanup before
  locktime.

**CLN API calls (via clnrest, keyed params):**
- `holdinvoice amount=<prepay_sat>msat description=d2-prepay-<swap_id>`
- `cancelholdinvoice payment_hash=<prepay_hash>` (refund path)

**Interaction with hard requirements:**
- R1 (no unconfirmed spend): unaffected — prepay is LN-side only.
- R2 (no underfunded claim): unaffected — prepay settles AFTER
  successful claim.
- R3 (don't sit on confirmed lockup): unaffected — prepay settlement
  is post-claim, CLTV cleanup handles the reverse.
- R4 (bundle coupling): not applicable — d2 has no bundle_payments;
  prepay is validated as a prerequisite in `server_add_swap_invoice`.
- R6 (fresh payment_hash): prepay gets its own fresh hash via
  `_require_fresh_payment_hash`.

### (2) Spread widening (onchain amount padding)
Punish honest clients by inflating the spread. Worse UX, doesn't bind
against fake swaps that never fund (the attacker never pays the
spread). **Rejected.**

### (3) Per-client rate limiting via datastore
Track swap attempts per pubkey; reject after N pending. Weaker: no
economic cost to attacker rotating keys. Complementary, not sufficient.

## Failure / Cleanup Paths

| Scenario | Action |
|---|---|
| Client pays prepay, vanishes before `server_add_swap_invoice` | Prepay expires at 300s CLTV. No swap state created. |
| Client pays prepay, submits invoice, never funds lockup | Expiry monitor (#37) fires `cancelholdinvoice` on prepay near locktime. Swap state cleaned. |
| Prepay expires before client pays | Swap rejected at `server_add_swap_invoice`. No state. |
| Client funds lockup, we claim, prepay settlement fails | OPEN QUESTION: can settlement fail if HTLC already returned? |

## Threat Table

| Attack | Prepay effect | Residual |
|---|---|---|
| #12 liquidity jam (fake invoices) | Attacker must pay prepay (claim_fee*2) per attempt. Cost is now positive. | Rotating keys still cheap; pair with (3) rate limiting. |
| Fake swap creation (no invoice) | No prepay created until `server_add_swap_invoice`. Monitoring cost remains. | Time-limited by locktime; expiry monitor cleans. |
| #10 batch theft (datastore read) | Unaffected — prepay doesn't touch secrets. | HSM split (#36) is the fix. |
| #25 block-gap expiry race | Unaffected — prepay uses same time-based monitor. | Already mitigated by #37. |

## What This Does NOT Fix

- The **race windows** from hold-invoice-analysis.md (HTLC cancellation
  between park and irrevocable commitment) stay until PTLC (#40).
- A malicious server that skips payment (hold-invoice-analysis: "A
  malicious server that skips the payment breaks the chain"). Our
  prepay settles AFTER claim, so the client is refunded if we don't
  claim — but if we claim and fail to settle, that's a new bug.
- #10 protocol limitation (Bitcoin Script cannot express branch expiry).

## Open Questions

- Exact `MIN_D2_PREPAY` floor: needs measurement of monitoring cost
  per swap. 500 sats is a guess.
- Should prepay be refundable (hold invoice) or forfeit (regular
  invoice)? Hold invoice is strictly better (refunds on our failure)
  but adds a hold-invoice to manage.
- Whether to bundle prepay settlement with claim in a single
  clnrest round-trip or allow async settlement.
