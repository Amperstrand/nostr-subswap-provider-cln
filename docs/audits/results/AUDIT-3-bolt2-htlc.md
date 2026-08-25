# AUDIT-3 Result: BOLT #2 HTLC / Hold-Invoice Semantics

- Date: 2026-08-21
- Commit audited: `5004547` (2026-08-21)
- Auditor: AI protocol auditor (AUDIT-3 prompt, executed as written)
- Files read:
  - Spec: `/home/ubuntu/src/bolts/02-peer-protocol.md` (Adding an HTLC, Forwarding
    HTLCs/HTLC timeouts, `cltv_expiry_delta` Selection), `/home/ubuntu/src/bolts/04-onion-routing.md`
    (Payload Format, Basic Multi-Part Payments, Failure Messages)
  - Impl: `swap-provider/plugin/invoices.py`, `swap-provider/plugin/cln_lightning.py`,
    `swap-provider/plugin/submarine_swaps.py`, `swap-provider/plugin/constants.py`,
    `swap-provider/plugin/json_db.py`
  - Reference: `/home/ubuntu/src/electrum/electrum/lnworker.py`,
    `/home/ubuntu/src/electrum/electrum/lnpeer.py` (`_check_unfulfilled_htlc`,
    `_check_accepted_final_htlc`, `_check_unfulfilled_htlc_set`),
    `/home/ubuntu/src/electrum/electrum/submarine_swaps.py`

Division of responsibility noted up front: this is a CLN *plugin*. Wire-level
BOLT #2 receiving checks (amount 0 / below `htlc_minimum_msat`, `cltv_expiry >=
500000000`, onion HMAC/TLV parse, duplicate `id` after reconnection) are enforced
by CLN core before `htlc_accepted` fires; the plugin only sees decoded HTLC+onion
dicts. Those MUSTs get N/A verdicts with that note. The plugin owns every
final-hop / MPP / hold-invoice semantic — that is where the findings are.

---

## Requirement verdicts (H-<n>)

### H-1: MUST allow multiple HTLCs with the same `payment_hash` (BOLT #2 line 2853)
Verdict: ✅
Evidence: `invoices.py:251-263` — `is_fully_funded` sums a *set* of same-hash
HTLCs (the `# BOLT #2:` quote block documents it); `cln_lightning.py:230-232`
adds each new distinct HTLC to `target_invoice.incoming_htlcs`.

### H-2: receiving `amount_msat` 0 or below own `htlc_minimum_msat` → SHOULD fail channel (BOLT #2 lines 2842-2845)
Verdict: N/A
Evidence: enforced by CLN core channel validation; plugin never sees such an
HTLC (`plugin_htlc_accepted_hook`, `cln_lightning.py:187`).

### H-3: `cltv_expiry` >= 500000000 → SHOULD fail channel (BOLT #2 lines 2848-2850)
Verdict: N/A
Evidence: CLN core commitment validation; no absolute-500000000 check exists or
is needed at plugin level.

### H-4: MUST decrypt onion and follow payload-reader requirements (BOLT #2 lines 2857-2862)
Verdict: ✅
Evidence: CLN core decrypts and hands the plugin the decoded payload
(`onion` dict, `cln_lightning.py:187`); the plugin implements the final-hop
reader checks below (H-7 … H-15).

### H-5: once `cltv_expiry` of an incoming HTLC has been reached (or is closer than the applicable delta): MUST fail that incoming HTLC (BOLT #2 lines 2591-2593)
Verdict: ⚠️
Evidence: receipt-time only — `cln_lightning.py:255-260` rejects HTLCs whose
`cltv_expiry_relative` is below the invoice's `min_final_cltv_expiry` (147) or
`MIN_FINAL_CLTV_DELTA_ACCEPTED` (144, `constants.py:40`). There is **no
height-based re-check while the set is parked**: electrum re-evaluates every
pending set on each htlc_switch pass and fails sets within
`MIN_FINAL_CLTV_DELTA_ACCEPTED` of expiry (`lnpeer.py:3103-3109`). Our parked
sets are bounded by invoice expiry (300 s) — safe on 10-min mainnet, but a
FUNDED main invoice parks for *hours* until the client's onchain claim, with no
CLTV-margin gate on the settle path. See PD-5.
Note: severity P1 (fast-blocks networks + late client claims can push settle
arbitrarily close to payer CLTV; no principal loss, force-close risk).

### H-6: fulfilling node MUST fail (and not forward) an HTLC whose fulfillment deadline is already past (BOLT #2 lines 2700-2702)
Verdict: ⚠️
Evidence: `HoldInvoice.settle`/`Htlc.settle` (`invoices.py:291-301`,
`172-181`) and `callback_handler` prepay settle (`cln_lightning.py:169-174`)
contain no CLTV/deadline check at all — only the `is_fully_funded` gate.
Electrum's equivalent settle gate is the per-set expiry re-check (H-5).
Severity P1, same root as PD-5.

### H-7: `payment_secret` missing or not matching expected for that `payment_hash` → MUST fail the HTLC with `incorrect_or_unknown_payment_details` (BOLT #4 lines 1526-1530)
Verdict: ✅ (with note)
Evidence: `cln_lightning.py:263-267` — `onion["payment_secret"] !=
decoded_invoice["payment_secret"]` → `htlc.fail()` → `400F`
(`invoices.py:156-163`).
Note (P2 cosmetic): comparison is `!=`, not constant-time; electrum uses
`util.constant_time_compare` (`lnpeer.py:2287`). Also our `400F`
`failure_message` is the bare 2-byte code without the 12 data bytes
(`u64 htlc_msat`, `u32 height`) the spec attaches (BOLT #4 lines 1364-1367;
electrum builds them at `lnpeer.py:2152-2154`). Payers' onion-error decoders
generally tolerate it, but it is non-conforming output. Same shape in the
tombstone fail at `cln_lightning.py:201-202`.

### H-8: amount paid less than amount expected → MUST fail the HTLC (BOLT #4 lines 1531-1533); MUST NOT fulfill any HTLCs of an incomplete set (BOLT #4 lines 402-405)
Verdict: ✅
Evidence: partial sets park — `is_fully_funded` (`invoices.py:251-263`)
requires `sum(ACCEPTED+SETTLED) >= amount_msat`; `HoldInvoice.settle` raises
`InsufficientFundedInvoiceError` on underfunded sets (`invoices.py:296-297`).
This is repo hard requirement R7 and it holds.

### H-9: amount paid more than twice the amount expected → SHOULD fail the HTLC with `incorrect_or_unknown_payment_details` (BOLT #4 lines 1536-1540)
Verdict: ❌
Evidence: no overpayment bound anywhere. `handle_htlc`
(`cln_lightning.py:220-281`) never reads `total_msat` or compares HTLC amount
to the invoice amount; `is_fully_funded` (`invoices.py:261-263`) accepts any
`sum >= amount`, and `settle` then settles **all** ACCEPTED HTLCs
(`invoices.py:298-300`). Electrum enforces `invoice_msat <= total_msat <=
2 * invoice_msat` (`lnpeer.py:2296-2298`). A single-HTLC overpay (or a
completing HTLC larger than the remainder) is settled in full — payer loses
the excess with no cap. Multi-part overpay is *partially* blocked by the
FUNDED gate (`cln_lightning.py:269-273` fails HTLCs arriving after
completion). Severity P2 (self-harm only — a malicious payer burns their own
sats — but the spec SHOULD exists exactly to catch sender bugs; dropped in
port). See PD-6.

### H-10: unknown `payment_hash` → MUST fail the HTLC with `incorrect_or_unknown_payment_details` (BOLT #4 lines 1534-1535)
Verdict: ⚠️
Evidence: `cln_lightning.py:195-204` — unknown, non-tombstoned hashes return
`{"result": "continue"}`, delegating the fail to CLN core (which fails unknown
payments itself); tombstoned (deleted/expired hold) hashes fail directly with
`400F` (`cln_lightning.py:196-202`, issue #25 fix — this is the correct
R5 shape). Delegation is functionally compliant; direct fail is what electrum
does for deleted payment info (`lnpeer.py:3178-3180`). P2 cosmetic: only the
tombstone path emits our own 400F.

### H-11: if `basic_mpp` supported: MUST add each HTLC to the HTLC set for that `payment_hash` (BOLT #4 line 396)
Verdict: ✅
Evidence: `Htlc.from_cln_dict` + `incoming_htlcs.add(htlc)`
(`cln_lightning.py:224-232`, `invoices.py:98-125`); invoices advertise
`BASIC_MPP_OPT` (`cln_lightning.py:449`).

### H-12: SHOULD fail the entire HTLC set if `total_msat` is not the same for all HTLCs in the set (BOLT #4 lines 397-399)
Verdict: ❌
Evidence: `total_msat` is never read anywhere in the plugin (grep: zero
references in `cln_lightning.py`/`invoices.py`; the only onion field consumed
is `payment_secret`, `cln_lightning.py:263`). Electrum checks uniformity per
set (`lnpeer.py:3070-3073`). Severity P2 (divergence; protects against payer
MPP bugs corrupting set accounting). See PD-6.

### H-13: if total `amt_to_forward` of the set >= `total_msat`: SHOULD fulfill all HTLCs in the set; if it fulfills any: MUST fulfill the entire set (BOLT #4 lines 400-401, 408-409)
Verdict: ✅
Evidence: completion is keyed on the invoice amount instead of `total_msat`
(equivalent for a compliant payer, see PD-6 for the edge), and fulfillment is
all-or-nothing: `HoldInvoice.settle` settles **every** ACCEPTED HTLC with the
preimage (`invoices.py:298-300`), `Htlc.settle` resolves each CLN request
(`invoices.py:172-181`). `_finish_normal_swap` settles after extracting the
preimage from the client's claim tx (`submarine_swaps.py:310-324`).

### H-14: incomplete set: MUST fail all HTLCs after a reasonable timeout; SHOULD wait >= 60 s; SHOULD use `mpp_timeout` (BOLT #4 lines 402-407)
Verdict: ⚠️
Evidence: timeout = invoice expiry 300 s (`add_normal_swap`,
`submarine_swaps.py:569-587`) enforced by `check_invoice_expiry` +
`cancel_all_htlcs` on a ≤10 s sweep (`cln_lightning.py:115-138`, `83-113`) —
satisfies ">= 60 s". But the failure code is `400F` (`Htlc.fail`,
`invoices.py:156-163`), not `mpp_timeout`: the `fail_timeout()`/`0017` path
(`invoices.py:164-171`) is **dead code in production** — `cancel_expired_htlcs`
(`invoices.py:273-289`) is called only from
`tests/test_hold_invoice_class.py:178,208`, never from `cln_lightning.py` or
`submarine_swaps.py`. Electrum times out incomplete sets at `MPP_EXPIRY = 120`
s (`lnworker.py:1004`, `lnpeer.py:3111-3118`) *before* invoice expiry, with
`MPP_TIMEOUT`. P2 interop: payers that re-split on `mpp_timeout` get a
terminal-looking `400F` instead. See PD-7.

### H-15: MUST require `payment_secret` for all HTLCs in the set (BOLT #4 line 408)
Verdict: ✅
Evidence: per-HTLC check `cln_lightning.py:263-267` — every HTLC of the set
must carry the invoice's secret or fail; combined with H-7 this covers the
set-level requirement.

---

## PORT DIVERGENCES (semantic diff vs electrum)

Numbered PD-<n>, severity: P0 funds-risk / P1 interop-or-conditional-funds /
P2 correctness/ops / P3 cosmetic. This is the highest-value section: 5 of 8
recent live bugs in this repo were port divergences.

### PD-1 (P0): prepay-expiry fall-through breaks the R4/F8 bundle coupling — server proceeds WITHOUT the prepay
Electrum: the callback gate is `is_payment_bundle_complete` — *all* sets of
the bundle (main + prepay) must be COMPLETE before anything settles or the
callback fires (`lnpeer.py:3206-3212`, `lnworker.py:2792-2809`). A client that
ignores `minerFeeInvoice` parks until MPP timeout and is refunded — the exact
F8 behavior (boltz-bridge AGENTS.md; FINDINGS.md F8).

Ours: the coupling lives only in `callback_handler`
(`cln_lightning.py:158-182`). When the main invoice is FUNDED, it looks up the
prepay; if the prepay hold is `None` **it falls through and fires the main
callback anyway**. `None` is treated as "settled-then-deleted … treat as
already redeemed" (comment at `cln_lightning.py:162-168`) — but no code path
deletes a settled prepay before the main callback (`_finish_normal_swap`
deletes both *after*; `_fail_swap` deletes both). The realistic producer of
`None` is the **expiry sweeper**: the prepay is its own HoldInvoice
(expiry 300 s, `submarine_swaps.py:580-587`); if the client never paid it,
`check_invoice_expiry` cancels and *deletes* it
(`cln_lightning.py:121-137`) while the FUNDED main invoice is skipped
(`funding_status not in [FUNDED, SETTLED]` guard). ≤ 5 s later
(`callback_handler` cadence) the funding tx is broadcast and the swap
completes with the prepay never collected.

Impact: main invoice amount = `lightning_amount - 2*claim_fee`
(`submarine_swaps.py:563-565`) while the onchain obligation is quoted from
the full `lightning_amount` — the server eats exactly the prepay (2 x
claim fee; ~8800 sats at the static 30 sat/vB fallback, ~1200 sats with the
fee oracle) per abused swap. Trigger client class exists in the wild: CLBOSS
ignores `minerFeeInvoice` (F8) — on electrum that behavior is harmless
(park→refund), on us it is a repeatable fee drain. Fix: distinguish
settled-and-deleted from expired-and-deleted (e.g. tombstone with status, or
check `get_payment_status`/prepay PR_PAID before proceeding; fail the main
set with `cancel_all_htlcs()` when the prepay expired unfunded).

### PD-2 (P1): settled-prepay deadlock parks the payer's HTLCs until CLTV (R5 class)
`callback_handler` (`cln_lightning.py:169-176`):
```python
if prepay_invoice is not None and prepay_invoice.funding_status is InvoiceState.FUNDED:
    prepay_invoice.settle(...)          # -> SETTLED, persisted
    ...
elif prepay_invoice is not None:
    continue                            # "not yet funded, wait"
```
A prepay in state **SETTLED** matches neither branch's first condition and
hits `continue` forever. Reachable when the plugin dies between
`update_invoice(prepay_invoice)` (SETTLED persisted to json_db) and
`callback(...)` — narrow crash window, but the consequence is permanent: the
main callback never fires, the FUNDED main invoice never expires
(`check_invoice_expiry` skips FUNDED/SETTLED, `cln_lightning.py:121-122`), and
the payer's parked HTLCs sit until their own CLTV. This is the same bug class
as the fixed "ln_to_onchain swaps hung in swap.created 30+ min" incident (the `None`
sibling was patched; the SETTLED sibling was not). Fix: treat SETTLED (or
preimage-known) prepay as redeemed and proceed.

### PD-3 (P1): `monitor_expiries` aborts the whole sweep on one bad invoice — and restart-stale HTLCs guarantee one
`Htlc.fail()` asserts `request_callback is not None` (`invoices.py:160`).
After a restart, persisted HTLCs load with `request_callback=None`
(`invoices.py:135,150`) and only regain a callback when CLN *replays* them
(`handle_htlc` find_htlc re-attach, `cln_lightning.py:225-229`). HTLCs that
were resolved while the plugin was down are never replayed. When such an
invoice expires, `cancel_all_htlcs` → `Htlc.fail()` → `AssertionError` →
caught by the blanket `except Exception` around the **entire for-loop**
(`cln_lightning.py:111-112`), which sleeps 10 s and restarts the sweep from
the top — every pass dies on the same invoice, and every hold invoice *after*
it in dict order never gets expiry-processed (payer funds park until CLTV).
The bool-purge guard (`cln_lightning.py:97-104`, earned bug `be5a97e`) fixed
one instance of exactly this starvation class; the callback-None assert is
another instance. Fix: per-invoice try/except inside the loop, and make
`fail()`/`settle()` tolerate callback-less HTLCs (log + drop from the set).

### PD-4 (P2): replayed already-SETTLED HTLC never gets re-resolved — hook request hangs
On replay of an HTLC we already settled (crash between our `set_result` and
CLN committing the fulfillment), `handle_htlc` finds the stored HTLC and
re-attaches the new request (`cln_lightning.py:225-229`, returns False) — but
nothing ever calls `set_result` on it, because `Htlc.settle` requires
ACCEPTED state (`invoices.py:174-175`) and the stored state is SETTLED. CLN
holds the HTLC pending until CLTV. Narrow crash window; payer-side park, no
principal loss. Fix: on re-attach, if stored state is SETTLED/CANCELLED,
re-issue the same resolution on the fresh request.

### PD-5 (P1): no height-based CLTV re-check while parked (dropped electrum per-set check)
Electrum re-evaluates every unfulfilled set each pass and fails any set whose
`blocks_to_expiry < accepted_expiry_delta` (`lnpeer.py:3103-3109`), and
per-HTLC at acceptance (`lnpeer.py:2229-2235`, plus the
`min_final_cltv_delta` check at `2272-2277`). Ours checks CLTV once at
receipt (`cln_lightning.py:255-260`) and never again: no check in
`callback_handler`, `HoldInvoice.settle`, or `_finish_normal_swap`. A FUNDED
main invoice legitimately parks for hours (until the client's onchain claim);
on fast-block networks (mutinynet: 147-block final CLTV ≈ 73 min) a late
claim lets us settle with minutes of CLTV margin left — the force-close race
BOLT #2's "fulfillment deadline" requirement exists to prevent. Fix: record
each HTLC's absolute `cltv_expiry`, refuse settle/continue past
`MIN_FINAL_CLTV_DELTA_ACCEPTED`.

### PD-6 (P2): `total_msat` dropped from the port entirely
Electrum validates: total_msat present (`lnpeer.py:2155-2157`), uniform
across the set (`3070-3073`), within `[invoice_msat, 2*invoice_msat]`
(`2296-2298`), and uses it as the completion threshold (`3157-3162`). Ours
reads only `onion["payment_secret"]` (`cln_lightning.py:263`); completion is
`sum(htlcs) >= invoice.amount_msat` (`invoices.py:261-263`). Consequences:
no overpay bound (H-9), no set-uniformity check (H-12), and
`amt_to_forward > htlc.amount_msat` (electrum
`lnpeer.py:2166-2172`, `FINAL_INCORRECT_HTLC_AMOUNT`) unchecked. All
payer-side error handling; P2. Fix: read `onion["total_msat"]` in
`handle_htlc`, enforce uniformity + the 2x bound.

### PD-7 (P2): MPP timeout semantics — 120 s/mpp_timeout became 300 s/400F; the mpp_timeout path is dead code
Electrum: `MPP_EXPIRY = 120` (`lnworker.py:1004`), failed with
`MPP_TIMEOUT` (`lnpeer.py:3111-3118`). Ours: incomplete sets die only at
invoice expiry (300 s) via `cancel_all_htlcs` → `400F`; `fail_timeout`
(`0017`) and `cancel_expired_htlcs` (600 s horizon,
`invoices.py:271-289`) exist, are unit-tested, and are wired to nothing
(verified: only test callers). Spec accepts the duration (SHOULD >= 60 s) but
the code drift misleads (dead code that looks like live protection). Either
wire `cancel_expired_htlcs` into `monitor_expiries` (restoring the 120-ish-s
mpp_timeout semantics) or delete it. Related: expired-invoice 400F matches
electrum's expired-invoice 400F (`lnpeer.py:3188-3191`) — that part is
faithful.

### PD-8 (P3): dropped per-swap locktime-vs-CLTV margin check
Electrum verifies per swap, at creation, that the onchain refund path
completes before the LN HTLC expiry: `locktime + MIN_LOCKTIME_DELTA +
SPENDER_FINALITY_DELAY < height + min_final_cltv_delta`
(`electrum/submarine_swaps.py:854-858`). Ours replaced it with the static
`assert_constants()` relationship (`submarine_swaps.py:231-239`) — adequate
only because `create_normal_swap` never overrides
`min_final_cltv_expiry_delta` (always the invoice default 147). Any future
caller passing a custom delta silently loses the guarantee.

### PD-9 (P3): `invoice_amount_sat <= 0` guard dropped
Electrum raises cleanly if `lightning_amount_sat - 2*mining_fee <= 0`
(`electrum/submarine_swaps.py:837-838`). Ours flows the negative amount into
`b11invoice_from_hash`, whose `assert amount_msat > 0`
(`cln_lightning.py:425`) turns a fee-spike-at-min-swap into an ugly assert
instead of a clean error. (Our min is 20000 sats; needs claim_fee > 10000
sats to trigger — only at extreme static-fallback feerates.) Related:
electrum's `_sanity_check_prepayment` caps prepay
(`electrum/submarine_swaps.py:737-745`); ours is an uncapped
`claim_fee * 2` (`submarine_swaps.py:564`).

### PD-10 (P3): `register_hold_invoice` dropped electrum's no-preimage assert
Electrum: `assert self.get_preimage(payment_hash) is None` at registration
(`lnworker.py:2917-2919`) — the callback would never fire otherwise. Ours
(`cln_lightning.py:386-390`) has no such check. Unreachable in the current
ln_to_onchain flow (server never holds the prepay), but the guard documents the
invariant.

### PD-11 (P3): duplicate-hash guards — electrum has three, ours has two and a no-op
Electrum `create_normal_swap` rejects a hash already in swaps, already having
a preimage, **or already in a payment bundle** (`electrum/submarine_swaps.py:781-788`).
Ours: `_require_fresh_payment_hash` covers swaps + preimage
(`submarine_swaps.py:510-518`); the bundle check is missing, and the
`listinvoices` duplicate check in `b11invoice_from_hash`
(`cln_lightning.py:431-433`) is a no-op for hold invoices because
`signinvoice` does not register the invoice in CLN's DB (only `rpc.invoice`
does — used solely by `get_regular_bolt11_invoice`). Residual risk is the
narrow post-`_fail_swap` replay window; `_require_fresh_payment_hash` catches
the common replay. P3.

### PD-12 (positive divergence): bundle coupling survives restart — stronger than electrum
Electrum's payment bundles are explicitly in-memory and dissolve on restart
(`lnworker.py:2757-2761`; re-bundled at startup,
`electrum/submarine_swaps.py:285-291`). Ours persists the coupling on the
HoldInvoice (`associated_invoice`, `invoices.py:233-243`, `303-313`) via
json_db, so restart mid-swap keeps prepay+main coupled without re-bundling.
Keep this — it is strictly better for the swapserver use case electrum's
docstring hand-waves about.

---

## Crash-restart analysis (Method step 4)

What is persisted (json_db, `hold_invoices` store): HoldInvoice fields,
incoming HTLC states/amounts/ids (`to_json`/`from_json`,
`invoices.py:127-151`), prepay association, funding status; swaps via
`submarine_swaps` store; tombstones (`cln_lightning.py:65`,
`411-413`).

What is re-derived on restart:
- CLN replays unresolved HTLCs → `plugin_htlc_accepted_hook` →
  `handle_htlc` find_htlc re-attaches the fresh request to the stored HTLC
  (`cln_lightning.py:225-229`; `Htlc.__eq__` ignores `created_at`, so replay
  matches — `invoices.py:109-114`). Good design, and it works.
- Swap-level hold callbacks are re-registered for live normal swaps
  (`submarine_swaps.py:159-169`).
- FUNDED main invoices survive: `check_invoice_expiry` skips FUNDED/SETTLED,
  `callback_handler` re-fires after re-registration.

Verdict on "does a restart park payer funds?" (R5): **yes, in three windows**:
1. PD-2 — crash between prepay settle and main callback → permanent park
   until payer CLTV (FUNDED invoice never expires, callback deadlocked).
2. PD-3 — HTLCs resolved while we were down are never replayed; their expiry
   assert aborts the whole monitor sweep → *other* invoices' expiry handling
   starves → their payer HTLCs park until CLTV.
3. PD-4 — crash after our `set_result` but before CLN commits the
   fulfillment → replayed HTLC re-attached but never re-resolved → park
   until CLTV.
None lose principal (payer HTLCs time out on-chain eventually), but all
violate R5's "never park a payer's funds" contract for hours. PD-1 (not a
restart bug) is the only P0.

---

## Prepay bundle coupling check (Method step 5)

`bundle_payments` (`cln_lightning.py:522-528`) attaches the prepay hash to
the main HoldInvoice and persists; `callback_handler`
(`cln_lightning.py:158-182`) implements the coupling: main FUNDED → prepay
must be FUNDED (settle prepay first — electrum achieves the same via the
bundle gate + preimage-known auto-settle, `lnpeer.py:3206-3230`) → only then
fire `hold_invoice_callback`, which broadcasts the funding tx
(`submarine_swaps.py:476-498`).

Coupling verdict: **preserved on the happy path and across restarts (PD-12),
broken at the prepay-expiry boundary (PD-1)** — the "fires only when BOTH MPP
sets arrive" invariant (R4, F8) does not hold when the prepay expires
unfunded: the sweep deletes it and the main callback fires anyway. The
CLBOSS-style prepay-ignoring client that F8 documented gets a swap without
paying the prepay.

---

## COVERAGE GAPS (spec requirements with no implementing code)

Candidates for new `# BOLT #4:` quote sites (greatspectations-verifiable):

1. Set-uniformity + completion threshold:
   `# BOLT #4: - SHOULD fail the entire HTLC set if `total_msat` is not the same for`
   `#  all HTLCs in the set.`
   Proposed site: `cln_lightning.py` `handle_htlc` (after the payment-secret
   check, ~line 267) — where a `total_msat` check would live if implemented.
2. Overpayment bound:
   `# BOLT #4: - if the amount paid is more than twice the amount expected:`
   `#  - SHOULD fail the HTLC.`
   Proposed site: same block, next to `is_fully_funded()` flip
   (`cln_lightning.py:276-277`).
3. Fulfillment deadline (BOLT #2):
   `# BOLT #2: A fulfilling node:`
   `#  - MUST fail (and not forward) an HTLC whose fulfillment deadline is already past.`
   Proposed site: `invoices.py` `HoldInvoice.settle` (line ~291) or
   `cln_lightning.py` `callback_handler`.
4. MPP timeout code:
   `# BOLT #4:  - MUST fail all HTLCs in the HTLC set after some reasonable timeout.`
   `#    - SHOULD use `mpp_timeout` for the failure message.`
   Proposed site: `cln_lightning.py` `check_invoice_expiry` (line ~124) if
   PD-7 is fixed by wiring `cancel_expired_htlcs`; otherwise document the
   intentional 400F-on-expiry choice there.

---

## FINDINGS SUMMARY

| ID | Finding | Severity | Verdicts affected |
|---|---|---|---|
| PD-1 | Prepay-expiry fall-through: swap proceeds without prepay (R4/F8 broken, server eats 2x claim fee per abuse; trigger client class known in wild) | **P0** | R4, bundle check |
| PD-2 | Settled-prepay deadlock parks payer HTLCs till CLTV (crash window) | P1 | R5, crash-safety |
| PD-3 | monitor_expiries sweep abort on callback-None HTLCs starves all expiry handling after restart | P1 | H-14, R5 |
| PD-5 | No height-based CLTV re-check while parked / at settle | P1 | H-5, H-6 |
| PD-4 | Settled-HTLC replay never re-resolved (hook hangs) | P2 | crash-safety |
| PD-6 | `total_msat` never validated (no uniformity, no 2x bound) | P2 | H-9, H-12 |
| PD-7 | mpp_timeout path dead code; incomplete sets fail at 300 s with 400F | P2 | H-14 |
| PD-8 | Per-swap locktime-vs-CLTV margin check dropped for static asserts | P3 | — |
| PD-9 | `invoice_amount_sat <= 0` + prepay-cap guards dropped | P3 | — |
| PD-10 | `register_hold_invoice` no-preimage assert dropped | P3 | — |
| PD-11 | Duplicate-hash: bundle guard missing, listinvoices guard is a no-op | P3 | R6 |
| — | 400F failure_message missing 12 data bytes; non-constant-time secret compare | P2-cosmetic | H-7 |
| PD-12 | Bundle coupling persisted across restart (better than electrum) | positive | — |

Counts: 1 x P0, 3 x P1, 3(+1 cosmetic) x P2, 4 x P3, 1 positive divergence.
Spec verdicts: 8 ✅, 4 ⚠️, 2 ❌, 2 N/A (CLN-core responsibilities), plus 1 ✅-with-note.

VERDICT: FAIL
