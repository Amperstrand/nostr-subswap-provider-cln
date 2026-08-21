# AUDIT-4: Swap Protocol — Onchain HTLC Scripts, Claim & Refund Flow

## ROLE
You are a Bitcoin/Lightning swap-protocol auditor. You audit THIS repo's
swap state machine against the reference implementation (electrum) it was
ported from. This is money-path code: every divergence is a potential
funds-loss bug.

## OBJECTIVE
Semantic diff of the swap lifecycle against electrum's submarine_swaps.py,
verdicts on every claim/refund invariant, and a port-divergence list.

## INPUTS (read all)
- Impl: `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/submarine_swaps.py`
  (FULL file, 1193 lines: SwapData, create/add normal+reverse swap,
  `server_create_swap`, `server_add_swap_invoice`, `_claim_swap`,
  `_create_and_sign_claim_tx`, `create_claim_tx` module fn, `_fail_swap`,
  `_finish_normal_swap`, `delete_finished_reverse_swap`,
  `create_funding_tx`, `broadcast_funding_tx`, amount math
  `_get_recv_amount`/`_get_send_amount`)
- Impl support: `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/transaction.py`
  (only as needed for claim-tx fee/size questions) and
  `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/lnutil.py`
  (`filter_suitable_recv_chans`, WITNESS_TEMPLATE_* if here)
- Reference: `/home/ubuntu/src/electrum/electrum/submarine_swaps.py`
  (2242 lines — the CURRENT electrum swap manager; read fully, at minimum:
  script construction, claim/refund branches, fee logic, locktime
  handling, request validation)
- Context: `/home/ubuntu/src/nostr-subswap-provider-cln/AGENTS.md`
  (hard requirements R1-R9 — audit against these too)

## METHOD — the semantic diff, function by function
1. Script templates (WITNESS_TEMPLATE_REVERSE_SWAP /
   WITNESS_TEMPLATE_NORMAL_SWAP): byte-level compare vs electrum
   (`construct_script` + templates). Slot order of pubkey/locktime/
   ripemd. is_reverse slot mapping in BOTH create_normal_swap and
   create_reverse_swap vs electrum's — a historical bug (423ed93) was
   exactly a d1-inverted slot order in addswapinvoice re-derivation.
2. `_claim_swap` vs electrum's equivalent: the funding-detection loop,
   underfund guard, preimage extraction from claim witness (normal
   swaps), refund branch (locktime checks, spent_height semantics:
   0=unconfirmed vs >0), REDEEM_AFTER_DOUBLE_SPENT_DELAY parity,
   should_bump_fee logic.
3. `_create_and_sign_claim_tx` + `create_claim_tx`: input sequencing,
   nsequence (locktime-enforcing vs anyone-can-spend), fee sizing
   (CLAIM_FEE_SIZE vs electrum), signature hash type, BelowDustLimit
   path.
4. Amount math: `_get_recv_amount` / `_get_send_amount` vs electrum —
   fee + spread application, min/max clamps, rounding (integer floor
   vs round), dust checks. Off-by-one here = quote mismatch = client
   rejects or we undercharge.
5. Request validation: `server_create_swap`/`server_add_swap_invoice`/
   `server_create_normal_swap` vs electrum's request handlers — field
   validation (A3/A4 pattern), pubkey length checks (their_pubkey 33B),
   script re-derivation on addswapinvoice (electrum recomputes and
   compares — do we?).
6. State machine: _fail_swap/_finish_normal_swap/
   delete_finished_reverse_swap — when is swap state removed, what
   happens to watchers/DB entries, restart recovery (swaps reloaded
   from json_db: `_add_or_reindex_swap`, lnwatcher re-registration).
7. Hard requirements R1-R9 from AGENTS.md: confirm each still holds
   in code (they have tests, but audit the CODE).

## VERDICT FORMAT
Same as AUDIT-1 (S-<n> numbering). Port-divergences get their own
section: `### D-<n>: <function> — <what electrum does that we don't (or vice versa)>`
with severity.

## OUTPUT
Write to `/home/ubuntu/src/nostr-subswap-provider-cln/docs/audits/results/AUDIT-4-swap-protocol.md`
(header, S-table, DIVERGENCES, COVERAGE GAPS — including which invariants
deserve a BOLT-adjacent quote or a test, FINDINGS SUMMARY, `VERDICT:` line).
