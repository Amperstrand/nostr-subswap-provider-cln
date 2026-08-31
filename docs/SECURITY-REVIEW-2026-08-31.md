# Security review 2026-08-31 — contracts-r1 hot paths (agent audit, static)

Three parallel hunters (HSM-split secrets / admission gates + breaker /
time-fee-claim machinery) over the deployed lineage, file:line-cited.
**PoC round deferred**: findings are static-source with citations; the
top candidates need the regtest lab (parallel session contention) —
priorities marked below. Severity is exploitability-calibrated per the
audit standard (no severity without a path).

## Hunter 1 — HSM-split secret handling (#36/#13)

**Post-audit correction (same day):** the headline below was recorded
against STALE line-memory — commit `4f63405` (2026-08-31 17:13Z, #43:
d1 HSM-split) had already landed BEFORE the hunter ran (17:40Z) and
the current tree derives the d1 refund key from the HSM
(`swap-claim-{payment_hash}` label, `privkey=null` + `claim_pubkey`
only). Verified current-tree: no `os.urandom(32)` privkey generation
remains; only the 16-byte `preimage_seed` (:1277). F1 is OBSOLETE —
kept below struck for the record. Likewise hunter-3's minor
`_payment_parked` note is superseded by `5dbef0b` (#42: tri-state
parked/absent/unknown, fail-closed). All OTHER load-bearing findings
re-verified line-by-line against the CURRENT tree (containment gap,
breaker None-hole at :1311-1315, catch-mismatch at :1056-1058,
`_convert_dict` guard gap, 0-conf payment queueing at ~:970-976,
200-page bail at bitcoin_core_rpc.py:406) — they HOLD.

- ~~**[HIGH, code-confirmed] d1 refund key still plaintext in
  datastore — the HSM-split covers only d2.**~~ **OBSOLETE: fixed by
  4f63405 (#43) pre-audit.** Original claim (for the record):
  `submarine_swaps.py:1130` (`os.urandom(32)`) → `:1213`
  (`privkey=our_privkey.hex()` → datastore). Residual truth: OLD-format
  records keep stored plaintext until expiry (backward compat, bounded
  by locktime — unchanged, and `5dbef0b` now ages out never-parked
  ones).
- **[MEDIUM] derived privkey never checked against stored
  `claim_pubkey`** (`:1293-1299` returns makesecret output
  unconditionally; `:1648` signs blind) — hsm_secret rotation (node
  rebuild / hsmtool) wedges claims as a misattributed
  TxBroadcastError loop ("Report bug on github") instead of a loud
  alarm. `server_add_swap_invoice:1381` catches it only pre-funding
  with a misleading error. No scheme-version marker on swap records
  (a future label-format change strands silently). Fix: canary
  (`sha256(makesecret("swap-canary"))` at init, compare at startup) +
  assert `ECPrivkey(derived).pub == claim_pubkey` in the claim path.
- **[LOW] `spending_txid` persisted before broadcast** (`:1000-1005`) —
  invalid-witness loop keeps retrying (spent_height stays None) but
  `server_add_swap_invoice:1383` permanently reports "already in
  flight".
- Positives: claim-time HSM outage retries safely (per-callback catch,
  10s/block/60s drivers; degrades to client refund at locktime, R1
  intact); no reachable key/preimage label collisions (R6's three
  domains); no secrets in logs.

## Hunter 2 — admission gates, option-E, datastore breaker

- **[MEDIUM-HIGH] option-E gate discharges on 0-conf (mempool)
  visibility** — payment queueing and #26 HTLC-parking start on an
  unconfirmed lockup (`submarine_swaps.py:954-958`; only the CLAIM
  broadcast is ≥1-conf gated, `:938`). Client registers invoice +
  broadcasts lockup → our HTLCs park → RBF-replace the lockup away.
  Gate cannot re-arm (`invoices_awaiting_funding` discarded at
  `:954-956`; `_evaluate_funding_gate` returns at `:783`). Bounded
  (15-attempt cap) but a free RBF-fee jam per swap — #12's residual.
- **[MEDIUM] `_remember_event` db.write sits OUTSIDE DM containment**
  (`:1953-1961` vs try at `:1918`) — a datastore write failure crashes
  the nostr consumer + taskgroup + plugin; the event id never
  persists, so relay replay re-crashes per event: a persistent
  crash-loop while DMs arrive. Exactly the containment class PORT
  FIND #13 exists for; the breaker would have answered 'try again'.
- **[MEDIUM] breaker cannot trip when it never saw a success**
  (`last_write_monotonic=None` → healthy forever; post-restart
  all-writes-fail = admission stays open, nothing persists) and it
  skips `server_add_swap_invoice` (phase 2 unguarded during outage —
  in-memory registered=True, lost on restart → funded client falls to
  grace-hold fail-open claim at locktime+grace, hours delayed).
- **[LOW-MEDIUM] error-distinction stragglers (#21 class)**:
  `spendable_capacity_sat` raises plain Exception (cln_chain.py:288-290)
  outside the CapacityProbeError try (submarine_swaps.py:1732) →
  'internal error serving createswap'; RouteHintUnavailableError /
  DuplicateInvoiceCreationError / Bolt11InvoiceCreationError all land
  in the same generic bucket (`:1737`→`1182`, cln_lightning.py:651-655).
  Hint-less refusal exists only for the RPC-failure case — RPC-OK +
  zero suitable channels still EMITS a hint-less invoice (the R9
  scenario inverted onto the payer; cln_lightning.py:649-684,
  lnutil.py:40-42).
- **[LOW] aggregate over-admission**: serial DM handling kills classic
  TOCTOU, but capacity probes check current state per admission with
  no outstanding-swap reservation — N sequential d2 admissions
  over-commit; failures push legit funded clients to locktime refunds
  (availability only; park-then-claim prevents loss).

## Hunter 3 — time-based fallback, fee oracle, claim path

- **[MEDIUM] `_claim_swap` catches the wrong exception at broadcast**
  — `lnwatcher.broadcast_raw_transaction` raises `BitcoinCoreRPCError`
  (bitcoin_core_rpc.py:434-442) but the handler catches
  `TxBroadcastError` (`submarine_swaps.py:1024-1031`) — the R3
  designated error path is dead code; failures escape as generic
  callback errors (timer retries save it).
- **[MEDIUM] three concurrent `_claim_swap` drivers, no reentrancy
  guard** (ChainMonitor timer/block, funding_gate_watch_loop `:773`,
  main_loop initial trigger `:487`) — double build+broadcast when fees
  differ across the oracle cache TTL; second tx → mempool-conflict →
  the F1 dead handler. Mostly benign (same preimage), but it makes F1
  live. Fix: per-swap asyncio.Lock.
- **[MEDIUM] fee oracle fetch is SYNC httpx inside the event loop**
  (fee_oracle.py:50, 5s timeout, no negative cache) — plugin-wide
  stall up to 5s per cache miss (claims, prepay pricing, offers);
  widens every race; O4's "never block a claim" intent violated in
  the liveness sense.
- **[MEDIUM] oracle clamps underprice exactly when it matters**:
  in-range-but-wrong values accepted with no cross-check; a mempool-
  stuck REVERSE claim has NO bump path (`should_bump_fee` only set in
  the `not is_reverse` branch, `:913-918`; reverse returns at
  `:993-994` with spent_height==0 forever). Recovery only via mempool
  eviction.
- **[MEDIUM] swap-record store lacks the R8 guard**: one malformed
  `submarine_swaps` entry (missing mandatory attr / bad hex) raises in
  `json_db._convert_dict` (`:435-443`) during `JsonDB.__init__` →
  plugin fails to start, persistently, until manual datastore surgery.
  `_swap_integrity_errors` runs post-construction — cannot catch it.
- **[HIGHEST-PRIORITY CANDIDATE, needs lab PoC] wallet-side spend
  reconciliation exhaustible by address spam** —
  `_fetch_spent_utxos` bails after 200 listtransactions pages
  (bitcoin_core_rpc.py:406) → `UtxosNotFoundError` → `_claim_swap`
  raises BEFORE preimage extraction (`:889-903`) → hold invoices never
  settle → client's LN payment reverses at CLTV while the client keeps
  the onchain claim = **funds loss** for d1 swaps with
  onchain_amount ≫ attack cost (200 × 330 sat dust decoys + fees).
  Also reachable by accumulated wallet history (the 200-page budget is
  GLOBAL, not per-address). CWE-400/667.

## Priority order for the fix lane (owner-gated)

1. listtransactions exhaustion (lab PoC first — the only funds-loss
   candidate; then per-address scoping or utxo-based reconciliation).
2. `_remember_event` containment + breaker None-hole + option-E
   0-conf discharge (three availability/DoS fixes, small diffs).
3. exception-type + reentrancy-lock + async oracle (claim-path
   hygiene bundle).
4. R8-analog load guard for the swaps section.
5. (was: d1 refund key HSM coverage — CLOSED by 4f63405/#43 pre-audit;
   the derived-vs-claim_pubkey canary check from hunter-1 F2 remains
   open and pairs naturally with it.)
