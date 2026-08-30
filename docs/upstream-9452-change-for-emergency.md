# Upstream #9452 — change_for_emergency assert crash: fix preparation
# and cross-implementation research

**Status:** analysis complete, fix branch prepared on OUR fork for human
review — **not submitted** (external-projects rule, owner directive
2026-08-30). Upstream issue ElementsProject/lightning#9452 was filed
2026-08-29, before the rule; keep-or-delete is the owner's call.

- Fork branch: `Amperstrand/lightning` →
  `fix/change-for-emergency-excess-as-change-assert` (commit `da1bf5cf`)
- Our mitigation (deployed): `crashguard-r1` / plugin commit `460c8de`
  (see issue #35 close-out for the forensic chain)

## The defect in one paragraph

`change_for_emergency()` (wallet/reservation.c) assumes it is entered
with change == 0, but `fundpsbt`/`utxopsbt` with `excess_as_change=true`
enter with the caller's excess as the change. The equality assert after
the split-excess branch is then unsatisfiable by construction —
`change_amount(c0 + fee + needed) = c0 + needed != needed` — so whenever
the node has anchor channels (the check is forced on, no API opt-out),
the unselected wallet is below `min-emergency-msat`, and the
change-from-excess cannot cover the reserve after its own output fee,
the RPC SIGABRTs lightningd. Retrying callers crash-loop the daemon
(five cores in five minutes, inr2 cln-swap-signet, 2026-08-29).

## How the other implementations handle the same situation

| | Reserve policy | Enforcement style | Daemon behavior on caller-induced funding shortfall |
|---|---|---|---|
| **lnd** | `AnchorChanReservedValue` = 10k sat per anchor channel, capped at 100k (`lnwallet/wallet.go`) | `CheckReservedValue()` computes the post-tx wallet balance — **counting the tx's own change output toward the reserve** — and returns the typed `ErrReservedValueInvalidated` | **Never aborts.** Typed Go error to the RPC caller. Also exposes `requiredreserve` as a query RPC and plumbs `WalletReserve` into coin-selection requests so callers pre-check |
| **eclair** | Advisory: notify the operator when the fee-bump reserve looks too low (PR #2104: "no perfect formula… rough estimation… notify when the situation becomes too risky") | Notification, not blocking; spend-time failures surface as typed errors | **Never aborts.** Config knobs for anchor spending; failures are operator-visible errors |
| **electrum** | `should_keep_reserve_utxo()` (wallet.py:1931) — the direct analog: keep a UTXO available for anchor fee-bumping | Raises the typed `NotEnoughFunds` exception; `make_unsigned_transaction` raises `NotEnoughFunds`/`NoDynamicFeeEstimates` at the RPC boundary | **Never aborts.** Daemon catches at the command layer and returns JSON-RPC errors; dust change folds into fees |
| **CLN (v26.06 + master today)** | `min-emergency-msat`, forced on for anchor-channel nodes | Afford corners return typed errors (`FUND_CANNOT_AFFORD`, 313 `FUND_CANNOT_AFFORD_WITH_EMERGENCY`) — but this one path asserts | **Aborts the daemon** (the outlier; zero emergency-reserve coverage in `tests/test_wallet.py`, which is how it survived) |

Unanimous peer practice: an RPC-reachable wallet-math corner is a typed
error, never a process abort. Assertions are for internal invariants
that caller input cannot influence.

## Where the mitigation belongs

**Both layers, with different jobs. The real fix is in Core Lightning.**

1. **Core (the bug):** daemon availability on RPC input is every peer's
   contract; lnd even implements the exact semantic CLN botched (change
   counts toward satisfying the reserve) without an assert. The fork
   branch relaxes the assert to the branch's actual goal — the change
   *covers* the reserve (`amount_sat_greater_eq`; still an equality when
   entering change is 0) — plus a pyln regression test
   (`test_utxopsbt_emergency_reserve_excess_as_change`) that crashes
   pre-fix and funds with a reserve-covering change post-fix.
2. **Ours (defense in depth, stays):** mirrors lnd's caller-side
   `WalletReserve` pattern — callers are expected to be reserve-aware.
   `create_transaction` refuses pre-RPC when even selecting everything
   would leave the change inside the crash window (free_total − max_ask
   < emergency + fee headroom). While any unfixed CLN runs in the fleet
   this guard is load-bearing (production crashed five times on
   2026-08-29); after a fixed CLN deploys fleet-wide, revisit whether to
   relax it to error-handling only.

## Fork branch — what was and was not verified

- The algebra and the crash conditions are proven (see #35 close-out:
  core forensics + the counterexample pinned in our test suite).
- The C change is a one-operator diff against master `fe09484b`,
  reusing `amount_sat_greater_eq` already used three lines above; **not
  compiled here** (no CLN build environment on this box).
- The pyln test follows `test_utxopsbt`'s harness shape (fund one UTXO,
  mine, `utxopsbt` with `opening_anchor_channel=True` to force the
  branch without channels); **not executed here** (their suite needs the
  pinned bitcoind harness). Reviewer should run:
  `pytest -vvv tests/test_wallet.py::test_utxopsbt_emergency_reserve_excess_as_change`

## Human-review checklist

1. Read the diff on the fork branch (2 files: reservation.c, test).
2. Run the pyln test above (and the neighboring fundpsbt/utxopsbt
   tests) in a CLN dev checkout.
3. Sanity-check the docstring numbers (50k UTXO, 25k ask, 25k reserve
   → excess ≈ 24.9k sits inside the window).
4. Decide: submit upstream (a human-only action per the
   external-projects rule), amend, or drop.
