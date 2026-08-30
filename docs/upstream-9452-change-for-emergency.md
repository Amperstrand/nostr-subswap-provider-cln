# Upstream #9452 — change_for_emergency crash: fix preparation,
# verification campaign, and cross-implementation research

**Status:** fix branch verified on OUR fork — **not submitted**
(external-projects rule, owner directive 2026-08-30). Upstream issue
ElementsProject/lightning#9452 was filed 2026-08-29 BEFORE the
mechanism was fully understood and BEFORE the rule; its "excess_as_change
makes the excess the entering change" narrative is **wrong in the
mechanism** (see CORRECTION below) — keep/amend/delete is the owner's
call, and any correction comment on it is a human-only action.

- **Fork branch (current):** `Amperstrand/lightning` →
  `fix/change-for-emergency-dust-shortfall` = `ce43b89e5`, a single
  commit on top of upstream/master `c1551c557` (the first branch
  `da1bf5cf` on the fork's stale master is superseded and deleted)
- Our mitigation (deployed, still valid): `crashguard-r1` / plugin
  commit `460c8de` — refuses the entire near-floor funding region
  regardless of flags, which is a superset of the true crash window

## CORRECTION — the real mechanism (2026-08-30 verification round)

The deterministic repro proved the crash is NOT primarily about
`excess_as_change`. The real window:

1. `wallet_has_funds()` (by pointer, v26.06 AND current master —
   introduced by e4d3cc8b0, 2024, "be a little more flexible with
   change for emergency reserve") reduces `needed` to the SHORTFALL:
   `emergency_sat` minus the unselected wallet.
2. When that shortfall is **below the dust limit** (< 546 sat — the
   unselected wallet sits within dust of the reserve), the change
   output the split branch promises cannot exist: `change_amount()`
   dust-caps to 0, and the equality
   `assert(amount_sat_eq(change_amount(*change,...), needed))` fails
   for any needed > 0 → FATAL SIGNAL 6.
3. `excess_as_change=true` is actually crash-PROTECTIVE on v26.06/master
   (it zeroes the split's excess → the typed 313 path). A plain call is
   the kill combo. The entering-change (c0>0) algebra is the second
   latent unsoundness, unreachable through these two callers today
   because of the zeroing.

Window width: **546 sats of wallet state** — which is why only a
production wallet under campaign churn ever hit it (inr2 signet,
2026-08-29 19:28–19:33, five cores).

## Fix shape (fork branch ce43b89e5)

Replace the assert with the honest promise check: if
`change_amount(change_after_fee_and_needed) < needed` → `return false`
(caller gets the typed FUND_CANNOT_AFFORD_WITH_EMERGENCY). Covers both
failure modes (dust-capped shortfall; any future entering-change
caller). No behavior change for the healthy path (needed ≥ dust, c0=0:
the constructed change covers exactly).

## Verification campaign (all on this host; 2026-08-30)

**CLN's own framework (authoritative), upstream/master tip:**

- **RED:** vanilla tip `c1551c557` — the 20-line regression test
  (`test_utxopsbt_emergency_reserve_dust_shortfall`: 60k selected UTXO +
  24_900 unselected vs 25k reserve) SIGABRTs the daemon at
  `wallet/reservation.c:481 change_for_emergency ← json_utxopsbt`
  (backtrace resolved in the harness log; the crash message string
  matches the inr2 core's recovered message verbatim).
- **GREEN (fix):** regression passes (typed 313 + daemon alive);
  property walk `test_utxopsbt_emergency_reserve_property` — 10 seeded
  rounds × 3 asks over random reserves/wallet granularities/
  rest-near-reserve shapes, asserting daemon liveness on every call +
  the change-covers-shortfall oracle — passes;
  adjacent-regression slice (fundpsbt/utxopsbt/reserveinputs/
  unreserve/withdraw, 19 tests) all pass on the fix build.
- Build notes: `--disable-rust` (cln-grpc needs a newer rustc than
  this host has — unrelated to the fix); valgrind wiring in the repo
  harness did not engage under our invocation (left to upstream CI;
  the change allocates nothing).
- History note: the fork's master snapshot (fe09484b-era) predates the
  e4d3cc8b0 merge — on that era the window is closed, which is why an
  earlier test run there passed on vanilla. Current tip and v26.06 are
  both vulnerable; the regression test is the discriminator.

**Playground/lab (production shape):**

- The fix builds and boots as a full node (make install → ubuntu:24.04
  image, DB migration 282→286, channels preserved, plugin loads with
  stable identity, offers publish).
- The end-to-end swap leg could NOT complete: upstream tip lightningd
  RESETS the INIT exchange with the lab's electrum-4.8.1 peers
  (both swallet and client refuse/re-drop) — a genuine
  implementation-drift wall between current CLN master and electrum
  4.8.1, unrelated to this fix. The pyln harness (which uses only
  CLN nodes) is the correct and sufficient verification surface.
- Lab restored to known-good afterwards (`lab-reset.sh --subswap`).
- The docker one-shot crash demo was abandoned mid-debug (quoting
  plumbing inside the container); the pyln RED demo carries the same
  evidence with a resolved backtrace.

## Independent verification round (2026-08-30, isolated container)

Fresh clone of the PUSHED branch (74a6b277) — not any working tree —
built and tested inside a pristine ubuntu:24.04 container (fresh
toolchain, fresh pip env, freshly downloaded bitcoind 27.1):

- 3/3 core tests pass (both deterministic dust-shortfall regressions —
  utxopsbt AND fundpsbt — plus the 10-round property walk)
- 20/20 adjacent slice passes (fundpsbt/utxopsbt/reserveinputs/
  unreserve/withdraw)
- Logs preserved at ~/verify-9452/ (moved out of /tmp after a parallel
  session's cleanup swept /tmp/opencode mid-campaign)

shc was DOWN during the window (control-plane DNS failure), so this ran
on the local host's container runtime instead of separate hardware —
fresh userspace/toolchain + fresh clone, same kernel. shc can still be
used for a hardware-independent rerun when it's back.

Build recipe earned (CLN tip from a bare ubuntu:24.04 — five failures
deep): apt `build-essential autoconf automake libtool git lowdown jq
sqlite3 libsodium-dev libsqlite3-dev libgmp-dev zlib1g-dev gettext
python3 python-is-python3 python3-pip python3-setuptools python3-dev
libssl-dev curl` + pip `pytest requests mako grpcio-tools uv` + the
repo's `contrib/pylightning/requirements.txt` + `-e
contrib/pyln-testing`. Tip's configure resolves python THROUGH uv, and
pytest must run from the repo root (running from tests/ breaks pyln's
lightningd path resolution).

## How the other implementations handle the same situation

| | Reserve policy | Enforcement style | Daemon behavior on caller-induced funding shortfall |
|---|---|---|---|
| **lnd** | `AnchorChanReservedValue` = 10k sat per anchor channel, capped at 100k (`lnwallet/wallet.go`) | `CheckReservedValue()` computes the post-tx wallet balance — **counting the tx's own change output toward the reserve** — and returns the typed `ErrReservedValueInvalidated` | **Never aborts.** Typed Go error to the RPC caller. Also exposes `requiredreserve` as a query RPC and plumbs `WalletReserve` into coin-selection requests so callers pre-check |
| **eclair** | Advisory: notify the operator when the fee-bump reserve looks too low (PR #2104: "no perfect formula… rough estimation… notify when the situation becomes too risky") | Notification, not blocking; spend-time failures surface as typed errors | **Never aborts.** Config knobs for anchor spending; failures are operator-visible errors |
| **electrum** | `should_keep_reserve_utxo()` (wallet.py:1931) — the direct anchor-reserve analog | Raises the typed `NotEnoughFunds`; dust change folds into fees at the RPC boundary | **Never aborts.** Daemon catches at the command layer and returns JSON-RPC errors |
| **CLN (v26.06 + master today)** | `min-emergency-msat`, forced on for anchor-channel nodes | Afford corners return typed errors (313) — but the dust-shortfall corner aborted the daemon since e4d3cc8b0 (Feb 2024) | **Aborts** (the outlier; zero emergency-reserve pytest coverage until this branch) |

Unanimous peer practice: an RPC-reachable wallet-math corner is a typed
error, never a process abort. Our fork fix brings CLN in line with all
three peers.

## Where the mitigation belongs

**Both layers.** Core owns the crash (fixed on the fork branch, pending
human review + submission decision). Our plugin's pre-RPC guard stays as
defense-in-depth — it mirrors lnd's caller-side `WalletReserve` pattern
and remains load-bearing for every unfixed CLN in the fleet (v26.06 in
production today). Its documented rationale needed this correction
(the guard's behavior is unchanged and still correct: it refuses the
whole near-floor region, a superset of the true window).

## Human-review checklist (fork branch ce43b89e5)

1. `git diff c1551c557..ce43b89e5` — one C hunk + two tests.
2. Run: `pytest -vvv tests/test_wallet.py::test_utxopsbt_emergency_reserve_dust_shortfall tests/test_wallet.py::test_utxopsbt_emergency_reserve_property`
   (a full CLN dev checkout; both pass on the fix, the first kills
   vanilla master).
3. Decide: submit upstream (human-only), amend, or drop. If submitted,
   consider also correcting the #9452 issue body's mechanism narrative
   (a human comment) — this document is the source of truth.
