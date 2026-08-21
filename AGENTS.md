# AGENTS.md — nostr-subswap-provider-cln

Operational guide for AI agents working on this project. Everything here is
grounded in the code in `swap-provider/plugin/` — file:line references are
the authority, this file is the map.

## Project Summary

A Core Lightning plugin that turns the CLN node itself into an Electrum-
compatible (reverse) submarine-swap provider: it uses the node's own wallet,
keys and database, announces itself via Nostr (kind 30315 offers, NIP-04
encrypted kind 25582 requests), and serves swap requests from Electrum
wallets and anything speaking the same protocol (e.g. the boltz-bridge
Worker). Fork of f321x/nostr-subswap-provider-cln, ported toward electrum
4.8.x (see PORT-NOTES.md). Experimental; live instance on signet.

Sibling repos: `../lightning-playground` (lab, e2e experiments, inr2 ops),
`../electrum` (client-side reference), `../boltz-bridge` (HTTP→Nostr proxy),
`../bolts` + `../greatspectations` (spec-quote checking, see below).

## Naming: swap directions are named OPPOSITE to Boltz

This codebase uses **Electrum's** naming (it is a port of electrum's
`submarine_swaps.py`). Boltz clients see the names swapped through the
boltz-bridge translation:

| Electrum / this code (`is_reverse`) | API `type` | Client does |
|---|---|---|
| normal swap (`is_reverse=False`) | `submarine` (dead API) / two-phase `createnormalswap`+`addswapinvoice` | **pays Lightning, receives onchain** |
| reverse swap (`is_reverse=True`) | `reversesubmarine` (via `createswap`) | **sends onchain, receives Lightning** |

When in doubt, follow `is_reverse` in `SwapData` — never the English word.

## The two swap lifecycles (server side, what actually happens)

### Normal swap (`create_normal_swap` → `add_normal_swap`, submarine_swaps.py:520-616)

1. Client generates the preimage, sends us `payment_hash` (+
   `their_pubkey`). We derive a fresh `our_privkey`; locktime = height +
   `LOCKTIME_DELTA_REFUND`. Redeem script: client-claims-with-preimage /
   us-refund-after-locktime (`WITNESS_TEMPLATE_REVERSE_SWAP` slots swapped
   vs the reverse direction).
2. We create a **hold invoice** for `payment_hash` (which WE cannot
   settle — we don't know the preimage) plus a **prepay hold invoice**
   (claim_fee × 2), bundled via `bundle_payments` — see hard requirement
   R4. Invoice expiry 300s.
3. Client pays both invoices → HTLCs park at our node → hold-invoice
   callback fires (`hold_invoice_callback`, submarine_swaps.py:459) → we
   create + broadcast the **funding/lockup tx** paying the HTLC script.
4. Client waits ≥1 conf, claims onchain — the claim witness **reveals the
   preimage**. Our lnwatcher sees the spend, extracts the preimage from
   the witness (`_claim_swap`, submarine_swaps.py:379-387), verifies
   `sha256(preimage) == payment_hash`, settles the parked hold invoices.
5. If the client never claims, we refund with our key after locktime.

Money: client's LN sats → us; our onchain sats → client. We are paid the
spread + prepay covers our claim-fee risk.

### Reverse swap (`create_reverse_swap` → `add_reverse_swap`, submarine_swaps.py:618-677)

1. Client asks for a reverse swap with `their_pubkey`. WE generate the
   preimage (`os.urandom(32)`), `payment_hash = sha256(preimage)`. Redeem
   script: **we**-claim-with-preimage / client-refund-after-locktime.
   We return the redeem script + onchain amount.
2. Client funds the lockup address, then registers **their invoice** for
   OUR `payment_hash` via `server_add_swap_invoice`; we park it in
   `invoices_to_pay` and start paying (their invoice is effectively a hold
   invoice — it cannot settle until the preimage is public).
3. `_claim_swap` watches the lockup. Once it has **≥1 confirmation** and
   value ≥ `onchain_amount`, we sign + broadcast the **claim/sweep tx**
   (submarine_swaps.py:434-444). Its witness **reveals the preimage**,
   which completes our in-flight payment of the client's invoice — the
   client's LN funds land atomically with our onchain claim.
4. If the client never funds (or underfunds), we never reveal; near
   locktime we drop the parked payment (`invoices_to_pay` pop).

Live evidence both directions work end-to-end (signet 2026-08-20):
lockup `4ecb1e4d…` (50850 sats) confirmed in block 318544; our sweep
`e3c670aa…` (4.18 sat/vB, batching two matured HTLCs, 128000 sats out)
confirmed the NEXT block 318545; the client's hold invoice settled in the
same window.

## Hard requirements (and why — do not "fix" these without deep thought)

Each is load-bearing for funds safety. The list is the contract; the code
enforces it; tests in `tests/test_e2e_bug_regressions.py` pin several.

- **R1 — Never spend an unconfirmed lockup.** The claim/sweep witness
  reveals the preimage irreversibly (it settles the counterparty's hold
  invoice). If we sweep a 0-conf lockup and the payer RBF/double-spends
  the funding tx, they keep the onchain funds AND their invoice settles
  with our revealed preimage — we lose the full amount. Gate:
  `if funding_height.conf > 0:` before broadcast (submarine_swaps.py:~439;
  the commented-out `LIGHTNING_ALLOW_INSTANT_SWAPS` is dead by design —
  `acceptZeroConf` is always false on Electrum servers).
- **R2 — Never claim an underfunded reverse lockup.** `txin.value_sats()
  < swap.onchain_amount` → skip (submarine_swaps.py:347-349). Claiming
  reveals the preimage for less than the agreed amount; once revealed, we
  cannot undo the LN side.
- **R3 — Never SIT on a confirmed lockup either.** Until the preimage is
  revealed, the counterparty's HTLCs park and their CLTV deadlines tick
  (BOLT #2 timeout discipline). A delayed sweep can kill a fully-funded
  swap and force refunds. Sweep promptly at a sane feerate (see
  optimizations O1/O2 for how to be prompt AND cheap).
- **R4 — Prepay invoice is coupled to the main invoice** via
  `bundle_payments` — the hold callback fires only when BOTH are fully
  paid (lnpeer MPP-set coupling). A client that ignores `minerFeeInvoice`
  gets HTLCs accepted-but-never-fulfilled until CLTV expiry. Do not
  remove the prepay; do not settle the main invoice on partial sets.
  (Verified the hard way by the playground: FINDINGS.md F8, 10 dead
  swaps.)
- **R5 — Never park a payer's funds on an unknown hash.**
  `hold_invoice_callback` with no swap state (post-restart orphan,
  replayed DM) or a funding failure must `cancel_all_htlcs()` NOW, not
  silently return (electrum's behavior — funds hang until CLTV). AUDIT
  A5; also issue #25 tombstones so replayed HTLCs fail fast.
- **R6 — Duplicate `payment_hash` rejection** (`_require_fresh_payment_hash`,
  AUDIT A3): a replayed hash would clobber swap state and hold invoices.
- **R7 — MPP sets must sum before settle.** `is_fully_funded` parks
  per-HTLC (BOLT #2 allows same-hash HTLCs) and `settle()` refuses
  underfunded sets. Settling early on a partial MPP set = giving away
  sats.
- **R8 — DB hygiene on load.** Hold-invoice store round-trips through
  JSON; anything that comes back as a non-HoldInvoice is skipped AND
  purged (walrus bug `8697957`, type-guard `be5a97e`) — a corrupt entry
  crashed the expiry monitor and took the plugin down with it.
- **R9 — Hint public channels too** (`filter_suitable_recv_chans`,
  lnutil.py). BOLT #11 only mandates `r` hints for private routes, but a
  payer with lagging gossip (fresh channels are ~20-40 blocks behind)
  raises NoPathFound on a hintless invoice — we strand them (live signet
  2026-08-20, fixed in `35cab8c`).

## Authoritative spec comments (greatspectations)

Spec quotes in comments are **machine-verified** against a real
lightning/bolts checkout by rustyrussell/greatspectations:

- Config: `specquotes.toml` (sibling checkout `../bolts`, BOLT markdown).
- Gate: `tests/test_spec_quotes.py` runs `greatspectations check` inside
  pytest (skips cleanly if the sibling checkouts are absent).
- To cite a spec next to code:

  ```python
  # BOLT #11: - MUST include exactly one `p` field.
  #  - MUST set `payment_hash` to the SHA2 256-bit hash of the `payment_preimage`
  #  that will be given in return for payment.
  ```

  Rules: quote the CURRENT spec text verbatim (whitespace-insensitive);
  commentary inside the block needs the per-line prefix `# Impl-note:` —
  every commentary line, not just the first (the tool drops asides
  per-line); run
  `PYTHONPATH=../greatspectations/src python3 -m greatspectations check
  --config specquotes.toml --comment-aside='# Impl-note:' <files>` to
  verify. When the spec changes, the check fails and you update the quote
  — that is the entire point: 8 drifted vendored quotes (SHOULD→MUST
  drift, renamed `r`-field names, one citing a deleted rule) were caught
  and refreshed the day this was adopted.

## Testing

```bash
python3 -m pytest tests/            # full unit suite (66 tests)
npx playwright test --project=signet  # live e2e via lightning-playground
```

Test styles in `tests/`: contract/code-inspection tests (assert the code
uses the right param names/patterns — `_code_only` strips comments so the
check sees executable code only), wire round-trips (hint encode→decode),
and behavioral tests against the HoldInvoice/Htlc classes. Every live bug
class gets a regression test BEFORE the fix is considered done (see
test_e2e_bug_regressions.py header).

Live signet swaps through the playground are pre-authorized (signet funds
are worthless): `python3 -m puppets.experiments.swaps --amount-sat 20000
"cln-direct"` from `../lightning-playground`. Keep swaps at the 20k-sat
federation minimum.

## Deployment (signet lab)

Build → ship the image → restart:

```bash
cd ../lightning-playground && bash docker/subswap/build.sh
docker save lab-cln-subswap:latest | gzip > /tmp/subswap.tar.gz
scp /tmp/subswap.tar.gz root@inr2.cashu.exchange:/tmp/
ssh root@inr2.cashu.exchange 'gunzip -c /tmp/subswap.tar.gz | docker load && \
    cd /opt/inr2-swapnet/deploy && docker compose up -d --force-recreate cln-swap'
```

Verify: `docker logs cln-swap-signet` shows `nostr is connected` and no
AttributeError spam. All CLN interaction goes through clnrest (see
lightning-playground AGENTS.md CLN API mandate) — no new
lightning-cli-over-ssh code.

## Future optimizations (and their tradeoffs)

None of these are implemented; all are sound ideas IF the hard
requirements above stay intact.

- **O1 — Batch matured claims into one tx.** When several reverse lockups
  confirm in the same window, spend them in one claim tx (the live sweep
  `e3c670aa` accidentally demonstrated this: two HTLC inputs, 850 sats
  total fee at 4.18 sat/vB instead of two ~445-vB txs). Saves per-tx
  overhead + fee. Tradeoff: coupling — one input's signing failure holds
  up all claims in the batch (violating R3's "don't sit" pressure), and
  bigger txs need more fee headroom under RBF. Batch by block, cap size,
  fall back to individual claims on any failure.
- **O2 — RBF-bump stuck claims.** If a broadcast claim hasn't confirmed in
  N blocks, bump its feerate (CLN wallet's unreserve+respend or manual
  RBF). Tradeoff: fee escalation on a fee-market spike can eat the swap
  spread; needs a max-bump cap and awareness that the preimage is already
  revealed (bumping only protects the onchain leg, R1 is moot post-broadcast).
- **O3 — Zero-conf acceptance under a risk limit.** Accept 0-conf lockups
  below a small amount cap with doublespend-detection (mempool
  propagation + RBF-punishing scoring). Tradeoff: R1 exists because
  0-conf claim = free doublespend option for the payer; any cap is a
  direct funds-risk budget. Almost never worth it outside regtest demos.
- **O4 — Fee policy pinned to a live oracle.** ✅ DONE 2026-08-21
  (`fee_oracle.py`, commit history): signet's native estimates are garbage
  → the old static fallback priced 222-vB claims at 60 sat/vB (4400 sats)
  when median blocks paid 0-6 sat/vB. `get_chain_fee` order is now CLN
  estimate → mempool-style oracle (`FEE_ORACLE_URL` env or per-net
  default; 5-min cache; 5s timeout; out-of-range = broken = fail-open)
  → `FALLBACK_FEE_SATVB`. The oracle must never block a claim (R3) —
  every error path falls through. Tradeoff (accepted): a third party
  (mempool.space / mutinynet.com) learns our claim-timing pattern;
  self-host with `FEE_ORACLE_URL` to avoid.
- **O5 — Parallel invoice payment for parked invoices.** `pay_pending_ln_
  invoices` retries serially with a 15-attempt cap; MPP-aware concurrent
  attempts would settle the client's invoice faster once we claim.
  Tradeoff: concurrent attempts can over-pay if a stale attempt settles
  late — needs strict per-hash in-flight tracking.
- **O6 — Refund sweeping automation.** Expired normal swaps' refund
  outputs currently rely on generic wallet sweeping; an explicit
  `spend_confirmed_refunds` pass would reclaim capital predictably.
  Tradeoff: more signing paths = more audit surface; the wallet already
  does a passable job.

## Gotchas

0. **Port electrum's architecture, not just its code** (earned 2026-08-21,
   issues #2-#7): both audit P0s and all four reader-MUST gaps were places
   where the port dropped a guard or invented a policy electrum had already
   solved. Canonical example: making the bolt11 decoder strict would have
   been WRONG — electrum keeps decode lenient (old invoices must stay
   parseable) and enforces MUSTs at the pay boundary
   (`lnworker._check_bolt11_invoice`); we now mirror that in
   `check_invoice_before_payment`. When adding validation, first ask "what
   does electrum do at this seam", then port that.
1. Swap direction naming (see above) — the #1 source of wrong "fixes".
2. `privkey`/`preimage`/`redeem_script` are stored HEX on SwapData in this
   port (bytes in upstream electrum) — `hex_to_bytes` before ECPrivkey
   (bit us: `803bbbe`).
3. CLN RPC takes KEYED params only via clnrest (`holdinvoice amount=`,
   not `amount_msat=`); `newaddr` needs explicit `addresstype=bech32`
   (v26.06 bare call returns only p2tr).
4. `PluginLogger` is printf-style — `.error("...%s", e)` crashes; use
   f-strings.
5. Walrus `:=` binds looser than `is not None` —
   `if x := get() is not None:` assigns the BOOL. Parens or two lines;
   a pattern-scan test guards this now.
6. Vendored electrum files keep their MIT headers; quote-refreshes in
   them are fine, behavior changes are not (they drift from upstream on
   purpose — document why in the commit).
