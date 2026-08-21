# AUDIT-4 Result: Swap Protocol — Onchain HTLC Scripts, Claim & Refund Flow

- Date: 2026-08-21
- Impl commit audited: `61146f8` (repo `nostr-subswap-provider-cln`)
- Files read (full): `swap-provider/plugin/submarine_swaps.py` (1193 lines),
  `swap-provider/plugin/constants.py`, `lnutil.py`, `chain_monitor.py`,
  `bitcoin_core_rpc.py` (get_addr_outputs/get_tx_height/get_transaction/broadcast),
  `cln_chain.py` (fee/wallet paths), `cln_lightning.py` (hold-invoice/callback/expiry
  paths), `invoices.py` (HoldInvoice), `transaction.py` (sign/sighash/nsequence paths),
  `bitcoin.py` (construct_script/dust_threshold), `utils.py` (log_exceptions).
- Reference read (full): `/home/ubuntu/src/electrum/electrum/submarine_swaps.py`
  (2242 lines, current electrum swap manager).
- Context: repo `AGENTS.md` hard requirements R1–R9.

Severity scale (per AUDIT-1): **P0** funds-risk / **P1** interop-or-conditional-funds /
**P2** cosmetic-or-hardening.

## S-table

| # | Invariant | Verdict |
|---|---|---|
| S-1 | Witness script template byte-parity with electrum | ✅ |
| S-2 | `create_normal_swap` slot mapping (7=their claim key, 13=our refund key) | ✅ |
| S-3 | `create_reverse_swap` slot mapping (7=our claim key, 13=their refund key) | ✅ |
| S-4 | `addswapinvoice` re-derivation slot order + hex-vs-bytes (historical bug 423ed93) | ✅ |
| S-5 | `_claim_swap` funding detection + underfund guard (R2) | ⚠️ reverse-only guard |
| S-6 | Preimage extraction from claim witness (normal swaps) | ❌ unguarded IndexError |
| S-7 | Refund branch, spent_height semantics, finality delay | ⚠️ parity w/ constant drift |
| S-8 | should_bump_fee logic | ✅ (old-electrum semantics kept) |
| S-9 | Claim tx construction: nsequence, sighash, CLTV, version, dust | ✅ |
| S-10 | Fee sizing (CLAIM_FEE_SIZE) | ⚠️ 136 vB vs electrum 150 vB |
| S-11 | `_get_recv_amount` math | ✅ |
| S-12 | `_get_send_amount` math | ✅ |
| S-13 | `server_create_swap` request validation | ✅ (2 of 3 electrum dup guards) |
| S-14 | `server_create_normal_swap` request validation | ✅ |
| S-15 | `server_add_swap_invoice` validation (hash match, amount, re-derive) | ⚠️ no cltv cap |
| S-16 | `_fail_swap` state cleanup | ⚠️ stale indexes, unconditional deletes |
| S-17 | `_finish_normal_swap` settle path | ✅ |
| S-18 | `delete_finished_reverse_swap` | ✅ |
| S-19 | Restart recovery (reload, reindex, re-register) | ⚠️ pop-if-no-invoice |
| S-20..28 | Hard requirements R1–R9 in code | R1✅ R2✅ R3✅ R4✅ R5✅ R6⚠️ R7✅ R8✅ R9✅ |

## Detailed verdicts

### S-1: Witness script template — byte-level parity
Verdict: ✅
Evidence: impl `submarine_swaps.py:71-88` vs electrum `submarine_swaps.py:103-120`.
Identical 16-item sequence: `OP_SIZE, PUSH(None)@1, OP_EQUAL, OP_IF, OP_HASH160,
PUSH(==20)@5, OP_EQUALVERIFY, PUBKEY@7, OP_ELSE, OP_DROP, PUSH(None)@10,
OP_CHECKLOCKTIMEVERIFY, OP_DROP, PUBKEY@13, OP_ENDIF, OP_CHECKSIG`. Slot indices
(1 preimage-len=32, 5 ripemd(payment_hash), 7 claim pubkey, 10 locktime, 13 refund
pubkey) match electrum exactly. `construct_script` (impl `bitcoin.py:296-313`) is the
vendored electrum implementation (index→value substitution, CScriptNum encoding for
the locktime int). Electrum renamed the constant `WITNESS_TEMPLATE_SWAP` (unified);
impl keeps the old name `WITNESS_TEMPLATE_REVERSE_SWAP` and uses it for both
directions — cosmetic only.

### S-2: `create_normal_swap` slot mapping (server serves client-reverse = `createswap`)
Verdict: ✅
Evidence: impl `submarine_swaps.py:533-536` — `{1:32, 5:ripemd(payment_hash),
7:their_pubkey, 10:locktime, 13:our_pubkey}`. Electrum `submarine_swaps.py:797-802`
— `refund_pubkey=our_pubkey, claim_pubkey=their_pubkey` → slot 7=claim=theirs,
13=refund=ours. **Match.** Client claims onchain with preimage; we refund after
locktime — directionally correct.

### S-3: `create_reverse_swap` slot mapping (server serves client-forward = `createnormalswap`)
Verdict: ✅
Evidence: impl `submarine_swaps.py:631-634` — `{7:our_pubkey, 13:their_pubkey}`.
Electrum `submarine_swaps.py:913-918` — `refund_pubkey=their_pubkey,
claim_pubkey=our_pubkey`. **Match.** WE claim with preimage; client refunds after
locktime.

### S-4: `addswapinvoice` re-derivation — the historical inverted-slot bug (423ed93)
Verdict: ✅ — verified fixed, both slot order and hex-vs-bytes handled.
Evidence: impl `submarine_swaps.py:719-730`:
```python
our_pubkey = ECPrivkey(hex_to_bytes(swap.privkey)).get_public_key_bytes(compressed=True)
redeem_script = construct_script(
    WITNESS_TEMPLATE_REVERSE_SWAP,
    {1: 32, 5: ripemd(payment_hash), 7: our_pubkey,
     10: swap.locktime, 13: their_pubkey})
if bytes.fromhex(swap.redeem_script) != redeem_script:
    raise RequestFieldError('refundPublicKey does not match phase-1')
```
Electrum `submarine_swaps.py:994-998` re-derives with `refund_pubkey=their_pubkey,
claim_pubkey=our_pubkey` and asserts equality. Slot 7=claim=OURS, 13=refund=THEIRS —
**the inverse of `create_normal_swap` (S-2), which is exactly what the d1-inverted
historical bug got wrong; the current code is correct.** Both port gotchas are
handled: `swap.privkey` hex→bytes before `ECPrivkey` (comment documents the
`803bbbe` bite) and `bytes.fromhex(swap.redeem_script)` before comparison (comment
documents the hex-vs-bytes rejection). A mismatched `refundPublicKey` cannot
mis-bind the refund path. Pinned by `tests/test_protocol_contract.py:124`
(`test_swaps_lib_reproduces_real_signet_scripts`).

### S-5: `_claim_swap` funding detection + underfund guard (R2)
Verdict: ⚠️ — reverse guard correct; normal-direction decoy guard missing.
Evidence: impl `submarine_swaps.py:346-357`:
```python
for txin in txos:
    if swap.is_reverse and txin.value_sats() < swap.onchain_amount:
        # amount too low, we must not reveal the preimage
        continue
    break
```
R2 (never claim an underfunded reverse lockup) holds — see S-26. Electrum
`submarine_swaps.py:560-575` applies the `< onchain_amount` skip to **both**
directions (comment: forward swap — "counterparty might create dust outputs to
the funding address, trying to distract us"), skips decoy local txs
(`block_height <= TX_HEIGHT_LOCAL`), and prefers confirmed utxos. The impl takes
the first list element with none of that. Divergences D-2/D-3.

### S-6: Preimage extraction from the client's claim witness (normal swaps)
Verdict: ❌ — unguarded `witness_elements()[1]`; crash-loop → P0 funds loss.
Evidence: impl `submarine_swaps.py:379-387`:
```python
claim_tx = await self.lnwatcher.get_transaction(txin.spent_txid)
for txin in claim_tx.inputs():
    preimage = txin.witness_elements()[1]
    if sha256(preimage) == swap.payment_hash:
```
`TxInput.witness_elements()` (impl `transaction.py:422-424`) returns `[]` for any
input without a witness; `[1]` then raises `IndexError`. Electrum
`submarine_swaps.py:537-547` (`extract_preimage`) guards:
`if not witness or len(witness) < 2: continue  # tx may be unsigned`.
The client fully controls the claim tx's input list (they may consolidate legacy
UTXOs into it); one legacy input anywhere before the swap input makes every
`_claim_swap` pass raise (`log_exceptions` re-raises, `utils.py:360-378`;
`ChainMonitor.trigger_callbacks` swallows per callback, `chain_monitor.py:37-43`).
The preimage is then never registered, `_finish_normal_swap` never runs, our hold
HTLCs park until CLTV and fail — the client keeps the onchain claim AND gets the
LN payment back. Attacker-craftable, full `onchain_amount` loss. **D-1 (P0).**
Also: the loop variable shadows the funding `txin` (D-16).

### S-7: Refund branch, spent_height semantics, finality delay
Verdict: ⚠️ — semantics match; constants drift.
Evidence: impl `submarine_swaps.py:356-357, 371-376, 388-400`. `spent_height`
comes from `_fetch_spent_utxos` (`bitcoin_core_rpc.py:345-346`): `None`=unspent,
`0`=spent-unconfirmed (`wallet_send_tx.get("blockheight", 0)` for mempool txs),
`>0`=confirmed height — matching electrum's TX_HEIGHT_UNCONFIRMED/confirmed split.
Refund-confirmed path (`spent_height >= 2` → `is_redeemed=True` → `_fail_swap`)
≈ electrum `618-625` (electrum uses `spender_is_final`, 6-conf). Reverse-swap
final cleanup (`spent_height > 0 and current_height - spent_height >
REDEEM_AFTER_DOUBLE_SPENT_DELAY` → `delete_finished_reverse_swap`) ≈ electrum
`600-609`, but impl uses `REDEEM_AFTER_DOUBLE_SPENT_DELAY = 30` (`lnutil.py:20`)
vs electrum `SPENDER_FINALITY_DELAY = 6` and `>` vs `>=` — conservative direction
(delays cleanup 24 extra blocks; no funds impact). D-8.

### S-8: should_bump_fee
Verdict: ✅
Evidence: impl `submarine_swaps.py:395-400` — for an unconfirmed normal-swap
refund, `claim_tx_fee * 1.1 < recommended_fee` → bump. This is the old-electrum
logic that current electrum deleted in favor of txbatcher RBF (`SweepInfo` +
`add_sweep_input`, electrum `644-670`). Semantics preserved for the refund path;
reverse claims have no RBF bump (documented future optimization O2 in AGENTS.md).
Note the bump path is reachable only when `spent_height == 0` and
`swap.preimage is None` — consistent.

### S-9: Claim tx construction — nsequence, sighash, CLTV, version, dust
Verdict: ✅
Evidence:
- `create_claim_tx` (impl `115-133`): `script_sig=b''`, `witness_script` set,
  `PartialTransaction.from_io([txin],[txout], version=2, locktime=locktime)`,
  `tx.set_rbf(True)` → nsequence `0xffffffff-2` (`transaction.py:2121-2125`),
  non-final → **BIP65 CLTV satisfiable** on the refund path; default input
  nsequence `0xffffffff-1` (`transaction.py:321`) is also non-final, so both paths
  are consensus-valid. `version=2` satisfies BIP65's version requirement.
- Reverse claim uses `locktime=0` (impl `904-905`) — preimage branch, CLTV unused;
  valid. Electrum `create_claim_txin` (`1560-1580`) passes `cltv_abs=None` for
  reverse — equivalent.
- `sign_tx` (impl `880-891`): witness `[sig, preimage|0, witness_script]`;
  `0` for the refund path makes `OP_SIZE` see 0 ≠ 32 → ELSE branch → CLTV+refund
  key — identical to electrum (`1547`, `1574-1578`). Sighash: BIP143 witness-v0
  with `scriptCode` from the witness script (`transaction.py:2197-2212`), default
  `Sighash.ALL` appended (`2281-2283`) — correct for P2WSH.
- BelowDustLimit: `_create_and_sign_claim_tx` raises when
  `value - fee(CLAIM_FEE_SIZE) < dust_threshold()` (impl `901-903`);
  `_claim_swap` catches and returns (`435-437`) ≈ electrum `663-670`.
- `assert txin.prevout.txid.hex() == swap.funding_txid` before signing (impl
  `886`) — good corruption guard (this assert is also what makes the S-6
  variable-shadowing edge self-limiting, D-16).

### S-10: Fee sizing
Verdict: ⚠️
Evidence: `CLAIM_FEE_SIZE = 136` (`constants.py:31`) used for the claim fee
deduction (`submarine_swaps.py:901`), `get_claim_fee()` (`465-466`) and the prepay
(`564`: `prepay_amount_sat = get_claim_fee() * 2` — matches electrum's
`mining_fee * 2` structure, `833`). Electrum uses `SWAP_TX_SIZE = 150`
(`64-75`) via `get_fee_for_txbatcher` (`710-715`). A real 1-in-1-out P2WSH claim
serializes to ~140-145 vB, so 136 slightly underprices vs electrum's deliberate
150 over-estimate; at mempool-minimum feerates the effective feerate can dip
below target (still above minrelay at sane rates). `LOCKUP_FEE_SIZE = 153`
(`constants.py:32`) is now dead — imported (`submarine_swaps.py:36`) but never
used; `server_update_pairs` deliberately uses one fee everywhere (port find #9,
`793-809`). D-9 (P2).

### S-11: `_get_recv_amount`
Verdict: ✅
Evidence: impl `820-848` vs electrum `1432-1460`. Reverse branch: bounds check →
`percentage_fee = ceil(pct*x/100)`, subtract `+ base_fee(lockup_fee)`, floor,
`< dust_threshold()` → None — formula-identical (impl `831-840` = electrum
`1443-1452`). Forward branch: `x -= normal_fee; ceil(x*pct/(100+pct)); bounds`
(impl `842-846` = electrum `1454-1458`). `server_update_pairs` computes
`percentage` in pure Decimal (`780`) matching electrum `1374` (the float bug,
AUDIT/#14, fixed), and mirrors electrum's >10% mining-fee hysteresis
(`804-808` = electrum `1382-1385`). Differences are cap-shape only (D-10):
impl has one `_max_amount` (direction-uniform, `787-792`) vs electrum's
directional `_max_forward`/`_max_reverse` with `_keep_leading_digits`
(`1378-1381`) — internally consistent since impl advertises one cap for both
directions. Electrum's public wrappers add an invertibility sanity check
(`1492-1519`) the impl lacks — client-side tooling, not needed server-side, but
see coverage gaps.

### S-12: `_get_send_amount`
Verdict: ✅
Evidence: impl `850-878` vs electrum `1462-1490`. Reverse: `x += base_fee`,
`ceil(x/((100-pct)/100))`, bounds — identical (impl `860-868` = electrum
`1472-1480`). Forward: bounds first, then `ceil(pct*x/100) + normal_fee`
(impl `869-876` = electrum `1481-1488`). This value becomes `expectedAmount`
in `server_create_normal_swap` (`953`), which the electrum client checks with
off-by-one tolerance (`1096-1098`) — formula parity means strict client quotes
pass (live-verified per AGENTS.md session logs).

### S-13: `server_create_swap` validation
Verdict: ✅ (minor gap)
Evidence: impl `960-1004`. `_require_amount` (int/bool/positive, `500-508`),
`_parse_client_key` with exact 32/33-byte length checks (`920-933`,
electrum uses bare asserts `1633-1634`), `_require_fresh_payment_hash`
(`970`; electrum performs the same two checks inside `create_normal_swap`
`781-788` plus a third `has_payment_bundle` check the impl lacks — D-11, P2).
Capacity guards (incoming LN `973-977`, onchain balance `978-981`) return clean
error dicts — electrum has no equivalent (impl stricter, fine). Old `submarine`
API returns an error dict (`996-999`) vs electrum's raised exception
(`1649-1650`) — equivalent client-visible failure. `pairId` assert mismatches
raise → generic error reply via `handle_request` (`1160-1173`).

### S-14: `server_create_normal_swap` validation
Verdict: ✅
Evidence: impl `935-958` = electrum `1602-1621` plus impl-only
`_require_amount`/`_parse_client_key`/outgoing-capacity guard. Response fields
match electrum exactly (`949-957` vs `1612-1620`, incl. `acceptZeroConf: False`).

### S-15: `server_add_swap_invoice` validation
Verdict: ⚠️ — core checks present and correct; CLTV cap missing.
Evidence: impl `684-735`. Present: bolt11 parse with clean error (`691-694`);
unknown/non-reverse swap rejected (`699-701` = electrum `986-989`); invoice
amount must equal swap amount (`702-705` = electrum `988`); preimage possession
check `sha256(preimage) == payment_hash` (`706-707` = electrum `991` — the
mismatched-invoice attack from playground issue #16 is blocked); in-flight
guard `spending_txid is None` (`708-709` = electrum `992`); full re-derivation
(S-4, `719-730` = electrum `993-998`); duplicate-bind guard (`731-732` =
electrum `999`). Missing vs electrum: `_check_bolt11_invoice(...,
max_min_final_cltv_delta=MAX_MIN_FINAL_CLTV_DELTA)` (electrum `980`) — we accept
and then PAY a client invoice with an unbounded `min_final_cltv_expiry`,
committing our outgoing HTLCs to an attacker-chosen CLTV (D-4, P1); and
electrum's `wallet.get_invoice(...) is None` duplicate-save guard (`1001`) —
impl saves unconditionally (`733`, D-12, P2).

### S-16: `_fail_swap`
Verdict: ⚠️
Evidence: impl `289-308` vs electrum `497-523`. Both keep funded swaps' state
(impl `306-307` ≈ electrum `505`), remove the lnwatcher callback, cancel/fail
hold-invoice HTLCs. Impl deletes payment info unconditionally (`301`) where
electrum conditions on `!= PR_PAID` (`517-523`) to preserve history (accounting
drift, P2); impl does not clean `self.prepayments` or the
`_swaps_by_funding_outpoint`/`_swaps_by_lockup_address` indexes (electrum pops
all under `swaps_lock`, `511-516`) — both indexes are write-only in the impl
(`766-771`; no read sites), so stale entries are a leak, not a correctness bug.
The prepay preimage also survives `_finish_normal_swap` (only the main hash's
payment info is deleted, `321`) — minor leak (D-15).

### S-17: `_finish_normal_swap`
Verdict: ✅
Evidence: impl `310-324`. Asserts preimage, settles the hold invoice, verifies
SETTLED state (with error log on failure), deletes hold invoices (main + prepay),
deletes payment info, removes watcher callback, pops swap, writes DB. Electrum's
equivalent is distributed (`611-617` save_preimage path + `602-609` cleanup);
impl's explicit settle-then-verify is reasonable. Preimage possession is
guaranteed by the S-6 extraction (`sha256(preimage) == payment_hash`, `384`).

### S-18: `delete_finished_reverse_swap`
Verdict: ✅
Evidence: impl `326-333` — delete invoice, remove callback, pop
`invoices_to_pay`, pop swap only if unfunded/redeemed, write DB. Matches its
call site (`371-376`) and electrum's finality cleanup semantics
(`600-609`).

### S-19: Restart recovery
Verdict: ⚠️
Evidence: impl `156-178`: swaps reloaded from `json_db`, `_payment_hash` set,
`_add_or_reindex_swap` re-run (≈ electrum `_add_swap`/`_reindex_swap`
`1353-1370`), prepayments rebuilt (`171-174` = electrum `282-283`), and
`main_loop` re-registers lnwatcher callbacks for all non-redeemed swaps
(`211-215` = electrum `304-309`). Divergence: for non-reverse swaps the impl
POPS the swap when the hold invoice is missing (`164-169`); electrum never
drops swap state on load. In practice a funded swap's hold invoice survives
(`check_invoice_expiry` skips FUNDED/SETTLED, `cln_lightning.py:127-130`) and
R8 purges corrupt entries, so the pop mostly hits legitimately-dead expired
swaps — but a R8-corrupted FUNDED entry would silently drop our refund-key
state (privkey lives only in the swap record). D-18 (P2). Impl also does not
re-run `register_address` on restart (relies on the bitcoin-core wallet's
persistent watch-only imports from `register_address`,
`bitcoin_core_rpc.py:137+`; `add_normal_swap` does call it at creation, `614`).

### S-20: R1 — never spend an unconfirmed lockup
Verdict: ✅
Evidence: `if funding_height.conf > 0:` gates the claim/refund broadcast
(`submarine_swaps.py:439-461`), with the spec-quote block documenting the
preimage-reveal double-spend rationale. `conf` comes from bitcoind
`confirmations` (`bitcoin_core_rpc.py:225-231`; esplora: 1 iff confirmed,
`222-224`). `acceptZeroConf` is hardcoded False (`952`). Pinned by
`tests/test_e2e_bug_regressions.py:208`
(`test_broadcast_gated_on_one_confirmation`). Electrum's equivalent is
txbatcher nsequence=1 (`1554-1558`, `645-646`) — same 1-conf guarantee,
different mechanism.

### S-21: R3 — never SIT on a confirmed lockup
Verdict: ✅
Evidence: no artificial delay between confirmation and broadcast; ChainMonitor
polls every 10s and fires callbacks on every new block (`chain_monitor.py:21-35`),
plus one trigger at startup (`submarine_swaps.py:217-218`). Live evidence in
AGENTS.md (claim `e3c670aa` one block after lockup `4ecb1e4d` confirmed).
Known bounded gap: a broadcast claim stuck in mempool is never RBF-bumped
(future O2, documented).

### S-22: R4 — prepay bundled with main invoice
Verdict: ✅
Evidence: `create_normal_swap` always `prepay=True` (`544`);
`add_normal_swap` creates the prepay hold invoice (claim_fee × 2, `563-567`),
bundles via `bundle_payments(swap_invoice, prepay_invoice)` (`589`) which
attaches the prepay to the main HoldInvoice (`cln_lightning.py:522-528`), and
`callback_handler` fires the funding callback only when the main invoice is
FUNDED **and** the prepay is FUNDED-or-already-settled
(`cln_lightning.py:169-193`, incl. the settled-then-deleted prepay fix).
Matches electrum's `bundle_payments` + MPP-coupling semantics (`860-875`,
lnpeer bundle gating) — the F8 lesson is enforced.

### S-23: R5 — never park a payer's funds on an unknown hash
Verdict: ✅
Evidence: `hold_invoice_callback` (`476-498`): no swap state → cancel HTLCs
now (`485-491`); funding failure → `_fail_swap` (`496-498`), with
`create_funding_tx` raising on `fundpsbt` None (`749-756`) so the handler
actually fires. Deliberate divergence from electrum (`761-776` returns
silently) per AUDIT A5/issue #10 — improvement, documented. Tombstones for
replayed HTLCs: `delete_hold_invoice` (`cln_lightning.py:403-415`) +
`plugin_htlc_accepted_hook` 400F path (`cln_lightning.py:199-206`), issue #25.

### S-24: R6 — duplicate payment_hash rejection
Verdict: ⚠️ (2 of electrum's 3 guards)
Evidence: `_require_fresh_payment_hash` (`510-518`) checks `swaps` and
`get_preimage` — exactly electrum's first two (`781-788`). Electrum's third
(`has_payment_bundle`, `786-788`) is absent (D-11). The impl has an additional
CLN-side guard (`b11invoice_from_hash` raises `DuplicateInvoiceCreationError`
if CLN still knows the hash, `cln_lightning.py:427-431`). Net exposure is a
narrow replay window after both swap state and preimage info are deleted —
low.

### S-25: R7 — MPP sets must sum before settle
Verdict: ✅
Evidence: `HoldInvoice.is_fully_funded` sums ACCEPTED+SETTLED HTLCs vs amount
(`invoices.py:251-261`, with the BOLT #2 same-hash quote); FUNDED status gates
the funding callback (`cln_lightning.py:173,193`); `Htlc.settle` refuses
non-ACCEPTED state (`invoices.py:172-182`). Same contract as electrum's
hold-invoice path.

### S-26: R2 — never claim an underfunded reverse lockup
Verdict: ✅
Evidence: `submarine_swaps.py:347-349` (`is_reverse and value_sats() <
onchain_amount → skip`). Pinned by `tests/test_e2e_bug_regressions.py:219`
(`test_underfunded_reverse_lockup_never_claimed`). The normal-direction gap is
S-5/D-2 (different exposure: our refund, not the preimage).

### S-27: R8 — DB hygiene on load
Verdict: ✅
Evidence: `monitor_expiries` type-guards every hold-invoice entry, purges
non-HoldInvoice values instead of crashing (`cln_lightning.py:96-107`); pinned
by `tests/test_e2e_bug_regressions.py:107`. Round-trip pinned at `:88`.

### S-28: R9 — hint public channels
Verdict: ✅
Evidence: `filter_suitable_recv_chans` (`lnutil.py:31-61`) selects ALL
`CHANNELD_NORMAL` channels (no private-only filter), sorts by inbound capacity,
cutoff heuristics, cap 15; `_get_route_hints` (`cln_lightning.py:483-515`)
appends `r` tags with the BOLT #11 quote block documenting the live NoPathFound
incident. Pinned by `tests/test_e2e_bug_regressions.py:229-246`.

## DIVERGENCES (port-divergence list)

### D-1: `_claim_swap` — unguarded preimage-witness extraction (P0)
What electrum does that we don't: `extract_preimage` skips inputs with
`len(witness) < 2` (electrum `537-547`); impl indexes `[1]` unconditionally
(`submarine_swaps.py:383`). A client claim tx containing one legacy
(non-witness) input before the swap input crashes `_claim_swap` on every pass
(`transaction.py:422-424` returns `[]`). The preimage is never registered, the
hold invoice never settles, our parked HTLCs fail at CLTV, the client is
refunded LN while keeping the onchain claim — attacker profit = our
`onchain_amount`. Fix: port electrum's guard verbatim
(`if len(witness) < 2: continue`). Funds-path P0.

### D-2: `_claim_swap` — underfund/decoy skip applies to reverse only (P1)
Electrum skips `value < onchain_amount` for BOTH directions and explains the
forward-direction dust-decoy distraction attack (electrum `564-571`); impl
guards reverse only (`submarine_swaps.py:347`). For normal swaps (we funded the
lockup; anyone can pay more utxos to the P2WSH address), an attacker-controlled
dust decoy that sorts first makes `_create_and_sign_claim_tx` raise
BelowDustLimit forever (`901-903`, `435-437`) — our post-locktime refund is
blocked and the real utxo is never selected. Griefing → locked funds (manual
intervention), not direct theft. Fix: drop the `swap.is_reverse and` from the
guard (exact electrum parity).

### D-3: `_claim_swap` — no local/decoy-tx skip, no confirmed-utxo preference (P2)
Electrum skips `block_height <= TX_HEIGHT_LOCAL` decoys and prefers confirmed
utxos (electrum `561-575`); impl's backend cannot see "local" txs the same way
(bitcoind wallet view), and `funding_height.conf > 0` gates broadcast, so the
exposure is limited to picking a mempool funding over a confirmed one in the
selection loop. Hardening only.

### D-4: `server_add_swap_invoice` — no CLTV cap on the client invoice we pay (P1)
Electrum runs `_check_bolt11_invoice(invoice, max_min_final_cltv_delta=435)`
(electrum `980`, `MAX_MIN_FINAL_CLTV_DELTA = 3*144+3` at `85`) before binding;
impl accepts any bolt11 (`submarine_swaps.py:691-696`) and then pays it — our
outgoing HTLCs commit to an attacker-chosen unbounded `min_final_cltv_expiry`
(funds-lock griefing; CLN's own maxcltv limits bound the worst case). Fix:
reject invoices with `min_final_cltv_expiry_delta > 3*144+3`.

### D-5: `_claim_swap` — `except TxBroadcastError` is dead code (P2)
The claim is broadcast via `self.lnwatcher.broadcast_raw_transaction`
(`460`), which raises `BitcoinCoreRPCError` (`bitcoin_core_rpc.py:371-380`);
`BitcoinCoreRPCError(Exception)` is not a `TxBroadcastError` (`utils.py:125`,
`bitcoin_core_rpc.py:441`). The intended handler (`462-463`) never fires; the
error escapes to `ChainMonitor.trigger_callbacks`' per-callback catch
(`chain_monitor.py:41-43`) — noisy log, retried next block, no RBF bump. Only
the funding path (`cln_chain.py:69-77`) actually raises `TxBroadcastError`.
Fix: catch both (or make `BitcoinCoreRPCError` subclass `TxBroadcastError`).

### D-6: `_claim_swap` — no MIN_LOCKTIME_DELTA_FOR_CLAIM guard on reverse claims (P2)
Electrum refuses to START a claim within 30 blocks of locktime unless the
preimage is already public, to avoid an RBF race against the counterparty
refund (electrum `81`, `651-652`, `635-637`); impl has no equivalent — the
only locktime logic left is the (dead, D-7) invoice-pop guard. Exposure: fee
waste on a lost race, not funds loss (a losing claim simply never confirms).
Also note impl's `constants.py` does not define
`MIN_LOCKTIME_DELTA_FOR_CLAIM` at all.

### D-7: `_claim_swap` — reverse-branch `preimage is None` block is dead code (P2)
For reverse swaps the impl stores its own preimage at creation
(`add_reverse_swap`, `665`), so `submarine_swaps.py:415-429` (get-preimage
fallback, stop-paying-near-locktime pop, invoices_to_pay scheduling) can never
execute — including the `remaining_time <= MIN_LOCKTIME_DELTA` pop that looks
like protection against paying near locktime. Payment scheduling actually
happens at bind time (`734`, same as current electrum `1000`), and payment
give-up is bounded by the 15-attempt cap + invoice expiry (`241-277`) — an
impl improvement over electrum's infinite 10-min retries (`459-474`). The dead
block should be deleted or made live to avoid false confidence.

### D-8: finality delay constant drift (P2/info)
Impl `REDEEM_AFTER_DOUBLE_SPENT_DELAY = 30` (`lnutil.py:20`) with strict `>`
(`373`) vs electrum `SPENDER_FINALITY_DELAY = 6` with `>=` (`86`, `600-601`).
Conservative direction (swap watched ~24 blocks longer); also impl's
`assert_constants` (`231-239`) does not include electrum's
`MAX_LOCKTIME_DELTA + SPENDER_FINALITY_DELAY < MIN_FINAL_CLTV_DELTA_ACCEPTED`
form (`90`) — both hold numerically today.

### D-9: fee-size constants (P2)
`CLAIM_FEE_SIZE = 136` vs electrum `SWAP_TX_SIZE = 150` (`constants.py:31` vs
electrum `64`); `LOCKUP_FEE_SIZE = 153` imported but unused
(`submarine_swaps.py:36`, no other reference). Claims are budgeted slightly
below their true serialized size (~140-145 vB). Fix: 150 (electrum parity) and
drop the dead constant.

### D-10: `server_update_pairs` cap shape (P2/info — documented)
One direction-uniform `_max_amount` = min(env cap, balance, LN send+recv) with
each term floored at 20000 (`787-792`) vs electrum's directional
forward/reverse caps with `_keep_leading_digits(2)` and MAX_SWAP_AMT=0.1 BTC
(`1376-1381`). The 20000 floor can advertise capacity above a near-empty
balance, but `server_create_swap`'s per-swap balance check (`978-981`) rejects
what the wallet cannot fund. Intentional per R3; keep documented.

### D-11: `_require_fresh_payment_hash` — missing `has_payment_bundle` guard (P2)
Electrum's third duplicate-hash guard (electrum `786-788`) is absent
(`510-518`); impl bundles live only inside HoldInvoice state
(`cln_lightning.py:522-528`), narrowing the exposure. Add the equivalent
check (any hold invoice or tombstone already knows the hash) for defense in
depth.

### D-12: `server_add_swap_invoice` — unconditional `save_invoice` (P2)
Electrum asserts the invoice is not already in the wallet before saving
(electrum `1001`); impl overwrites by id (`733`). Same-id invoices are
content-identical in practice; cosmetic.

### D-13: `add_normal_swap` — no runtime locktime-vs-invoice-CLTV margin check (P2/info)
Electrum re-checks `locktime + MIN_LOCKTIME_DELTA + SPENDER_FINALITY_DELAY <
height + min_final_cltv_delta` per invoice (electrum `854-858`); impl relies
on `assert_constants` (`231-239`) making the invariant structural
(70+66=136 < 147). Sound while the constants hold; add the runtime check if
constants ever become configurable.

### D-14: funding via direct tx vs electrum txbatcher (info)
Electrum batches the funding output with other wallet payments
(`hold_invoice_callback` electrum `761-776` + `create_funding_output`
`1176-1177`); impl builds and broadcasts a dedicated 1-output RBF tx
(`737-764`, `492-498`). Fee/privacy tradeoff, no protocol impact. Impl's
`broadcast_funding_tx` sets `funding_txid` before broadcasting (`763-764`);
if the broadcast raises, `_fail_swap` keeps the record (funded) while
cancelling HTLCs — recoverable on restart via the re-registered callback, but
worth a note in ops runbooks.

### D-15: payment-info/index cleanup asymmetries (P2)
`_fail_swap` deletes RECEIVED/SENT payment info unconditionally (`301`) where
electrum preserves PR_PAID history (`517-523`); `_finish_normal_swap` never
deletes the prepay hash's preimage (`318-321` vs main `321`); `_swaps_by_*`
indexes are never popped (write-only structures, `766-771`). Accounting/leak
only.

### D-16: `_claim_swap` — `txin` loop-variable shadowing (P2)
The preimage-extraction loop reuses `txin` (`382`), clobbering the funding
utxo binding. Reachable fall-through only in a 1-block window
(spent_height==1 or bump-needed, preimage-None, past locktime) and is caught
by `sign_tx`'s `assert txin.prevout.txid.hex() == swap.funding_txid`
(`886`) — crash-loop until `spent_height >= 2` resolves it. Rename the loop
variable (electrum extracted a helper precisely to avoid this).

### D-17: dead spend handling for unconfirmed spends (info)
Impl returns on `spent_height is not None and not should_bump_fee` (`431`)
— treats an unconfirmed spend as done unless a refund bump is due; electrum
re-arms via txbatcher for confirmed spends only (`642-643`). Combined with
D-5 this means a mempool-stuck claim is never replaced (O2, documented).

### D-18: restart pop-if-no-hold-invoice without funding check (P2)
`__init__` pops non-reverse swaps whose hold invoice is gone
(`164-169`); electrum never drops swap state on load (`278-293`). FUNDED
invoices survive the expiry sweeper (`cln_lightning.py:127-130`), so the
practical trigger is the R8 corruption path — exactly the case where dropping
the swap record also drops the only copy of the refund `privkey`. Fix: only
pop when `swap.funding_txid is None` (mirror `_fail_swap`'s condition).

## COVERAGE GAPS (invariants deserving a quote or a test)

1. **D-1 regression test (P0 fix gate):** build a claim tx fixture with one
   legacy input + the P2WSH swap input; assert `_claim_swap` extracts the
   preimage instead of raising. The existing
   `test_swaps_lib_reproduces_real_signet_scripts` covers script bytes only.
2. **Normal-swap decoy-dust test (D-2):** two utxos at the lockup address
   (dust + real); assert the real one is selected for refund. Currently only
   the reverse direction is pinned (`test_underfunded_reverse_lockup_never_claimed`).
3. **Refund-tx consensus test:** sign a real post-locktime refund with the
   ported `create_claim_tx`/`sign_tx` and assert acceptance by bitcoind
   policy (BIP65: version 2, non-final nsequence, nlocktime=swap.locktime,
   BIP143 sighash). No test currently constructs a *refund* witness; the
   consensus-validity combination is only exercised live by accident.
4. **BOLT-adjacent quote candidates:** (a) BOLT #2 `cltv_expiry` discipline
   at the D-4 site (quote the accepting-node MUST on unreasonable expiry
   next to the future cltv cap); (b) a BIP65 note is not a BOLT quote —
   cite it as `# Impl-note:` beside `create_claim_tx`'s locktime/nsequence
   coupling instead, so the non-final-nsequence invariant is pinned in code;
   (c) R1's existing quote block is the model — mirror it at S-5 (underfund
   guard) once D-2 is fixed.
5. **Invertibility sanity (S-11/S-12):** port electrum's
   `calc-invert-sanity-check` (electrum `1492-1519`) as a unit test over the
   full [min,max] range at several percentages — cheap early-warning for
   future fee-formula edits (the AUDIT/#14 class).
6. **`server_update_pairs` floor test:** assert `_max_amount >= _min_amount`
   and that a sub-20000 balance still yields a truthful per-swap rejection
   (D-10).
7. **D-5 test:** assert claim-broadcast failure is caught and retried
   (mock `broadcast_raw_transaction` raising `BitcoinCoreRPCError`).

## FINDINGS SUMMARY

- P0 (funds-risk): **1** — D-1 unguarded preimage-witness extraction.
- P1 (conditional funds / interop): **2** — D-2 normal-swap decoy/underfund
  guard missing (refund lockable); D-4 no CLTV cap on client invoice we pay.
- P2 (hardening/cosmetic/info): **13** — D-3, D-5, D-6, D-7, D-8, D-9, D-11,
  D-12, D-13, D-15, D-16, D-18 (+D-10 documented-intentional, D-14/D-17 info).
- R1–R9: all nine confirmed present in code (R6 with the D-11 gap). The
  historical 423ed93 inverted-slot bug in addswapinvoice re-derivation is
  verified FIXED (S-4), with both port gotchas (hex privkey, hex redeem_script)
  handled and pinned by tests.
- Core protocol parity: script templates, slot orders in all three
  construction sites, amount math, offer fee hysteresis, hold-invoice
  bundling, and the 1-conf claim gate are semantically faithful to current
  electrum.

VERDICT: FAIL — one P0 (D-1) on the funds path: a maliciously-shaped client
claim tx crashes preimage extraction every block, forcing CLTV refund of the
payer's HTLCs while the onchain claim stands. Fix D-1 (one-line guard, electrum
parity), add regression test 1, then re-audit S-6 before mainnet
consideration; D-2 and D-4 should follow before any mainnet enablement
(`MAINNET_ENABLED` stays frozen).
