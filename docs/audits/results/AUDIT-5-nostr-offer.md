# AUDIT-5 RESULT: Nostr Offer Surface & PoW

- **Date:** 2026-08-21
- **Repo commit audited:** `61146f8c90a7a494813e9e15341ca86bb3a0d227` (`61146f8 ci+docs: spec-quote-drift workflow …`)
- **Auditor method:** our announcement/PoW/DM surface checked against the authority electrum clients actually enforce — the CLIENT-side parser `/home/ubuntu/src/electrum/electrum/submarine_swaps.py` (`NostrTransport._get_pairs_loop`, 2054-2119) and `electrum/util.py:get_nostr_ann_pow_amount` (2466-2476) — then diffed against electrum's server side (`publish_offer` 1986-2013, `run_nostr_server` 313-346, `set_nostr_proof_of_work` 438-457, `_handle_requests` 2191-2219). Live test evidence: `pytest tests/test_plugin_config_pow.py tests/test_protocol_contract.py` → **11/11 PASSED** (incl. the 200-vector electrum-authority PoW cross-check, `test_protocol_contract.py:100-114`), plus an additional 5,000-random-vector cross-check run during this audit: **0 mismatches**.

**Files read (evidence sources):**

| File | Role |
|---|---|
| `swap-provider/plugin/offer.py` (82 lines, full) | Impl: `nostr_ann_pow_bits`, `mine_ann_pow_nonce`, `build_offer_content`, `build_offer_tags` |
| `swap-provider/plugin/submarine_swaps.py` | Impl: `NostrTransport` 1007-1192, `run_nostr_server` 181-206, `server_update_pairs` 778-810 |
| `swap-provider/plugin/plugin_config.py` | Impl: PoW pinning 53-75, `ANN_NET_NAME` 76-88, keypair 200-207, `nostr_relays_csv` 183-185 |
| `swap-provider/plugin/cln_swap_provider.py` | Impl: plugin lifecycle (main-loop exit path 81-86) |
| `swap-provider/plugin/constants.py` | `BitcoinMutinynet.NET_NAME="mutinynet"` (198-200), `NETS_LIST` (207) |
| `/home/ubuntu/src/electrum/electrum/submarine_swaps.py` | Reference: server publish + client parse (lines cited inline below) |
| `/home/ubuntu/src/electrum/electrum/util.py:2423-2476` | Reference: `gen_nostr_ann_pow` (miner), `get_nostr_ann_pow_amount` (VERIFIER) |
| `/home/ubuntu/src/electrum/electrum/simple_config.py:959` | Reference: `SWAPSERVER_POW_TARGET` default=30 |
| `/home/ubuntu/src/electrum/electrum/plugins/swapserver/swapserver.py` | Reference plugin shim (51 lines — real logic lives in submarine_swaps.py) |
| `tests/test_plugin_config_pow.py`, `tests/test_protocol_contract.py` | Pinning tests (full read; both green this session) |
| git `8c12e27` | `ANN_NET_NAME` commit (constants.py +9, plugin_config.py +12, tests +45) |

---

## N-Table (summary)

| # | Check | Verdict |
|---|---|---|
| N-1 | PoW preimage byte-parity with electrum's CLIENT verifier | ✅ |
| N-2 | Bit-count semantics (leading-zero bits incl. zero-byte runs, all-zero digest) | ✅ |
| N-3 | Pubkey operand is x-only 32B end-to-end (mine ≡ verify ≡ event pubkey) | ✅ |
| N-4 | `pow_nonce` hex encoding ↔ client `int(..., 16)` parse | ✅ |
| N-5 | Pow target default 30 = electrum default; pinned-nonce fail-loud validation | ✅ |
| N-6 | Offer content: exact JSON key set | ✅ |
| N-7 | Field semantics/units: sats everywhere; percentage 0.5 = 0.5%; millionths/10000 parity | ✅ |
| N-8 | max_forward/max_reverse: single combined cap vs electrum per-direction caps | ⚠️ P2 |
| N-9 | Electrum's no-liquidity publish guard absent (floor-clamp design instead) | ⚠️ Note |
| N-10 | kind 30315, `d` tag `electrum-swapserver-5`, client `#d` filter match | ✅ / ⚠️ P2 dead constant |
| N-11 | `r` `net:` tag + `ANN_NET_NAME` override (commit 8c12e27) | ✅ |
| N-12 | `expiration` tag arithmetic parity; who actually enforces freshness | ✅ / doc note |
| N-13 | DM framing: kind 25582, NIP-04, `p` tag, subscription query | ✅ |
| N-14 | Reply etiquette (`reply_to`), error replies always sent | ✅ (improvement) |
| N-15 | Request handling inline — no queue/backpressure vs electrum queue(5)+drop | ⚠️ P2 DoS |
| N-16 | `dm_replies` mutated without `is_server` guard (defaultdict growth) | ⚠️ P2 DoS |
| N-17 | Replay: in-session event-id dedup (improvement); cross-restart = parity | ✅ / parity |
| N-18 | Unauthenticated state-mutating DMs | parity (protocol-inherent) |
| N-19 | Rotation: 600s cadence / 610s expiry margin; immediate first publish | ✅ |
| N-20 | Publish-failure isolation: only `TimeoutError` caught — other exceptions kill the plugin | ⚠️ P1 |
| N-21 | DM-listener death → offer keeps advertising (inherited electrum flaw) | parity note |

---

## Detailed Verdicts

### N-1: PoW preimage — THE critical check
Verdict: ✅ (byte-for-byte)

Electrum's **client-side verifier** (`electrum/submarine_swaps.py:2085-2086` calls it on every ingested offer):

```python
# electrum/util.py:2466-2476  — the authority clients enforce
def get_nostr_ann_pow_amount(nostr_pubk: bytes, nonce: Optional[int]) -> int:
    if not nonce or nonce < 0:
        return 0
    hash_preimage = b'electrum-' + nostr_pubk
    digest = hash_function(hash_preimage + nonce.to_bytes(32, 'big')).digest()
    digest = int.from_bytes(digest, 'big')
    return hash_len_bits - digest.bit_length()      # 256 - bit_length
```

Our miner/counter (`offer.py:23-37`):

```python
pre = b"electrum-" + bytes.fromhex(pubkey_xonly_hex) + nonce.to_bytes(32, "big")
digest = hashlib.sha256(pre).digest()
```

Preimage = ASCII `"electrum-"` ‖ 32-byte x-only pubkey ‖ nonce as **big-endian 32 bytes** — identical construction, identical operand order, identical nonce width (`to_bytes(32, 'big')` both sides; electrum's miner pins the same width at `util.py:2428`). **Empirical proof:** the electrum-authority test (`test_protocol_contract.py:102-114`, 200 vectors) passed this session, plus 5,000 fresh random vectors compared in-audit against the real `electrum.util.get_nostr_ann_pow_amount` — **0 mismatches**.

### N-2: Bit-count semantics
Verdict: ✅

Electrum counts `256 - digest.bit_length()` over the big-endian integer. Ours walks bytes: zero bytes add 8 and continue; the first nonzero byte adds `8 - byte.bit_length()` then stops (`offer.py:30-36`). For a digest whose first nonzero byte `v` sits at index `i`: electrum's `bit_length = (31-i)*8 + v.bit_length()` → `256 - bit_length = i*8 + 8 - v.bit_length()` — algebraically identical, including the degenerate all-zero digest (both return 256). One theoretical edge: electrum short-circuits `nonce <= 0` to 0 bits (`util.py:2468-2469`) while ours would happily score `nonce=0`; a pinned `ANN_POW_NONCE=0` that hashed to ≥30 bits would pass our startup validation but score 0 with every client. Probability ≈ 2⁻³⁰ for that one nonce and requires explicitly pinning `0` — negligible, noted for completeness.

### N-3: Pubkey operand — x-only, end-to-end consistent
Verdict: ✅

The client verifies against `bytes.fromhex(event.pubkey)` — the 32-byte x-only nostr event pubkey (`electrum/submarine_swaps.py:2080,2086`). Electrum's server mines against `nostr_keypair.pubkey[1:]` — compressed key minus prefix byte (`submarine_swaps.py:440,449`). Ours: `nostr_keypair.pubkey.hex()[2:]` at both mining and pinned-nonce validation (`plugin_config.py:57,65`) and `self.nostr_pubkey = keypair.pubkey.hex()[2:]` for the transport identity (`submarine_swaps.py:1031`, same as electrum `:1879`). Verified live: `ECPrivkey.get_public_key_bytes()` returns 33 bytes, so `[2:]` strips exactly the one prefix byte — mine-key ≡ verify-key ≡ signed-event-pubkey. (Tests pin the shape: stub keypairs are `"02"+pubk`, `test_plugin_config_pow.py:50,80`.)

### N-4: `pow_nonce` hex encoding
Verdict: ✅

Both emit Python `hex(nonce)` (i.e. lowercase `0x…`): ours `offer.py:69`, electrum `submarine_swaps.py:1998`. Client parses `int(content.get('pow_nonce', "0"), 16)` (`submarine_swaps.py:2085`) — Python `int()` accepts the `0x` prefix. Pinned by `test_protocol_contract.py:83`.

### N-5: Target default + pinned-nonce validation
Verdict: ✅

Electrum client default `SWAPSERVER_POW_TARGET = 30` (`simple_config.py:959`); ours `ANN_POW_TARGET_BITS` default `"30"` (`plugin_config.py:54`). Where electrum silently re-mines an insufficient nonce at startup (`set_nostr_proof_of_work`, `submarine_swaps.py:438-457`), ours **fails loud** on a pinned nonce below target (`plugin_config.py:59-63`, test `test_pinned_nonce_below_target_fails_loud`) and refuses to run targets >24 bits without a pinned nonce (`:71-75`) — 30-bit mining is delegated to `../nostr-pow-bench` by design. Equal safety, better diagnosability; the error message even names the pubkey to mine for.

### N-6/N-7: Offer content keys, semantics, units
Verdict: ✅

Exact key-set parity (`offer.py:62-71` vs electrum `submarine_swaps.py:1991-1999`; pinned by `test_protocol_contract.py:78-86`):
`percentage_fee` (float, ≤4.7.1 compat, both sides comment it), `mining_fee`, `min_amount`, `max_forward_amount`, `max_reverse_amount`, `relays` (CSV), `pow_nonce` (hex).

Units: everything is **sats** on both sides — client feeds these straight into `SwapFees` (`submarine_swaps.py:2097-2103`) and compares against sat swap amounts (`check_invoice_amount` :1425-1431). `min_amount`: ours hardcodes 20000 (`submarine_swaps.py:781`) = electrum's `MIN_SWAP_AMOUNT_SAT = 20_000` (`:77`). `percentage`: identical formula `Decimal(SWAPSERVER_FEE_MILLIONTHS)/10000` (ours `:780`, electrum `:1374`) → e.g. 5000 ppm publishes `0.5` meaning 0.5%; client re-derives `Decimal(str(0.5))` and divides by 100 in its fee math — float round-trip documented safe in our code (`:778-779`). `mining_fee`: single fee with electrum's exact >10% adoption hysteresis mirrored (`:804-807` ↔ electrum `:1382-1385`, port find #9/A1). `relays`: joined without spaces (`plugin_config.py:184-185`), matching the client's bare `split(',')` (`:2093`) and `[:10]` cap is client-side.

### N-8: max_forward / max_reverse — combined cap ⚠️ P2
Electrum advertises **per-direction** caps: `max_forward = min(ln_recv, onchain, MAX)` and `max_reverse = min(ln_send, MAX)` (`submarine_swaps.py:1378-1379`). Ours advertises ONE cap for both directions: `min(env MAX_SWAP_AMOUNT, onchain balance, ln_recv + ln_send)` (`submarine_swaps.py:787-792`). A node with 0 recv and 500k send capacity advertises `max_forward_amount = 500k` that it cannot serve — forward swaps beyond true recv capacity are only rejected at request time (`server_create_normal_swap` capacity check, `:941-944`, polite error reply). Not a wire-format bug (clients accept it), but the offer can overstate a direction's real ceiling — capacity-honesty divergence from the reference.

### N-9: No-liquidity publish guard ⚠️ Note
Electrum skips publishing when both caps are below min (`submarine_swaps.py:1988-1990`). Ours floors `_max_amount` at 20000 (`:789-791`, R3 comment) so it always publishes — deliberate design (keep discovery alive; per-request checks backstop). Same family as N-8: offer may promise floor-level capacity the node can't fund; request-time errors mitigate.

### N-10: kind + `d` tag
Verdict: ✅ / ⚠️ dead constant

Kind 30315 (`offer.py` consumers; transport publishes `kind=self.STATUS_NIP38` = 30315, `submarine_swaps.py:1017,1098`) = electrum `USER_STATUS_NIP38` (:1869, :2007). `d` tag `electrum-swapserver-5` from `offer.py:16,79` matches the client's relay filter `#d: ["electrum-swapserver-5"]` and post-hoc re-check (`electrum/submarine_swaps.py:2059, 2072`) — version 5 both sides. **P2 trap:** our `NostrTransport` class still declares `NOSTR_EVENT_VERSION = 2` (`submarine_swaps.py:1020`) — dead (nothing references it; `publish_offer` imports the tag builder from `offer.py`), but any future use of the class constant for a filter or d-tag makes us invisible to every current client. Same for the typo'd dead `FEE_UPDATE_INVERVAL_SEC` (:1018).

### N-11: `net:` tag + ANN_NET_NAME (commit 8c12e27)
Verdict: ✅

Tag shape `["r", "net:<name>"]` (`offer.py:80`) matches electrum's publisher (:2002) and the client's relay-level `#r: [f"net:{constants.net.NET_NAME}"]` filter + re-check (:2060, 2074). The override is correct and well-guarded: default `net_name = CLN network NET_NAME` (`plugin_config.py:76`); `ANN_NET_NAME` must be a known `AbstractNet` subclass name else startup refuses (`:81-88`, `BitcoinMutinynet.NET_NAME="mutinynet"` exists in `constants.py:198-200`) — fail-loud on an ambiguous tag. The commit's premise checks out against the client parser: the `r` tag **is** the only network discriminator electrum clients apply to offers (no chain check in `_get_pairs_loop`), so a mutinynet node on CLN's `network=signet` correctly becomes discoverable as `net:mutinynet` and correctly invisible to signet clients. Tests pin default, override (incl. `build_offer_tags` output `["r","net:mutinynet"]`), and unknown-rejected (`test_plugin_config_pow.py:86-128`).

### N-12: `expiration` tag
Verdict: ✅ / doc note

Arithmetic parity: ours `str(ts + 600 + 10)` (`offer.py:18-20,81`) = electrum `str(now() + OFFER_UPDATE_INTERVAL_SEC + 10)` (:1871, :2003); pinned by `test_protocol_contract.py:91-92`. Doc imprecision only: our comment `offer.py:19-20` says "electrum ignores offers whose expiration is in the past when scanning" — in this electrum checkout the client never reads the `expiration` tag at ingest; freshness is enforced via `created_at ± 3600s` (:2076-2078) and the 3600s cache window in `get_recent_offers` (:1977). The expiration tag functions as a NIP-40 relay-retention hint; the 10s margin semantics are identical to upstream either way.

### N-13: DM framing
Verdict: ✅

Subscription `{"kinds":[25582], "limit":0, "#p":[nostr_pubkey]}` (`submarine_swaps.py:1108`) — identical to electrum (:2161). Outbound: pre-encrypt NIP-04, explicit `kind=25582` (never the aionostr `direct_message=` kind-4 trap — port find #8), `[['p', recv]]` tag (:1184-1192) — mirrors electrum's server reply path (:2017-2029). Request ingestion decrypts with our privkey + sender pubkey (:1107,1117) as electrum does (:2160,2164).

### N-14: Reply etiquette + error replies
Verdict: ✅ (improvement)

`r['reply_to'] = event_id` (:1174) = electrum (:2210); client futures keyed `(server_pubkey, prev_event_id)` resolve on it (:2172-2182). Ours is stricter than electrum in the good direction: every failure mode produces a reply the client can act on — unknown method `{'error': ...}` (:1157-1159) vs electrum's raise-then-generic-error (:2208-2219); `RequestFieldError` → `{'error': str(e)}` (:1163-1166, issue #11); internal errors → `{'error': 'internal error serving …'}` (:1167-1173). Electrum's client surfaces any `error` dict via `SwapServerError` (:2049-2051) — our shapes satisfy it everywhere.

### N-15: No request backpressure ⚠️ P2
Electrum decouples ingestion from handling with `asyncio.Queue(maxsize=5)` and **drops** overflow with a warning (:1885, 2184-2187), consuming at a 5s cadence (:2195). Ours `await self.handle_request(content)` inline in the DM stream loop (:1134): no cap, no drop policy; a flood of NIP-04-valid requests is processed serially, and a slow handler (swap creation, invoice RPC) stalls the entire DM listener. Confidentiality of the shared nostr key limits who can produce valid ciphertexts, but any nostr pubkey can encrypt to us — the queue-less design converts a request flood into listener stall.

### N-16: Unguarded `dm_replies` on the server ⚠️ P2
Ours: `self.dm_replies = defaultdict(asyncio.Future)` (:1032) and `if 'reply_to' in content: self.dm_replies[content['reply_to']].set_result(content)` (:1126-1127) with **no `is_server` guard**. Electrum guards the branch with `if not self.sm.is_server and 'reply_to' in content` (:2172) — on a server that dict is never touched. We are always the server (`assert` at :1046), so this branch is pure attack surface: any DM containing `reply_to` inserts an entry + Future that nothing awaits or evicts — unbounded unauthenticated memory growth (slow, one small object per DM, but structurally a leak). Inherited from the 2025 fork; electrum's shape is the fix.

### N-17: Replay dedup
Verdict: ✅ improvement / parity

In-session: ours dedups on nostr event id (`seen_event_ids`, :1114,1121-1123) and isolates per-request failures (try/except per event :1132-1139, port find #13) — electrum has no dedup at all (its own todo at our `:1146` origin; electrum's `_handle_requests` relies on per-request try/except only, :2199-2219). Cross-restart: neither persists processed ids; relays replay stored DMs after restart. Ours survives replay via per-event isolation (a replayed `addswapinvoice` on a spent swap hits the documented assertion and is logged+skipped, :1109-1139); a replayed `createnormalswap` would create a fresh swap (no freshness check there — electrum identical, `:1602-1621`). Parity at worst, better in-session.

### N-18: Unauthenticated state mutation
Verdict: parity (protocol-inherent)

Any nostr pubkey can call `createswap` / `createnormalswap` / `addswapinvoice` and mutate server state (hold invoices, HTLCs). Identical in electrum — swap safety rests in the HTLC scripts/keys, not DM authentication, and both sides bound damage with per-request capacity checks (:941-981; electrum :1602-1653) and the 20k floor. No regression vs reference.

### N-19: Rotation cadence
Verdict: ✅

Ours: publish immediately on connect, then 30s while the advertised cap is still converging, else 600s (`submarine_swaps.py:188-203`); expiration = publish-time + 610s (`offer.py:81`) — worst-case live window of 10s after the next scheduled publish, identical margin math to electrum (check every 30s, publish if liquidity/fee changed or ≥600s elapsed, :326-346; expiry 600+10, :2003). Our cold start is *better*: first offer goes out immediately, while electrum's `last_update = now()` (:324) can delay the first publication up to ~10 minutes. A lapsed offer does not touch in-flight swaps (DMs never read the offer) — it costs new-client discovery and leaves existing clients on cached pairs, exactly as upstream. Our `is_initialized` retry-faster loop (:192-194) and 15s transport restart on timeout (:204-206) further tighten recovery.

### N-20: Publish-failure isolation ⚠️ P1
Electrum's `publish_offer` is `@ignore_exceptions` (:1984-1985) — any failure (relay error, non-timeout exception) is swallowed and the 30s loop retries. Ours has no such guard: `run_nostr_server` catches **only** `asyncio.TimeoutError` (:204); any other exception out of `server_update_pairs()`/`publish_offer()` propagates through the `OldTaskGroup` (:223-225), tears down `main_loop`, and surfaces as `CLNSwapProvider.run`'s "main loop exited unexpectedly" (`cln_swap_provider.py:86`) — the whole plugin dies instead of retrying the publish. One persistent relay-level non-timeout error (e.g. aionostr raising on a relay OK/NOTICE failure, or `get_fee` failing while bitcoind is down) is a full server outage; under electrum's model it's a skipped announcement.

### N-21: DM-listener death vs live offer — inherited
Verdict: parity note

If `check_direct_messages` itself dies (exception outside the per-event try, e.g. inside `get_events`), our transport `main_loop` logs "Nostr taskgroup died" and returns (:1063-1069) — but the publishing loop in `run_nostr_server` keeps announcing a server whose DM listener is gone. Electrum has the identical structure and flaw (taskgroup death logged at :1931-1932 while `run_nostr_server` keeps publishing). Not a divergence — an inherited availability weakness worth a future fix (e.g. cross-link listener liveness to `is_initialized`).

---

## DIVERGENCES (vs electrum reference)

1. **[P1] N-20** — publish/update exceptions other than `TimeoutError` crash the entire plugin (ours `submarine_swaps.py:204,223-225` → `cln_swap_provider.py:86`); electrum swallows via `@ignore_exceptions` (`:1984`). Fix shape: wrap the inner publish loop body or adopt electrum's ignore-on-publish semantics.
2. **[P2] N-16** — `dm_replies` defaultdict mutated by any `reply_to` DM on an always-server transport (`:1126-1127`); electrum guards with `not self.sm.is_server` (`:2172`). Unauthenticated unbounded memory growth.
3. **[P2] N-15** — request handling inline, no bounded queue/drop policy (`:1134`); electrum `Queue(maxsize=5)` + drop (:2184-2187). Flood → listener stall.
4. **[P2] N-8** — single combined `max_forward`/`max_reverse` cap (`:787-792`) vs electrum per-direction caps (`:1378-1379`); offer can overstate one direction's capacity (request-time checks backstop).
5. **[P2] N-10** — dead `NOSTR_EVENT_VERSION = 2` / `FEE_UPDATE_INVERVAL_SEC` class constants (`:1018,1020`) contradict the live version-5 wire format from `offer.py`; a trap for future maintenance.
6. **[Note] N-9** — no no-liquidity publish guard (floored caps instead) — deliberate R3 design, differs from electrum's skip.
7. **[Note] N-12** — `offer.py:19-20` comment overstates the expiration tag's role; client freshness is `created_at ± 1h` (`:2076-2078`), expiration is a relay hint.
8. **[Note] N-14/N-17** — ours replies on every error path and dedups event ids in-session; electrum does neither. Improvements, listed for the record.

**Non-divergences explicitly cleared:** PoW preimage, bit counting, x-only key operand, nonce hex form, target default, content key set/units/semantics, d/r/expiration tag arithmetic, kind 30315/25582, NIP-04 framing, subscription query, `reply_to` contract — all byte- or behavior-identical to the electrum client-side enforcers, with live test + 5,200-vector empirical proof (N-1..N-7, N-10, N-11, N-13, N-14, N-19).

## COVERAGE GAPS

| Gap | What is unpinned | Risk |
|---|---|---|
| G-1 | No test pins `nostr_ann_pow_bits("…", 0)` vs electrum's `nonce<=0 → 0 bits` short-circuit (N-2 edge) | theoretical only (≈2⁻³⁰) |
| G-2 | No test pins the published **kind** (30315) — `build_offer_tags` output is tested (`test_protocol_contract.py:88-92`) but the transport's `kind=self.STATUS_NIP38` site (`submarine_swaps.py:1098`) is not asserted anywhere | a kind typo would ship green |
| G-3 | No test pins `publish_offer`'s mapping `mining_fee_sat=sm.normal_fee` / shared `_max_amount` for both directions (N-8) — the combined-cap divergence is unpinned and could regress either way silently | capacity-honesty drift |
| G-4 | The dead `NOSTR_EVENT_VERSION = 2` constant has no tripwire (e.g. an assertion/test that the transport never uses it) | future misuse undetected |
| G-5 | No test exercises `run_nostr_server`'s non-timeout exception path (N-20) — the P1 is untested by construction | fix could regress silently |

## FINDINGS SUMMARY

| Severity | Count | Items |
|---|---|---|
| ❌ P0 (spoofing/funds) | 0 | — wire format is byte-faithful to what clients enforce; offer is key-signed, PoW-gated, net-tag-scoped |
| ⚠️ P1 (availability) | 1 | N-20: non-timeout publish/update exception kills the whole plugin (electrum tolerates) |
| ⚠️ P2 (DoS/honesty/maintenance) | 4 | N-16 unguarded `dm_replies` growth; N-15 no request backpressure; N-8 combined cap overstates per-direction capacity; N-10 dead version-2 constant trap |
| Notes (parity/design) | 4 | N-9 floored-cap publish policy; N-12 expiration doc comment; N-18 unauthenticated DM mutation (protocol-inherent, HTLC-bound); N-21 listener-death-vs-live-offer (inherited from electrum) |
| Improvements over reference | 3 | fail-loud pinned-nonce validation (N-5); reply-on-every-error (N-14); in-session replay dedup + immediate first publish (N-17, N-19) |

The critical check holds: the miner in `offer.py` matches electrum's **client-side verifier** byte for byte — same `"electrum-"` prefix, same 32-byte x-only operand end-to-end, same big-endian 32-byte nonce, equivalent leading-zero-bit counting — proven by the electrum-authority test (200 vectors) plus 5,000 additional in-audit vectors with zero mismatches, and both pinning test files green (11/11). All remaining findings are availability/robustness polish, none affect client acceptance of the offer.

VERDICT: PASS-WITH-WARNINGS
