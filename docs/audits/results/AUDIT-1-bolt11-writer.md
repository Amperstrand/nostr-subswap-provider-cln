# AUDIT-1 RESULT: BOLT #11 Invoice Writer Path

- **Date:** 2026-08-21
- **Repo commit audited:** `61146f8c90a7a494813e9e15341ca86bb3a0d227` (`61146f8 ci+docs: spec-quote-drift workflow …`)
- **Auditor method:** every writer-side MUST/SHOULD/MAY in `/home/ubuntu/src/bolts/11-payment-encoding.md` (current checkout, 863 lines) checked against CODE (not comments), then diffed against the electrum reference encoder.

**Files read (evidence sources):**

| File | Role |
|---|---|
| `/home/ubuntu/src/bolts/11-payment-encoding.md` | Spec (full read) |
| `/home/ubuntu/src/bolts/09-features.md` (lines 39–43) | BOLT 9 feature-bit table (for W-23) |
| `swap-provider/plugin/cln_lightning.py` (587 lines) | Impl: `b11invoice_from_hash`, `_get_route_hints`, `_get_payment_secret` |
| `swap-provider/plugin/lnaddr.py` (569 lines) | Impl: `lnencode_unsigned`, `shorten_amount`, `tagged5/8`, `LnAddr` |
| `swap-provider/plugin/lnutil.py` (LnFeatures, `filter_suitable_recv_chans`) | Support |
| `swap-provider/plugin/constants.py` (CLTV deltas, HRP tables) | Support |
| `swap-provider/plugin/invoices.py` (LN_EXPIRY_NEVER) | Support |
| `swap-provider/plugin/segwit_addr.py` (`bech32_encode`/`decode`) | Support |
| `swap-provider/plugin/utils.py` (`ShortID`) | Support |
| `swap-provider/plugin/plugin_config.py` (network parse) | Support |
| `swap-provider/plugin/cln_plugin.py` (`derive_secret`) | Support |
| `swap-provider/plugin/submarine_swaps.py` (sole caller chain) | Support |
| `/home/ubuntu/src/electrum/electrum/bolt11.py` (594 lines) | Reference encoder |
| `/home/ubuntu/src/electrum/electrum/invoices.py:92` | Reference LN_EXPIRY_NEVER |

---

## Requirement Table (summary)

| # | Requirement (spec line) | Verdict |
|---|---|---|
| W-1 | MUST encode in Bech32 (L37) | ✅ |
| W-2 | SHOULD use upper case for QR codes (L38) | N/A |
| W-3 | MAY exceed 90-char BIP-173 limit (L39) | ✅ |
| W-4 | MUST encode `prefix` for the payment currency (L66) | ✅ |
| W-5 | MUST include `amount` when a minimum is required (L67–68) | ✅ |
| W-6 | `amount` positive decimal integer, no leading 0s (L69) | ✅ |
| W-7 | `p` multiplier ⇒ last decimal `0` (L70) | ✅ |
| W-8 | SHOULD use shortest amount representation (L71–72) | ✅ |
| W-9 | `timestamp` = unix seconds, big-endian, 35 bits (L115–116) | ✅ |
| W-10 | `signature` = compact ECDSA/secp256k1 over SHA-256(HRP‖data), R‖S+recid (L117–121) | ✅ (delegated) |
| W-11 | MUST include exactly one `p` (L168) | ✅ |
| W-12 | MUST include exactly one `s` (L169) | ✅ |
| W-13 | `payment_hash` = SHA-256 of `payment_preimage` (L170–171) | ✅ |
| W-14 | exactly one `d` or exactly one `h` (L172) | ✅ |
| W-14a | `d` MUST be valid UTF-8 (L173–174) | ⚠️ P2 (latent) |
| W-15 | `x` minimal `data_length` (L180–182) | ✅ |
| W-16 | SHOULD include `c`; MUST equal minimum accepted cltv (L183–186) | ✅ live / ⚠️ P1 latent |
| W-17 | MAY include `n` = signing pubkey (L187–188) | N/A (MAY, not used) |
| W-18 | `f` MUST be valid form if included (L189–192) | N/A live (encoder validated) |
| W-19 | `r` hints when no public channel (L193–201) | ✅ / ⚠️ P2 robustness |
| W-20 | `9` minimal length or omitted when zero (L202–206) | ✅ |
| W-21 | MUST pad field data to multiple of 5 bits (L207) | ✅ |
| W-22 | most-preferred field first (L208–209) | ✅ |
| W-23 | `9` compliant with BOLT 9 origin-node requirements (L315–317) | ✅ |

---

## Detailed Verdicts

### W-1: MUST encode the payment request in Bech32 (BIP-0173)
Verdict: ✅
Evidence: `swap-provider/plugin/lnaddr.py:253`
```python
return bech32_encode(segwit_addr.Encoding.BECH32, hrp, data5)
```
Note: vanilla BECH32 constant (not BECH32M) — correct; BOLT #11 readers reject bech32m. Identical to electrum `bolt11.py:254`.

### W-2: SHOULD use upper case for QR codes
Verdict: N/A
Evidence: `swap-provider/plugin/lnaddr.py:253` produces lowercase; the writer path serves invoice strings over the Nostr/HTTP API — no QR rendering happens in this repo (the boltz-bridge GUI QR-encodes independently). The SHOULD is scoped to QR presentation, not the encoded string.

### W-3: MAY exceed the 90-character BIP-173 limit
Verdict: ✅
Evidence: `swap-provider/plugin/segwit_addr.py:82-85`
```python
def bech32_encode(encoding: Encoding, hrp: str, data: List[int]) -> str:
    combined = data + bech32_create_checksum(encoding, hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])
```
No length cap in the encoder (the 90-char check exists only in `bech32_decode`, `segwit_addr.py:94`, and is bypassed with `ignore_long_length=True` at `lnaddr.py:394`). Invoices always exceed 90 chars, which the spec permits.

### W-4: MUST encode `prefix` using the currency required for successful payment
Verdict: ✅
Evidence: `swap-provider/plugin/lnaddr.py:159-163`
```python
if addr.amount:
    amount = addr.net.BOLT11_HRP + shorten_amount(addr.amount)
...
hrp = 'ln' + amount
```
`net` comes from `plugin_config.py:160-171`, which maps CLN's `network` config to the net class and **raises** on unknown values (`raise Exception(f"Invalid network type: {network_type}")`), so no silent wrong-HRP fallback. Signet maps to `BitcoinSignet.BOLT11_HRP = "tbs"` (`constants.py:192`) → HRP `lntbs`, matching spec L52. Mainnet `bc` (`constants.py:93`), testnet `tb` (`constants.py:131`), regtest `bcrt` (`constants.py:170`) — all match spec L50–52.

### W-5: MUST include `amount` if a minimum is required
Verdict: ✅
Evidence: `swap-provider/plugin/cln_lightning.py:425` + `lnaddr.py:158-159`
```python
assert amount_msat > 0, f"b11invoice_from_hash: amount_msat must be > 0, but got {amount_msat}"
```
Swaps always require an exact amount; `addr.amount` is a positive `Decimal` so the truthiness test at `lnaddr.py:158` always includes it in the HRP.

### W-6: `amount` = positive decimal integer, no leading 0s
Verdict: ✅
Evidence: `swap-provider/plugin/lnaddr.py:45`
```python
return str(amount) + unit
```
`amount` at that point is a plain `int` (L36); `str(int)` cannot emit leading zeros or signs. Byte-identical to electrum `bolt11.py:48`.

### W-7: `p` multiplier ⇒ last decimal of `amount` MUST be `0`
Verdict: ✅
Evidence: `swap-provider/plugin/lnaddr.py:283-285` (guard) + `lnaddr.py:36-45` (encoder)
```python
if value * 10**12 % 10:
    # max resolution is millisatoshi
    raise LnInvoiceException(f"Cannot encode {value!r}: too many decimal places")
```
The setter rejects sub-millisatoshi amounts, so the pico-integer fed to `shorten_amount` is always divisible by 10 — a `p`-suffixed output necessarily ends in `0`. Writer amounts originate as int msat (`cln_lightning.py:454`), always passing the guard. Same construction as electrum (`bolt11.py:284-286`).

### W-8: SHOULD use shortest representation (largest multiplier / none)
Verdict: ✅
Evidence: `swap-provider/plugin/lnaddr.py:37-44`
```python
units = ['p', 'n', 'u', 'm']
for unit in units:
    if amount % 1000 == 0:
        amount //= 1000
    else:
        break
```
Divides by 1000 while possible, i.e. picks the largest applicable multiplier, falling through to no multiplier when all four divide. Example verified: 20 000 msat → 20000/1e11 BTC → 200000 pico → `200n`. Identical to electrum `bolt11.py:40-47`.

### W-9: `timestamp` = seconds since 1970-01-01 UTC, big-endian (35 bits)
Verdict: ✅
Evidence: `swap-provider/plugin/cln_lightning.py:463` + `lnaddr.py:166` + `lnaddr.py:124-126`
```python
date=int(time.time()),
```
```python
data5 = int_to_data5(addr.date, bit_len=35)
```
```python
assert bit_len % 5 == 0, bit_len
if val.bit_length() > bit_len:
    raise ValueError(f"{val=} too big for {bit_len=!r}")
```
Current time is written at creation; 35-bit fixed-width big-endian with an explicit overflow guard (fails loudly in year ~2603 rather than truncating). Same as electrum (`bolt11.py:168`, `121-136`).

### W-10: `signature` = compact ECDSA secp256k1 over SHA-256(HRP ‖ data-without-sig, 0-padded), 64-byte R‖S + recovery id
Verdict: ✅ (delegated to CLN `signinvoice`)
Evidence: `swap-provider/plugin/cln_lightning.py:465-473`, `lnaddr.py:248-251`
```python
# We sign externally with the Core Lightning RPC
# we add a dummy signature which is neccessary for CLN parsing but will be replaced by CLN again
dummy_signature = bytes([15] * 104)
data5 += dummy_signature
```
```python
signed = self._rpc.call("signinvoice", {"invstring": b11invoice_unsigned})["bolt11"]
```
Note: this repo never signs locally. It emits a bech32-valid string whose last 104 5-bit groups (65 bytes = 520 bits, correct signature width) are dummies, and CLN strips/replaces them with a real recoverable signature before the invoice is returned to any payer. The dummy values (15) are legal 5-bit values, and only `lnencode_unsigned` + `signinvoice` in sequence form the writer; the single call site (`cln_lightning.py:465-473`) always does both, and a `signinvoice` failure raises `Bolt11InvoiceCreationError` (L475-477) so no unsigned invoice can escape. **Port-divergence (deliberate):** electrum signs in-library (`bolt11.py:244-252`, `ecdsa_sign_recoverable`). Low-S/recovery-id correctness is CLN's contract; there is no local post-signing decode-verify — acceptable, but a decode-before-return would be cheap defense-in-depth.

### W-11: MUST include exactly one `p` field
Verdict: ✅
Evidence: `swap-provider/plugin/lnaddr.py:171-173` + `lnaddr.py:189-191`
```python
assert addr.paymenthash is not None
data5 += tagged8('p', addr.paymenthash)
tags_set.add('p')
```
```python
if k in ('d', 'h', 'n', 'x', 'p', 's', '9'):
    if k in tags_set:
        raise LnEncodeException("Duplicate '{}' tag".format(k))
```
32-byte hash → `data_length` 52 always (`tagged8` + `convertbits`). Duplicate impossible (guard). `b11invoice_from_hash` enforces 32-byte hash input (`cln_lightning.py:428-430`).

### W-12: MUST include exactly one `s` field
Verdict: ✅
Evidence: `swap-provider/plugin/cln_lightning.py:464` + `lnaddr.py:175-177`
```python
payment_secret=self._get_payment_secret(payment_hash))
```
```python
if addr.payment_secret is not None:
    data5 += tagged8('s', addr.payment_secret)
    tags_set.add('s')
```
The secret is always supplied on this path (parameter is unconditional), so `s` is always emitted, 32 bytes → `data_length` 52. This checkout's spec text (L169) is **unconditional** ("MUST include exactly one `s` field") — stronger than the conditional payment-secret-feature rule referenced by the audit method; both are satisfied. Uniqueness: duplicate guard `lnaddr.py:189-191`.

**Payment-secret randomness check (method item 5):** `_get_payment_secret` (`cln_lightning.py:516-520`):
```python
return sha256(sha256(self._payment_secret_key) + payment_hash)
```
`_payment_secret_key` is a 32-byte secret derived from the CLN HSM via `makesecret` (`cln_plugin.py:72-79`, keying at `cln_lightning.py:67`). The outer SHA-256 over key‖payment_hash yields a fresh unpredictable 32-byte value per invoice — **not constant across invoices** (varies with payment_hash). Compliant.

### W-13: MUST set `payment_hash` to the SHA-256 of the `payment_preimage` that will be given
Verdict: ✅
Evidence: `cln_lightning.py:307-311` (prepay) / `cln_lightning.py:426-430` (client-supplied)
```python
payment_preimage = os.urandom(32)
payment_hash = sha256(payment_preimage)
```
Prepay invoices: hash generated here from a random preimage — exact by construction. Swap invoices: the client supplies the hash (they hold the preimage and reveal it by claiming the onchain HTLC — see impl-note `cln_lightning.py:442-445`); the hash *is* the SHA-256 of the preimage that will be given in return for payment, so the writer-side MUST holds. The writer cannot re-derive an unknown preimage — length is validated (32 bytes, L428-430) which is the maximum locally checkable.

### W-14: MUST include exactly one `d` or exactly one `h`
Verdict: ✅
Evidence: `cln_lightning.py:458` + `lnaddr.py:242-246`
```python
('d', message if message and len(message) > 0 else f"swap {datetime.now()}"),
```
```python
if 'd' in tags_set and 'h' in tags_set:
    raise ValueError("Cannot include both 'd' and 'h'")
if 'd' not in tags_set and 'h' not in tags_set:
    raise ValueError("Must include either 'd' or 'h'")
```
A `d` is always present (fallback literal when message empty); `h` never emitted on this path; both exclusion directions enforced. Identical to electrum `bolt11.py:239-242`. The SHOULD "complete description" is met by the callers' fixed descriptions ('Submarine swap' / 'Submarine swap mining fees', `submarine_swaps.py:572,583`).

### W-14a: if `d` included: MUST be valid UTF-8
Verdict: ⚠️
Evidence: `lnaddr.py:219-220`
```python
# truncate to max length: 1024*5 bits = 639 bytes
data5 += tagged8('d', v.encode()[0:639])
```
Note: **P2 (latent) interop.** Byte-slicing at 639 can split a multi-byte UTF-8 codepoint, emitting an invalid-UTF-8 `d` — readers must treat the invoice as malformed. Unreachable today: both callers pass short ASCII literals (max 'Submarine swap mining fees', 26 bytes) and the empty-message fallback is ASCII; `message` is not client-controlled in the current call chain. The electrum reference has the identical latent flaw (`bolt11.py:212-213`) — port-faithful, not drift. Suggested fix: truncate on a codepoint boundary, e.g. `v.encode()[:639].decode('utf-8', 'ignore').encode()` (or `errors='ignore'` semantics).

### W-15: MAY include one `x`; if included, minimum `data_length` (no leading 0 field-elements)
Verdict: ✅
Evidence: `cln_lightning.py:459` + `lnaddr.py:221-223` + `lnaddr.py:127-134`
```python
('x', LN_EXPIRY_NEVER if expiry == 0 else expiry),
```
```python
expirybits = int_to_data5(v)
data5 += tagged5('x', expirybits)
```
`int_to_data5` without `bit_len` emits only significant groups (loop from `val != 0`, reversed) → minimal length, no leading zero groups. Exactly one `x` (duplicate guard). Swap callers use `expiry=300` (2 groups) — matches the spec's minimal-encoding example shape (L413-415).

**`LN_EXPIRY_NEVER` safety (method item 7):** `invoices.py:88` — `LN_EXPIRY_NEVER = 100 * 365 * 24 * 60 * 60` = 3 153 600 000 s. `bit_length()` = 32 → 7 5-bit groups, `data_length` 7 ≪ 1023; every group value < 32 by construction, so bech32 encoding of this "huge" int is safe (no 8-bit overflow path — values are base-32 digits, not bytes). **Byte-identical constant and identical encoding approach as the electrum reference** (`electrum/invoices.py:92`) — no port divergence. Semantics: 100 years ≈ "never"; readers compute timestamp+expiry ≈ year 2126. (Adjacent payee-side SHOULD, spec L357-359: expired holds are cancelled at `cln_lightning.py:121-137`, using `created_at` which equals invoice `date` — consistent.)

### W-16: SHOULD include one `c`; MUST set `c` to the minimum cltv_expiry accepted for the last HTLC; minimal `data_length`
Verdict: ✅ in the live path / ⚠️ latent param hazard
Evidence: `cln_lightning.py:456-457` + `constants.py:40-43` + `cln_lightning.py:255-260`
```python
('c', MIN_FINAL_CLTV_DELTA_FOR_INVOICE if min_final_cltv_expiry_delta is None
           else min_final_cltv_expiry_delta),
```
```python
MIN_FINAL_CLTV_DELTA_ACCEPTED = 144
MIN_FINAL_CLTV_DELTA_FOR_INVOICE = MIN_FINAL_CLTV_DELTA_ACCEPTED + 3   # = 147
```
```python
if (incoming_htlc["cltv_expiry_relative"] < decoded_invoice["min_final_cltv_expiry"] or
    incoming_htlc["cltv_expiry_relative"] < MIN_FINAL_CLTV_DELTA_ACCEPTED):
    ... htlc.fail()
```
Live path: invoice advertises `c`=147 and the receiver enforces ≥ max(147, 144) = 147 — the advertised minimum **is** the accepted minimum; encoding is minimal (`int_to_data5`, L228-230). The sole call chain never passes the override (`submarine_swaps.py:537-576` and `569-587` leave it `None`).
Note: **P1 (latent, currently unreachable) interop.** `min_final_cltv_expiry_delta` is unvalidated: any future caller passing a value < 144 would produce an invoice advertising a `c` *below* the enforced floor (`cln_lightning.py:255-260`), so payer HTLCs that follow the invoice would all be failed — a spec-MUST violation and a broken swap, though failing HTLCs do not strand payer funds (clean fail, not loss). Suggested fix: `max(min_final_cltv_expiry_delta, MIN_FINAL_CLTV_DELTA_ACCEPTED)` (or assert ≥).

### W-17: MAY include one `n` field (= signing pubkey)
Verdict: N/A
Evidence: no `('n', …)` tag anywhere in the writer path (grep over `cln_lightning.py` / `submarine_swaps.py` call sites; tag list at `cln_lightning.py:455-462`). The spec makes `n` optional ("Otherwise performing public-key recovery is required"); CLN's `signinvoice` signs with the node key so recovery works. The `n` encoder exists and is correct if ever needed (`lnaddr.py:226-227`).

### W-18: MAY include `f`; if included for Bitcoin, MUST be valid witness v/program, or 17+P2PKH hash, or 18+P2SH hash
Verdict: N/A live (encoder validated)
Evidence: `cln_lightning.py:461` (`('f', fallback_address)`, always `None` from both callers — `submarine_swaps.py:574,585`) and `lnaddr.py:215-217` skips `None`. When used, `encode_fallback_addr` (`lnaddr.py:77-93`) accepts only a decodable segwit address or a net-matching P2PKH/P2PKH-hash (`wver` 17/18) and **raises** otherwise — cannot emit an invalid `f`. Matches electrum `bolt11.py:79-95`.

### W-19: if no public channel on the pubkey: MUST include ≥1 `r` field with ordered entries
Verdict: ✅ (spec condition not triggered) / ⚠️ robustness note
Evidence: `cln_lightning.py:450,483-514` + `lnutil.py:31-61` + `utils.py:395`
```python
routing_hints = self._get_route_hints(amount_msat)
```
```python
short_id = ShortID.from_str(channel["short_channel_id"])
routing_hints.append(('r', [(
    bytes.fromhex(channel["peer_id"]),
    short_id, ...)]))
```
The node's channels are public (CLN hub), so the MUST's precondition is false; hints are nonetheless emitted deliberately for both public and private channels (impl-note `cln_lightning.py:488-493`, rationale `lnutil.py:33-39` — payer-gossip-independence, earned live 2026-08-20). Entry layout is wire-correct: `ShortID` is a `bytes` subclass (`utils.py:395`) of exactly 8 bytes (`from_components`, 3+3+2 big-endian), so `route += pubkey; route += scid` (`lnaddr.py:201-205`) concatenates 33+8+4+4+2 = 51 bytes/entry, matching spec L156-160. Fields sourced from the remote `channel_update` values (`cln_lightning.py:510-512`), as the spec Note requires.
Note: **P2 robustness (not a spec violation).** If `listpeerchannels` RPC fails, `_get_route_hints` logs and returns `[]` (`cln_lightning.py:497-500`) — the invoice still ships with zero hints, and payers with lagging gossip can hit NoPathFound (the exact failure the impl-note documents). Failing the invoice creation (or retrying the RPC) would be safer than emitting a possibly-unpayable invoice.

### W-20: `9` non-zero ⇒ minimal `data_length`; zero ⇒ omit entirely
Verdict: ✅
Evidence: `lnaddr.py:231-235` + `lnaddr.py:127-134`
```python
elif k == '9':
    if v == 0:
        continue
    feature_bits = int_to_data5(v)
    data5 += tagged5('9', feature_bits)
```
Zero-value features are skipped (`continue` — no `9` field emitted); non-zero values get minimal encoding (most-significant group is non-zero by construction of `int_to_data5`). Our vector `LnFeatures(0) | VAR_ONION_REQ | PAYMENT_SECRET_REQ | BASIC_MPP_OPT` = 0b10_0100_0001_0000_0000 (bits 8, 14, 17) → 4 groups, first group = 4 ≠ 0. Byte-identical logic to electrum `bolt11.py:224-228`.

### W-21: MUST pad field data to a multiple of 5 bits using 0s
Verdict: ✅
Evidence: `lnaddr.py:115-116` + `segwit_addr.py:111` (`convertbits` pads) + `lnaddr.py:112` (`tagged5` length header)
```python
def tagged8(char: str, data8: Sequence[int]) -> Sequence[int]:
    return tagged5(char, convertbits(data8, 8, 5))
```
Every field body is a list of 5-bit values before reaching `bech32_encode`; `convertbits(8→5, pad=True)` zero-pads byte fields to the 5-bit boundary (e.g. 32-byte hash → 52 groups). Integer tags are pure base-32 digit lists. The invoice's data part is therefore always a whole number of 5-bit groups — the "0 bits appended to pad to a byte boundary" for signing is CLN's job inside `signinvoice` (W-10). Identical to electrum.

### W-22: if offering more than one of any field type, most-preferred first
Verdict: ✅
Evidence: `lnutil.py:44-45` + `cln_lightning.py:505-512`
```python
# sort by inbound capacity
suitable_channels.sort(key=lambda x: x["receivable_msat"], reverse=True)
```
The only field type emitted multiply is `r` (one tag per channel, ≤ 15 — `lnutil.py:61`), and hints are ordered most-receivable-capacity-first, a defensible preference ordering. All other multi-capable tags are single-instance (duplicate guard `lnaddr.py:189-191`).

### W-23: `9` MUST be a feature vector compliant with BOLT 9 origin-node requirements
Verdict: ✅
Evidence: `cln_lightning.py:449` + `lnutil.py:85,94,98` + `bolts/09-features.md:39,42-43`
```python
invoice_features = LnFeatures(0) | LnFeatures.VAR_ONION_REQ | LnFeatures.PAYMENT_SECRET_REQ | LnFeatures.BASIC_MPP_OPT
```
```python
VAR_ONION_REQ = 1 << 8          # 09-features.md:39  "8/9  var_onion_optin"
PAYMENT_SECRET_REQ = 1 << 14    # 09-features.md:42  "14/15 payment_secret"
BASIC_MPP_OPT = 1 << 17         # 09-features.md:43  "16/17 basic_mpp (dep: payment_secret)"
```
All three bits are assigned in BOLT 9; no unknown-even bits (which would make strict readers fail). The one declared dependency — `basic_mpp` requires `payment_secret` — is satisfied by `PAYMENT_SECRET_REQ` in the same vector, and the mandatory `s` field accompanies it (W-12), which is exactly what the payment-secret/MPP reader rules (spec L228-231, L322-325) need. **Calibration note:** the audit method's "bit 12 / bit 14" numbering reflects an older BOLT 9; in this spec checkout payment_secret is 14/15 and basic_mpp 16/17, and the code matches the checkout. Setting the *required* (even) variants of var_onion and payment_secret is legitimate for an invoice from a modern node (both are ASSUMED in BOLT 9), and every current payer (CLN/LND/Eclair/electrum) satisfies them.

---

## Port-Divergence Check vs electrum reference (`/home/ubuntu/src/electrum/electrum/bolt11.py`)

Line-by-line comparison of the encode path (`shorten_amount`, `encode_fallback_addr`, `tagged5/8`, `int_to_data5`, tag switch, d/h exclusivity, bech32 tail) shows the vendored `lnaddr.py` is **behaviorally identical** to electrum's `encode_bolt11_invoice` except:

1. **Signing (deliberate):** electrum signs in-library (`bolt11.py:244-252`, `ecdsa_sign_recoverable`, recovery-id appended); we append a 104×5-bit dummy and delegate to CLN `signinvoice` (`lnaddr.py:248-251`, `cln_lightning.py:466-473`). No dropped validation on our side; the final-sig correctness obligation moves to CLN.
2. **Exception class names** (`LnEncodeException` vs `BOLT11EncodeException`): cosmetic.
3. **Quote comments refreshed 2026-08-20** in our fork (e.g. `lnaddr.py:29-31,183-188,440-442`): comments only, zero behavioral delta.
4. Electrum validates nothing on the writer path that we omit — no port-divergence findings beyond item 1. `LN_EXPIRY_NEVER` is byte-identical (100 years) in both.
5. `_get_payment_secret` differs in construction from electrum's lnworker (`sha256(sha256(hsm_secret)‖payment_hash)` here vs electrum's key‖payment_hash shape) — both are per-invoice 32-byte secrets from a node-held key; equivalent security, not a spec issue.

## COVERAGE GAPS (spec writer-MUSTs with no `# BOLT #11:` quote site)

Machine-verified quote sites exist for W-6/7/8 (`lnaddr.py:25-28`), W-22 (`lnaddr.py:181-182`), W-14 (`lnaddr.py:242`), W-11/12/13 (`cln_lightning.py:437-441`), W-16 (`cln_lightning.py:446-448`), W-19 (`cln_lightning.py:484-487`). The following writer requirements have **no quote site** — proposed exact text and anchor:

| Gap | Spec text (verbatim) | Proposed location |
|---|---|---|
| G-1 (W-1) | `# BOLT #11: A writer:` / `#  - MUST encode the payment request in Bech32 (see BIP-0173)` | `lnaddr.py`, above L253 (`return bech32_encode(...)`) |
| G-2 (W-9) | `# BOLT #11: A writer:` / `#  - MUST set timestamp to the number of seconds since Midnight 1 January 1970, UTC in big-endian.` | `lnaddr.py`, above L166 (`data5 = int_to_data5(addr.date, bit_len=35)`) |
| G-3 (W-10) | `# BOLT #11: - MUST set signature to a valid compact ECDSA signature over secp256k1 of the SHA-256 hash of: the human-readable part (as UTF-8 bytes) concatenated with the data part (excluding the signature), with 0 bits appended to pad to a byte boundary.` / `# Impl-note: signing is delegated to CLN signinvoice; the dummy tail below only reserves the 520-bit field.` | `lnaddr.py`, above L250 (dummy signature) or `cln_lightning.py` above L468 |
| G-4 (W-4) | `# BOLT #11: A writer:` / `#  - MUST encode prefix using the currency required for successful payment.` | `lnaddr.py`, above L159 (HRP assembly) |
| G-5 (W-15) | `# BOLT #11: - if x is included:` / `#  - MUST use the minimum data_length possible, i.e. no leading 0 field-elements.` | `lnaddr.py`, above L222 (`expirybits = int_to_data5(v)`) |
| G-6 (W-18) | `# BOLT #11: - MAY include one or more f fields.` / `#  - for Bitcoin payments:` / `#  - MUST set an f field to a valid witness version and program, OR to 17 followed by a public key hash, OR to 18 followed by a script hash.` | `lnaddr.py`, above L77 (`encode_fallback_addr`) |
| G-7 (W-20) | `# BOLT #11: - if 9 contains non-zero bits:` / `#  - MUST use the minimum data_length possible to encode the non-zero bits with no 0 field-elements at the start.` / `#  - otherwise:` / `#  - MUST omit the 9 field altogether.` | `lnaddr.py`, above L231 (`elif k == '9':`) |
| G-8 (W-21) | `# BOLT #11: - MUST pad field data to a multiple of 5 bits, using 0s.` | `lnaddr.py`, above L115 (`tagged8`) |
| G-9 (W-23) | `# BOLT #11: A writer:` / `#  - MUST set the 9 field to a feature vector compliant with the` / `#  [BOLT 9 origin node requirements](09-features.md#requirements).` | `cln_lightning.py`, above L449 (invoice_features) |

## FINDINGS SUMMARY

| Severity | Count | Items |
|---|---|---|
| ❌ P0 (funds-risk) | 0 | — |
| ⚠️ P1 (interop) | 1 | W-16 latent: unvalidated `min_final_cltv_expiry_delta` override could advertise a `c` below the enforced 144 floor (unreachable today — sole call chain passes `None`) |
| ⚠️ P2 (cosmetic/latent) | 2 | W-14a: 639-byte `d` truncation can split a UTF-8 codepoint (callers pass short ASCII; electrum has the same flaw); W-19: silent hint-less invoice on `listpeerchannels` RPC failure |
| Notes (no severity) | 3 | W-10 signing delegated to CLN (dummy-tail design, single verified call site); audit-method bit numbering 12/14 is stale vs this spec checkout (actual: 14/16-17, code correct); `x`=`LN_EXPIRY_NEVER` (100y) encodes safely in 7 groups and matches electrum exactly |

Writer-side verdict tally: 18 ✅, 2 ⚠️ (W-14a, W-16), 3 N/A (W-2 QR-only SHOULD, W-17 optional `n`, W-18 optional `f`), 0 ❌. Every ⚠️ is latent-or-adjacent — the live invoice path (sole call chain `submarine_swaps.py:569/580` → `b11invoice_from_hash` → `lnencode_unsigned` → `signinvoice`) honors every applicable writer-side MUST/SHOULD.

VERDICT: PASS-WITH-WARNINGS
