# AUDIT-2 Result: BOLT #11 Invoice Reader Path

- **Date:** 2026-08-21
- **Commit audited:** `78d9332` (`78d93323cadfd389928ad4066fa23d4e4ccdd47d`, nostr-subswap-provider-cln)
- **Auditor:** AI protocol auditor (ultrawork session)
- **Files read:**
  - Spec: `/home/ubuntu/src/bolts/11-payment-encoding.md` (full, incl. valid/invalid examples)
  - Impl: `swap-provider/plugin/lnaddr.py` (569 lines), `swap-provider/plugin/segwit_addr.py` (159 lines)
  - Reference: `/home/ubuntu/src/electrum/electrum/bolt11.py` (594 lines)
  - Callers: `swap-provider/plugin/invoices.py` (`from_bech32`, `rhash`), `swap-provider/plugin/submarine_swaps.py` (`server_add_swap_invoice`, `handle_request`, `pay_pending_ln_invoice`), `swap-provider/plugin/cln_lightning.py` (`pay_invoice`)
  - ECC: `electrum_ecc` 0.0.x (`~/.local/lib/python3.12/site-packages/electrum_ecc/keys.py`)
- **Method note:** every spec example invoice (valid + invalid) was executed
  through the repo's real `lndecode` (runner: `/tmp/opencode/audit2_empirical.py`,
  output excerpts inline below). Verdicts cite code, not comments.

## Requirement Table

| Req | Spec (line) | Requirement (reader) | Verdict |
|-----|-------------|----------------------|---------|
| R-1 | 42-43 | Parse as Bech32 per BIP-0173, no 90-char limit, handle uppercase | ✅ |
| R-2 | 44-45 | Incorrect checksum → MUST fail | ✅ |
| R-3 | 75-76 | Unknown `prefix` → MUST fail | ✅ (note) |
| R-4 | 77-78 | Empty `amount` → SHOULD indicate unspecified | ✅ |
| R-5 | 80-82 | Non-digit amount / bad multiplier → MUST fail | ✅ |
| R-6 | 83-85 | Multiply amount by multiplier | ✅ |
| R-7 | 86-87 | `p` multiplier, last decimal ≠ 0 → MUST fail | ✅ (indirect) |
| R-8 | 124 | MUST check signature valid | ✅ (note) |
| R-9 | 212 | MUST skip `f` fields with unknown version | ✅ (note) |
| R-10 | 213 | Fixed data_length `p`,`h`,`s`,`n` = 52/52/52/53 → MUST fail | ❌ P1 |
| R-11 | 214 | Exactly one of `d`/`h` → else MUST fail | ❌ P2 |
| R-12 | 215-216 | Unknown odd feature bits → MUST ignore | ✅ (trivial) |
| R-13 | 217-219 | Unknown even feature bits → MUST fail | ❌ P1 |
| R-14 | 219 | SHOULD indicate unknown bit to user | N/A |
| R-15 | 220-221 | `h` must match hashed description | N/A |
| R-16 | 222-223 | Valid `n` → MUST verify sig with it (no recovery) | ✅ |
| R-17 | 224-225 | With `n`: non-low-S sig → MUST fail | ✅ |
| R-18 | 226-227 | No `n` → recovery MUST accept high-S and low-S | ✅ |
| R-19 | 228-229 | No valid `s` field → MUST fail | ❌ P1 |
| R-20 | 230-231 | Use `s` as payment_secret | N/A (delegated) |
| R-21 | 232-233 | No `c` field → use expiry delta ≥ 18 | ✅ |
| R-22 | 234-235 | `m` field → use as payment_metadata | ⚠️ P2 |
| R-23 | 236-238 | Non-minimal data_length `c`/`x`/`9` → SHOULD treat invalid | ⚠️ P2 |
| R-24 | 320-321 | Missing transitive feature deps → MUST NOT attempt payment | ⚠️ P1 |
| R-25 | 322-325 | MPP only if `basic_mpp` offered | N/A (delegated) |

Counts: ✅ 14 · ❌ 4 · ⚠️ 3 · N/A 4

## Detailed Verdicts

### R-1: Parse as Bech32 (BIP-0173), no char limit, uppercase handling
Verdict: ✅
Evidence: `lnaddr.py:394` `bech32_decode(invoice, ignore_long_length=True)`;
`segwit_addr.py:88-99` (mixed-case reject at :91, last-`1` separator at :93,
HRP printable-ASCII guard at :97, charset via `CHARSET_INVERSE` :101-104).
Empirical: the spec's all-uppercase example decodes OK; the no-`1` example is
rejected. Bech32m checksums are correctly refused (`lnaddr.py:399-400`
"must be using vanilla BECH32") — invoices must not use BIP-350.

### R-2: Incorrect checksum → MUST fail
Verdict: ✅
Evidence: `segwit_addr.py:63-71,105-107` (polymod must equal BECH32 const);
`lnaddr.py:397-398` `raise LnDecodeException("Bad bech32 checksum")`.
Empirical: spec's invalid-checksum example → `RAISED LnDecodeException`.
(The no-separator example also raises here with a slightly misleading
message — cosmetic only.)

### R-3: Unknown prefix → MUST fail
Verdict: ✅
Evidence: `lnaddr.py:404-408` — `hrp.startswith('ln')` plus
`hrp[2:].startswith(net.BOLT11_HRP)` both raise `LnDecodeException`.
Note: the check is `startswith`, so e.g. `lntbs` against expected `lntb`
passes the prefix check and only fails later in `unshorten_amount`
(amountstr `'s…'` → non-digit). Fail-closed, message misleading (P2,
cosmetic — identical behavior in electrum `bolt11.py:427-428`).

### R-4: Empty amount → SHOULD indicate unspecified
Verdict: ✅
Evidence: `lnaddr.py:429-430` — amount stays `None`; callers distinguish
via `get_amount_msat() is None` (`lnaddr.py:304-307`). In the swap-server
entry path a None/zero amount is rejected anyway by the amount-match check
(`submarine_swaps.py:702-705`).

### R-5: Non-digit amount or invalid multiplier → MUST fail
Verdict: ✅
Evidence: `lnaddr.py:64-69` — `re.fullmatch(r"\d+[pnum]?", …)` else
`raise LnDecodeException`. All four multiplier letters covered.
Empirical: `2500x` example → `RAISED LnDecodeException: Invalid amount
'2500x'`. The HRP printable-ASCII guard (`segwit_addr.py:96-98`) blocks
non-ASCII Unicode digits that Python's `\d` would otherwise match.
(Limitations that remain: leading zeros and bare `0` are accepted — the
spec constrains those on the writer only; the server's amount-match check
neutralizes them here.)

### R-6: Multiply by multiplier value
Verdict: ✅
Evidence: `lnaddr.py:57-62,71-74` — `Decimal(amount[:-1]) / units[unit]`
with p/n/u/m = 10^12/10^9/10^6/10^3. Matches spec table (unit is BTC).

### R-7: `p` multiplier with non-zero last decimal → MUST fail
Verdict: ✅
Evidence: no explicit trailing-zero test in `unshorten_amount`
(`lnaddr.py:47-74`), but the assignment `addr.amount = …` (`lnaddr.py:430`)
routes into the millisatoshi-resolution guard `lnaddr.py:283-285`
(`if value * 10**12 % 10: raise LnInvoiceException`). A `p` amount whose
last decimal ≠ 0 is exactly a sub-millisatoshi amount, so the guard is
equivalent to the spec rule.
Empirical: `lnbc2500000001p…` example → `RAISED LnInvoiceException:
Cannot encode Decimal('0.002500000001'): too many decimal places`.
Note: raise type is `LnInvoiceException`, not `LnDecodeException` —
cosmetic (it's the parent class; both callers catch broadly).

### R-8: MUST check signature valid
Verdict: ✅
Evidence: `lnaddr.py:553-567` — hash over `hrp + data` padded to byte
boundary (`convertbits(…, 5, 8, True)`), then either `ecdsa_verify` (with
`n`) or pubkey recovery. Empirical: the "signature is not recoverable"
example → RAISED.
Note: the recovery failure surfaces as `InvalidECPointException` (from
electrum_ecc), which escapes the `LnDecodeException`-only contract
documented at `lnaddr.py:390` — callers all catch `Exception` so it is
fail-closed (P2, cosmetic).

### R-9: MUST skip `f` fields with unknown version
Verdict: ✅
Evidence: `lnaddr.py:96-107` (`parse_fallback_addr`: 17 P2PKH, 18 P2SH,
≤16 segwit via validated round-trip `segwit_addr.py:153-159`, else None)
+ `lnaddr.py:490-497` (None → `unknown_tags`, continue). Empirical: the
"fields which must be ignored" example decodes with the version-19 `f`
field in `unknown_tags`. Identical to electrum `bolt11.py:98-109,509-516`.
Note: an empty `f` field (declared length 0) hits `data5[0]` →
`IndexError` instead of a clean skip — fail-closed via the caller's broad
except (P2, cosmetic; same in electrum).

### R-10: Fixed data_length p/h/s/n = 52/52/52/53 → MUST fail the payment
Verdict: ❌
Evidence: the quote at `lnaddr.py:438-442` (refreshed 2026-08-20) says
MUST fail — but the CODE SKIPS:
```python
lnaddr.py:511-514  (same pattern at :502-505 h, :517-520 s, :523-526 n)
    elif tag == 'p':
        if data_length != 52:
            addr.unknown_tags.append((tag, tagdata))
            continue
```
Empirical: the spec's "fields which must be ignored" example — which
contains wrong-length `p`(51), `p`(53), `h`(51), `h`(53), `s`(51), `s`(53),
`n`(52), `n`(54) — **decodes successfully**; all wrong-length fields land
in `unknown_tags` and later valid fields win.
Note: severity **P1 interop/robustness**. Blast radius traced: an invoice
whose only `p` field has wrong length decodes with `paymenthash = None`,
then `Invoice.rhash` (`invoices.py:522-525`,
`self._lnaddr.paymenthash.hex()`) raises a raw `AttributeError` **outside**
the try/except in `server_add_swap_invoice` (`submarine_swaps.py:691-695`)
— caught only by the dispatcher backstop (`submarine_swaps.py:1167-1173`)
as `{'error': 'internal error serving addswapinvoice'}`. Fail-closed, but
unclean (no actionable error, logs as internal error). A wrong-length `s`
slides through entirely (see R-19). Suggested fix: in each of the four
branches raise `LnDecodeException(f"{tag} field length {data_length} != …")`
instead of `unknown_tags.append/continue` — the code then matches its own
machine-verified quote. (Electrum `bolt11.py:521-545` skips too — shared
upstream violation of the current MUST; this repo's refreshed quote makes
the drift explicit.)

### R-11: Neither `d` nor `h`, or both → MUST fail
Verdict: ❌
Evidence: no check anywhere in `lndecode` — `d` appended at
`lnaddr.py:499-500`, `h` at `:502-506`, nothing requires exclusivity or
presence. The d/h xor check exists only in the *encoder*
(`lnaddr.py:242-246`).
Note: severity **P2 interop**. An invoice with neither field decodes;
`from_bech32` builds it with `message=''` (`invoices.py:447`). Fail-closed
only late: CLN re-parses the raw string at pay time
(`cln_lightning.py:298`) and rejects description-less invoices, so the
swap fails after onchain lockup (client burns chain fees, waits for
refund). Electrum `bolt11.py` decode has the same gap — shared, not port
drift. Suggested fix: mirror the encoder's `tags_set` check at the end of
the tag walk.

### R-12: Unknown odd feature bits → MUST ignore
Verdict: ✅
Evidence: `lnaddr.py:533-535` — the `9` field is stored as a raw int in
tags and never interpreted anywhere in-repo (no interpretation ⇒ nothing
to act on ⇒ ignored). The spec's valid example with odd bit 99 set
decodes fine (empirical: features value 633825300114114700748351619328).

### R-13: Unknown even feature bits → MUST fail the payment
Verdict: ❌
Evidence: nothing checks feature bits after decode. `LnAddr.get_features`
is **commented out** (`lnaddr.py:309-311`), and the deferral comment at
`lnaddr.py:536-540` points at `lnworker._check_invoice` — **which does
not exist in this repo** (grep: no `_check_invoice` outside that comment).
Empirical: the spec's *invalid* example "unknown even feature 100"
(`lnbc25m1pvjluez…`) **DECODED OK** with feature int containing bit 100.
Note: severity **P1 interop**. The bind path (`server_add_swap_invoice`)
accepts such an invoice; failure happens only at pay time when CLN
refuses it (`cln_lightning.py:298` → pay fails → swap failed after the
client's onchain lockup — wasted chain fees + refund delay; the payer-side
attempt cap at `submarine_swaps.py:247-255` limits the retry spam). No
server-funds-loss path (the rhash==sha256(preimage) bind check at
`submarine_swaps.py:706-707` is the real gate). Suggested fix: re-enable
`get_features`, and in `server_add_swap_invoice` reject invoices with
unknown even bits (mirror electrum's `validate_features` +
`ln_compare_features`, `bolt11.py:332-342`) so bad invoices fail at bind,
before lockup.

### R-14: SHOULD indicate unknown bit to the user
Verdict: N/A
Evidence: headless swap server — no user-facing surface exists for invoice
features, and nothing logs unknown bits. (Electrum surfaces this in its
GUI; there is no equivalent here to be non-compliant with.)

### R-15: `h` field must match the hashed description
Verdict: N/A
Evidence: the description transport is explicitly unspecified by the spec
("transport mechanism … is transport specific"), this server never
receives or renders a long description, and it never displays invoice
descriptions from untrusted invoices. Nothing to check against; no
injection surface reached (see also Security Considerations, spec:280-301 —
the decoded `d` string is only stored/logged here).

### R-16: Valid `n` → MUST verify signature with `n` (not recovery)
Verdict: ✅
Evidence: `lnaddr.py:557-565` — `if addr.pubkey:` (set only from a
correct-length `n` at `:523-528`) → `ecc.ECPubkey(addr.pubkey).ecdsa_verify(…)`
else raise `LnDecodeException("bad signature")`. Empirical: the high-S
`n`-field example is rejected as "bad signature" (not via recovery).

### R-17: With `n`: signature not low-S → MUST fail
Verdict: ✅
Evidence: `lnaddr.py:560` calls `ecdsa_verify` with electrum_ecc's default
`enforce_low_s=True` (`electrum_ecc/keys.py:267-275`: normalization is
skipped, high-S then fails verification).
Empirical (both directions): spec's "Non canonical signature (high-S) with
'n' field defined" → `RAISED LnDecodeException: bad signature`; direct
probe — flipped high-S sig verifies `False` with the default and `True`
with `enforce_low_s=False`, proving the flag genuinely binds.

### R-18: No `n` → recovery MUST accept high-S and low-S
Verdict: ✅
Evidence: `lnaddr.py:566-567` — `ecc.ECPubkey.from_ecdsa_sig64(…)`
recovers the pubkey for any valid (r,s,recid) regardless of S lowness.
Empirical: the spec's valid "Public-key recovery with high-S signature"
example decodes OK.

### R-19: No valid `s` field → MUST fail the payment
Verdict: ❌
Evidence: `s` is only ever *set* (`lnaddr.py:517-521`); absence leaves
`payment_secret = None` with no check. Empirical: the spec's *invalid*
"Missing required `s` field" example **DECODED OK** (`s=None`), and
`Invoice.from_bech32` succeeds — runner output: `from_bech32 OK, rhash =
0001020304050607, amount_sat = 2000000` — i.e. it would bind.
Note: severity **P1 interop**. Same late-fail shape as R-13: CLN enforces
payment_secret-vs-features at pay time; a feature-bearing no-`s` invoice
fails only after onchain lockup. The deferral comment (`lnaddr.py:536-540`)
justifies leniency by "opening old wallets" — a wallet concern that does
not transfer to this headless swap server. Suggested fix: reject
`addr.payment_secret is None` in `server_add_swap_invoice` (or in
`lndecode` directly).

### R-20: Use `s` as payment_secret
Verdict: N/A
Evidence: this server never constructs onion payloads — it hands the raw
bolt11 string to CLN (`cln_lightning.py:298`), which applies the payment
secret itself. The decoded `addr.payment_secret` is used only for
debug/display. Nothing in-repo can violate this MUST.

### R-21: No `c` field → use min_final_cltv_expiry_delta ≥ 18
Verdict: ✅
Evidence: `lnaddr.py:331-335` — `get_min_final_cltv_delta()` defaults to
18. The actual payment is made by CLN from the raw string (which contains
`c` when present; CLN applies its own ≥18 default otherwise).

### R-22: `m` field → use as payment_metadata
Verdict: ⚠️
Evidence: `lndecode` has no `m` branch — it falls to
`addr.unknown_tags.append` (`lnaddr.py:541-542`); the metadata is not
surfaced on `LnAddr`.
Note: severity **P2 cosmetic**. Harmless in practice because the raw
string is passed through to CLN, which reads `m` itself; electrum's
decoder has the identical gap (`bolt11.py` — no `m` branch). Suggested
fix: add an `elif tag == 'm':` branch storing the bytes, for parity with
future callers that inspect it.

### R-23: Non-minimal `data_length` for `c`/`x`/`9` → SHOULD treat invalid
Verdict: ⚠️
Evidence: `int_from_data5` (`lnaddr.py:137-141`) accepts leading zero
field-elements; no minimality check on `x` (`:508-509`), `c`
(`:530-531`), or `9` (`:533-534`).
Note: severity **P2 cosmetic** (SHOULD-level; malleability/non-canonical
encodings accepted). Electrum identical — shared gap.

### R-24: Feature vector missing known transitive deps → MUST NOT attempt payment
Verdict: ⚠️
Evidence: as with R-13, no in-repo feature validation exists
(`get_features` commented out, `lnaddr.py:309-311`; no
`validate_features` ported — electrum has both, `bolt11.py:328-342`).
The MUST is ultimately satisfied by delegation: CLN refuses to pay
feature-inconsistent invoices (`cln_lightning.py:298`), so a payment is
never completed.
Note: severity **P1 interop as a warning** — same post-lockup failure
cost as R-13; the port-divergence vs electrum (feature-surfacing API
removed, replacement validator never added) is the actionable part.

### R-25: MPP only if `basic_mpp` offered
Verdict: N/A
Evidence: payment execution is wholly delegated to CLN, which gates MPP
on the invoice's feature bits. The server never splits payments itself.

## Caller Trace — what happens to validation failures

1. **Entry (untrusted wire):** nostr DM → `handle_request`
   (`submarine_swaps.py:1144-1176`) → `server_add_swap_invoice`
   (`:684-735`).
2. **Decode failures → clean reply, not swallowed:**
   `Invoice.from_bech32` (`invoices.py:436-443`) wraps `lndecode` in
   `except Exception → raise InvoiceError`; `server_add_swap_invoice`
   re-wraps into `RequestFieldError` (`:691-694`), which
   `handle_request` turns into an error DM (`:1163-1166`). No bare-except
   swallow on the decode path.
3. **Backstop:** any other exception (e.g. the R-10 `AttributeError` from
   `rhash`, `invoices.py:525`) is caught at `submarine_swaps.py:1167-1173`
   → `{'error': 'internal error serving addswapinvoice'}`, and
   `check_direct_messages` wraps the handler again (`:1133-1139`) — no
   hang, no taskgroup death. Fail-closed but noisy/misleading.
4. **Funds safety is NOT BOLT-11's job here:** any self-signed invoice
   passes signature validation (inherent to bolt11 without `n`-pinning),
   so the real gates are the bind checks: `rhash == sha256(server
   preimage)` (`:706-707`), amount match (`:702-705`), redeem-script
   re-derivation from `refundPublicKey` (`:719-730`), and in-flight
   guards (`:708-709`, `:731-732`). These held in all gap scenarios.
5. **Pay time:** `pay_pending_ln_invoice` (`:241-277`) → CLN `pay` with
   the raw string (`cln_lightning.py:294-300`); CLN re-parses and is the
   layer that actually enforces R-13/R-19/R-24/R-25. Post-attempt expiry
   check at `:267-268`; retry cap 15 attempts (`:247-255`).

## Electrum Reference Divergence Notes

- The decode path is a near-exact port: same skip-not-fail for wrong-length
  p/h/s/n (electrum `bolt11.py:521-545`), no d/h xor check, no missing-`s`
  check, no `m` branch, no non-minimal-length check. **All four ❌/⚠️ gaps
  are shared with upstream electrum** — they are inherited spec violations,
  not port-introduced.
- Real port divergences found: (a) electrum exposes
  `get_features`/`validate_and_compare_features` (`bolt11.py:328-342`) —
  the vendored copy commented them out (`lnaddr.py:309-323`); (b) the
  vendored comment claims validation happens "just before we try paying
  the invoice (in lnworker._check_invoice)" (`lnaddr.py:537`) — that
  function does not exist in this repo; the paying node is CLN. Net
  effect: every feature-bit MUST shifts from "validated by this process"
  (electrum) to "validated by a downstream process" (CLN, post-lockup).
- The vendored quotes (refreshed 2026-08-20) are *ahead* of electrum's
  stale comment text (electrum `bolt11.py:456-460` still quotes the old
  "MUST skip" wording) — this repo knows the current spec; the code just
  hasn't caught up with its own quotes (R-10 is the clearest instance).

## COVERAGE GAPS (no quote site + no code)

Proposed quote additions (text verbatim from
`/home/ubuntu/src/bolts/11-payment-encoding.md`; whitespace reflowed to
comment style):

1. **R-11 (d xor h)** — add at end of tag-walk loop, `lnaddr.py:542`
   (after the `else: addr.unknown_tags.append(...)` branch):
   `# BOLT #11: - MUST fail the payment if neither a `d` field nor an `h` field is present, or if both are present.`
2. **R-13/R-12 (feature bits)** — add in the `9` branch, `lnaddr.py:533`:
   `# BOLT #11: - if the `9` field contains unknown _odd_ bits that are non-zero:`
   `#  - MUST ignore the bit.`
   `# BOLT #11: - if the `9` field contains unknown _even_ bits that are non-zero:`
   `#  - MUST fail the payment.`
3. **R-19 (missing `s`)** — add near the signature check, `lnaddr.py:553`:
   `# BOLT #11: - if a valid `s` field is not provided:`
   `#  - MUST fail the payment.`
4. **R-17 (low-S)** — add at the verify call, `lnaddr.py:560` (behavior
   already compliant; quote documents why `ecdsa_verify`'s default
   matters):
   `# BOLT #11: - If the signature is not compliant with the low-S standard rule:`
   `#  - MUST fail the payment`
5. **R-7 (p multiplier)** — add in `unshorten_amount`, `lnaddr.py:68`:
   `# BOLT #11: - if multiplier is `p` and the last decimal of `amount` is not 0:`
   `#  - MUST fail the payment.`
   (Currently enforced indirectly via the msat guard `lnaddr.py:283-285`.)
6. **R-23 (non-minimal lengths)** — add at `lnaddr.py:508` (x branch):
   `# BOLT #11: - if a `c`, `x`, or `9` field is provided which has a non-minimal `data_length``
   `#  (i.e. begins with 0 field elements):`
   `#  - SHOULD treat the invoice as invalid.`

## FINDINGS SUMMARY

| Severity | Count | Items |
|----------|-------|-------|
| P0 funds-risk | 0 | — (bind-time preimage/amount/script checks held in every gap scenario) |
| P1 interop | 4 | R-10 ❌, R-13 ❌, R-19 ❌, R-24 ⚠️ |
| P2 cosmetic | 5 | R-11 ❌, R-22 ⚠️, R-23 ⚠️, R-8 note, R-9 note |

Highlights: 4 explicit reader MUSTs violated by the parser (R-10, R-11,
R-13, R-19), all inherited from upstream electrum and all compensated
downstream (bind-time crash→error-reply, or CLN re-parse at pay time —
the latter only *after* the client's onchain lockup, at real cost).
R-10 is also a quote-vs-code drift: the refreshed `# BOLT #11:` quote at
`lnaddr.py:438-442` says MUST fail; the code skips.

VERDICT: FAIL
