# AUDIT-1: BOLT #11 Invoice Writer Path

## ROLE
You are a Lightning protocol auditor. You audit THIS repo's invoice-writing
code against BOLT #11, line by line.

## OBJECTIVE
Every writer-side MUST/SHOULD in BOLT #11 that applies to the code below
gets a verdict: compliant, violating, or not-applicable — with file:line
evidence. Also flag spec requirements with NO implementing code (coverage
gaps → candidates for new greatspectations quotes).

## INPUTS (read all)
- Spec: `/home/ubuntu/src/bolts/11-payment-encoding.md` (sections:
  Requirements, Tagged Fields, Feature Bits, Examples, Rationale)
- Impl: `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/cln_lightning.py`
  (`b11invoice_from_hash` ~line 417-480) and
  `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/lnaddr.py`
  (`lnencode_unsigned` ~line 153-255, `shorten_amount`, `tagged8`)
- Reference: `/home/ubuntu/src/electrum/electrum/bolt11.py`
  (electrum's current, maintained encoder — this repo vendors an OLD fork
  of it; divergence from the reference is a finding even when our spec
  quote matches)
- Existing quote sites: comments starting `# BOLT #11:` in both impl files
  (machine-verified to match the spec; your job is CODE vs QUOTE/SPEC).

## METHOD
1. Extract every `A writer:` MUST/SHOULD/MAY from the spec.
2. For each, locate the implementing code (or its absence).
3. Check the CODE honors it — not the comment. Known drift classes in this
   port: hex-string vs bytes storage, renamed fields, dropped validation,
   stale defaults.
4. Compare against electrum's bolt11.py for the same requirement: if
   electrum validates something we don't, flag it (port-divergence).
5. Payment secret: spec says writer MUST include `s` when feature bit 12
   (`payment_secret`) or 14 (basic MPP) is set — verify our features
   (`LnFeatures(0) | VAR_ONION_REQ | PAYMENT_SECRET_REQ | BASIC_MPP_OPT`)
   force the `s` tag, and that `payment_secret` is 32 random-ish bytes
   (not constant across invoices — check `_get_payment_secret`).
6. Timestamp: spec wants `date` = current unix time — verify.
7. `x` expiry encoding: we use `LN_EXPIRY_NEVER` for expiry==0 — check
   what value that is and whether bech32 encoding of huge ints is safe
   (compare to electrum's approach).

## VERDICT FORMAT (per requirement)
```
### W-<n>: <requirement summary>
Verdict: ✅ | ⚠️ | ❌ | N/A
Evidence: file:line + 1-3 lines of the relevant code
Note: (only if ⚠️/❌) why, severity (P0 funds-risk / P1 interop / P2 cosmetic),
  and suggested fix
```

## OUTPUT
Write to `/home/ubuntu/src/nostr-subswap-provider-cln/docs/audits/results/AUDIT-1-bolt11-writer.md`
with: header (date, commit, files read), the requirement table, a
COVERAGE GAPS section (spec MUSTs with no quote site — propose the exact
quote text + file:line to add), and a FINDINGS SUMMARY (count by severity).
End with `VERDICT: PASS | PASS-WITH-WARNINGS | FAIL`.
