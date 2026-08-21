# AUDIT-2: BOLT #11 Invoice Reader Path

## ROLE
You are a Lightning protocol auditor. You audit THIS repo's invoice
decoding/parsing code against BOLT #11 reader requirements.

## OBJECTIVE
Every reader-side MUST/SHOULD in BOLT #11 gets a verdict with file:line
evidence; flag coverage gaps (unimplemented reader MUSTs). This is the
parser that touches untrusted wire data — every validation gap is a
potential DoS or funds bug.

## INPUTS (read all)
- Spec: `/home/ubuntu/src/bolts/11-payment-encoding.md`
- Impl: `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/lnaddr.py`
  (`lndecode` ~line 388+, `unshorten_amount`, `parse_fallback_addr`,
  `pull_tagged`, and the tag-walking loop) and
  `/home/ubuntu/src/nostr-subswap-provider-cln/swap-provider/plugin/segwit_addr.py`
  (bech32_decode, convertbits)
- Reference: `/home/ubuntu/src/electrum/electrum/bolt11.py` (current
  electrum decoder) — divergence from its validations is a finding
- Existing quote sites: `# BOLT #11:` comments in lnaddr.py

## METHOD
1. Extract every `A reader:` MUST/SHOULD from the spec.
2. For each, find our handling. Pay special attention to:
   - unknown even feature bits → MUST fail the payment (how do we
     surface feature bits after decode? does anything check them?)
   - fixed data_length enforcement (p/h/s/n = 52/52/52/53) — our quote
     says MUST fail; does the CODE fail, or just skip?
   - `d` xor `h` exactly-one enforcement
   - signature recovery + low-S acceptance rules
   - `n` field usage when present
   - bech32 checksum/case rules (mixed case rejection)
   - amount parsing: multiplier table, non-digit rejection, `p`-multiplier
     trailing-zero rule
3. Trace what the DECODER's callers do with validation failures — a
   raise that's swallowed by a bare `except` is a ⚠️ at best.
4. Compare each validation against electrum's bolt11.py decode path.

## VERDICT FORMAT
Same as AUDIT-1 (R-<n> numbering).

## OUTPUT
Write to `/home/ubuntu/src/nostr-subswap-provider-cln/docs/audits/results/AUDIT-2-bolt11-reader.md`
(header, table, COVERAGE GAPS, FINDINGS SUMMARY, `VERDICT:` line).
