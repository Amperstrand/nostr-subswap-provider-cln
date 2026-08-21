# Spec-Quote + AI Audit Program

Three layers, per the hackathon-tooling `greatspectations-ai-audit`
methodology (`/home/ubuntu/src/hackathon-tooling/docs/greatspectations-ai-audit-methodology.md`):

1. **Layer 1 — mechanical drift**: verbatim BOLT quotes in source comments,
   verified by greatspectations. `specquotes.toml` + `tests/test_spec_quotes.py`
   (pytest gate, skips without sibling checkouts) + CI workflow
   `.github/workflows/spec-quote-drift.yml`.
2. **Layer 2 — semantic AI audit**: `AUDIT-{1..5}-*.md` prompts in this dir
   dispatch an agent that reads spec + code + electrum reference and writes
   PASS/WARN/FAIL verdicts with file:line evidence into `results/`.
   Re-runnable: `opencode --prompt docs/audits/AUDIT-4-swap-protocol.md`
   or via parallel background agents (all five ≈ 30 min wall clock).
3. **Layer 3 — divergence database**: the reference implementation is
   `../electrum` (the port source). Port-divergence is the #1 historical
   bug class here (5 of 8 live bugs 2026-08-20). AUDIT-3/4 carry explicit
   port-divergence sections; keep them current when electrum moves.

## Audit cells

| Cell | Scope | Spec | Result |
|---|---|---|---|
| AUDIT-1 | BOLT #11 writer path (invoice creation) | 11-payment-encoding | results/AUDIT-1-bolt11-writer.md |
| AUDIT-2 | BOLT #11 reader path (lndecode, untrusted input) | 11-payment-encoding | results/AUDIT-2-bolt11-reader.md |
| AUDIT-3 | BOLT #2/#4 HTLC, MPP, hold-invoice semantics | 02-peer-protocol, 04-onion | results/AUDIT-3-bolt2-htlc.md |
| AUDIT-4 | Swap protocol vs electrum (funds path) | repo AGENTS.md R1-R9 | results/AUDIT-4-swap-protocol.md |
| AUDIT-5 | Nostr offer + PoW (client discovery surface) | electrum swapserver plugin | results/AUDIT-5-nostr-offer.md |

## Cadence

- Layer 1: every push (CI).
- Layer 2: after any change to the audited files, or when electrum/bolts
  update (re-run the affected cell only).
- Findings: file GitHub issues for P0/P1; add a greatspectations quote at
  the fix site so the requirement stays pinned.
