# Security Analysis: Electrum Submarine Swap Protocol — Attack Vectors,
# Funds at Risk, and the Complete Threat Model

**Date:** 2026-08-30
**Scope:** Issues #10, #12, #13, #25 in Amperstrand/nostr-subswap-provider-cln,
cross-referenced against the electrum reference implementation and our
deployed mitigations.
**Classification:** Internal (Amperstrand only) — contains exploit details.
Do NOT post on external projects without owner authorization.

---

## 1. The Attack Model

Three distinct adversary classes:

| Adversary | Access | What they control |
|---|---|---|
| **Malicious swap-server operator** | Full server, CLN RPC, datastore | Can extract all secrets, bypass all code gates, broadcast raw transactions |
| **Malicious client** | Nostr connection to the server | Can create swaps, register invoices, fund or not fund lockups |
| **Timing adversary** | Network observer | Can exploit block-gap windows, invoice-expiry races |

The swap protocol has TWO directions with DIFFERENT trust models:

| Direction | Who generates the preimage | Who holds the claim key | Trust required |
|---|---|---|---|
| **d1 (LN→onchain)** / `createswap` reversesubmarine | CLIENT | CLIENT | None — the client reveals the preimage only upon payment; the server cannot steal |
| **d2 (onchain→LN)** / `createnormalswap` | SERVER (at creation) | SERVER | FULL — the server CAN claim the lockup without paying; only code gates prevent it |

**All attacks below target d2.** The d1 direction is trustless by design.

---

## 2. Attack #10: Claim-without-payment (FUNDS AT RISK)

### What the attacker needs

- The claim private key (`swap.privkey`)
- The preimage (`swap.preimage`)
- Both stored in the CLN datastore from the moment of `createnormalswap`

### The exploit — step by step

```
Prerequisites: attacker controls the server (or has CLN RPC access)

Step 1: Victim calls createnormalswap(invoiceAmount=20000)
        → Server generates preimage R, claim key (a, A), refund locktime
        → Returns lockup_address, expectedAmount, timeoutBlockHeight
        → Server stores: {privkey: hex(a), preimage: hex(R), ...}
          in datastore key ['swap-provider', 'jsondb']

Step 2: Victim calls addswapinvoice(bolt11=<their hold invoice>)
        → Server registers the invoice, parks it (option-E gate)
        → Invoice is queued but NOT paid yet

Step 3: Victim funds the lockup (sends 20,238 sat to lockup_address)
        → Transaction confirmed on-chain
        → The onchain output is now spendable by EITHER:
          a) preimage R + claim key A (at ANY height)
          b) refund key (at height ≥ locktime, 70 blocks from creation)

Step 4: ATTACK — the attacker bypasses all plugin code:
        a) Reads the datastore: datastore(['swap-provider', 'jsondb'])
           → Extracts hex(a) and hex(R) for the victim's swap
        b) Constructs a raw P2WSH claim transaction:
           - Input: the lockup outpoint
           - Witness: [signature_with_A, preimage_R, redeem_script]
           - Output: attacker's own address
           - nLockTime: 0 (the preimage branch has NO temporal constraint)
           - nSequence: 0xFFFFFFFF (no relative lock)
        c) Signs the transaction hash with key a
        d) Broadcasts via sendrawtransaction (any node, not just ours)

Step 5: The victim's hold invoice is never paid (no HTLC ever parked)
        → Their LN-side payment fails / expires
        → Their 20,238 sat onchain is gone (spent by the attacker)
        → The victim CANNOT refund: the output is already spent
```

### Why the victim cannot defend

The victim's refund branch requires `nLockTime ≥ timeoutBlockHeight` (70
blocks from creation). The attacker's claim branch has NO temporal
constraint — it's valid from the moment the lockup confirms. The race
is:

```
Attacker's claim: available IMMEDIATELY (preimage + key)
Victim's refund:  available after 70 BLOCKS

→ The attacker ALWAYS wins this race.
```

The only client-side defense: **don't fund until the server's LN payment
has committed HTLCs** (the park-then-claim gate — but this requires the
CLIENT to implement it, which the electrum client does NOT do by
default).

### Funds at risk: YES — full lockup amount per swap

Every d2 swap where the lockup is funded and the server hasn't yet paid
is at risk. The attacker can sweep ALL funded lockups simultaneously
(read the datastore → batch-construct claims → broadcast all).

### Prepayment analysis

**d2 has NO prepayment.** The prepay mechanism (`minerFeeInvoice`)
exists only for d1 (LN→onchain). An attacker mounting this exploit pays
zero cost — they need only the datastore read.

For d1, the prepay partially protects: the server commits the prepay
amount before the client reveals the preimage. But the prepay is small
(~278 sat on mutinynet) and doesn't cover the main amount.

---

## 3. Attack #12: Liquidity jamming (DoS — pre-option-E; FIXED)

### What the attacker needs

- A nostr connection to the server (free, public by design)
- Lightning hold invoices (free to create)
- ZERO onchain funds

### The exploit — step by step (against electrum's implementation)

```
Step 1: Attacker calls createnormalswap(invoiceAmount=20000) × N
        → N swaps created, each with 20k minimum

Step 2: Attacker calls addswapinvoice × N with their hold invoices
        → In electrum: invoices IMMEDIATELY queued for payment
          (invoices_to_pay[key] = 0)
        → Server starts paying all N invoices in parallel

Step 3: Each payment parks 20k sat in in-flight HTLCs
        → Total outbound liquidity jammed: N × 20k sat
        → HTLCs sit until their CLTV expires (144+ blocks)

Step 4: Attacker NEVER funds any lockup
        → Zero cost to attacker
        → Server's legitimate clients are refused (no outbound capacity)

Result: N × 20k sat of outbound LN liquidity unavailable for the
duration of the HTLC CLTVs. The server also burns fees on payment
attempts that eventually fail.
```

### Our mitigation (deployed): option-E funding gate

The option-E gate (#24) parks every invoice in `invoices_awaiting_funding`
until onchain lockup evidence is observed. A 30-block timeout fails the
swap cleanly. **The payment never fires without funding.**

**Post-option-E status: this attack is neutralized.** An unfunded swap
costs the server zero liquidity.

### Prepayment analysis

d2 has no prepayment, so the attacker doesn't even need to pay a small
amount to mount this. Adding a d2 prepay would increase the attacker's
cost but not eliminate the attack (prepay CLTVs expire too).

---

## 4. Attack #25: Block-gap expiry race (FUNDS AT RISK — timing-dependent)

### The exploit — step by step

```
Prerequisites: signet network (5-10 minute block gaps)

Step 1: Victim calls createnormalswap during a block gap
        → Swap created, lockup address returned

Step 2: Victim calls addswapinvoice with a 300-second-expiry hold invoice
        → Invoice registered

Step 3: Victim funds the lockup (onchain tx in mempool, unconfirmed)
        → The ChainMonitor callback only fires on NEW BLOCKS
        → No new block arrives for 5-10 minutes (signet gap)

Step 4: The 300-second invoice expires (wall-clock time)
        → The payment can no longer fly (invoice is dead)

Step 5: Eventually a block arrives
        → The callback fires, sees the funded lockup
        → The claim path runs (park-then-claim tries to pay, fails)
        → The provider eventually claims the lockup (protocol-legally)
        → The victim received NOTHING for their onchain funds
```

### Funds at risk: YES — full lockup amount (observed: 21,269 sat)

This is the same theft-class outcome as #10, but triggered by timing
rather than malice. The server doesn't need to be malicious — it just
needs to be slow (waiting for a block) while the invoice dies
(wall-clock).

### Prepayment analysis

Prepayments don't help — the issue is that block-triggered monitoring
is slower than wall-clock invoice expiry.

### Fix: time-based re-check

Add a wall-clock check in the monitoring loop: for swaps with parked
invoices approaching expiry, trigger the claim path immediately instead
of waiting for a block. Moderate effort, eliminates the race on signet.

---

## 5. Attack #13: Secrets exposure — THE ENABLER

This is not a standalone attack — it's the **force multiplier** for #10.

### What's exposed

Every swap record in the CLN datastore contains:
```json
{
  "privkey": "<hex of claim private key>",
  "preimage": "<hex of preimage>",
  "lockup_address": "<P2WSH address>",
  "redeem_script": "<hex of witness script>",
  ...
}
```

All in one JSON blob, stored as a single string in the CLN datastore
key `['swap-provider', 'jsondb']`, inside `lightningd.sqlite`.

### Who can access it

- **Anyone with CLN RPC access** (the `datastore` command)
- **Anyone who can read the SQLite file** (filesystem access)
- **Anyone who reads the CLN log** (if the debug-buffer replay fires —
  now mitigated by our size-only logging fix)

### Combined attack: #13 + #10 = zero-effort batch theft

```
Step 1: Gain CLN RPC access (or read lightningd.sqlite)
Step 2: datastore(key=['swap-provider', 'jsondb'])
        → Returns the full JSON with ALL swaps' keys and preimages
Step 3: For each swap with a funded, unclaimed lockup:
        → Extract privkey + preimage + redeem_script
        → Construct a claim transaction
Step 4: Batch-broadcast all claims
        → Every funded lockup is swept in one block
```

The plugin's three code gates (option-E, park-then-claim,
LN-commitment) are completely bypassed — the attacker goes directly to
the blockchain.

---

## 6. The Complete Threat Matrix

| Attack | Adversary | Cost to attacker | Funds at risk? | DoS? | Prepay helps? | Our mitigation | Residual risk |
|---|---|---|---|---|---|---|---|
| **#10** Claim-without-payment | Malicious operator | Zero (datastore read) | ✅ FULL lockup per swap | No | ❌ No prepay for d2 | Park-then-claim + option-E + LN-commitment (code gates) | Operator bypass: HIGH until #13 HSM-split; then MEDIUM |
| **#12** Liquidity jamming | Malicious client | Zero (nostr + free invoices) | No | ✅ N × 20k sat outbound jammed | ❌ No | Option-E funding gate (deployed) | LOW (gate closes it) |
| **#25** Block-gap expiry race | Timing (no adversary needed) | Zero | ✅ FULL lockup per swap | No | ❌ No | None yet | MEDIUM on signet (fixable) |
| **#13** Secrets exposure | Operator / RPC / filesystem | Zero (already has access) | Enabler for #10 | No | N/A | Size-only logging (deployed) | MEDIUM (HSM-split pending) |

### Interaction effects

- **#13 amplifies #10**: without #13, the operator needs to understand
  the code to extract keys; with #13, it's a single RPC call
- **#25 is a non-malicious version of #10**: same outcome (client loses
  funds), different trigger (timing vs. intent)
- **#12 is neutralized by #24**: the option-E gate was designed for
  exactly this attack class

---

## 7. What we can do — prioritized

### Already done (deployed in production)

| Defense | What it protects | Issue |
|---|---|---|
| Option-E funding gate | Prevents paying unfunded swaps (blocks #12) | #24 |
| Park-then-claim gate | Our code never claims without parking HTLCs | #26 |
| LN-commitment check | Claim only if invoice registered + payment alive | — |
| Size-only logging | No secrets in logs (defuses #13's amplifier) | #13 |
| Provider blocklist | Known harvesting providers refused | bridge-side |
| Crash-window guard | #35/#9452 fix (daemon no longer SIGABRTs near the reserve floor) | #35 |
| Client CLTV validation | Rejects invoices with too-short CLTV | #14 item 4 |

### Implementable now (moderate effort)

| Defense | What it protects | Effort | Priority |
|---|---|---|---|
| **Time-based re-check** (monitoring loop) | Eliminates #25's block-gap race | Low | HIGH — real sat losses |
| **HSM-split of secrets** | Removes #13's datastore exposure; #10's operator-bypass gets harder | Medium | HIGH — biggest single security win |
| **Debug-buffer exclusion for secret categories** | Prevents future accidental secret dumps via buffer replay | Low | MEDIUM |
| **Per-swap capacity reservation** | Prevents a single client from consuming all outbound capacity | Low | LOW (optimization) |

### Protocol-level (requires ecosystem coordination)

| Defense | What it protects | Blocker |
|---|---|---|
| **Adaptor signatures** | The claim secret only exists after the payment succeeds — structurally eliminates #10 | Requires Lightning PTLC support or protocol change |
| **PTLC-based swaps** | The natural evolution — no preimage exists until payment | Lightning protocol evolution (BOLT12 path) |
| **Client-side park-before-fund** | Victim waits for server's HTLC to park before funding | Requires electrum client change (upstream) |

---

## 8. How to better document and highlight this

### What we have now

- Issue tracker entries (#10, #12, #13, #25) — detailed but scattered
- AGENTS.md "onchain_to_ln is not trustless" section — accurate but brief
- docs/research/onchain-to-ln-trust-model.md — the original analysis
- This document — the comprehensive security model

### What's missing

1. **A security-model one-pager** in the README (visible to anyone
   evaluating the plugin): "What an honest operator provides vs. what
   a malicious operator CAN do — with the specific gates that prevent
   each attack."

2. **A trust-boundary diagram**: show visually where funds are at risk
   at each step of the swap, and which gates protect each transition.

3. **An incident-response playbook**: if we discover a provider is
   exploiting #10 (like the harvesting providers already blocklisted),
   what's the procedure? (Blocklist → forensic → affected-client
   notification?)

4. **A client-facing warning**: the electrum client doesn't implement
   park-before-fund. A client that funds immediately after
   addswapinvoice is exposed to #10. This should be documented in the
   README's security section.

5. **Regular audit against this document**: each new deployment or
   protocol change should be checked against this threat model to
   verify no new attack surfaces are introduced.

---

## Appendix A: The witness template (annotated)

```
OP_SIZE              → push size of top stack item
32                   → push 32
OP_EQUAL             → is the witness item 32 bytes?
OP_IF                → if yes (it's a preimage):
  OP_HASH160         →   hash the preimage with RIPEMD160
  <ripemd160(R)>     →   push the expected hash
  OP_EQUALVERIFY     →   verify: preimage hashes to expected value
  <claim_pubkey>     →   push the server's public key
OP_ELSE              → if no (not a preimage):
  OP_DROP            →   drop the "false" size check result
  <locktime>         →   push the refund height (creation + 70)
  OP_CLTV            →   verify: nLockTime ≥ locktime (LOWER BOUND ONLY)
  OP_DROP            →   drop the verified locktime
  <refund_pubkey>    →   push the client's public key
OP_ENDIF
OP_CHECKSIG          → verify the signature against the chosen pubkey
```

**The vulnerability:** the IF branch has NO temporal constraint. Adding
`<locktime> OP_CLTV` there would mean "valid AFTER locktime" — the
opposite of what's needed. Bitcoin Script cannot express "valid ONLY
BEFORE locktime." This is a fundamental scripting-language limitation.

## Appendix B: Prepayment coverage by direction

| Direction | Prepay? | Amount | What it protects | What it doesn't |
|---|---|---|---|---|
| d1 (LN→onchain) | ✅ Yes (minerFeeInvoice) | ~278 sat (mutinynet) / ~7k (signet) | Server commits small amount before client reveals preimage | Doesn't cover the main swap amount if server goes offline after prepay |
| d2 (onchain→LN) | ❌ No | N/A | N/A | No pre-commitment from server — the client funds onchain with zero server commitment |

**d2 is the under-protected direction.** Adding a d2 prepay (server
pays a small LN invoice before the client funds) would increase the
attacker's cost for #10 but not eliminate it (the server still has the
preimage and can claim at any height).
