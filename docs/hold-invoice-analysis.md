# Hold Invoice Analysis: The Atomic Binding Mechanism in d2
# (educational document — how it works, what it protects, where it doesn't)

## The core question

"Could a hold invoice mitigate the #10 attack (server claims without
paying)?"

**Short answer:** the hold invoice IS the atomic binding mechanism —
it's already in the protocol. It's what makes the swap "atomic" at all.
But in the d2 direction, the binding only holds if the server actually
sends the payment. A malicious server that skips the payment breaks the
atomic chain. The hold invoice creates the *link* but can't *enforce*
it.

## How the hold invoice works — both directions

### d1 (LN→onchain) — the trustless direction

```
CLIENT generates preimage R
CLIENT creates hold invoice keyed to sha256(R)
SERVER pays the hold invoice
  → HTLC parks at CLIENT's node (channel commitment)
  → CLIENT sees the parked HTLC, decides to settle
CLIENT settles by revealing R
  → R propagates back through the LN route to the SERVER
SERVER uses R to claim the onchain lockup

TRUSTLESS because: the CLIENT controls when R is revealed.
The server gets R only if the client settles, which happens
only if the LN payment arrives. The client can always refund
their onchain side if they never settle.
```

### d2 (onchain→LN) — the non-trustless direction

```
SERVER generates preimage R (at createnormalswap time)
SERVER returns sha256(R) as preimageHash in the swap terms
CLIENT creates a hold invoice keyed to sha256(R)
  → CLIENT does NOT have R (can't settle without it)
SERVER pays the hold invoice
  → HTLC parks at CLIENT's node
  → The parked HTLC is the server's commitment to pay
SERVER claims the onchain lockup with R
  → R is revealed in the claim transaction's witness
CLIENT extracts R from the claim witness
CLIENT settles the hold invoice with R
  → Parked HTLC completes → client receives LN funds

NOT TRUSTLESS because: the SERVER has R from the beginning.
The server can claim the lockup WITHOUT ever paying the invoice.
No parked HTLC → nothing to settle → client gets nothing.
```

## What the hold invoice DOES protect

| Protection | Mechanism | Direction |
|---|---|---|
| **Atomic settlement link** | Same preimage R settles both the onchain claim and the LN hold | Both |
| **Server commitment signal** | Parked HTLC = binding channel commitment (hard to revoke after revocation) | d2 (our #26 gate checks this) |
| **Payment-before-claim ordering** | Our park-then-claim gate refuses to claim without parked HTLCs | d2 (code-level, bypassable) |
| **Client observes server's intent** | Client can check if HTLCs are parked before funding more | d2 (requires client-side check) |

## What the hold invoice DOES NOT protect

| Gap | Why | Direction |
|---|---|---|
| **Server claims without paying** | Server has R from creation; hold invoice can't prevent direct blockchain spend | d2 (the #10 attack) |
| **HTLC cancellation race** | Server can fail the HTLC back before irrevocable commitment | d2 (parked ≠ irrevocable until revocation) |
| **Timing (block gaps)** | Invoice can expire before block-triggered monitoring fires | d2 on signet (#25) |
| **Operator bypass** | Anyone with the privkey + preimage can bypass all code gates | d2 (the #13 amplifier) |

## The race window in park-then-fund

Even if the client waits for parked HTLCs before funding the lockup:

```
Step 1: Server sends payment → HTLC parks at client's node
Step 2: Client sees parked HTLC → decides to fund lockup
Step 3: SERVER CANCELS the HTLC (fails it back)
Step 4: Client funds lockup (based on stale observation)
Step 5: Server claims lockup with preimage (HTLC already cancelled)

The gap: between "HTLC parks" (step 1) and "HTLC is irrevocably
committed" (after the next commitment-signed + revoke-and-ack exchange),
the sender can cancel. This window is typically 1-3 commitment rounds
(~1-10 seconds on a healthy channel).

MITIGATION: after funding, the client should VERIFY the HTLC is still
parked. If it's gone → immediately attempt refund. This narrows but
doesn't eliminate the race.
```

## Design option: d2 prepayment hold (cost-increasing, not eliminating)

What if the server had to park a prepayment hold invoice BEFORE the
client funds?

```
Modified d2 protocol:
Step 1: Server creates swap (generates preimage R)
Step 2: Client creates main hold invoice keyed to sha256(R)
Step 3: Server parks a PREPAYMENT hold (e.g., 10% of swap amount)
        keyed to the SAME sha256(R)
Step 4: Client verifies prepayment is parked
Step 5: Client funds the onchain lockup
Step 6a: HONEST server: pays main invoice → claims → both settles complete
Step 6b: MALICIOUS server: claims without paying
         → Preimage revealed in claim witness
         → Client settles the PREPAYMENT (gets 10% back)
         → Client loses 90% (not 100%)

ECONOMICS: theft now costs 10% instead of 0%. Still profitable but
less attractive. At 50% prepayment, the attack nets only 50% — same
as honest operation with fees, removing the incentive.
```

**Limitation:** the prepayment also expires via CLTV. If the server
never claims and the client never funds, the prepayment refunds. The
prepayment doesn't GUARANTEE recovery — it increases the attacker's
cost proportionally.

**This is the same mechanism as d1's `minerFeeInvoice`, applied to the
d2 direction.** Electrum's protocol doesn't have it for d2; adding it
would be a protocol extension.

## Why the long-term fix is adaptor signatures (PTLC)

The fundamental problem: in d2, the server generates the preimage at
creation time. The hold invoice is keyed to the server's hash, so the
server ALWAYS has the settlement secret.

With adaptor signatures / PTLCs:
- The "preimage" doesn't exist until the payment succeeds
- The claim key requires an adaptor signature that can only be
  completed when the LN payment reveals the scalar
- A malicious server literally CANNOT construct a claim without paying
- The hold invoice becomes the ONLY way to obtain the claim secret

This eliminates the entire #10 attack class structurally. But it
requires Lightning Network protocol evolution (PTLC support in BOLTs).

## Summary for the security model

| Mechanism | What it does | Attack it prevents | Attack it doesn't |
|---|---|---|---|
| **Hold invoice (existing)** | Atomic link between onchain claim and LN settlement | Accidental non-payment (client always gets paid if server pays) | Intentional claim-without-pay |
| **Park-then-claim gate (ours, #26)** | Server code refuses to claim without parked HTLCs | Honest server misbehaving (bug/failure path) | Malicious operator bypassing code |
| **Client park-before-fund** | Client waits for parked HTLC before funding | Server that never intends to pay | HTLC cancellation race |
| **d2 prepayment hold (proposed)** | Server commits N% before client commits | Zero-cost theft (attacker pays N%) | Partial-loss theft (attacker still nets 100%-N%) |
| **Adaptor signatures (future)** | Claim secret only exists after payment | ALL claim-without-pay attacks | None (structural fix) |
