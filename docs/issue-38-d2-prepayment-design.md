# #38 Design: D2 Prepayment Hold — Parallel Option
# (prototype design, not implemented — for review)

## Goal

Add an OPTIONAL prepayment mechanism for the d2 (onchain→LN) direction
that increases the cost of a claim-without-payment attack from 0% to
N% of the swap amount. Implemented as a feature-flagged parallel option
so existing behavior is unchanged when disabled.

## The design space

### What exists today (d1's prepay pattern)

For d1 (LN→onchain), the server creates TWO hold invoices:
- Main invoice: the swap amount (client pays this)
- Prepay invoice (`minerFeeInvoice`): the mining fee (client pays this first)

The prepay serves as a fee-griefing defense: the server commits the
onchain funding only after BOTH the prepay and main arrive (F8 bundle).

### What we'd add for d2

For d2 (onchain→LN), the flow is inverted: the SERVER pays the CLIENT's
hold invoice, and the CLIENT funds the onchain lockup. A prepayment
would mean the SERVER commits a small hold invoice BEFORE the client
needs to fund.

## Proposed protocol extension

### New env var (the feature flag)

```
SWAPSERVER_D2_PREPAY_PCT=0  (default: disabled; 10 = 10% prepayment)
```

When 0 (default): existing behavior, no change.
When >0: the server includes a prepayment hold invoice in the
createnormalswap response.

### Wire format change (backward-compatible)

The `createnormalswap` response gains an OPTIONAL field:

```json
{
  "id": "...",
  "preimageHash": "...",
  "acceptZeroConf": false,
  "expectedAmount": 20238,
  "timeoutBlockHeight": 319900,
  "address": "bcrt1q...",
  "redeemScript": "...",
  "prepaymentInvoice": "lntbs..."   // NEW — only present when enabled
}
```

**Existing clients that don't understand `prepaymentInvoice` simply
ignore it** — the field is additional, not a replacement. The swap
proceeds normally (option-E gate, park-then-claim, etc.).

**New clients that understand it** can:
1. Pay the prepayment hold invoice (a small amount, e.g., 10% of swap)
2. Wait for the server's HTLCs to park on the MAIN invoice
3. Only then fund the onchain lockup

The prepayment is a server-side commitment that makes the
claim-without-payment attack cost the attacker N%.

### How the prepayment hold works

The prepayment is a HOLD INVOICE created by the CLIENT (not the server),
keyed to the same payment_hash as the main swap. The server pays it
alongside the main invoice (or as a separate payment).

Wait — that's backwards. Let me reconsider.

For d2, the CLIENT creates the hold invoice. The SERVER pays it. So
the prepayment direction should be: the SERVER creates a SEPARATE small
hold invoice that the CLIENT pays. This commits the CLIENT to the swap
(griefing defense) but doesn't protect against the server claiming.

Actually, the correct d2 prepayment is: the SERVER parks a hold invoice
(a NEW one, separate from the main swap invoice) with the CLIENT. The
client can settle this prepayment if the server claims without paying
the main invoice.

```
Step 1: Server creates swap (preimage R, hash H)
Step 2: Server ALSO creates a prepayment hold keyed to H
        (same hash, separate invoice)
Step 3: Client pays the prepayment hold (small amount, e.g., 10%)
        → Server's HTLC parks at client's node
Step 4: Client sees the prepayment parked → proceeds with the swap
        (creates main hold invoice, registers with server)
Step 5a: HONEST server: pays main → claims → both settle → done
Step 5b: MALICIOUS server: claims without paying main
         → Preimage R revealed in claim witness
         → Client settles the prepayment (recovering 10%)
         → Client loses 90% instead of 100%
```

**Problem:** the client pays the prepayment — this means the CLIENT
commits funds first, not the server. That's backwards for d2 where
the server should be the one committing.

### Revised design: server-side prepayment hold

The SERVER creates a hold invoice payable TO the server, and the
preimage is the SAME R as the main swap. The SERVER sends this
prepayment invoice to the client in the createnormalswap response.

The CLIENT pays the prepayment (a small amount). The server's HTLC
parks on its own node (incoming payment to the server's prepayment
invoice). This doesn't directly prevent the server from claiming
without paying the main invoice — the prepayment is already paid to
the server.

**This doesn't work for d2.** The prepayment pattern from d1 doesn't
translate because the payment directions are inverted.

### The correct d2 prepayment: server-side bond

What we actually need is a server-side BOND — something the server
loses if it claims without paying. The bond can't be a Lightning
payment (the server is the payer in d2, not the receiver).

Options:

**Option A: Onchain bond**
The server locks a small amount onchain at a known address, spendable
only if the swap completes honestly (by the server revealing the
preimage) or refundable to the client after the locktime.

Implementation: a second P2WSH output with a script like:
```
OP_IF
    <preimage_hash> OP_HASH160 OP_EQUALVERIFY <server_key>
OP_ELSE
    <swap_locktime> OP_CLTV OP_DROP <client_key>
OP_ENDIF
OP_CHECKSIG
```
The server must reveal the preimage to recover the bond. If the server
claims the main lockup (revealing the preimage), the client can also
spend the bond (they now have the preimage from the claim witness).

**Complexity:** HIGH — this is essentially a second HTLC onchain,
requiring a new transaction, new script management, and integration
with the existing claim path.

**Option B: Channel-state bond**
The server sends a payment that parks at the client's node and can only
be settled by the client after seeing the preimage. This IS what the
main swap hold invoice already does — the problem is the server can
skip paying it.

**The insight:** the main swap's hold invoice IS the bond. The issue
isn't that it doesn't exist — it's that the server can bypass paying
it. The prepayment question is really: "how do we make bypassing the
payment cost something?"

**Option C: Reputation/staking (not a protocol change)**
The most practical option: the boltz-bridge already maintains a
PROVIDER_BLOCKLIST. We could add a "bond" concept where providers
stake onchain funds that are seized if they're caught harvesting.
This is off-chain, reputation-based, and already partially implemented.

**Option D: Feature-flagged protocol variant (the pragmatic answer)**
Accept that a true d2 prepayment requires either an onchain bond
(Option A) or a PTLC (the structural fix). In the meantime, provide
a PROTOCOL SIGNAL that clients can use:

Add a field to the createnormalswap response:
```json
{
  "providerBond": {
    "address": "bcrt1q...",  // onchain address where the provider has a bond
    "amount": 50000           // bond amount
  }
}
```

This is informational — the client can verify the bond exists onchain
and decide whether to proceed. The bond itself is managed out-of-band
(the provider locks funds at the address; the bridge or client can
verify). No protocol enforcement, just transparency.

## Recommendation

**Don't implement a d2 prepayment hold.** After extensive analysis:

1. The d1 prepay pattern doesn't translate to d2 (inverted payment
   directions)
2. An onchain bond is complex and duplicates the existing hold-invoice
   mechanism
3. The electrum client ALREADY implements park-before-fund (issue #41
   finding), which is the real client-side defense
4. The structural fix is PTLC/adaptor signatures (#40), not a
   prepayment
5. The provider blocklist + reputation system is the practical
   mitigation we already have

**What we SHOULD do instead:**
- Document the `providerBond` informational field as a future option
- Focus on the HSM-split (#36) to reduce the operator-theft enabler
- Track PTLC (#40) as the real long-term fix
- The feature-flag/setting system the user asked about is valuable for
  other things (enable/disable directions, fee tiers, etc.) and should
  be designed separately

## Feature-flag system (the broader ask)

The user asked about "a setting thing where we enable/disable different
forms of swapping." This is a good architectural direction:

```python
# plugin_config.py — new settings block
config.swap_modes = {
    "ln_to_onchain": True,      # d1: createswap/reversesubmarine
    "onchain_to_ln": True,      # d2: createnormalswap/addswapinvoice
    "d2_prepay": False,          # future: d2 prepayment bond
    "d2_park_enforce": True,     # server-side park-then-claim enforcement
}
```

This would allow the operator to disable specific swap modes, enable
future experimental features independently, and advertise the modes
in the nostr offer (so clients know what's available).

Implementation: a new `SWAP_MODES` env var (JSON or CSV), parsed at
startup, enforced at the RPC boundary (reject requests for disabled
modes with a typed error), and advertised in the offer.
