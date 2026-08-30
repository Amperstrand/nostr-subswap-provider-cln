## <u>Submarine Swap provider plugin for CLN</u>
<mark>This plugin is functional but experimental. Usage on mainnet is very reckless!</mark>

<mark>Please report any issues on GitHub and use only on testnet/signet.</mark>

<mark>There is one active instance of this plugin running on signet for client testing.</mark>

This [Core Lightning](https://github.com/ElementsProject/lightning) plugin allows to
the operator to act as provider for [(reverse) submarine swaps](https://docs.lightning.engineering/the-lightning-network/multihop-payments/understanding-submarine-swaps)
to users of the
[Electrum Wallet](https://electrum.org) (and others implementing the same, open protocol).
Communication is facilitated via [Nostr](https://nostr.com), and the plugin uses the CLN node's database, wallet
and (newly derived) keys to operate, so the user does not have to manage any additional
backup, wallet or Nostr identity.

### <u>Incentives (Reason to run this plugin alongside CLN)</u>
The swap provider can charge a proportional fee for the liquidity provided.
There is no risk of financial loss for the swap provider, as the swap is atomic and
the mining fees required to unwind an unclaimed swap are settled by a separate lightning payment.
A competitive fee can be chosen according to market conditions,
fees of other providers can be seen in the Electrum Wallet.


### <u>Installation</u>
#### Bitcoin Core backend
The Plugin relies on a Bitcoin Core backend Core Lightning is setup to use. **Bitcoin Core has to enable** ```txindex=1```
for the plugin to work. The Plugin automatically uses the RPC credentials CLN is using and doesn't require any additional setup.

#### Plugin installation

You can find a detailed guide on how to install plugins in CLN using the reckless package manager
[-> here <-](https://docs.corelightning.org/docs/plugins).

For reckless to find the plugin you first have to add this repository:
```bash
reckless source add https://github.com/f321x/nostr-subswap-provider-cln
```

Then you can install the plugin:
```bash
reckless install --network=signet swap-provider
```

### <u>Configuration</u>
The plugin settings are configured using [environment variables](https://kinsta.com/knowledgebase/what-is-an-environment-variable/).

The following variables are available:
- `NOSTR_RELAYS`: A comma-separated string of nostr relay URIs. Example: `wss://nos.lol,wss://relay.primal.net,wss://nostr.mom`
- `SWAP_FEE_PPM`: Fee to charge for swaps in ppm. Example: `10000` (1%)
- `CONFIRMATION_TARGET_BLOCKS`: Desired confirmation speed of onchain transactions. Example: `6`
- `FALLBACK_FEE_SATVB`: Fallback feerate to use if no reliable fee estimation is possible. Example:`65`
- `PLUGIN_LOG_LEVEL` (optional): Level of Log output. Examples: `DEBUG`, `INFO`, `WARNING`, `ERROR`

### <u>Libraries</u>
This plugin uses a lot of Electrum Wallet code that has been stripped/modified for this use case.
It also uses the `pyln-client` library to communicate with CLN over the RPC interface.
## Client mode (SWAP_MODE=client)

The plugin can also run as a pure **client** of other Electrum-protocol
swap providers: no offers published, no DMs served, no hold invoices —
just discovery, gated swaps, and onchain claims (`swapclient`,
`swapclient-offers`, `swapclient-status` RPCs).

```bash
SWAP_MODE=client lightningd ... --plugin=swap-provider.py
lightning-cli swapclient-offers
lightning-cli swapclient amount_sat=50000 [provider=<pubkey>]
```

`cli-swap.py` (repo root) is an educational walker over that mode: it
prints the state machine, narrates every state with the attack it
defends against, and dry-runs by default (`--execute` moves sats).

The client implementation is the Python twin of the C++ client in
`../clboss` (branch `nostr-swaps`, see its NOSTR-SWAP.md for the full
bug ledger and e2e history); both are pinned to the same live swap
values in their tests.

## Security Model (read before operating)

Submarine swaps have **two directions with different trust properties**.
Understanding this is essential for both operators and clients.

### Direction summary

| Direction | Client action | Trustless? | Why |
|---|---|---|---|
| **LN→onchain** (`createswap` reversesubmarine) | Pays LN invoice, receives onchain | ✅ Yes | Client generates the preimage; server can't claim without payment |
| **onchain→LN** (`createnormalswap` + `addswapinvoice`) | Sends onchain, receives LN | ⚠️ No | Server generates the preimage and *can* claim without paying |

### What protects onchain→LN swaps (the non-trustless direction)

```
┌─────────────────────────────────────────────────────────────────┐
│  onchain→LN swap lifecycle (d2)                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  createnormalswap ──→ addswapinvoice ──→ client funds lockup   │
│       │                      │                      │           │
│   [SERVER has                [GATE 1: option-E       │           │
│    preimage                  funding gate]            │           │
│    from here]                 │                      │           │
│                              ▼                      ▼           │
│                       invoice PARKED          onchain tx         │
│                       (not paid yet)          confirmed          │
│                              │                      │           │
│                              ▼                      ▼           │
│                    [GATE 2: funding           lockup spendable   │
│                     observed onchain]          by EITHER branch  │
│                              │                      │           │
│                              ▼                      │           │
│                    payment fires (LN HTLC)          │           │
│                              │                      │           │
│                              ▼                      │           │
│                    [GATE 3: park-then-claim]        │           │
│                    HTLC parked = server             │           │
│                    committed LN funds               │           │
│                              │                      │           │
│                              ▼                      ▼           │
│                              └──── claim broadcast ──┘           │
│                                      │                           │
│                                      ▼                           │
│                            preimage revealed                    │
│                            in claim witness                     │
│                                      │                           │
│                                      ▼                           │
│                            client settles hold                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Gates 1-3 are code-level policies in this plugin.** They prevent our
own server from claiming without paying. They do NOT prevent:

- **A malicious operator** bypassing the code and broadcasting a raw
  claim directly (the claim key + preimage are in the datastore)
- **A compromised plugin** (code injection bypasses all gates)
- **A race window** between HTLC parking and irrevocable commitment

### What clients should do

If you're a client sending onchain funds:
- **Wait for the server's HTLC to park** before funding the lockup
- Check `listholdinvoices` (or equivalent) for incoming payment status
- If no HTLC is parked, don't fund — the server hasn't committed

### What operators should know

- The claim privkey + preimage for every swap are stored in the CLN
  datastore (readable via `datastore` RPC)
- Anyone with CLN RPC access can extract a complete sweep kit
- The HSM-split design (issue #36) would move secrets to HSM-derived
  storage — designed, tested, awaiting implementation
- Keep CLN RPC access restricted (runes, network isolation)

### Known limitations (protocol-level)

- The onchain→LN direction's witness script has **no claim-time
  expiry** — the preimage branch is spendable at any height, even
  after the refund branch unlocks. This is a Bitcoin Script
  limitation, not an implementation bug.
- The long-term fix is adaptor signatures / PTLCs (Lightning protocol
  evolution — see issue #40)
- Every submarine swap implementation (electrum, Boltz, ours) shares
  this property

For the complete analysis: `docs/security-analysis-2026-08-30.md`,
`docs/hold-invoice-analysis.md`, `docs/issue-10-electrum-vulnerability-study.md`
