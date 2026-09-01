# Issue #8 research: zero-conf JIT channels

**Status:** research delivered 2026-09-02 (web-verified, sources inline).
**Recommendation: GO-WITH-CONSTRAINTS — signet/mutinynet/regtest only,
never an unrestricted mainnet default.**

## 1. LSPS2 status and implementations

LSPS2 is **not a BOLT**. It is an LSP working-group spec, published as
**bLIP-52** (status *Active*); the older LSP-spec repo labeled LSPS2
"For Implementation" and was archived January 2025. Transport is
JSON-RPC over BOLT 8 (LSPS0).

- bLIP-52: https://github.com/lightning/blips/blob/master/blip-0052.md
- LSPS2 readme: https://github.com/BitcoinAndLightningLayerSpecs/lsp/blob/main/LSPS2/README.md

Reference implementation: LDK's `lightning-liquidity` crate (client +
service handlers) — https://docs.rs/lightning-liquidity

**CLN:** PR #8569 merged 2025-11-13 adds *experimental, no-MPP,
"LSP trusts client"* LSPS2 support (MPP, client-trusts-LSP mode, broad
validation and integration tests explicitly still missing).
https://github.com/ElementsProject/lightning/pull/8569 — evidence of
in-tree work, NOT a stable release feature. Blockstream's `cln-lsps`
implements LSPS0/1 only and was archived 2025-10-14.

Claims that Eclair/LND/ZEUS-Olympus/Alby Hub support LSPS2 *specifically*
are unverified — several run proprietary JIT flows instead.

## 2. CLN zero-conf support

Supported since **v0.12.0** (2022-08), described as high-trust /
LSP-oriented, peers should be whitelisted:
https://blog.blockstream.com/core-lightning-v0-12-0/

Mechanisms (current docs):
- `fundchannel ... mindepth=0` — usable without confirmation
- `channel_type` with `option_zeroconf` (bit 50) + `option_scid_alias` (bit 46)
- the `openchannel` hook can return `mindepth=0`
- CLN warns: low mindepth exposes the node to double-spending unless the
  peer is trusted or forwards are rejected until confirmation
- `--dev-fast-gossip` is NOT the mechanism (gossip timing only)

Sources: https://docs.corelightning.org/reference/fundchannel ,
https://docs.corelightning.org/reference/hook-openchannel ,
https://docs.corelightning.org/reference/openchannel_init

## 3. The attack and the real mitigations

Classic: LSP accepts an unconfirmed funding tx, client spends the new
channel balance, funding is RBF-replaced → LSP loses the full channel
amount while the client's Lightning spend may already be irreversible.

Mitigations, honest ranking:
1. **Trust restriction / allowlist** — CLN's own recommendation; the only
   complete one.
2. **RBF policy** — avoid accepting replaceable funding where enforceable;
   reduces but does not eliminate risk.
3. **SCID aliases** — solve identification/gossip, NOT double-spending.
4. **Min-depth docking** — create now, enable meaningful forwards after
   confirmation; defeats the purpose for the first payment.
5. **Script-enforced / third-party funding** (Lightning Pool co-signing)
   — stronger, not available to a normal CLN wallet-funded open.
   https://docs.lightning.engineering/lightning-network-tools/pool/zero-confirmation-channels

LSPS2 itself documents the two-party deadlock (LSP withholds funding
until preimage; client withholds preimage until funding) — an additional
trust assumption is required.

## 4. Electrum support

Real and recent: **PR #10463 merged 2026-04-28** (spesmilo/electrum) —
JIT channel opening, trusted-peer handling, funding-tx validation,
failure cleanup, fee sanity (rejects fees >10% of channel size),
deterministic remote SCID aliases, zeroconf signaling stopped to
untrusted peers. This is Electrum-specific JIT, **not LSPS2** (earlier
work, PR #8671, explicitly diverged).

## 5. Precedent

Verified: LND/Lightning Pool (third-party co-signing, anchor channels).
Voltage Flow 2.0 describes zero-conf + preimage-hash flows but without
verifiable anti-double-spend detail. Olympus/ZEUS, Alby Hub, Blockstream
Green: no authoritative current evidence of LSPS2-compatible zero-conf
JIT — treat as unverified.

## Risk model for THIS plugin

We are the LSP/funder. Loss = the full unconfirmed channel amount per
attacker, plus open-then-abandon DoS. Route hints, SCID aliases, nostr
identity, payment hashes do NOT make the funding final.

## GO-WITH-CONSTRAINTS (test networks first)

All of: allowlisted Electrum peers only; explicit `option_zeroconf` +
`option_scid_alias`; per-client and global exposure caps; reject
RBF-signaling funding inputs where enforceable; only the single bounded
swap flow through the channel (no arbitrary forwards); funding-tx
verification (script/amount/mempool acceptance); configurable min-depth
docking; fail-closed on disconnect/funding-failure/timeout;
persist+reconcile pending channels across restart; require the Electrum
2026 JIT client behavior; instrument replacement/dropped-funding/
duplicate-open/non-cooperation/restart-race tests.

For production the preferred target is **one-confirmation JIT**; zero-conf
stays an explicitly priced, capped trust feature. This aligns with the
existing `jit_channel.py` stub: `SWAPSERVER_JIT_CHANNEL` already opens
AFTER a payment failure ("no route") — i.e. post-hoc liquidity repair —
which does not carry the zero-conf risk at all. Zero-conf would be a new,
separate opt-in lane.
