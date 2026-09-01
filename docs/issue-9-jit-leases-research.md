# Issue #9 research: JIT channel leases / liquidity-ads-style commitments

**Status:** research delivered 2026-09-02 (web-verified, sources inline).
**Recommendation: GO-WITH-CONSTRAINTS for prototyping; NO-GO as a
prerequisite of the current Electrum-protocol swap flow.**

## 1. Spec status

Liquidity ads began as **BOLT #878 "option_will_fund"** (dual-funding
liquidity purchase with a timelocked lease concept) — still a draft
design discussion, not a ratified BOLT. https://github.com/lightning/bolts/pull/878

**BOLT #1145** ("Advertise liquidity ads rates") was closed in favor of
**#1153 ("Extensible Liquidity Ads")**, whose current direction explicitly
AVOIDS mandatory script-enforced lease duration — enforcement is
economic/reputational (sellers may close or splice out early; buyers
blacklist). https://github.com/lightning/bolts/pull/1145 ,
https://github.com/lightning/bolts/pull/1153

Consequence: the "on-chain lease output with CSV/CLTV enforcement" is an
older/proposed design — do NOT assume it from current CLN liquidity ads.

## 2. CLN shipped mechanics

Dual funding since v0.10.0; `funder` plugin policy + lease rates since
v0.10.1 (https://blog.blockstream.com/setting-up-liquidity-ads-in-c-lightning/).
Still documented as experimental. RPC surface: `openchannel_init` with
`request_amt` + `compact_lease`, PSBT rounds via `openchannel_update` /
`openchannel_signed`; `fundchannel` exposes the same lease params;
hooks `openchannel2` (seller side accept/reject/contribute).
https://docs.corelightning.org/reference/openchannel_init etc.

Standard lease: ~4,032 blocks (~4 weeks); buyer pays flat upfront fee +
proportional fee + funding-weight compensation (`lease_fee_base_sat`,
`lease_fee_basis`, `funding_weight`).

## 3. Can a plugin drive a leased open?

Technically yes (openchannel_init → update → signed, or fundchannel
params). Operationally sensitive: dual-fund + liquidity ads remain
version/policy-sensitive; **`openchannel_bump` on a leased channel loses
the lease** (https://docs.corelightning.org/reference/openchannel_bump).
Maturity: dual funding v0.10-era experimental; splicing experimental
v24.11 → **default-on v26.04**.

## 4. Electrum compatibility

Electrum's swap protocol negotiates NO liquidity ads / dual-funding /
lease rates. Alignment would need a channel-provisioning phase BEFORE
the swap (LSPS2-shaped), which is not wire-compatible with the current
Electrum swap messages — client changes or a provider-side extension
would be required.

## 5. Alternatives ranked for "JIT opens retain capacity"

1. **Splicing** (v26.04 default-on): splice-in to replenish existing
   channel capacity without close — strongest native mechanism, needs
   peer/protocol cooperation Electrum doesn't have yet.
2. **SCID-alias zeroconf JIT**: startup latency + discoverability, but
   no capacity retention (see issue #8 doc).
3. **Routing-fee policy on JIT channels** (`setchannel`/`setchannelfee`):
   trivially deployable, recovers capital statistically — but no
   commitment from the client, so not a lease.

## Fit for this plugin

- Treat CLN liquidity ads as a **CLN↔CLN provisioning feature**, not an
  Electrum swap feature (our JIT clients are electrum wallets).
- Never claim cryptographically-enforced lease retention from current
  liquidity ads — #1153 explicitly dropped that.
- Keep swap safety independent of any lease: a lease failure must never
  strand or partially settle a swap.
- Long-term retention mechanism: splicing, once client interop exists.
- If we ever want paid inbound provisioning for electrum clients, the
  alignment target is LSPS2 (or a provider-specific phase), not BOLT #878.

The existing `jit_channel.py` (post-"no route" repair opens with a
liquidity factor) already captures the practical 80%: capacity is
repaired when routing fails, priced implicitly by swap fees — no lease
contract needed for the current traffic profile.
