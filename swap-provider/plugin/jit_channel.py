"""JIT channel opener — when no route exists, open one.

LSP model (user insight 2026-08-21): the provider has a huge CLTV window
(70 blocks from swap creation — the user's lockup confirms well before
the invoice must be paid). If `pay` fails with "no route", the provider
can open a channel to the payee node, wait for lockin, and retry.

## Timing proof (the binding constraint)

The JIT channel must be usable before the EARLIER of:
  A) the bolt11 invoice expiry (typically 3600s for onchain_to_ln swaps)
  B) the onchain CLTV (locktime - tip ≈ 70 blocks from creation)

But the payment attempt only STARTS after the user's lockup confirms
(1 conf for the provider to see the preimage-revealing claim). So the
real window for the JIT open is:
    available = min(A, B) - (lockup_confirm_time + first_pay_attempt_time)

On mutinynet (30s blocks): min(3600s, 35min) - (~1min) = ~54min → 18x margin
On signet (5-min blocks): min(3600s, 350min) - (~6min) = ~54min → 18x margin
The 10-min lockin wait is well inside even the worst case.

## Feature gating

Off by default. Enable with `SWAPSERVER_JIT_CHANNEL=<pct>` env or the
`swapserver.jit_channel` plugin option. The value is the extra liquidity
percentage retained on our side after routing the payment:
  unset / 0 = disabled (no behavior change)
  20 = 20% extra retained (a 100k invoice opens a 120k+fee channel)
  50 = 50% extra (more retained for future swaps to the same node)

FUTURE: payer-controlled sizing — the client's swap request may carry
`jit_channel_pct` to request more retained liquidity in exchange for
a higher swap fee (mirroring liquidity-ads negotiation, but reactive
and folded into the swap fee rather than a separate lease payment).

## Channel sizing (the liquidity question)

The channel must be large enough that the payment succeeds through it,
plus retained liquidity for future payments. The sizing has three knobs:

  invoice_amount + fee_buffer    — the minimum to route this payment
  × liquidity_factor            — how much extra to retain (0.2-0.5)
  floored at min_channel        — CLN dust minimum (50k sat)
  capped at max_per_invoice     — wallet-drain guard (10x invoice)

With the default liquidity_factor=0.25, a 20k invoice opens a 50k channel
(floored): 20k routes the payment, 30k stays our side for the next swap.

## Comparison to CLN liquidity ads

Both solve "I need inbound capacity to receive". Key differences:

| | Liquidity ads (BOLT) | Our JIT opener |
|---|---|---|
| Initiator | client requests a lease | provider acts on payment failure |
| Fee model | client pays upfront lease fee | provider absorbs (recovers via swap fees) |
| Timing | pre-arranged | reactive, just-in-time |
| Protocol | requires BOLT #12-adjacent support | zero client changes (any bolt11 wallet) |
| Scope | generic inbound | specifically to complete a pending swap |
| Trust | lease fee is on-chain escrowed | our funds at risk until channel earns back |

"Better" for our use case: zero client cooperation required, works with
any wallet that can make an invoice, self-healing (only fires when a
real payment is stuck). "Different": it's not general-purpose inbound
liquidity — it's a swap-completion mechanism that happens to create
lasting channel capacity as a side effect.

Abuse resistance: the sizing cap + feature gate + the fact that the
JIT-opened channel is OUR outbound means repeated "force a channel open"
attacks cost us only the channel-opening tx fee, and each opened channel
retains value (it's our funds). A per-invoice open is never larger than
10x the invoice amount.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

# ── feature gating ──────────────────────────────────────────────────────
# Env var: SWAPSERVER_JIT_CHANNEL=0|1|2
#   0/unset = disabled
#   1 = enabled, conservative liquidity_factor (0.20)
#   2 = enabled, generous liquidity_factor (0.50)
# Plugin option: swapserver.jit_channel=<same values>


def _jit_pct_from_env() -> float:
    """Parse SWAPSERVER_JIT_CHANNEL as a percentage (e.g. "20" = 20%).

    Valid values: 0 (disabled), or any positive number interpreted as
    the extra liquidity percentage retained on our side after routing
    the payment. "20" means a 100k invoice opens a channel with 20k
    extra retained. Invalid values disable.
    """
    raw = os.environ.get("SWAPSERVER_JIT_CHANNEL", "0")
    try:
        pct = float(raw)
        return pct if pct >= 0 else 0.0
    except (ValueError, TypeError):
        return 0.0


def _jit_pct_from_option(rpc, option_name: str = "swapserver.jit_channel") -> float:
    """Read the plugin option as a percentage. Falls back to 0."""
    try:
        result = rpc.listconfigs(config=option_name)
        config = result.get("#{}#".format(option_name), {})
        raw = config.get("value_str", config.get("value_int", "0"))
        pct = float(raw)
        return pct if pct >= 0 else 0.0
    except Exception:
        return 0.0


def jit_enabled(rpc=None) -> bool:
    """True if JIT channel opening is enabled (pct > 0 from env or option)."""
    return jit_liquidity_factor(rpc) > 0


def jit_liquidity_factor(rpc=None) -> float:
    """The liquidity retention factor as a fraction (e.g. 0.20 for 20%).

    Sources (highest wins):
      - SWAPSERVER_JIT_CHANNEL env (percentage, e.g. "20" or "35.5")
      - swapserver.jit_channel plugin option (same format)
      - 0 = disabled

    FUTURE (payer-controlled): allow the payment request to carry a
    hint of how much extra they'd pay for more liquidity — the swap
    request could include `jit_channel_pct` and the provider would use
    max(operator_setting, client_requested) when sizing the open. This
    mirrors liquidity-ads negotiation but reactive: the client pays via
    the swap fee, not a separate lease.
    """
    return max(_jit_pct_from_env(), _jit_pct_from_option(rpc) if rpc else 0.0) / 100.0


# ── constants ────────────────────────────────────────────────────────────

# routing fee buffer on top of the invoice (covers CLN's fee assessment
# when routing through the new channel; CLN reserves fee headroom on
# the payer side, so the channel needs invoice + routing margin)
JIT_FEE_BUFFER_SAT = 1_000

# Receiver-side floor dominates: electrum payees enforce
# MIN_FUNDING_SAT = 200_000 (lnutil.py) and kill openingd below it
# (live-earned in the regtest JIT live-fire — a 50k open died with
# "openingd died" and the peer dropped). CLN's own floor is lower,
# but the opener must clear the strictest common receiver.
JIT_MIN_CHANNEL_SAT = 200_000

# wallet-drain guard: never open a channel more than 10x the invoice
JIT_MAX_PER_INVOICE = 10

# lockin wait timeout (10 min = generous for both networks)
JIT_LOCKIN_TIMEOUT_S = 600


# ── route-failure detection ─────────────────────────────────────────────

# Exact signatures from CLN pay failures (earned: these are the literal
# strings observed in live runs; do NOT add loose matches that would
# false-positive on temporary failures a retry would fix)
NO_ROUTE_SIGNATURES = [
    "no connection between source and destination",
    "no path found",
    "could not find a route",
    "unable to find a path",
    "no route",
    "There is no connection",
    "Could not find a usable set of paths",
    # xpay 205 when the payee is entirely absent from the gossip map
    # (zero-channel fresh node — live-captured in the regtest JIT
    # live-fire; the classic phrasings don't cover it)
    "Unknown destination node",
    "insufficient capacity for direct",
]


def is_no_route_failure(pay_result) -> bool:
    """True when the payment failed specifically because there's no
    route to the payee — the JIT channel trigger condition."""
    if isinstance(pay_result, dict):
        msg = str(pay_result.get("message", "")) + " " + str(pay_result.get("log", ""))
    else:
        msg = str(pay_result)
    msg_lower = msg.lower()
    return any(sig.lower() in msg_lower for sig in NO_ROUTE_SIGNATURES)


# ── channel sizing ──────────────────────────────────────────────────────

def jit_channel_size(invoice_sat: int, liquidity_factor: float = 0.20) -> int:
    """Right-size the JIT channel for liquidity retention.

    The channel is sized at: invoice + fee_buffer + invoice×liquidity_factor,
    floored at JIT_MIN_CHANNEL_SAT and capped at invoice × JIT_MAX_PER_INVOICE.

    The liquidity_factor is the KEY design choice: it determines how much
    outbound capacity we RETAIN on our side after the payment routes.
    A 20k invoice at factor=0.20 opens a channel with 4k extra; at
    factor=0.50, 10k extra. The extra stays on our side — useful for
    the next swap to the same node without needing another open.
    """
    base = invoice_sat + JIT_FEE_BUFFER_SAT
    with_liquidity = base + int(invoice_sat * liquidity_factor)
    size = max(with_liquidity, JIT_MIN_CHANNEL_SAT)
    return min(size, invoice_sat * JIT_MAX_PER_INVOICE + JIT_FEE_BUFFER_SAT)


# ── safety checks ───────────────────────────────────────────────────────

def sufficient_onchain(amount_sat: int, rpc) -> bool:
    """True if confirmed spendable onchain covers the channel + emergency."""
    try:
        funds = rpc.listfunds()
        spendable = sum(
            o["amount_msat"] // 1000
            for o in funds.get("outputs", [])
            if o.get("status") == "confirmed" and not o.get("reserved")
        )
        # CLN min-emergency-msat is ~25k
        return spendable >= amount_sat + 25_000
    except Exception:
        return False


def has_channel_to(node_id: str, rpc) -> bool:
    """True if we already have any channel (any state) to this node.

    CLN v26 moved channels out of listpeers' per-peer nesting into
    listpeerchannels — read BOTH shapes (live-earned: the nested-only
    read double-opened a JIT channel while the first awaited lockin).
    """
    try:
        for chan in rpc.listpeerchannels().get("channels", []):
            if chan.get("peer_id") == node_id:
                return True
    except Exception:
        pass
    return False


def decode_payee_node(bolt11: str, rpc) -> Optional[str]:
    """Extract the payee node ID from a bolt11 invoice via clnrest decode."""
    try:
        decoded = rpc.decode(bolt11)
        return (
            decoded.get("payee")
            or decoded.get("destination")
            or decoded.get("node_id")
        )
    except Exception as e:
        logger.warning(f"jit: decode payee failed: {e}")
        return None


# ── the JIT open ────────────────────────────────────────────────────────

def open_jit_channel(node_id: str, invoice_sat: int, rpc,
                     liquidity_factor: float = 0.20) -> Optional[dict]:
    """Open a JIT channel to node_id sized for this invoice + retention.

    Returns the fundchannel result dict, or None on failure.
    """
    size = jit_channel_size(invoice_sat, liquidity_factor)
    if not sufficient_onchain(size, rpc):
        logger.warning(f"jit: insufficient onchain for {size}sat channel")
        return None

    try:
        try:
            rpc.connect(node_id)
        except Exception:
            pass  # already connected is fine

        result = rpc.fundchannel(node_id, f"{size}sat")
        logger.info(
            f"jit: opened {size}sat channel to {node_id[:12]}… "
            f"(invoice {invoice_sat}sat + {size - invoice_sat}sat liquidity; "
            f"txid: {result.get('txid', '?')[:12]}…)"
        )
        return result
    except Exception as e:
        logger.warning(f"jit: fundchannel failed: {e}")
        return None


def wait_channel_lockin(node_id: str, rpc,
                        timeout_s: int = JIT_LOCKIN_TIMEOUT_S) -> bool:
    """Wait until any channel to node_id reaches CHANNELD_NORMAL.

    On mutinynet this is 1.5-3 min; on signet 15-30 min. Both are well
    inside the min(invoice_expiry, CLTV) window (see timing proof above).
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            # CLN v26: channels are NOT under listpeers peers — poll the
            # flat listpeerchannels shape (nested-only read polled blind
            # for 600s while the channel was already NORMAL)
            for chan in rpc.listpeerchannels().get("channels", []):
                if chan.get("peer_id") != node_id:
                    continue
                state = chan.get("state")
                if state == "CHANNELD_NORMAL":
                    scid = chan.get("short_channel_id", "?")
                    logger.info(
                        f"jit: channel to {node_id[:12]}… is "
                        f"OPEN (scid {scid})"
                    )
                    return True
                if state in ("CHANNELD_AWAITING_LOCKIN",):
                    logger.debug(
                        f"jit: lockin pending "
                        f"(scid {chan.get('short_channel_id', '?')})"
                    )
        except Exception as e:
            logger.debug(f"jit: poll error: {e}")
        time.sleep(10)
    logger.warning(
        f"jit: channel to {node_id[:12]}… not ready in {timeout_s}s"
    )
    return False
