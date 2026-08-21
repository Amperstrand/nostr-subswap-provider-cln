"""JIT channel opener — when no route exists, open one.

LSP model (user insight 2026-08-21): the provider has a huge CLTV window
(70 blocks from swap creation — the user's lockup confirms well before
the invoice must be paid). If `pay` fails with "no route", the provider
can open a channel to the payee node, wait for lockin, and retry.

Timing on each network:
  mutinynet (30s blocks): 35 min window, 1.5-3 min lockin → 10x margin
  signet (5 min blocks): 5.8 hr window, 15-30 min lockin → 10x margin
  regtest: instant (mine blocks)

Safety:
  - only opens when the failure is specifically "no route to payee"
  - checks existing channels first (don't duplicate)
  - caps the channel size (invoice_amount + buffer, not the provider's whole wallet)
  - falls through to normal retry if the open fails
"""
from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

# cap: don't open a channel larger than 10x the invoice (dust protection
# and wallet-drain guard); don't open smaller than 50k (CLN minimum dust)
JIT_MAX_MULTIPLE = 10
JIT_MIN_CHANNEL_SAT = 50_000
# fee buffer on top of the invoice amount for routing fees
JIT_FEE_BUFFER_SAT = 1_000

# route-failure signatures from CLN's pay result (earned: exact strings
# from live failures — do not regex loosely, we don't want false positives
# on temporary failures that a retry would fix)
NO_ROUTE_SIGNATURES = [
    "no connection between source and destination",
    "no path found",
    "could not find a route",
    "unable to find a path",
    "no route",
    "There is no connection",
    "Could not find a usable set of paths",
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


def decode_payee_node(bolt11: str, rpc) -> Optional[str]:
    """Extract the payee node ID from a bolt11 invoice via clnrest decode."""
    try:
        decoded = rpc.decode(bolt11)
        # cln decode returns the payee in different fields depending on version
        return (
            decoded.get("payee")
            or decoded.get("destination")
            or decoded.get("node_id")
        )
    except Exception as e:
        logger.warning(f"jit: decode payee failed: {e}")
        return None


def has_channel_to(node_id: str, rpc) -> bool:
    """True if we already have any channel (any state) to this node."""
    try:
        peers = rpc.listpeers(node_id)
        for peer in peers.get("peers", []):
            if peer.get("id") == node_id and peer.get("channels"):
                return True
    except Exception:
        pass
    return False


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


def jit_channel_size(invoice_sat: int) -> int:
    """Right-size the channel: covers the invoice + fees, not the wallet."""
    size = max(invoice_sat + JIT_FEE_BUFFER_SAT, JIT_MIN_CHANNEL_SAT)
    return min(size, invoice_sat * JIT_MAX_MULTIPLE)


def open_jit_channel(node_id: str, invoice_sat: int, rpc) -> Optional[dict]:
    """Open a JIT channel to node_id sized for this invoice.

    Returns the fundchannel result dict, or None on failure.
    The caller should wait for lockin then retry the payment.
    """
    size = jit_channel_size(invoice_sat)
    if not sufficient_onchain(size, rpc):
        logger.warning(f"jit: insufficient onchain for {size}sat channel")
        return None

    try:
        # connect first (fundchannel auto-connects but explicit is safer)
        try:
            rpc.connect(node_id)
        except Exception:
            pass  # already connected is fine

        result = rpc.fundchannel(node_id, f"{size}sat")
        logger.info(
            f"jit: opened {size}sat channel to {node_id[:12]}… "
            f"(txid: {result.get('txid', '?')[:12]}…)"
        )
        return result
    except Exception as e:
        logger.warning(f"jit: fundchannel failed: {e}")
        return None


def wait_channel_lockin(node_id: str, rpc, timeout_s: int = 600) -> bool:
    """Wait until any channel to node_id reaches CHANNELD_NORMAL.

    On mutinynet this is 1.5-3 min; on signet 15-30 min. The CLTV
    window (70 blocks) provides the margin.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            peers = rpc.listpeers(node_id)
            for peer in peers.get("peers", []):
                if peer.get("id") != node_id:
                    continue
                for chan in peer.get("channels") or []:
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
