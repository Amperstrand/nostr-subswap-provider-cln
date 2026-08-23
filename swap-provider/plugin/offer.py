"""Offer wire-format for the electrum swapserver nostr announcement.

Pure module — no pyln, no relays, no wallet: this is the import seam the
M2 port tests pin (PORT-NOTES.md). Format is electrum 4.8.1's publish_offer
(spesmilo/electrum submarine_swaps.py, NOSTR_EVENT_VERSION = 5) exactly;
the archived plugin's 2025 format (no pow_nonce, pre-versioning d-tag) is
rejected by every current client — that gap is why this module exists.
"""
from __future__ import annotations

import hashlib
import json
import time

# electrum submarine_swaps.NostrTransport constants (4.8.1)
NOSTR_EVENT_VERSION = 5
STATUS_NIP38 = 30315
OFFER_UPDATE_INTERVAL_SEC = 60 * 10
# electrum ignores offers whose expiration is in the past when scanning
OFFER_EXPIRY_MARGIN_SEC = 10


def nostr_ann_pow_bits(pubkey_xonly_hex: str, nonce: int) -> int:
    """Electrum's announcement PoW: leading zero bits of
    sha256(b"electrum-" || pubkey_xonly(32B) || nonce_be32).
    Matches electrum.util.get_nostr_ann_pow_amount byte-for-byte
    (cross-checked against the sibling checkout's vectors)."""
    pre = b"electrum-" + bytes.fromhex(pubkey_xonly_hex) + nonce.to_bytes(32, "big")
    digest = hashlib.sha256(pre).digest()
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


def mine_ann_pow_nonce(pubkey_xonly_hex: str, target_bits: int,
                       start: int = 0, deadline_s: float | None = None) -> int | None:
    """Best-effort in-process miner — tests use low targets (<=20 bits);
    production targets (30) come from ../nostr-pow-bench (rust ~90s/core,
    cuda ~1s) and are pinned via config like electrum's ann_pow_nonce."""
    if deadline_s is not None:
        stop_at = time.monotonic() + deadline_s
    for nonce in range(start, 1 << 62):
        if deadline_s is not None and nonce % 4096 == 0 and time.monotonic() > stop_at:
            return None
        if nostr_ann_pow_bits(pubkey_xonly_hex, nonce) >= target_bits:
            return nonce
    return None


def build_offer_content(*, percentage_fee: float, mining_fee_sat: int,
                        min_amount_sat: int, max_forward_sat: int,
                        max_reverse_sat: int, relays_csv: str,
                        pow_nonce: int,
                        jit_channel_pct: float = 0.0,
                        server_version: str = '') -> str:
    """Content JSON exactly as electrum 4.8.1 publishes it (percentage_fee
    is kept as float for <=4.7.1 client compat — same reasoning upstream).
    pow_nonce is hex-encoded, matching electrum's hex(sm.config.…).

    jit_channel_pct: optional LSP capability advertisement (the
    SWAPSERVER_JIT_CHANNEL liquidity percentage). Emitted ONLY when > 0
    so non-JIT providers keep byte-identical offers. Safe on the wire:
    electrum's announcement parser reads only its known keys and
    ignores extras (verified in 4.8.1 source, submarine_swaps.py
    _offers parsing).

    server_version: self-identification for OUR deployments (e.g.
    'cln-subswap/v0.3.0-12ab'); absent on stock electrum and third
    parties, so bridge-side fingerprinting can tell ours from theirs
    without a key registry."""
    offer = {
        "percentage_fee": float(percentage_fee),
        "mining_fee": int(mining_fee_sat),
        "min_amount": int(min_amount_sat),
        "max_forward_amount": int(max_forward_sat),
        "max_reverse_amount": int(max_reverse_sat),
        "relays": relays_csv,
        "pow_nonce": hex(int(pow_nonce)),
    }
    if server_version:
        offer["server_version"] = server_version
    if jit_channel_pct and jit_channel_pct > 0:
        offer["jit_channel_pct"] = float(jit_channel_pct)
    return json.dumps(offer)


def build_offer_tags(net_name: str, now: int | None = None) -> list[list[str]]:
    """d/r/expiration tags exactly as electrum 4.8.1 builds them. The
    single-letter 'r' tag is relay-indexable (network filtering)."""
    ts = int(time.time()) if now is None else now
    return [
        ["d", f"electrum-swapserver-{NOSTR_EVENT_VERSION}"],
        ["r", f"net:{net_name}"],
        ["expiration", str(ts + OFFER_UPDATE_INTERVAL_SEC + OFFER_EXPIRY_MARGIN_SEC)],
    ]
