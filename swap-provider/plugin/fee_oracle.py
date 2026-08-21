"""Mempool-style feerate oracle (AGENTS.md O4).

Live-observed motivation (2026-08-21): on signet, CLN's `feerates` returns
empty estimates (signet fee estimation is garbage), so every claim priced
at FALLBACK_FEE_SATVB=60 sat/vB while median signet blocks paid 0-6
sat/vB — the same disease that priced a 222-vB claim at 4400 sats on the
electrum provider (fixed on-box there by pinning fee_policy.swaps to
mempool.space halfHourFee; playground ffb4687).

Priority in get_chain_fee: CLN estimate > oracle > static fallback.
The oracle is fail-open: any error, timeout, or out-of-range value falls
back — it must never block a claim (R3: don't sit on confirmed lockups).
"""
import time
from typing import Optional, Type

import httpx

from . import constants
from .constants import AbstractNet

# sat/vB sanity clamps — outside this the oracle is lying or broken
_MIN_SAT_VB = 1
_MAX_SAT_VB = 300
_CACHE_TTL_SEC = 300

_cache: dict = {}  # url -> (fetched_at_monotonic, sat_vb)


def default_oracle_url(net: Type[AbstractNet]) -> Optional[str]:
    name = getattr(net, "NET_NAME", None)
    if name == "mainnet":
        return "https://mempool.space/api"
    if name == "signet":
        return "https://mempool.space/signet/api"
    if name == "mutinynet":
        return "https://mutinynet.com/api"
    return None  # regtest/testnet4: no public oracle, CLN/fallback only


def fetch_fee_sat_vb(base_url: str, *, timeout: float = 5.0) -> Optional[float]:
    """halfHourFee from a mempool.space-compatible API, cached 5 min.

    Returns None on ANY failure — callers fall back, never block."""
    now = time.monotonic()
    hit = _cache.get(base_url)
    if hit is not None and now - hit[0] < _CACHE_TTL_SEC:
        return hit[1]
    try:
        resp = httpx.get(f"{base_url.rstrip('/')}/v1/fees/recommended",
                         timeout=timeout)
        resp.raise_for_status()
        sat_vb = float(resp.json()["halfHourFee"])
    except Exception:
        return None
    if not (_MIN_SAT_VB <= sat_vb <= _MAX_SAT_VB):
        return None
    _cache[base_url] = (now, sat_vb)
    return sat_vb


def configured_oracle_url(config) -> Optional[str]:
    """FEE_ORACLE_URL env pin, else network default, else None."""
    url = getattr(config, "fee_oracle_url", None)
    if url:
        return url
    return default_oracle_url(constants.net)
