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
import asyncio
import time
from typing import Optional, Type

import httpx

from . import constants
from .constants import AbstractNet

# sat/vB sanity clamps — outside this the oracle is lying or broken
_MIN_SAT_VB = 1
_MAX_SAT_VB = 300
_CACHE_TTL_SEC = 300
# on-loop refresh respawn backoff (a dead endpoint would otherwise get
# one new task per fee call)
_REFRESH_BACKOFF_SEC = 10.0

_cache: dict = {}  # url -> (fetched_at_monotonic, sat_vb)
_last_refresh_attempt: dict = {}


def default_oracle_url(net: Type[AbstractNet]) -> Optional[str]:
    name = getattr(net, "NET_NAME", None)
    if name == "mainnet":
        return "https://mempool.space/api"
    if name == "signet":
        return "https://mempool.space/signet/api"
    if name == "mutinynet":
        return "https://mutinynet.com/api"
    return None  # regtest/testnet4: no public oracle, CLN/fallback only


def _fetch_uncached(base_url: str, timeout: float) -> Optional[float]:
    try:
        resp = httpx.get(f"{base_url.rstrip('/')}/v1/fees/recommended",
                         timeout=timeout)
        resp.raise_for_status()
        sat_vb = float(resp.json()["halfHourFee"])
    except Exception:
        return None
    if not (_MIN_SAT_VB <= sat_vb <= _MAX_SAT_VB):
        return None
    return sat_vb


async def _refresh_cache(base_url: str, timeout: float) -> None:
    """Async fetch (httpx.AsyncClient — never blocks the event loop)."""
    sat_vb = None
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                f"{base_url.rstrip('/')}/v1/fees/recommended")
            resp.raise_for_status()
            sat_vb = float(resp.json()["halfHourFee"])
    except Exception:
        sat_vb = None
    if sat_vb is not None and _MIN_SAT_VB <= sat_vb <= _MAX_SAT_VB:
        _cache[base_url] = (time.monotonic(), sat_vb)


def fetch_fee_sat_vb(base_url: str, *, timeout: float = 5.0) -> Optional[float]:
    """halfHourFee from a mempool.space-compatible API, cached 5 min.

    Returns None on ANY failure — callers fall back, never block.

    C3 (security review 2026-08-31): when invoked ON the event loop
    (claims, prepay pricing, offers), a direct sync httpx.get stalled
    the WHOLE plugin for up to `timeout` per cache miss. On-loop calls
    now serve stale-while-revalidate: the cache hit returns
    immediately (even past TTL), a single background task refreshes,
    and a cold cache returns None this once (the caller's fail-open
    path — CLN estimate or fallback — prices the fee; correctness is
    unchanged per O4). Off-loop callers keep the blocking fetch."""
    now = time.monotonic()
    hit = _cache.get(base_url)
    if hit is not None and now - hit[0] < _CACHE_TTL_SEC:
        return hit[1]
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None:
        last_attempt = _last_refresh_attempt.get(base_url, 0.0)
        if now - last_attempt >= _REFRESH_BACKOFF_SEC:
            _last_refresh_attempt[base_url] = now
            loop.create_task(_refresh_cache(base_url, timeout))
        if hit is not None:
            return hit[1]  # stale but immediate; refresh in flight
        return None  # cold: caller's fail-open prices this round
    sat_vb = _fetch_uncached(base_url, timeout)
    if sat_vb is not None:
        _cache[base_url] = (now, sat_vb)
    return sat_vb


def configured_oracle_url(config) -> Optional[str]:
    """FEE_ORACLE_URL env pin, else network default, else None."""
    url = getattr(config, "fee_oracle_url", None)
    if url:
        return url
    return default_oracle_url(constants.net)
