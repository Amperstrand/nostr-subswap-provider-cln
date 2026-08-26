"""Traffic attribution (audit round 8, issue #24 operator directive:
"allow strangers to swap on signet — varied random testing is NICE —
but we need monitoring to distinguish our own testing from strangers'").

OBSERVABILITY ONLY, the same contract as health.py: this module never
acts, never gates, never rejects. Strangers are welcome traffic; the
attribution layer exists so the operator can tell the lab's own test
clients from third-party swappers when reading logs, swapprovider-health
and the new swapprovider-swaps RPC.

Signals (cheap+true, in order of trust):
1. The nostr DM envelope's signer pubkey — the transport sets it AFTER
   decryption (a client-supplied requester field in the payload is
   always overridden), so every swap request is attributable to the
   key that actually sent it. Recorded into the swap record as
   `requester_npub` at creation (persisted, additive field).
2. The TEST_NPUBS registry (env, comma list of npub… or 64-hex
   pubkeys of OUR OWN test clients) — classification is EXPLICIT
   registration only. A refund-pubkey pattern heuristic was considered
   and rejected (the e2e-37 test client used a deterministic test
   pattern key, but heuristics misclassify strangers as ours — the
   registry is the honest signal).

Classes: 'ours' (requester npub is registered) | 'stranger' (npub
known but not registered — their npub is visible to the operator,
fine on signet) | 'unknown' (no npub on the record: pre-r8 records,
or a request path with no DM envelope).

The e2e-37 §4 manual-unwedge would have been trivial with this: the
swap record would have carried requester_npub and the operator could
have told the lab's own test client from ambient strangers instantly.
"""
import threading
import time
from typing import Optional

# attribution labels — also the counter keys and the RPC `attributed`
# values; keep in sync with tests/test_attribution.py
OURS = "ours"
STRANGER = "stranger"
UNKNOWN = "unknown"
LABELS = (OURS, STRANGER, UNKNOWN)


def normalize_npub(value) -> Optional[str]:
    """Accept a 64-hex-char x-only pubkey or an npub (NIP-19) and
    return the 64-hex form (the DM envelope's event_pubkey is hex).
    Anything else -> None (never raises: a junk TEST_NPUBS entry must
    not take config loading down)."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    if value.startswith("npub1"):
        try:
            from electrum_aionostr.util import from_nip19
            return from_nip19(value)["object"].hex()
        except Exception:
            return None
    if len(value) == 64:
        try:
            int(value, 16)
        except ValueError:
            return None
        return value.lower()
    return None


def parse_test_npubs(raw) -> tuple:
    """Parse the TEST_NPUBS comma list into a tuple of normalized hex
    pubkeys. Invalid entries are dropped (the caller logs the count);
    absent/empty -> () — honest: every requester then reads stranger."""
    if not isinstance(raw, str) or not raw.strip():
        return ()
    out = []
    for item in raw.split(","):
        normalized = normalize_npub(item)
        if normalized is not None:
            out.append(normalized)
    # tuple: stable for tests, hashable, config-str friendly
    return tuple(dict.fromkeys(out))  # dedupe, keep order


def classify_requester(npub_hex, test_npubs) -> str:
    """ours | stranger | unknown — pure set membership, no heuristics
    (the registry is the only 'ours' signal, per the r8 design)."""
    if not npub_hex:
        return UNKNOWN
    normalized = normalize_npub(npub_hex)
    if normalized is None:
        return UNKNOWN
    return OURS if normalized in set(test_npubs or ()) else STRANGER


class AttributionTracker:
    """Thread-safe since-boot swap-REQUEST counters per attribution
    label. Requests are counted at DM dispatch (asyncio thread); the
    snapshot is read from the pyln RPC thread — hence the lock, the
    HealthTracker pattern. Swap RECORDS get deleted on completion, so
    live-record counting alone would undercount strangers; this counter
    survives record cleanup (boot-scoped, nothing persisted)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counts = {label: 0 for label in LABELS}

    def note_request(self, label: str) -> None:
        with self._lock:
            self._counts[label] = self._counts.get(label, 0) + 1

    def reset(self) -> None:
        """Test hook."""
        with self._lock:
            self._counts = {label: 0 for label in LABELS}

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._counts)


attribution_tracker = AttributionTracker()


def _swap_state(swap, sm) -> str:
    """Honest state string derived from the record + live bookkeeping
    (read-only, memory-only checks — no RPCs, same rule as health)."""
    key = swap.payment_hash.hex() if swap._payment_hash else None
    if swap.is_redeemed:
        return "redeemed"
    if key is not None and key in getattr(sm, "invoices_awaiting_funding", set()):
        return "awaiting_lockup"  # parked by the #12/#24-E funding gate
    if key is not None and key in getattr(sm, "invoices_to_pay", {}):
        return "paying"
    if swap.spending_txid is not None:
        return "claimed"
    if swap.funding_txid is not None:
        return "funded"
    return "created"


def describe_swap(swap, sm, test_npubs) -> dict:
    """One swapprovider-swaps row. The requester's npub is included
    verbatim (hex) — operator-visible by design (signet); 'attributed'
    is the classification against the registry."""
    label = classify_requester(swap.requester_npub, test_npubs)
    created_at = getattr(swap, "created_at", None)
    return {
        "payment_hash": swap._payment_hash,
        # house direction names (AGENTS.md table): is_reverse=True =
        # onchain_to_ln (client funds lockup, receives LN)
        "direction": "onchain_to_ln" if swap.is_reverse else "ln_to_onchain",
        "state": _swap_state(swap, sm),
        "requester_npub": swap.requester_npub,
        "attributed": label,
        "onchain_amount": swap.onchain_amount,
        "age_sec": None if created_at is None else round(time.time() - created_at),
    }


def list_recent_swaps(provider, limit=None) -> dict:
    """The swapprovider-swaps RPC body: newest swaps first (by
    created_at; pre-r8 records without one sort last, oldest-first
    among themselves), `limit` capped at 100, default 20."""
    sm = getattr(provider, "swap_manager", None)
    if sm is None:
        return {"swaps": [], "count": 0,
                "note": "swap manager not initialized"}
    test_npubs = getattr(getattr(provider, "config", None), "test_npubs", ()) or ()
    swaps = list(getattr(sm, "swaps", {}).values())
    swaps.sort(key=lambda s: getattr(s, "created_at", None) or 0, reverse=True)
    if limit is None:
        limit = 20
    try:
        limit = max(0, min(int(limit), 100))
    except (TypeError, ValueError):
        limit = 20
    rows = [describe_swap(s, sm, test_npubs) for s in swaps[:limit]]
    counts = {label: 0 for label in LABELS}
    for s in swaps:
        counts[classify_requester(s.requester_npub, test_npubs)] += 1
    return {
        "swaps": rows,
        "count": len(rows),
        "total_live": len(swaps),
        "attributed_live": counts,
        "test_npubs_registered": len(test_npubs),
    }


def attribution_health_section(provider) -> dict:
    """The `attribution` block of swapprovider-health: registry size,
    since-boot request counters, live-record counts per label. Every
    part optional (pre-init the RPC must answer honestly)."""
    sm = getattr(provider, "swap_manager", None)
    test_npubs = getattr(getattr(provider, "config", None), "test_npubs", ()) or ()
    live = {label: 0 for label in LABELS}
    if sm is not None:
        for s in list(getattr(sm, "swaps", {}).values()):
            live[classify_requester(s.requester_npub, test_npubs)] += 1
    return {
        "test_npubs_registered": len(test_npubs) if sm is not None else None,
        "requests_since_boot": attribution_tracker.snapshot(),
        "live_swaps": live if sm is not None else None,
    }
