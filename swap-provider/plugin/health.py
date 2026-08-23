"""Heartbeat/liveness tracker (audit round 5, issues #20/#21/#23 —
audit R2 + F12): per-subsystem last-alive timestamps, consecutive-error
counters and the swapprovider-health report.

OBSERVABILITY only: the r4 death policies (utils.fatal_exit, the
supervised taskgroup escalation, the nostr withdrawal) remain the ACTION
half — this module never acts, it just makes the state a monitor can
read every 30s via `lightning-cli swapprovider-health`.

Beat sites piggyback the existing cycle points (no new polling loops):
chain-monitor beats once per monitoring_loop pass (10s), payment-loop
once per pay_pending_ln_invoices pass (5s), nostr-consumer on every
event the DM generator yields, offer-publisher on every publish attempt
(success or withdrawal — a failed attempt is still a live publisher
pass), pyln-plugin-thread on every watchdog check (30s).

Module-level singleton on purpose (the globals.get_plugin_logger
pattern): the subsystems that must beat are constructed by different
collaborators (SwapManager, ChainMonitor, NostrTransport) and several
are rebuilt on restart (the nostr transport) — a tracker that lives
inside any one of them would lose history exactly when that subsystem
dies, which is the moment it matters.
"""
import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

# heartbeat specs: how stale a beat may get before it means something.
# chain-monitor and payment-loop are tight fixed-period loops — a beat
# past dead_after means the loop is WEDGED (the r4 fatal policy should
# have exited us already; if we are still serving, the RPC says dead).
# offer-publisher has a legitimate 600s announce cadence (10s while
# withdrawn/retrying), so it only ever degrades, never reads dead.
# nostr-consumer is event-driven — a quiet relay can legitimately yield
# nothing for hours, so its verdict comes from the transport state
# (nostr mode up/down), not from beat recency.
SPECS = {
    "chain-monitor": {"period_sec": 10, "stale_after_sec": 45, "dead_after_sec": 90},
    "payment-loop": {"period_sec": 5, "stale_after_sec": 30, "dead_after_sec": 60},
    "offer-publisher": {"period_sec": 600, "stale_after_sec": 750, "dead_after_sec": None},
    "nostr-consumer": {"period_sec": None, "stale_after_sec": None, "dead_after_sec": None},
    "pyln-plugin-thread": {"period_sec": 30, "stale_after_sec": None, "dead_after_sec": None},
}
SUBSYSTEMS = list(SPECS)

# a subsystem that has not beaten yet is "starting", not dead, for this
# long after boot — the RPC must stay honest during plugin init
STARTUP_GRACE_SEC = 90
# a hold invoice closer than this to its expiry counts as expiring-soon
EXPIRING_SOON_SEC = 300

PYLN_THREAD = "pyln-plugin-thread"
NOSTR_CONSUMER = "nostr-consumer"
OFFER_PUBLISHER = "offer-publisher"
CHAIN_MONITOR = "chain-monitor"
PAYMENT_LOOP = "payment-loop"


class HealthTracker:
    """Thread-safe last-alive/error-streak state for every subsystem.

    Beats arrive from asyncio tasks and (for the RPC snapshot) are read
    from the pyln plugin thread — hence the lock. Everything here is
    in-memory observability state; nothing persists, nothing acts."""

    def __init__(self):
        self._lock = threading.Lock()
        self.boot_monotonic = time.monotonic()
        self.boot_wall = datetime.now(timezone.utc)
        # same self-ID the nostr offer carries (baked at image build)
        self.version = os.environ.get("SWAP_PROVIDER_VERSION", "cln-subswap/dev")
        self._beats = {}  # subsystem -> time.monotonic() of last beat
        self._details = {}  # subsystem -> last detail str
        self._error_streaks = defaultdict(int)  # F12: consecutive errors
        # "up" (transport connected) | "down" (withdrawn, restarting) |
        # "never-connected" (boot state) — mirrors r4's withdrawal mode
        self._nostr_mode = "never-connected"
        self._nostr_reason = ""

    def beat(self, subsystem: str, detail: str = None) -> None:
        with self._lock:
            self._beats[subsystem] = time.monotonic()
            if detail is not None:
                self._details[subsystem] = detail

    def note_error(self, subsystem: str, detail: str = None) -> None:
        """F12 (visibility only): count consecutive errors per
        subsystem; note_success resets. No rate-limiting here."""
        with self._lock:
            self._error_streaks[subsystem] += 1
            if detail is not None:
                self._details[subsystem] = detail

    def note_success(self, subsystem: str) -> None:
        with self._lock:
            self._error_streaks[subsystem] = 0

    def note_nostr_up(self) -> None:
        with self._lock:
            self._nostr_mode = "up"
            self._nostr_reason = ""

    def note_nostr_down(self, reason: str) -> None:
        """Called at the exact r4 withdrawal sites — the tracker only
        MIRRORS the withdrawal, it never triggers it."""
        with self._lock:
            self._nostr_mode = "down"
            self._nostr_reason = reason

    @property
    def nostr_mode(self) -> str:
        with self._lock:
            return self._nostr_mode

    def _age_ms(self, subsystem, now_mono):
        with self._lock:
            ts = self._beats.get(subsystem)
        if ts is None:
            return None
        return int((now_mono - ts) * 1000)

    def reset(self) -> None:
        """Test hook: clear beats/streaks/mode (boot anchors stay)."""
        with self._lock:
            self._beats.clear()
            self._details.clear()
            self._error_streaks.clear()
            self._nostr_mode = "never-connected"
            self._nostr_reason = ""


tracker = HealthTracker()


def _fmt_age(seconds: float) -> str:
    return f"{seconds:.0f}s"


def _pyln_thread_alive(provider):
    handler = getattr(provider, "plugin_handler", None)
    probe = getattr(handler, "thread_alive", None)
    if probe is None:
        return None  # no live probe available (stub/early boot) — use the beat
    return probe()


def _grace_held_count(sm):
    """Swaps currently held by the #10 grace policy: announced held,
    not yet released (swept / commitment arrived / record gone).
    Memory-only checks — the health snapshot must not issue RPCs."""
    held = 0
    lnworker = getattr(sm, "lnworker", None)
    for key, swap in list(getattr(sm, "swaps", {}).items()):
        if swap.is_redeemed or swap.funding_txid is None:
            continue
        if key not in sm._grace_hold_logged or key in sm._grace_release_logged:
            continue
        if key in getattr(sm, "invoices_to_pay", {}):
            continue  # commitment arrived late — no longer held
        if key in getattr(sm, "invoices_awaiting_funding", set()):
            continue
        if lnworker is not None and lnworker.get_invoice(key) is not None:
            continue
        held += 1
    return held


def _inflight_payment_count(sm):
    from .constants import PAYMENT_INFLIGHT_LOCK
    invoices = getattr(sm, "invoices_to_pay", {})
    return sum(1 for v in list(invoices.values()) if v == PAYMENT_INFLIGHT_LOCK)


def _expiring_soon_count(lnworker):
    holds = getattr(lnworker, "_hold_invoices", None)
    if holds is None:
        return 0
    from .invoices import InvoiceState
    now = time.time()
    count = 0
    for inv in list(holds.values()):
        try:
            if inv.funding_status in (InvoiceState.FUNDED, InvoiceState.SETTLED):
                continue
            if inv.created_at + inv.expiry - now < EXPIRING_SOON_SEC:
                count += 1
        except AttributeError:
            continue  # non-HoldInvoice junk (db round-trip hazard) — not ours to count
    return count


def build_report(provider) -> dict:
    """Assemble the swapprovider-health JSON. Read-only, side-effect
    free, safe to call every 30s from monitoring (pyln thread).
    `provider` is the CLNSwapProvider (or a stub); every part is
    optional — the RPC is registered before init completes and must
    answer honestly ("starting") during that window."""
    now_mono = time.monotonic()
    uptime = now_mono - tracker.boot_monotonic
    starting = uptime < STARTUP_GRACE_SEC
    reasons = []
    dead_reasons = []

    def subsystem_state(name: str) -> dict:
        with tracker._lock:
            ts = tracker._beats.get(name)
            detail = tracker._details.get(name, "")
            streak = tracker._error_streaks.get(name, 0)
        age_ms = None if ts is None else int((now_mono - ts) * 1000)
        spec = SPECS[name]
        if name == PYLN_THREAD:
            alive = _pyln_thread_alive(provider)
            if alive is None:
                alive = ts is not None or starting
        elif name == NOSTR_CONSUMER:
            # event-driven: aliveness is the transport state, not recency
            # (a "down" is positive knowledge from r4's withdrawal — the
            # startup grace must not mask it)
            mode = tracker.nostr_mode
            alive = mode == "up" or (starting and mode == "never-connected")
            if ts is None and mode != "down":
                detail = detail or "no events received yet (quiet relay is not an error)"
        elif ts is None:
            alive = starting
            detail = detail or "starting"
        elif spec["dead_after_sec"] is not None and (now_mono - ts) > spec["dead_after_sec"]:
            alive = False
            dead_reasons.append(
                f"{name}: no pass in {_fmt_age(now_mono - ts)} "
                f"(wedged; period {spec['period_sec']}s)")
        elif (now_mono - ts) > spec["stale_after_sec"]:
            alive = True
            reasons.append(f"{name}: beat stale {_fmt_age(now_mono - ts)} "
                           f"(period {spec['period_sec']}s)")
        else:
            alive = True
        if streak:
            reasons.append(f"{name}: {streak} consecutive errors"
                           + (f" ({detail})" if detail else ""))
        return {"alive": bool(alive), "last_seen_ms_ago": age_ms,
                "detail": detail, "error_streak": streak}

    subsystems = {name: subsystem_state(name) for name in SUBSYSTEMS}

    # nostr mode drives the degraded verdict for r4's withdrawal state
    nostr_mode = tracker.nostr_mode
    if nostr_mode == "down":
        with tracker._lock:
            why = tracker._nostr_reason
        reasons.append("nostr: down — offer withdrawn, transport restarting"
                       + (f" ({why})" if why else ""))
    elif nostr_mode == "never-connected" and not starting:
        reasons.append("nostr: never connected since boot")

    # pyln pipe late-death: the live probe may have flipped since the
    # last watchdog pass — subsystem_state already re-probed it, and a
    # dead probe appends its own reason below (beat alone is stale info)
    if not subsystems[PYLN_THREAD]["alive"]:
        dead_reasons.append("pyln plugin thread is not alive (pipe died)")

    verdict = "dead" if dead_reasons else ("degraded" if reasons else "ok")

    config = getattr(provider, "config", None)
    sm = getattr(provider, "swap_manager", None)
    lnworker = getattr(provider, "cln_lightning", None)
    json_db = getattr(provider, "json_db", None)
    storage = getattr(json_db, "storage", None)

    datastore = None
    if storage is not None:
        gen = getattr(storage, "last_generation", None)
        wrote_at = getattr(storage, "last_write_monotonic", None)
        datastore = {
            "generation": gen,
            "last_write_ms_ago": None if wrote_at is None
            else int((now_mono - wrote_at) * 1000),
        }

    return {
        "version": tracker.version,
        "boot_wall_time": tracker.boot_wall.isoformat(),
        "uptime_sec": round(uptime, 1),
        "verdict": verdict,
        "reasons": dead_reasons + reasons if verdict != "ok" else [],
        "subsystems": subsystems,
        "nostr_mode": nostr_mode,
        "sweep_grace_blocks": getattr(config, "sweep_grace_blocks", None),
        "grace_held_swaps": _grace_held_count(sm) if sm is not None else None,
        "inflight_payments": _inflight_payment_count(sm) if sm is not None else None,
        "expiring_soon_invoices": _expiring_soon_count(lnworker) if lnworker is not None else None,
        "datastore": datastore,
    }
