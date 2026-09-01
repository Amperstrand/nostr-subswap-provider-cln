"""Orphan-HTLC reaper regression suite (#44 comment class, corrected).

The 2026-08-31 orphan: a parked inbound HTLC whose deferred
htlc_accepted response died with the plugin rides to its own CLTV
(~22h). The issue comment proposed dev-fail(channel_id, htlc_id) — but
CLN's dev-fail takes a PEER id and fails the WHOLE channel (verified
against ElementsProject/lightning peer_control.c json_dev_fail + live
`help dev-fail` = "dev-fail id"), so per-HTLC auto-failing is OFF the
table: it would nuke a healthy channel to clear one orphan.

Contract under test (observability-only reaper):
  - candidates: direction 'in', state RCVD_ADD* (parked inbound)
  - four safety guards: no swap record, no hold invoice, no payment
    info, AND aged past ORPHAN_GRACE_BLOCKS (first-seen ledger; a
    restart resets it — conservative)
  - reporting: ERROR once per hash (with cltv ETA), listed by every
    subsequent scan; guard-failing HTLCs are NEVER reported
  - an RPC outage in the ownership check skips the candidate (never
    report blind)
  - wired into main_loop's supervised tasks

Run: python3 -m pytest tests/test_orphan_reaper.py -v
"""
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin.constants import ORPHAN_GRACE_BLOCKS  # noqa: E402
from plugin.submarine_swaps import SwapManager, SwapData  # noqa: E402

ORPHAN = 'dd' * 32


def _htlc(ph, *, direction='in', state='RCVD_ADD_ACK_REVOCATION'):
    return {'payment_hash': ph, 'direction': direction, 'state': state,
            'amount_msat': 20_000_000, 'short_channel_id': '319019x96x0',
            'expiry': 320481, 'id': 0}


def _mk_sm(htlcs, holds=None, statuses=None, status_error=False) -> SwapManager:
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.swaps = {}
    sm.wallet = MagicMock()
    sm.wallet.get_local_height = AsyncMock(return_value=1000)
    sm.lnworker = MagicMock()
    sm.lnworker._rpc.listhtlcs = MagicMock(return_value={'htlcs': htlcs})
    sm.lnworker.get_hold_invoice = MagicMock(
        side_effect=lambda b: (holds or {}).get(b.hex()))
    if status_error:
        sm.lnworker.get_payment_statuses = MagicMock(
            side_effect=Exception('listpays rpc failed'))
    else:
        sm.lnworker.get_payment_statuses = MagicMock(
            side_effect=lambda k: (statuses or {}).get(k, []))
    sm._orphan_first_seen = {}
    sm._orphan_reported = set()
    return sm


class TestOrphanDetection:
    async def test_fresh_unknown_hash_waits_out_grace(self):
        sm = _mk_sm([_htlc(ORPHAN)])
        assert await sm._scan_orphan_htlcs() == []  # grace not aged
        assert sm._orphan_first_seen[ORPHAN] == 1000

    async def test_aged_orphan_reported_once(self):
        sm = _mk_sm([_htlc(ORPHAN)])
        await sm._scan_orphan_htlcs()  # seed first-seen
        sm.wallet.get_local_height = AsyncMock(
            return_value=1000 + ORPHAN_GRACE_BLOCKS + 1)
        first = await sm._scan_orphan_htlcs()
        assert [o['payment_hash'] for o in first] == [ORPHAN]
        assert first[0]['cltv_expiry'] == 320481
        errs = [c.args[0] for c in sm.logger.error.call_args_list]
        assert sum('ORPHAN inbound HTLC' in m for m in errs) == 1
        second = await sm._scan_orphan_htlcs()
        assert len(second) == 1  # still listed…
        errs = [c.args[0] for c in sm.logger.error.call_args_list]
        assert sum('ORPHAN inbound HTLC' in m for m in errs) == 1  # …log-once

    async def test_all_four_guards_block_reporting(self):
        """swap record / hold invoice / payment info / ownership-RPC
        outage — any of these means the HTLC is not a reportable orphan."""
        swap = SwapData(
            is_reverse=False, locktime=5000, onchain_amount=1,
            lightning_amount=1, redeem_script=b"\x51" * 10,
            preimage=None, prepay_hash=None, privkey=None,
            lockup_address="tb1qfake", receive_address="",
            funding_txid=None, spending_txid=None, is_redeemed=False)
        swap._payment_hash = 'ee' * 32
        htlcs = [
            _htlc('ee' * 32),                       # has swap record
            _htlc('11' * 32),                       # has hold invoice
            _htlc('22' * 32),                       # has payment info
            _htlc('33' * 32),                       # ownership RPC outage
            _htlc('44' * 32, direction='out'),      # not inbound
            _htlc('55' * 32, state='RCVD_REMOVE_ACK_REVOCATION'),  # leaving
        ]
        sm = _mk_sm(htlcs,
                    holds={'11' * 32: object()},
                    statuses={'22' * 32: ['pending']},
                    status_error=False)
        sm.swaps['ee' * 32] = swap
        # age everything past grace in one shot
        sm._orphan_first_seen = {h['payment_hash']: 0 for h in htlcs}
        sm._orphan_reported.clear()
        sm.wallet.get_local_height = AsyncMock(return_value=1000)
        # force the ownership-RPC-outage candidate's checker to blow up
        calls = {'33' * 32: 0}

        def statuses_or_raise(k):
            if k == '33' * 32:
                calls[k] += 1
                raise Exception('listpays rpc failed')
            return (statuses or {}).get(k, [])
        sm.lnworker.get_payment_statuses = MagicMock(side_effect=statuses_or_raise)
        found = await sm._scan_orphan_htlcs()
        assert found == [], found
        assert calls['33' * 32] >= 1  # the blind-skip path was exercised


def _code_only(path: Path) -> str:
    src = path.read_text()
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = re.sub(r"'''[\s\S]*?'''", '', src)
    lines = [l for l in src.splitlines() if not l.strip().startswith("#")]
    return "\n".join(lines)


class TestWiringSourceContract:
    def test_reaper_loop_is_a_supervised_main_loop_task(self):
        code = _code_only(_plugin / "submarine_swaps.py")
        assert "self.orphan_htlc_watch_loop()," in code, \
            "the reaper scan must run on a supervised main_loop task"
        assert "await self._scan_orphan_htlcs()" in code
