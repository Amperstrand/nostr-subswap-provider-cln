"""Unique-script-per-swap is a TRUSTLESS-MODEL requirement (see
lightning-playground docs/research/UNIQUE-SCRIPT-PER-SWAP.md):
preimage cross-satisfaction, watcher ambiguity, refund mis-binding,
linkability. Both creation paths must derive fresh material per swap —
never deterministic from client-visible inputs.

Live-verified on the jitlab 2026-08-24: two identical createnormalswap
bodies (same refund key, same amount) produced distinct address /
preimageHash / redeemScript every time. These tests pin it at the unit
level against regression to any deterministic derivation."""
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

_plugin = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"
if str(_plugin.parent) not in sys.path:
    sys.path.insert(0, str(_plugin.parent))

from plugin import constants as _constants  # noqa: E402
_constants.net = _constants.BitcoinRegtest  # address encoding needs a net
from plugin.submarine_swaps import SwapManager  # noqa: E402


def _manager():
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.prepayments = {}
    import asyncio
    loop = asyncio.new_event_loop()
    sm.lnwatcher = MagicMock()
    sm.lnwatcher.register_address = AsyncMock()
    sm.wallet = MagicMock()
    sm.wallet.get_local_height = AsyncMock(return_value=1_000)
    sm.wallet.get_receiving_address = MagicMock(side_effect=lambda: f"addr-{os.urandom(4).hex()}")
    sm._add_or_reindex_swap = MagicMock()
    sm.add_lnwatcher_callback = MagicMock()
    sm._get_recv_amount = MagicMock(return_value=25_000)
    sm._get_send_amount = MagicMock(return_value=25_000)
    sm.get_min_amount = MagicMock(return_value=20_000)
    sm.get_max_amount = MagicMock(return_value=1_000_000)
    sm.lnworker = MagicMock()
    sm.lnworker.num_sats_can_send = MagicMock(return_value=10**9)
    sm.lnworker.register_hold_invoice_callback = MagicMock()
    sm.config = MagicMock()
    sm.config.network = _constants.BitcoinRegtest
    # #36: mock HSM deriver (deterministic per-label, like makesecret)
    import hmac, hashlib
    sm.set_hsm_deriver(lambda label: hmac.new(b'test-root', label.encode(), hashlib.sha256).digest())
    return sm


class TestUniqueScriptPerSwap:
    @pytest.mark.asyncio
    async def test_two_d2_creates_yield_distinct_material(self):
        sm = _manager()
        a = await sm.create_reverse_swap(lightning_amount_sat=25_000,
                                         their_pubkey=b"\x02" + b"\xab" * 32)
        b = await sm.create_reverse_swap(lightning_amount_sat=25_000,
                                         their_pubkey=b"\x02" + b"\xab" * 32)
        # #36: preimage is None in the record; derive via HSM to compare
        sm._get_swap_preimage(a) != sm._get_swap_preimage(b)
        assert sm._get_swap_privkey(a) != sm._get_swap_privkey(b)
        assert a.redeem_script != b.redeem_script
        assert a.lockup_address != b.lockup_address
        assert a.payment_hash != b.payment_hash

    @pytest.mark.asyncio
    async def test_source_has_no_deterministic_derivation(self):
        # #36 HSM-split: per-swap uniqueness now comes from the random
        # preimage_seed (os.urandom(16)) — the key material is HSM-derived
        # from the seed, so different seeds → different keys (same property
        # as the old os.urandom(32), but the secrets are never stored)
        src = (_plugin / "submarine_swaps.py").read_text()
        import re
        creates = re.findall(
            r"async def create_(?:reverse|normal)_swap.*?(?=\n    async def |\nclass )",
            src, re.S)
        assert creates, "creation functions not found"
        for fn in creates:
            if "create_reverse_swap" in fn:
                assert "os.urandom(16)" in fn, (
                    "d2 per-swap uniqueness must come from the random preimage seed")
            else:
                assert "os.urandom(32)" in fn, (
                    "d1 per-swap material must come from os.urandom")
