"""Regression tests for issue #31: the offer cap and the createswap
accept gate counted wallet coins CLN will refuse to spend.

LIVE 2026-08-28 15:26:12Z, cln-swap-mutinynet (B-mode campaign, swap
cff928cd…, 44,232 sat): the offer advertised max 67,475
(balance_sat() = confirmed∧unreserved × 0.9 = 74,750 × 0.9) and the
accept gate passed 44,232 against it — then the funding was refused:

    utxopsbt … error: {'code': 313, 'message': 'We would not have
    enough left for min-emergency-msat 25000sat'}

CLN keeps an emergency reserve (min-emergency-msat, default 25,000 sat;
listconfigs: {'min-emergency-msat': {'value_msat': 25000000,
'source': 'default'}}) that no wallet spend may dip below. A payer had
already fully funded (43,954 sat parked) when the provider discovered
it could not fund — the exact "negotiate a swap the node can't fund"
failure the R3/#14 cap work exists to prevent.

Fix contract (this file):
  1. CLNChainWallet.spendable_capacity_sat() = balance_sat() −
     min-emergency reserve (reserve fetched once via listconfigs,
     value_msat form; CLN-default 25,000 sat on any lookup failure —
     under-advertising is the safe direction).
  2. The offer cap (server_update_pairs) uses spendable_capacity_sat,
     never bare balance_sat().
  3. The createswap onchain accept gate ditto — reject BEFORE the
     payer funds, not after.

Run: python3 -m pytest tests/test_min_emergency_capacity.py -v
"""
import re
import sys
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"

if str(PLUGIN_DIR.parent) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR.parent))

from plugin.cln_chain import CLNChainWallet  # noqa: E402
from plugin.submarine_swaps import SwapManager  # noqa: E402

FREE_P2WPKH = "0014" + "1f" * 20

# Live-pinned 2026-08-28, pyln socket RPC on cln-swap-mutinynet (CLN
# v26.06): the RAW listconfigs result wraps every option under a
# 'configs' key — the flat view earlier tests used is what clnrest-style
# renderings show, NOT what the plugin's rpc sees.
SOCKET_LISTCONFIGS = {
    "configs": {
        "min-emergency-msat": {
            "value_msat": 10000000,
            "source": "/root/.lightning/lightning-config:16",
        },
    },
}

# The clnrest-rendered flat view (kept for backward-compat parsing).
LIVE_LISTCONFIGS = {
    "min-emergency-msat": {"value_msat": 25000000, "source": "default"},
}


def _wallet(*, confirmed_free_sat, listconfigs=LIVE_LISTCONFIGS):
    rpc = MagicMock()
    rpc.listfunds.return_value = {"outputs": [
        {"txid": "bb" * 32, "output": 0,
         "amount_msat": confirmed_free_sat * 1000,
         "status": "confirmed", "reserved": False,
         "scriptpubkey": FREE_P2WPKH}]}
    if isinstance(listconfigs, Exception):
        rpc.listconfigs.side_effect = listconfigs
    else:
        rpc.listconfigs.return_value = listconfigs
    wallet = CLNChainWallet(
        plugin_rpc=rpc, config=MagicMock(), logger=MagicMock())
    return wallet, rpc


class TestSpendableCapacity:
    def test_subtracts_live_shaped_reserve(self):
        wallet, _ = _wallet(confirmed_free_sat=80_000)

        cap = wallet.spendable_capacity_sat()

        assert cap == 80_000 * 0.9 - 25_000, \
            "capacity must be balance_sat() minus min-emergency reserve"

    def test_falls_back_to_cln_default_when_listconfigs_fails(self):
        wallet, _ = _wallet(confirmed_free_sat=80_000,
                            listconfigs=Exception("rpc down"))

        cap = wallet.spendable_capacity_sat()

        assert cap == 80_000 * 0.9 - 25_000, \
            "lookup failure must assume the CLN default reserve (25k sat)"

    def test_reserve_fetched_once(self):
        wallet, rpc = _wallet(confirmed_free_sat=80_000)

        wallet.spendable_capacity_sat()
        wallet.spendable_capacity_sat()

        assert rpc.listconfigs.call_count == 1, \
            "the reserve is node config — cache it, do not RPC per tick"

    def test_reads_socket_wrapped_shape(self):
        """The shape the plugin's rpc ACTUALLY returns (live 2026-08-28
        16:46-17:06Z): options nested under 'configs'; the top-level
        probe silently fell back to 25,000 and the gate rejected three
        clboss ticks at '18,535 spendable' with true capacity 33,535."""
        wallet, _ = _wallet(confirmed_free_sat=80_000,
                            listconfigs=SOCKET_LISTCONFIGS)

        cap = wallet.spendable_capacity_sat()

        assert cap == 80_000 * 0.9 - 10_000, \
            "configs-wrapped listconfigs must yield the configured reserve"

    def test_accepts_msat_string_form(self):
        wrapped_str = {"configs": {"min-emergency-msat": "10000000msat"}}
        wallet, _ = _wallet(confirmed_free_sat=80_000,
                            listconfigs=wrapped_str)

        cap = wallet.spendable_capacity_sat()

        assert cap == 80_000 * 0.9 - 10_000

    def test_unreadable_reserve_warns_never_silent(self):
        """The availability killer: a missing/unrecognized reserve must
        WARN, not silently assume — the silent fallback understated
        capacity by 15k sat for 40 minutes (live 2026-08-28)."""
        wallet, _ = _wallet(confirmed_free_sat=80_000,
                            listconfigs={"configs": {}})

        cap = wallet.spendable_capacity_sat()

        assert cap == 80_000 * 0.9 - 25_000, \
            "fallback direction stays safe (CLN default reserve)"
        assert wallet.logger.warning.called, \
            "an unreadable reserve MUST be loud — silent fallback hid a " \
            "live mis-parse for three quotation ticks"


class TestOfferCap:
    def _sm(self, balance_sat, reserve_sat):
        sm = SwapManager.__new__(SwapManager)
        sm.logger = MagicMock()
        sm.wallet = MagicMock()
        sm.wallet.balance_sat.return_value = balance_sat
        sm.wallet.min_emergency_reserve_sat.return_value = reserve_sat
        sm.wallet.spendable_capacity_sat.return_value = balance_sat - reserve_sat
        sm.wallet.get_chain_fee.return_value = 139
        sm.lnworker = MagicMock()
        sm.lnworker.num_sats_can_receive.return_value = 10_000_000
        sm.lnworker.num_sats_can_send.return_value = 10_000_000
        sm.config = MagicMock()
        sm.config.swapserver_fee_millionths = 2000
        sm.config.max_swap_amount = 10_000_000
        sm.percentage = Decimal("0.2")
        sm.normal_fee = None
        return sm

    def test_max_amount_is_reserve_aware(self):
        """Live case: pool 74,750 sat, reserve 25,000 — the offer must
        cap at 49,750, not 67,475 (74,750 × 0.9 balance_sat illusion)."""
        sm = self._sm(balance_sat=74_750, reserve_sat=25_000)

        sm.server_update_pairs()

        assert sm._max_amount == 49_750, \
            "advertised max must be spendable capacity, not bare balance"


def _code_only(path: Path) -> str:
    src = path.read_text()
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = re.sub(r"'''[\s\S]*?'''", '', src)
    lines = [l for l in src.splitlines() if not l.strip().startswith("#")]
    return "\n".join(lines)


class TestAcceptGateContract:
    def test_gate_is_reserve_aware(self):
        """Code contract: the createswap onchain gate must reject on
        spendable capacity (before the payer funds), never on the
        reserve-blind balance_sat()."""
        code = _code_only(PLUGIN_DIR / "submarine_swaps.py")
        assert "self.wallet.spendable_capacity_sat() < lightning_amount_sat" in code, \
            "accept gate must compare against reserve-aware capacity"
        assert "self.wallet.balance_sat() < lightning_amount_sat" not in code, \
            "the reserve-blind gate accepted swaps CLN then refused at utxopsbt 313 (live 2026-08-28)"
