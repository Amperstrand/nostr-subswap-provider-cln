"""Regression tests for issue #30 (reservation leak) and the live-earned
R5 cancel gap in _fail_swap — both observed live 2026-08-28 on
cln-swap-mutinynet during the clboss v0.17 B-mode campaign.

ISSUE #30 — create_funding_tx failure paths abandon utxopsbt
reservations. `utxopsbt(reserve=12)` reserves the selected inputs; any
path that then abandons the ask WITHOUT spending them leaves the wallet
locked until reservation expiry (live 2026-08-27/28: stale reservations
of 12,535 + 17,074 + 54,000 = 83,609 sat locked of 103,664 confirmed —
swap-dead provider for hours). The abandon paths with no release today:

  1. psbt assembly (from_raw_psbt/add_outputs/set_rbf/serialize) raises
  2. signpsbt fails (line ~132, returns None while inputs stay reserved)
  3. sendpsbt fails at broadcast (inputs reserved, tx never mines)

(The dusty-escalation loop already unreserves; utxopsbt RPC failures
like code 313 reject atomically and reserve nothing — live-verified
2026-08-28 15:26:12Z: `We would not have enough left for
min-emergency-msat 25000sat`.)

R5 GAP — _fail_swap never cancels a normal swap's parked HTLCs. The
cancel branch was gated on `swap.payment_hash in
self.lnworker._hold_invoice_callbacks`, but SwapData.payment_hash is
BYTES while the registry normalizes to HEX-string keys
(cln_lightning.register_hold_invoice_callback) — bytes is never `in` a
hex-keyed dict, so the branch is dead code on EVERY normal-swap failure.
Live timeline (2026-08-28, swap cff928cd…, clboss client, 44,232 sat):

    15:26:12.681  callback_handler: invoice cff928cd fully funded, calling callback
    15:26:12.684  ERROR utxopsbt 313 (min-emergency-msat) -> funding tx failed
    15:26:12.684  WARNING failing swap cff928cd… / swap + watcher deleted
    [no cancel_all_htlcs ever fires]
    -> payer's 4 parked MPP HTLCs (43,954 sat) hang until CLTV ~3381386;
       the 278-sat prepay was already settled (taken) at 15:26:12.681.

Fix contract (this file):
  1. create_transaction releases (unreserveinputs, psbt form) the
     reservation when assembly or signpsbt fails.
  2. broadcast_transaction releases the reservation when sendpsbt fails.
  3. _fail_swap cancels a normal swap's parked hold-invoice HTLCs
     whether or not the funding callback is still registered (both
     hex-keyed registry states), and unregisters it if present.

Run: python3 -m pytest tests/test_reservation_leak.py -v
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pyln.client import RpcError

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"

if str(PLUGIN_DIR.parent) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR.parent))

from plugin.cln_chain import CLNChainWallet  # noqa: E402
from plugin.submarine_swaps import SwapData, SwapManager  # noqa: E402
from plugin.transaction import PartialTxOutput  # noqa: E402
from plugin.utils import TxBroadcastError  # noqa: E402

# Real inputs-only fundpsbt output captured from the live node
# (2026-08-20, reused from test_cltv_locked_coin_selection.py).
CANNED_PSBT = (
    "cHNidP8BAF4CAAAAAeTzBs9cErlZKRgOJanUaxqpbXdXAeSW4uW6MgC6qfU5"
    "AAAAAAD9////AQqBAQAAAAAAIlEg5GX1Slw/1RDwGvBGJA+2VE2HKeA2ibj/"
    "d39y742y2glO3AQAAAEAfQIAAAABHPSN4iro4h5ldotHrXNQ6tECTW2LiYW1"
    "/H5GTViFbCMBAAAAAP3///8CwNQBAAAAAAAWABSUnL1S6BemaZgxHSbRoWty"
    "eNy+cqr+BwAAAAAAIlEg0v0s/9DJsNLCFHWQUbWoNjMPAgPBJC6wcPNUzGo"
    "QVjAv3AQAAQEfwNQBAAAAAAAWABSUnL1S6BemaZgxHSbRoWtyeNy+cgAA"
)

FREE_P2WPKH = "0014" + "1f" * 20


def _free_output(txid="bb" * 32, vout=0, sats=50_000_000):
    return {"txid": txid, "output": vout, "amount_msat": sats,
            "status": "confirmed", "reserved": False,
            "scriptpubkey": FREE_P2WPKH}


def _wallet_with_pool(outputs):
    rpc = MagicMock()
    rpc.listfunds.return_value = {"outputs": outputs}
    rpc.utxopsbt.return_value = {"psbt": CANNED_PSBT, "excess_msat": 600_000}
    rpc.signpsbt.return_value = {"signed_psbt": CANNED_PSBT}
    wallet = CLNChainWallet(
        plugin_rpc=rpc, config=MagicMock(), logger=MagicMock())
    return wallet, rpc


def _lockup_output():
    return PartialTxOutput(scriptpubkey=bytes.fromhex(FREE_P2WPKH),
                           value=20_000)


def _assert_unreserved_with(rpc, psbt: str):
    assert rpc.unreserveinputs.called, \
        "abandoned funding ask must release its utxopsbt reservation"
    args = [c.args[0] if c.args else c.kwargs.get("psbt")
            for c in rpc.unreserveinputs.call_args_list]
    assert psbt in args, f"unreserveinputs must be called with {psbt!r}, got {args!r}"


class TestUnreserveOnAbandonedFunding:
    """Issue #30: every abandon-without-spend path releases the wallet."""

    def test_signpsbt_failure_unreserves(self):
        wallet, rpc = _wallet_with_pool([_free_output()])
        rpc.signpsbt.side_effect = Exception("signpsbt boom")

        tx = wallet.create_transaction(outputs_without_change=[_lockup_output()],
                                       rbf=True)

        assert tx is None
        _assert_unreserved_with(rpc, CANNED_PSBT)

    def test_psbt_assembly_failure_unreserves(self, monkeypatch):
        wallet, rpc = _wallet_with_pool([_free_output()])

        class Boom:
            @staticmethod
            def from_raw_psbt(_psbt):
                raise ValueError("psbt assembly boom")

        monkeypatch.setattr("plugin.cln_chain.PartialTransaction", Boom)

        tx = wallet.create_transaction(outputs_without_change=[_lockup_output()],
                                       rbf=True)

        assert tx is None
        _assert_unreserved_with(rpc, CANNED_PSBT)

    def test_broadcast_failure_unreserves(self):
        wallet, rpc = _wallet_with_pool([_free_output()])
        rpc.sendpsbt.side_effect = RpcError(
            "sendpsbt", -26, "bad-txns-inputs-missingorspent")
        signed_tx = MagicMock()
        signed_tx._serialize_as_base64.return_value = CANNED_PSBT

        with pytest.raises(TxBroadcastError):
            wallet.broadcast_transaction(signed_tx)

        _assert_unreserved_with(rpc, CANNED_PSBT)

    def test_happy_path_never_unreserves(self):
        """Guard: a funding tx that completes must keep its reservation —
        the inputs are about to be spent by sendpsbt."""
        wallet, rpc = _wallet_with_pool([_free_output()])

        tx = wallet.create_transaction(outputs_without_change=[_lockup_output()],
                                       rbf=True)

        assert tx is not None
        assert not rpc.unreserveinputs.called


def _normal_swap():
    swap = SwapData(
        is_reverse=False, locktime=5000, onchain_amount=19821,
        lightning_amount=20000, redeem_script=b"\x51" * 10,
        preimage=None, prepay_hash=b"\xcc" * 32, privkey=b"\x01" * 32,
        lockup_address="tb1qfake", receive_address="", funding_txid=None,
        spending_txid=None, is_redeemed=False)
    swap._payment_hash = (b"\xbb" * 32).hex()
    return swap


def _sm_with_parked_invoice(callbacks):
    """SwapManager with a parked hold invoice for the swap's main hash.
    `callbacks` mirrors the lnworker registry state (hex-keyed)."""
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.db = MagicMock()
    sm.swaps = {}
    sm.invoices_to_pay = {}
    sm.invoices_awaiting_funding = set()
    sm._funding_gate_deadline = {}
    sm.lnwatcher = MagicMock()
    sm.lnworker = MagicMock()
    sm.lnworker._hold_invoice_callbacks = callbacks
    parked = MagicMock(name="hold_invoice")

    def _get(payment_hash, *args, **kwargs):
        key = payment_hash if isinstance(payment_hash, str) else payment_hash.hex()
        return parked if key == (b"\xbb" * 32).hex() else None

    sm.lnworker.get_hold_invoice = MagicMock(side_effect=_get)
    return sm, parked


class TestFailSwapCancelsParkedHtlcs:
    """R5: a failed normal swap must cancel the payer's parked HTLCs NOW —
    live-earned 2026-08-28 15:26Z (cff928cd…): the bytes/hex gate made the
    cancel branch dead code and 43,954 sat parked until CLTV."""

    def test_cancels_after_callback_dispatch(self):
        """The funding-failure path: callback already popped from the
        registry (or never re-registered) — cancel must still fire."""
        sm, parked = _sm_with_parked_invoice(callbacks={})
        swap = _normal_swap()
        sm.swaps[swap.payment_hash.hex()] = swap

        sm._fail_swap(swap, 'funding tx failed')

        assert parked.cancel_all_htlcs.called, \
            "payer HTLCs must be cancelled on a failed normal swap (R5)"
        assert sm.lnworker.delete_hold_invoice.called

    def test_cancels_when_callback_still_registered(self):
        """The bytes/hex mismatch case: registration present under the HEX
        key while the gate probed with BYTES — cancel must fire and the
        registration must be removed."""
        key = (b"\xbb" * 32).hex()
        sm, parked = _sm_with_parked_invoice(callbacks={key: lambda ph: None})
        swap = _normal_swap()
        sm.swaps[swap.payment_hash.hex()] = swap

        sm._fail_swap(swap, 'funding tx failed')

        assert parked.cancel_all_htlcs.called, \
            "payer HTLCs must be cancelled on a failed normal swap (R5)"
        sm.lnworker.unregister_hold_invoice_callback.assert_called_once_with(
            swap.payment_hash)
        # a swap with no live funding drops its chain watch and record
        sm.lnwatcher.remove_callback.assert_called_with(swap.lockup_address)
        assert swap.payment_hash.hex() not in sm.swaps
