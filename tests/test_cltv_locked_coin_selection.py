"""Regression tests for issue #29: the funding coin selection spent
CLTV-locked channel-close machinery outputs as funding-tx inputs.

LIVE BUG (2026-08-26 19:31Z, mutinynet cln-swap): fundpsbt selected the
wallet's own P2WSH machinery outputs (HTLC-timeout outputs from old
channel closes, e.g. 0be690ad…:4 / 75829f98…:6) as inputs. These are
spendable only via branches that demand nLockTime >= their CLTV (BIP65)
or a CSV delay (BIP112) — a funding tx built at the current tip
violates the encumbrance and bitcoind rejects the WHOLE tx at broadcast:

    sendpsbt -26 mandatory-script-verify-flag-failed
    (Locktime requirement not satisfied), input 0 …

The swap then fails at the funding leg (payer HTLCs park, then cancel) —
deterministic whenever the selector's coin choice lands on a machinery
output.

Fix contract (this file):
  1. create_transaction selects inputs ONLY from plain key-script
     outputs (P2WPKH / P2TR of our keys) via an explicit utxo list
     (utxopsbt) — CLN's fundpsbt pool has no machinery filter and this
     CLN has no `exclusions` param (-32602, live-probed 2026-08-28).
  2. The machinery classification is by scriptPubKey shape: P2WSH in the
     CLN wallet is always channel-close machinery (to_local CSV /
     HTLC-timeout CLTV / anchors); onchaind sweeps those into plain
     wallet outputs on its own, so excluding them loses nothing.

Run: python3 -m pytest tests/test_cltv_locked_coin_selection.py -v
"""
import re
from pathlib import Path
from unittest.mock import MagicMock

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"

import sys
if str(PLUGIN_DIR.parent) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR.parent))

from plugin.cln_chain import CLNChainWallet  # noqa: E402
from plugin.transaction import PartialTxOutput  # noqa: E402


def _code_only(path: Path) -> str:
    src = path.read_text()
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = re.sub(r"'''[\s\S]*?'''", '', src)
    lines = [l for l in src.splitlines() if not l.strip().startswith("#")]
    return "\n".join(lines)


# Real inputs-only fundpsbt output captured from the live node
# (2026-08-20, reused from test_e2e_bug_regressions.py) — good enough to
# exercise the from_raw_psbt -> add_outputs -> set_rbf -> serialize
# pipeline against the mocked RPC.
CANNED_PSBT = (
    "cHNidP8BAF4CAAAAAeTzBs9cErlZKRgOJanUaxqpbXdXAeSW4uW6MgC6qfU5"
    "AAAAAAD9////AQqBAQAAAAAAIlEg5GX1Slw/1RDwGvBGJA+2VE2HKeA2ibj/"
    "d39y742y2glO3AQAAAEAfQIAAAABHPSN4iro4h5ldotHrXNQ6tECTW2LiYW1"
    "/H5GTViFbCMBAAAAAP3///8CwNQBAAAAAAAWABSUnL1S6BemaZgxHSbRoWty"
    "eNy+cqr+BwAAAAAAIlEg0v0s/9DJsNLCFHWQUbWoNjMPAgPBJC6wcPNUzGo"
    "QVjAv3AQAAQEfwNQBAAAAAAAWABSUnL1S6BemaZgxHSbRoWtyeNy+cgAA"
)

# scriptPubKey shapes from the live bad outpoints (mutinynet
# 0be690ad…:4, 75829f98…:6 — P2WSH, the channel-close machinery class)
MACHINERY_P2WSH = "0020" + "ab" * 32
# plain wallet-key shapes (what newaddr bech32 / p2tr give us)
FREE_P2WPKH = "0014" + "1f" * 20
FREE_P2TR = "5120" + "2f" * 32


def _wallet_with_pool(outputs):
    rpc = MagicMock()
    rpc.listfunds.return_value = {"outputs": outputs}
    rpc.utxopsbt.return_value = {"psbt": CANNED_PSBT, "excess_msat": 600_000}
    rpc.fundpsbt.return_value = {"psbt": CANNED_PSBT, "excess_msat": 600_000}
    rpc.signpsbt.return_value = {"signed_psbt": CANNED_PSBT}
    wallet = CLNChainWallet(
        plugin_rpc=rpc, config=MagicMock(), logger=MagicMock())
    return wallet, rpc


class TestCltvLockedCoinSelection:
    def test_funding_selects_only_free_inputs(self):
        """Acceptance criterion #29-1: a pool containing an unmet-CLTV
        machinery output + free outputs must produce a funding tx whose
        input selection contains ONLY the free outpoints."""
        locked = {"txid": "aa" * 32, "output": 4, "amount_msat": 20_017_000,
                  "status": "confirmed", "reserved": False,
                  "scriptpubkey": MACHINERY_P2WSH}
        free1 = {"txid": "bb" * 32, "output": 0, "amount_msat": 50_000_000,
                 "status": "confirmed", "reserved": False,
                 "scriptpubkey": FREE_P2WPKH}
        free2 = {"txid": "cc" * 32, "output": 1, "amount_msat": 40_000_000,
                 "status": "confirmed", "reserved": False,
                 "scriptpubkey": FREE_P2TR}
        wallet, rpc = _wallet_with_pool([locked, free1, free2])

        out = PartialTxOutput(scriptpubkey=bytes.fromhex(FREE_P2WPKH),
                              value=20_000)
        tx = wallet.create_transaction(outputs_without_change=[out], rbf=True)

        assert tx is not None, "funding pipeline must complete on a pool with free outputs"
        assert rpc.utxopsbt.called, "selection must go through an explicit-utxo RPC"
        offered = rpc.utxopsbt.call_args.kwargs["utxos"]
        assert f"{'bb' * 32}:0" in offered, "free P2WPKH output must be selectable"
        assert f"{'cc' * 32}:1" in offered, "free P2TR output must be selectable"
        assert f"{'aa' * 32}:4" not in offered, \
            "CLTV-locked machinery output must never be offered as a funding input"
        assert not rpc.fundpsbt.called, \
            "the unfiltered pool call is the bug: fundpsbt selects machinery outputs"

    def test_reserved_and_unconfirmed_outputs_are_not_offered(self):
        """Even plain outputs must only be offered when confirmed and
        unreserved (matching CLN's own availability semantics)."""
        outputs = [
            {"txid": "dd" * 32, "output": 0, "amount_msat": 10_000_000,
             "status": "unconfirmed", "reserved": False,
             "scriptpubkey": FREE_P2WPKH},
            {"txid": "ee" * 32, "output": 0, "amount_msat": 20_000_000,
             "status": "confirmed", "reserved": True,
             "scriptpubkey": FREE_P2WPKH},
            {"txid": "ff" * 32, "output": 0, "amount_msat": 30_000_000,
             "status": "confirmed", "reserved": False,
             "scriptpubkey": FREE_P2WPKH},
        ]
        wallet, rpc = _wallet_with_pool(outputs)

        out = PartialTxOutput(scriptpubkey=bytes.fromhex(FREE_P2WPKH),
                              value=10_000)
        tx = wallet.create_transaction(outputs_without_change=[out], rbf=True)

        assert tx is not None
        offered = rpc.utxopsbt.call_args.kwargs["utxos"]
        assert f"{'ff' * 32}:0" in offered
        assert f"{'dd' * 32}:0" not in offered, "unconfirmed output must not be offered"
        assert f"{'ee' * 32}:0" not in offered, "reserved output must not be offered"

    def test_pool_with_only_locked_outputs_fails_cleanly(self):
        """No plain outputs at all: the wallet must return None (the
        existing 'could not fund' path fails the swap cleanly) instead
        of building a doomed tx."""
        locked = {"txid": "aa" * 32, "output": 4, "amount_msat": 20_017_000,
                  "status": "confirmed", "reserved": False,
                  "scriptpubkey": MACHINERY_P2WSH}
        wallet, rpc = _wallet_with_pool([locked])

        out = PartialTxOutput(scriptpubkey=bytes.fromhex(FREE_P2WPKH),
                              value=20_000)
        tx = wallet.create_transaction(outputs_without_change=[out], rbf=True)

        assert tx is None
        assert not rpc.utxopsbt.called

    def test_funding_call_is_source_contracted(self):
        """Code contract: the funding path offers an explicitly filtered
        utxo list (utxopsbt); the blind fundpsbt pool call is extinct in
        create_transaction."""
        code = _code_only(PLUGIN_DIR / "cln_chain.py")
        assert "utxopsbt" in code, \
            "funding must use the explicit-utxo RPC (utxopsbt)"
        assert "self.rpc.fundpsbt(" not in code, \
            "fundpsbt (unfiltered pool incl. CLTV/CSV machinery outputs) must not fund swaps"
