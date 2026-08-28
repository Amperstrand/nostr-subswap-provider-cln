"""Contract tests pinning the createswap onchainAmount seam (issue #33).

LIVE 2026-08-28 15:46Z (swap b046b93b, 30,821 sat): the clboss client
R2-checks the on-chain lockup value against the onchainAmount the
server DECLARED in its createswap reply (persisted at swap creation;
compared by the fork's scan_prevalidate / ClaimTxHandler). Any drift
between the declared value and the funded output = every claim skipped,
the swap dies at locktime with both legs healthy.

That incident's root cause was CLIENT-side (the fork persisted the
gross ask instead of the declared net — fixed in ../clboss
NostrService.cpp, deployed 2026-08-28 16:26Z). These tests pin the
SERVER side of the seam so it can never drift silently:

  1. create_funding_tx pays EXACTLY swap.onchain_amount to
     swap.lockup_address (the value the client will R2-compare).
  2. The createswap reply's "onchainAmount" field is swap.onchain_amount.

Both are GREEN-on-purpose pins (contract tests, the repo's
code-inspection style) — the contract they freeze was earned live.

Run: python3 -m pytest tests/test_swap_amount_contract.py -v
"""
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "swap-provider" / "plugin"

if str(PLUGIN_DIR.parent) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR.parent))

from plugin.submarine_swaps import SwapData, SwapManager  # noqa: E402


def _normal_swap(onchain_amount, lockup_address):
    swap = SwapData(
        is_reverse=False, locktime=5000, onchain_amount=onchain_amount,
        lightning_amount=30821, redeem_script=b"\x51" * 10,
        preimage=None, prepay_hash=b"\xcc" * 32, privkey=b"\x01" * 32,
        lockup_address=lockup_address, receive_address="", funding_txid=None,
        spending_txid=None, is_redeemed=False)
    swap._payment_hash = (b"\xbb" * 32).hex()
    return swap


def _sm():
    sm = SwapManager.__new__(SwapManager)
    sm.logger = MagicMock()
    sm.wallet = MagicMock()
    return sm


class TestFundingPaysDeclaredAmount:
    def test_funding_tx_pays_exactly_onchain_amount(self, monkeypatch):
        """The lockup output value must be byte-for-byte the value the
        reply declared — the client's R2 gate is an EXACT match."""
        captured = []

        class RecordingOutput:
            @classmethod
            def from_address_and_value(cls, address, value):
                captured.append((address, value))
                out = MagicMock()
                out.value = value
                return out

        monkeypatch.setattr(
            "plugin.submarine_swaps.PartialTxOutput", RecordingOutput)
        sm = _sm()
        swap = _normal_swap(onchain_amount=30620,
                            lockup_address="tb1qt5f8ztexqc8g9nxz82dv8dpmt"
                                           "7lw2hz52dwmg9n8rjj5g7q0rh5qr63mlg")
        # live values from b046b93b: lockup 30,620 declared and funded
        sm.create_funding_tx(swap=swap)

        assert captured == [(swap.lockup_address, 30620)], \
            "create_funding_tx must pay exactly swap.onchain_amount to " \
            "swap.lockup_address — the client R2-compares the on-chain " \
            "value against the declared onchainAmount (issue #33)"


def _code_only(path: Path) -> str:
    src = path.read_text()
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = re.sub(r"'''[\s\S]*?'''", '', src)
    lines = [l for l in src.splitlines() if not l.strip().startswith("#")]
    return "\n".join(lines)


class TestReplyDeclaresFundedAmount:
    def test_reply_onchain_amount_is_swap_onchain_amount(self):
        """Code contract: the createswap reply field is the same
        swap.onchain_amount the funding tx pays — never a re-derivation
        (a re-derivation can drift under fee hysteresis and R2-skip
        every claim, the exact #33 failure shape)."""
        code = _code_only(PLUGIN_DIR / "submarine_swaps.py")
        assert '"onchainAmount": swap.onchain_amount' in code, \
            "the reply must declare swap.onchain_amount verbatim"
