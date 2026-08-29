"""Regression: the offer's reverse cap must be receive-gated.

Live incident (playground #61, 2026-08-29): provider d23907e3
advertised maxReverse 51,500 while refusing a 20,000-sat
'reversesubmarine' createswap with 'not enough incoming capacity' —
publish_offer passed the send+receive-sum cap (_max_amount) for BOTH
directions, but the reverse serve gate (server_create_swap) checks
num_sats_can_receive() alone. One-sided CLN nodes (all-local
channels) therefore advertised reverse swaps they could not serve.

Pinned at the source seam (code-inspection style, like
test_min_emergency_capacity): the receive-gated calculation exists in
server_update_pairs, and the publisher passes it for max_reverse.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent / "swap-provider" / "plugin" / "submarine_swaps.py"


def _code_only(path: Path) -> str:
    return "\n".join(
        line for line in path.read_text().splitlines()
        if not line.lstrip().startswith("#"))


def test_reverse_cap_is_receive_gated_in_server_update_pairs():
    code = _code_only(PLUGIN)
    assert "self._max_reverse_amount = min(" in code
    assert "int(self.lnworker.num_sats_can_receive())\n" in code.replace(
        "            ", "").replace("\t", "") or \
        "num_sats_can_receive())" in code


def test_publisher_passes_directional_caps():
    code = _code_only(PLUGIN)
    assert "max_forward_sat=self.sm._max_amount," in code
    assert "max_reverse_sat=self.sm._max_reverse_amount," in code
    # the conflation this regression kills:
    assert "max_reverse_sat=self.sm._max_amount," not in code
