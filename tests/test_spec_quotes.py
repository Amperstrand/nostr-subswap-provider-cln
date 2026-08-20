"""Gate: every BOLT quote in source comments matches the actual spec.

Uses greatspectations (rustyrussell/greatspectations, zero pip deps on
python >= 3.11) against a lightning/bolts checkout. Both are sibling
checkouts — CI or a fresh machine without them SKIPS this test rather
than failing; the repo docs (specquotes.toml header) show how to set up.

Why this matters: the vendored lnaddr.py carried BOLT #11 quotes that had
drifted from the spec ("SHOULD fail" -> "MUST fail the payment",
`feebase` -> `fee_base_msat`, one quote citing a deleted rule). Anyone
reading those comments was reading folklore. This test makes stale
authoritative comments a CI failure instead.

Run: python3 -m pytest tests/test_spec_quotes.py -v
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
GREATSPECTATIONS = REPO.parent / "greatspectations" / "src"
BOLTS = REPO.parent / "bolts"

pytestmark = pytest.mark.skipif(
    not GREATSPECTATIONS.is_dir() or not BOLTS.is_dir(),
    reason="greatspectations + lightning/bolts sibling checkouts not present "
           "(see specquotes.toml header for setup)",
)

QUOTED_FILES = [
    "swap-provider/plugin/cln_lightning.py",
    "swap-provider/plugin/lnaddr.py",
    "swap-provider/plugin/invoices.py",
    "swap-provider/plugin/submarine_swaps.py",
]


def test_bolt_quotes_match_spec():
    env = {**__import__("os").environ, "PYTHONPATH": str(GREATSPECTATIONS)}
    proc = subprocess.run(
        [sys.executable, "-m", "greatspectations", "check",
         "--config", "specquotes.toml", "--comment-aside=# Impl-note:",
         *QUOTED_FILES],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        f"spec-quote drift detected (exit {proc.returncode}):\n"
        f"{proc.stdout}{proc.stderr}\n"
        "Fix: update the quoted comment to the CURRENT spec text "
        "(bolts checkout above), or mark non-spec commentary lines "
        "with '# Impl-note:'."
    )


def test_no_unprefixed_impl_notes():
    """Aside lines must EVERY carry the '# Impl-note:' prefix — the tool
    drops asides per-line, so an unprefixed continuation silently joins
    the quote and breaks matching (bit us during adoption)."""
    for rel in QUOTED_FILES:
        text = (REPO / rel).read_text()
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if "# Impl-note:" in line:
                continue
            # a line directly after an Impl-note that is a bare comment
            # continuation inside the same block
            prev = lines[i - 1] if i else ""
            if (prev.lstrip().startswith("# Impl-note:")
                    and line.strip().startswith("#")
                    and "BOLT #" not in line):
                    # bare continuation of an aside: only legal if blank or
                    # indented code follows; flag same-indent comment lines
                if line[:len(line) - len(line.lstrip())] == \
                        prev[:len(prev) - len(prev.lstrip())]:
                    pytest.fail(
                        f"{rel}:{i + 1}: comment continues an Impl-note "
                        f"without its own '# Impl-note:' prefix:\n{line}"
                    )
