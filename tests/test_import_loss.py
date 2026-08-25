# Regression tests for the wallet-import-loss crash loop (live 2026-08-24:
# a restarted bitcoind wallet lost persisted swaps' address imports;
# _claim_swap raised UnknownAddressError every block, replaying a critical
# error and taking the swap server's callback loop down with it).
#
# Source-contract style (raw-file asserts): the plugin module imports only
# inside the deployed container env (pyln pin); behavioral tests for it run
# there — these pins run anywhere and guard the same contract.
from pathlib import Path

SRC = (Path(__file__).resolve().parent.parent
       / 'swap-provider' / 'plugin' / 'submarine_swaps.py').read_text()


def test_claim_swap_catches_unknown_address_and_re_registers():
    assert 'except UnknownAddressError:' in SRC
    # the recovery action, not just the catch
    assert 'await self.lnwatcher.register_address(swap.lockup_address)' in SRC
    # the fatal path is gone: get_addr_outputs must sit inside the try
    try_block = SRC.split('try:\n            txos = await self.lnwatcher.get_addr_outputs')
    assert len(try_block) >= 2, 'get_addr_outputs must be inside a try (the raw call crash-looped)'


def test_main_loop_re_registers_persisted_lockups_before_callbacks():
    # the re-registration pass must precede the callback pass
    loop = SRC[SRC.index('async def main_loop'):]
    loop = loop[:loop.index('tasks = [')]
    assert 'await self.lnwatcher.register_address(swap.lockup_address)' in loop
    assert 'self.add_lnwatcher_callback(swap)' in loop
    assert loop.index('register_address') < loop.index('add_lnwatcher_callback')


def test_unknown_address_error_referenced():
    assert 'UnknownAddressError' in SRC  # the catch names the exact class (no bare except)
