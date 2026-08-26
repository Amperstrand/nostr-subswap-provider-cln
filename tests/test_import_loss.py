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


# ─── #28 residual: FUNDED-abandonment watchdog (2026-08-25) ──────────────────
# A fully-parked hold whose swap funding never happened parked FOREVER:
# the sweeper skips FUNDED (waiting for claim→settle), so the payer's
# HTLC dangled to CLTV (~95min) pinning capacity (live: run-A 19.7k,
# 90+min, three later swaps failed with no failcode). The watchdog
# cancels FUNDED holds past expiry×2. These are source-contract pins
# (module imports only inside the container env).

def test_funded_abandonment_watchdog_exists():
    src = (Path(__file__).resolve().parent.parent
           / 'swap-provider' / 'plugin' / 'cln_lightning.py').read_text()
    assert 'funding_status is InvoiceState.FUNDED' in src
    assert 'invoice.expiry * 2 < time.time()' in src
    assert 'ABANDONED funded hold' in src  # the log line operators grep for


def test_watchdog_runs_before_the_unfunded_branch():
    import re
    src = (Path(__file__).resolve().parent.parent
           / 'swap-provider' / 'plugin' / 'cln_lightning.py').read_text()
    fn = src[src.index('def check_invoice_expiry'):]
    m = re.search(r'\n    def ', fn[10:])  # next method boundary
    fn = fn[:m.start() + 10] if m else fn
    watchdog = fn.index('funding_status is InvoiceState.FUNDED')
    unfunded = fn.index('funding_status not in')
    assert watchdog < unfunded, 'FUNDED watchdog must be evaluated first (it returns True)'


def test_watchdog_cleans_all_three_registrations():
    """cancel + unregister callback + delete — a partial cleanup re-strands."""
    src = (Path(__file__).resolve().parent.parent
           / 'swap-provider' / 'plugin' / 'cln_lightning.py').read_text()
    fn = src[src.index('ABANDONED funded hold'):]
    fn = fn[:fn.index('def ') if 'def ' in fn else len(fn)]
    assert 'cancel_all_htlcs()' in fn
    assert 'unregister_hold_invoice_callback' in fn
    assert 'delete_hold_invoice' in fn


# ─── #28 root fix: hold-callback re-registration on restart ─────────────────
# The callback dict starts empty each process; a FUNDED hold parked before
# a restart never fired its funding callback afterward. main_loop must
# re-register it alongside the lnwatcher re-registration.

def test_main_loop_re_registers_hold_callbacks():
    src = (Path(__file__).resolve().parent.parent
           / 'swap-provider' / 'plugin' / 'submarine_swaps.py').read_text()
    fn = src[src.index('async def main_loop'):]
    import re as _re
    m = _re.search(r'\n    async def ', fn[10:])
    fn = fn[:m.start() + 10] if m else fn
    assert 'register_hold_invoice_callback' in fn, 'main_loop must re-register hold callbacks'
    # the guard: only is_reverse (server PoV) + registered + unfunded swaps
    assert 'swap.registered and swap.funding_txid is None' in fn


def test_create_normal_swap_still_registers_live():
    src = (Path(__file__).resolve().parent.parent
           / 'swap-provider' / 'plugin' / 'submarine_swaps.py').read_text()
    # live path unchanged: create_normal_swap registers at creation time
    assert src.count('register_hold_invoice_callback') >= 3  # live + main_loop re-arm + this doc


# ─── #23 A1/A2/A3: logging severity + aggregation + no-print contracts ──────

def test_logger_uses_real_levels():
    src = (Path(__file__).resolve().parent.parent / 'plugin_src' / 'plugin' / 'cln_logger.py').read_text() \
        if (Path(__file__).resolve().parent.parent / 'plugin_src').exists() \
        else (Path(__file__).resolve().parent.parent / 'swap-provider' / 'plugin' / 'cln_logger.py').read_text()
    # warn/error ride their REAL pyln levels (the old workaround collapsed
    # everything to level="info")
    assert 'level="warn"' in src
    assert 'level="error"' in src
    assert 'CLN/plugin doesnt support WARN' not in src


def test_no_bare_print_in_plugin_runtime():
    # audit #23 A3: print() writes to the pyln JSON-RPC pipe — the known
    # one was submarine_swaps.py:1338; none may return
    src = (Path(__file__).resolve().parent.parent / 'swap-provider' / 'plugin' / 'submarine_swaps.py').read_text()
    import re
    offenders = [l for l in src.splitlines()
                 if re.match(r'\s+print\(', l) and 'unknown message' not in l]
    assert offenders == [], f'bare print() in plugin runtime: {offenders}'


def test_expire_pass_error_aggregation():
    src = (Path(__file__).resolve().parent.parent / 'swap-provider' / 'plugin' / 'cln_lightning.py').read_text()
    assert 'err_counts' in src                # the aggregation dict exists
    assert 'n == 1 or n % 50 == 0' in src     # first + 1-in-50 cadence
    assert 'errored {n}×' in src or 'errored ' in src  # summary shape


def test_callback_dispatch_is_default_visible():
    # the #28 lesson: the funding-callback dispatch must be visible at
    # default level — "never called" vs "called and failed"
    src = (Path(__file__).resolve().parent.parent / 'swap-provider' / 'plugin' / 'cln_lightning.py').read_text()
    fn = src[src.index('def callback_handler'):]
    assert '_logger.info(' in fn, 'callback dispatch must log at info'
    assert 'calling callback' in fn
    assert 'callback returned' in fn
