#!/usr/bin/env python3
"""
Core Lightning submarine swap provider plugin using the Electrum Nostr submarine swap protocol.
To run install requirements (pip install -r requirements.txt), then
cp swap-provider/* in the CLN plugin dir, or set plugin=/path/to/swap-provider.py in the CLN config to run.
"""

import asyncio
import os
import sys
import traceback
from plugin.cln_swap_provider import CLNSwapProvider


async def main():
    """main function starting the plugin"""
    swap_provider = CLNSwapProvider()
    try:
        await swap_provider.run()
    except BaseException as e:
        # issue #16: a crash must be VISIBLE (plugin.log at ERROR — the
        # old bare stderr print never reached the CLN log) and TERMINAL.
        # Returning from here would hand control back to asyncio.run,
        # which blocks forever joining the immortal monitoring threads
        # (loop.shutdown_default_executor) while the process keeps
        # serving the htlc hook — the half-alive zombie the audit
        # verified. BaseException on purpose: a CancelledError or
        # KeyboardInterrupt escaping run() must hard-exit too, or the
        # same executor join hangs. Supervised subsystems (issue #17,
        # e.g. the chain watch) route their fatal deaths here as well.
        details = f"swap provider plugin crashed: {e!r}\n{traceback.format_exc()}"
        logger = getattr(swap_provider, "logger", None)
        try:
            if logger is None:
                raise AttributeError  # not initialized yet — stderr fallback
            logger.error(details)
        except Exception:
            print(f"ERROR: {details}", file=sys.stderr, flush=True)
        os._exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        # issue #16: control can NEVER fall out of asyncio.run — its
        # cleanup joins the immortal monitoring threads forever (the
        # verified zombie hang). main() already hard-exits on every exit
        # path; this guard makes the hang structurally unreachable even
        # if a future edit adds an escape that bypasses the handler.
        os._exit(1)
