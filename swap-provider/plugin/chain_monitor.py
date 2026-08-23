import asyncio
from typing import Callable, Optional, List

from .cln_logger import PluginLogger
from .bitcoin_core_rpc import BitcoinCoreRPC, BitcoinRPCCredentials
from .health import tracker
from .utils import supervise, fatal_exit


class ChainMonitor(BitcoinCoreRPC):
    def __init__(self, logger: PluginLogger, bcore_rpc_credentials: BitcoinRPCCredentials) -> None:
        """Takes the bitcoin core rpc config from cln and uses bcore as chain backend"""
        super().__init__(logger, bcore_rpc_credentials)
        self.callbacks = {}
        self.monitoring_task = None

    async def run(self) -> None:
        """Run the chain monitor"""
        await super()._init()
        # issue #17 (audit F02): the chain watch used to be fire-and-forget
        # — a death vanished with NO log line at all while the plugin kept
        # serving offers and hold-invoice HTLCs. DEATH POLICY: FATAL. Every
        # claim/refund/expiry action is driven by this loop; without it the
        # plugin is money-dead while looking alive, so it routes to the #16
        # policy (ERROR log + hard exit — lightningd / the restart policy
        # revive us). Transient RPC errors are NOT deaths: monitoring_loop
        # retries them every 10s with an ERROR log per pass.
        self.monitoring_task = supervise(
            asyncio.create_task(self.monitoring_loop()),
            logger=self._logger,
            name="chain-monitor",
            on_death=self._on_monitoring_death)

    def _on_monitoring_death(self, exc: BaseException) -> None:
        fatal_exit(
            f"chain-watch (monitoring_loop) died: {exc!r} — no claim/refund/"
            f"expiry handling can run; refusing the half-alive mode",
            logger=self._logger)

    async def monitoring_loop(self) -> None:
        """Main monitoring loop, triggering callbacks on each new block"""
        # issue #17: the initial height fetch used to run OUTSIDE any try
        # (before the loop) — a bitcoind hiccup at plugin start killed the
        # task instantly and silently. The baseline fetch now shares the
        # same retry-with-log loop as every later poll; only an exception
        # ESCAPING this loop (BaseException or a bug in the handler) is a
        # death, and run()'s supervision makes that fatal.
        last_height = None
        while True:
            try:
                blockheight = await self.get_local_height()
                # heartbeat: one beat per pass — a beat that goes stale
                # means the loop itself is wedged (a hanging RPC without
                # timeout), which the fatal policy cannot catch
                tracker.beat("chain-monitor", detail=f"height={blockheight}")
                if last_height is None:
                    last_height = blockheight
                elif blockheight > last_height:
                    self._logger.debug(f"ChainMonitor: New blockheight: {blockheight}")
                    if len(self.callbacks) > 0:
                        self._logger.debug(f"{len(self.callbacks)} monitored submarine swaps.")
                    last_height = blockheight
                    await self.trigger_callbacks()
                tracker.note_success("chain-monitor")
            except Exception as e:
                self._logger.error(f"ChainMonitor: Error in monitoring loop: {e}")
                # F12: bitcoind down = the r4 RETRY policy in action —
                # surfaced as a degraded-driving error streak, not a death
                tracker.note_error("chain-monitor", detail=f"rpc error: {e}")
            await asyncio.sleep(10)

    async def trigger_callbacks(self) -> None:
        """Trigger all callbacks for monitored addresses"""
        for callback in list(self.callbacks.values()):
            try:
                await callback()
            except Exception as e:
                self._logger.error(f"ChainMonitor: Error in chain callback: {e}")

    def add_callback(self, lookup_address, callback: Callable) -> None:
        self._logger.debug(f"ChainMonitor: Adding callback for address {lookup_address}")
        self.callbacks[lookup_address] = callback

    def remove_callback(self, lookup_address) -> None:
        self._logger.debug(f"ChainMonitor: Removing callback for address {lookup_address}")
        self.callbacks.pop(lookup_address, None)
