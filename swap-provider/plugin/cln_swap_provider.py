import asyncio
from typing import Optional

from .cln_logger import PluginLogger
from .cln_plugin import CLNPlugin
from .cln_chain import CLNChainWallet
from .cln_lightning import CLNLightning
from .plugin_config import PluginConfig
from .chain_monitor import ChainMonitor
from .cln_storage import CLNStorage
from .health import build_report, tracker
from .json_db import JsonDB
from .submarine_swaps import SwapManager
from .utils import supervise, fatal_exit

# cadence of the pyln pipe late-death watchdog (#23): the dispatch
# thread is probed on a 30s sleep loop — the same cadence monitoring
# polls swapprovider-health, so a dead pipe is caught within one
# monitoring period
PYLN_WATCHDOG_INTERVAL_SEC = 30


class CLNSwapProvider:
    def __init__(
        self,
        plugin_handler: Optional[CLNPlugin] = None,
        logger: Optional[PluginLogger] = None,
        config: Optional[PluginConfig] = None,
        json_db: Optional[JsonDB] = None,
        chain_monitor: Optional[ChainMonitor] = None,
        cln_chain_wallet: Optional[CLNChainWallet] = None,
        cln_lightning: Optional[CLNLightning] = None,
        swap_manager: Optional[SwapManager] = None
    ):
        self.plugin_handler = plugin_handler
        self.logger = logger
        self.config = config
        self.json_db = json_db
        self.chain_monitor = chain_monitor
        self.cln_chain_wallet = cln_chain_wallet
        self.cln_lightning = cln_lightning
        self.swap_manager = swap_manager

    async def initialize(self):
        # cln plugin handler — swapprovider-health is registered up front:
        # the method must be in pyln's dispatch table before plugin.run()
        # answers lightningd's getmanifest. The handler answers honestly
        # at every stage (parts missing during init report as "starting")
        self.plugin_handler = await CLNPlugin(
            rpc_methods=[("swapprovider-health", self._swapprovider_health_rpc)])

        # logging to cln logs
        self.logger = PluginLogger("swap-provider", self.plugin_handler.plugin.log)

        # user config (from .env file or env)
        self.config = PluginConfig.from_cln_and_env(cln_plugin_handler=self.plugin_handler,
                                            logger=self.logger)
        # data storage using cln database trough rpc api
        storage = CLNStorage(db_string_writer=self.plugin_handler.plugin.rpc.datastore,
                             db_string_reader=self.plugin_handler.plugin.rpc.listdatastore,
                             logger=self.logger)
        # storage.wipe()
        self.json_db = JsonDB(s=storage.read(), storage=storage, logger=self.logger)


        self.chain_monitor = ChainMonitor(bcore_rpc_credentials=self.config.bcore_rpc_credentials,
                                          logger=self.logger)
        self.chain_monitor.set_lookup_mode(
            getattr(self.config, "chain_lookup_mode", "txindex"),
            getattr(self.config, "esplora_urls", []))
        await self.chain_monitor.run()

        # cln chain wallet
        self.cln_chain_wallet = CLNChainWallet(plugin_rpc=self.plugin_handler.plugin.rpc,
                                               config=self.config,
                                               logger=self.logger)

        # cln lightning handlers
        self.cln_lightning = CLNLightning(plugin_instance=self.plugin_handler,
                                          config=self.config,
                                          db=self.json_db,
                                          logger=self.logger)
        await self.cln_lightning.run()

        # swap manager
        self.swap_manager = SwapManager(wallet=self.cln_chain_wallet,
                                        lnworker=self.cln_lightning,
                                        db=self.json_db,
                                        chain_monitor=self.chain_monitor,
                                        plugin_config=self.config,
                                        logger=self.logger)

    def _swapprovider_health_rpc(self, plugin=None, **kwargs) -> dict:
        """`lightning-cli swapprovider-health`: read-only liveness
        snapshot (audit R2) — no side effects, safe to poll every 30s.
        Executed on the pyln dispatch thread; build_report touches only
        in-memory state under the tracker lock."""
        return build_report(self)

    async def _pyln_pipe_watchdog(self):
        """#23 pyln pipe late-death detection: if the dispatch thread
        dies (pipe closed / dispatcher crash) the asyncio side keeps
        serving hold-invoice state in blissful silence — probe
        thread_alive() every 30s and route to the r4 fatal policy.
        lightningd's own shutdown SIGTERMs us first, so reaching the
        fatal branch means the pipe died WITHOUT a signal."""
        while True:
            await asyncio.sleep(PYLN_WATCHDOG_INTERVAL_SEC)
            tracker.beat("pyln-plugin-thread")
            if not self.plugin_handler.thread_alive():
                fatal_exit(
                    "pyln plugin dispatch thread died — the RPC pipe is "
                    "gone while the process lives (late-death mode); "
                    "refusing the half-alive mode",
                    logger=self.logger)

    async def run(self):
        if not self.is_initialized:
            await self.initialize()
        # issue #17 supervision shape: an escaped watchdog death is
        # FATAL — silent loss of the late-death probe is itself the
        # half-alive mode it exists to catch
        supervise(asyncio.create_task(self._pyln_pipe_watchdog()),
                  logger=self.logger, name="pyln-pipe-watchdog",
                  on_death=lambda exc: fatal_exit(
                      f"pyln pipe watchdog died: {exc!r}",
                      logger=self.logger))
        # await asyncio.sleep(100000000)
        await self.swap_manager.main_loop()
        raise Exception("CLNSwapProvider main loop exited unexpectedly")

    @property
    def is_initialized(self) -> bool:
        if (self.plugin_handler
            and self.logger
            and self.config
            and self.json_db
            and self.cln_chain_wallet
            and self.cln_lightning
            and self.swap_manager
            and self.chain_monitor):
            return True
        return False
