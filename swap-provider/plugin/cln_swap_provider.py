import asyncio
import time
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
        rpc_methods = [("swapprovider-health", self._swapprovider_health_rpc),
                       ("swapprovider-swaps", self._swapprovider_swaps_rpc)]
        if getattr(PluginConfig, "SWAP_MODE_DEFAULT", None) is None:
            # client RPCs register unconditionally (they no-op with a
            # clean error outside client mode); this keeps getmanifest
            # stable across SWAP_MODE changes without a restart race
            rpc_methods += [
                ("swapclient-offers", self._swapclient_offers_rpc),
                ("swapclient", self._swapclient_swap_rpc),
                ("swapclient-status", self._swapclient_status_rpc),
            ]
        self.plugin_handler = await CLNPlugin(rpc_methods=rpc_methods)

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
        # #36 HSM-split: inject the HSM derivation function so the
        # SwapManager can derive claim keys and preimages from CLN's HSM
        self.swap_manager.set_hsm_deriver(self.plugin_handler.derive_secret)
        # C4 early warning: bind hsm_secret at startup (loud alarm on
        # change; the per-swap claim-path pubkey check is the guard)
        self.swap_manager.verify_hsm_canary()

        # client mode (design 12): a client of electrum-protocol swap
        # servers -- discovery, gated reverse swaps, onchain claims.
        # Registered up front like the health RPC (same getmanifest
        # rule); no-ops unless SWAP_MODE=client.
        self._asyncio_loop = asyncio.get_running_loop()
        if self.config.swap_mode == "client":
            from .swap_client import SwapClient
            self.swap_client = SwapClient(
                plugin_rpc=self._plugin_rpc,
                config=self.config,
                logger=self.logger,
                chain_monitor=self.chain_monitor,
                wallet=self.cln_chain_wallet,
                db=self.json_db)
        else:
            self.swap_client = None

    async def _plugin_rpc(self, method: str, *args, **kwargs):
        """Thin async wrapper over the pyln pipe (client-mode RPCs:
        pay/getinfo/newaddr -- keyed params per the clnrest mandate)."""
        return await self.plugin_handler.plugin.rpc.__getattr__(method)(
            *args, **kwargs)

    def _swapclient_offers_rpc(self, plugin=None, **kwargs) -> dict:
        """`lightning-cli swapclient-offers`: currently discovered
        providers (kind 30315 with PoW+freshness gates applied)."""
        if self.swap_client is None:
            return {"error": "not in client mode (SWAP_MODE=client)"}
        return {"offers": [
            {"pubkey": o.server_pubkey, "fee_pct": o.percentage_fee,
             "mining_fee": o.mining_fee, "min": o.min_amount,
             "max_reverse": o.max_reverse, "age_s": int(time.time()) - o.timestamp}
            for o in self.swap_client.offers.values()]}

    def _swapclient_swap_rpc(self, plugin=None, amount_sat=None, **kwargs) -> dict:
        """`lightning-cli swapclient amount_sat=<n> [provider=<hex>]`:
        run one gated reverse swap (pay LN, receive onchain)."""
        if self.swap_client is None:
            return {"error": "not in client mode (SWAP_MODE=client)"}
        if not amount_sat:
            return {"error": "amount_sat required (satoshis)"}
        fut = asyncio.run_coroutine_threadsafe(
            self.swap_client.reverse_swap(
                lightning_amount_sat=int(amount_sat),
                provider=kwargs.get("provider")),
            self._asyncio_loop)
        try:
            return fut.result(timeout=400)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}

    def _swapclient_status_rpc(self, plugin=None, **kwargs) -> dict:
        """`lightning-cli swapclient-status`: our swap rows."""
        if self.swap_client is None:
            return {"error": "not in client mode (SWAP_MODE=client)"}
        out = []
        for k, s in self.swap_client.swaps.items():
            out.append({"payment_hash": k, "onchain": s.onchain_amount,
                        "state": "claimed" if s.is_redeemed else "open",
                        "spending_txid": s.spending_txid})
        return {"swaps": out}

    def _swapprovider_health_rpc(self, plugin=None, **kwargs) -> dict:
        """`lightning-cli swapprovider-health`: read-only liveness
        snapshot (audit R2) — no side effects, safe to poll every 30s.
        Executed on the pyln dispatch thread; build_report touches only
        in-memory state under the tracker lock."""
        return build_report(self)

    def _swapprovider_swaps_rpc(self, plugin=None, limit=None, **kwargs) -> dict:
        """`lightning-cli swapprovider-swaps [limit]`: recent swaps
        with traffic attribution (#24 r8) — {payment_hash, direction,
        state, requester_npub, attributed, onchain_amount, age_sec}.
        Read-only, in-memory records only; safe to poll. Monitoring
        surface: attribution NEVER gates stranger traffic."""
        from .attribution import list_recent_swaps
        return list_recent_swaps(self, limit=limit)

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
        if self.config.swap_mode == "client":
            # client mode: ONLY the client loops (offers + DM demux +
            # chain watcher). The server loops (hold invoices, offer
            # publishing, DM serving) never start -- client mode must
            # not carry server attack surface.
            await self.swap_client.run()
            raise Exception("swap client main loop exited unexpectedly")
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
