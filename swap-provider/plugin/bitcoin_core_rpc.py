import traceback

import attr
from bitcoinrpc import BitcoinRPC, RPCError as BitcoinRPCError
from typing import Optional, Tuple, List, Union
from httpx import Timeout as HttpxTimeout
import asyncio
import time
from decimal import Decimal

from .cln_logger import PluginLogger
from .lnutil import bytes_to_hex
from .transaction import Transaction, PartialTxInput, TxOutpoint
from .utils import TxMinedInfo, descsum_create
from .bitcoin import COIN

class BitcoinCoreRPC:
    def __init__(self, logger: PluginLogger,
                        bcore_rpc_credentials: 'BitcoinRPCCredentials' = None):
        self._wallet_name = "cln-subswapplugin"
        # PyPI bitcoinrpc selects wallets via the URL path (/wallet/<name>),
        # unlike the dead f321x fork's wallet_name kwarg
        self.iface = BitcoinRPC.from_config(
            url=f"{bcore_rpc_credentials.url}/wallet/{self._wallet_name}",
            auth=bcore_rpc_credentials.auth,)
        self._logger = logger
        self._network = bcore_rpc_credentials.network
        # lookup mode (txindex|esplora) + esplora base URL; set via
        # set_lookup_mode before _init when running under the plugin
        self._chain_lookup_mode = "txindex"
        self._esplora_urls = []

    async def _test_connection(self) -> None:
        """Test the connection to the Bitcoin Core node"""
        try:
            result = await self.iface.getblockchaininfo()
            self._logger.debug(f"ChainMonitor: Connected to Bitcoin Core: {result}")
            assert result["blocks"] > 10  # simple sanity check of result
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor: Could not connect to Bitcoin Core: {e}")

    async def _txindex_enabled(self) -> bool:
        """Check if txindex is enabled"""
        try:
            result = await self.iface.acall(method="getindexinfo", params=[], timeout=HttpxTimeout(5))
            self._logger.debug(f"ChainMonitor: _txindex_enabled: {result}")
            if not result.get("txindex", False) or not result["txindex"].get("synced", False):
                return False
            return True
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor _txindex_enabled: Could not get blockchain info: {e}")

    async def _create_or_load_wallet(self, wallet_name: str) -> None:
        """We create or load an existing wallet without private keys to look up addresses.
        This wallet won't be used for to control any funds, only to monitor addresses."""
        try:
            await self.iface.acall(method="loadwallet", params=[wallet_name, True], timeout=HttpxTimeout(5))
        except BitcoinRPCError as e:
            if e.error["code"] == -35:
                self._logger.debug("ChainMonitor _create_or_load_wallet: Wallet already loaded")
                return
            elif e.error["code"] == -18:
                self._logger.debug("ChainMonitor _create_or_load_wallet: Wallet not found, creating...")
            else:
                raise BitcoinCoreRPCError(f"ChainMonitor _create_or_load_wallet: Could not load wallet: {e}")

            # wallet is not loaded if we didn't return above
            try:
                await self.iface.acall(method="createwallet",
                                       params=[wallet_name, True, True, "", False, True, True, False],
                                       timeout=HttpxTimeout(5))
            except BitcoinRPCError as e:
                raise BitcoinCoreRPCError(f"ChainMonitor _create_or_load_wallet: Could not create wallet: {e}")

    async def _validate_wallet_name(self, wallet_name: str) -> None:
        """Check if the correct wallet is loaded (and not some other wallet, e.g. through other application)"""
        try:
            wallet_info = await self.iface.acall(method="getwalletinfo", params=[], timeout=HttpxTimeout(5))
            if wallet_info["walletname"] != wallet_name:
                raise WrongWalletLoadedError(f"ChainMonitor: Wallet name mismatch: {wallet_info['walletname']}")
        except BitcoinRPCError as e:
            raise BitcoinCoreRPCError(f"ChainMonitor: Could not get wallet info: {e}")

    async def _init(self):
        """Initialize the Bitcoin Core RPC connection. Retries: bitcoind
        (or its wallet) may still be starting when the plugin launches —
        a single-shot connect killed the plugin on fast lab resets and
        would kill it on any node restart race (port find #11)."""
        assert self.iface is not None, "ChainMonitor: Bitcoin Core RPC interface not set"
        assert self._logger is not None, "ChainMonitor: Logger not set"
        last_err = None
        for attempt in range(60):
            try:
                await self._test_connection()
                break
            except Exception as e:
                last_err = e
                if attempt % 6 == 0:
                    self._logger.info(f"ChainMonitor: waiting for Bitcoin Core: {e}")
                await asyncio.sleep(5)
        else:
            raise BitcoinCoreRPCError(f"ChainMonitor: bitcoind never came up: {last_err}")
        # txindex only required in txindex lookup mode; esplora mode keeps
        # bitcoind prunable (see plugin_config CHAIN_LOOKUP_MODE tradeoffs)
        if self._chain_lookup_mode == "txindex":
            if not await self._txindex_enabled():
                raise BitcoinCoreRPCError("ChainMonitor: txindex is not enabled "
                                          "(or set CHAIN_LOOKUP_MODE=esplora)")
        await self._create_or_load_wallet(self._wallet_name)
        await self._validate_wallet_name(self._wallet_name)
        while not await self.is_up_to_date():
            self._logger.info("ChainMonitor: Waiting for chain to sync")
            await asyncio.sleep(10)
        self._logger.debug("Bitcoin Core RPC connection: Initialized")

    async def is_up_to_date(self) -> bool:
        """We check if bcore is fully synced as best as we can"""
        try:
            result = await self.iface.getblockchaininfo()
            if result["blocks"] < 10:  # simple sanity check of result
                raise BitcoinCoreRPCError("ChainMonitor is_up_to_date: Not enough blocks")
            if not result["blocks"] == result["headers"]:
                return False

            blockheader = await self.iface.getblockheader(block_hash=result["bestblockhash"],
                                                          verbose=True)
            # freshness gate makes sense on live networks only: regtest
            # chains sit idle between lab actions (tip hours old), which
            # deadlocked the plugin's startup sync forever (port find #3)
            if self._network != "regtest" and \
                    blockheader["time"] < time.time() - 60 * 60:
                return False
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor is_up_to_date: Could not get blockchain info: {e}")
        return True

    async def register_address(self, address: str) -> None:
        """Add an address to the wallet so bitcoin core begins monitoring it. This should happen right after creation
        so we don't have to rescan which would be very slow."""

        # Create a descriptor for the address
        descriptor = descsum_create(f"addr({address})")

        # Create the import request
        import_request = [{
            "desc": descriptor,
            "timestamp": "now",  # Use "now" to avoid rescanning
            "internal": False,
            "active": False  # We only want to watch the address, not make it active
        }]

        try:
            result = await self.iface.acall(
                method="importdescriptors",
                params=[import_request],
                timeout=HttpxTimeout(5)
            )

            # Check the result array
            if not result or len(result) == 0:
                raise BitcoinCoreRPCError("ChainMonitor register_address: Empty response from importdescriptors")

            import_result = result[0]  # Get first (and only) result, because we only imported one descriptor

            # Check for success
            if not import_result['success']:
                # If there's an error object, use it
                if 'error' in import_result:
                    error_msg = import_result['error']
                    raise BitcoinCoreRPCError(f"ChainMonitor register_address: Import failed: {error_msg}")
                # If there are warnings, include them
                elif 'warnings' in import_result:
                    warnings = ', '.join(import_result['warnings'])
                    raise BitcoinCoreRPCError(f"ChainMonitor register_address: Import failed with warnings: {warnings}")
                else:
                    raise BitcoinCoreRPCError("ChainMonitor register_address: Import failed without specific error")

        except BitcoinRPCError as e:
            if e.error["code"] == -4:
                raise WrongWalletLoadedError(
                    f"ChainMonitor: Legacy wallet loaded in bitcoin core, we need a descriptor wallet {e}"
                )
            raise BitcoinCoreRPCError(f"ChainMonitor register_address: Could not import address: {e}")

    def set_lookup_mode(self, mode: str, esplora_urls: list[str] | str = "") -> None:
        self._chain_lookup_mode = mode
        self._esplora_urls = ([u.rstrip("/") for u in esplora_urls]
                              if isinstance(esplora_urls, list)
                              else ([esplora_urls.rstrip("/")] if esplora_urls else []))

    async def _esplora_get(self, path: str) -> Optional[dict | str]:
        # trustedcoin pattern: iterate endpoints until one answers;
        # transport errors AND 4xx both fall through to the next
        import aiohttp
        last_exc = None
        for base in self._esplora_urls:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{base}{path}",
                                           timeout=aiohttp.ClientTimeout(total=20)) as r:
                        if r.status in (400, 404):
                            return None  # esplora convention: unknown txid
                        r.raise_for_status()
                        ct = r.headers.get("Content-Type", "")
                        return await (r.json() if "json" in ct else r.text())
            except Exception as e:
                last_exc = e
                continue
        raise BitcoinCoreRPCError(f"esplora lookup {path} failed on all "
                                  f"{len(self._esplora_urls)} endpoints: {last_exc}")

    async def get_tx_height(self, txid_hex: str) -> TxMinedInfo:
        if self._chain_lookup_mode == "esplora":
            # esplora GET /tx/{txid}: status{confirmed, block_height,
            # block_hash, block_time} + top-level locktime — all TxMinedInfo
            # fields in ONE call (no blockheader round-trip needed)
            tx = await self._esplora_get(f"/tx/{txid_hex}")
            if tx is None:
                raise BitcoinCoreRPCError(f"ChainMonitor get_tx_height: esplora "
                                          f"does not know tx {txid_hex}")
            status = tx.get("status") or {}
            confirmed = status.get("confirmed", False)
            return TxMinedInfo(
                height=status.get("block_height") if confirmed else None,
                conf=1 if confirmed else 0,  # esplora gives no conf count; confirmed is what flows check
                timestamp=status.get("block_time") if confirmed else None,
                txpos=None,
                header_hash=status.get("block_hash") if confirmed else None,
                wanted_height=tx.get("locktime") if tx.get("locktime", 0) > 0 else None,
            )
        try:
            raw_tx = await self.iface.getrawtransaction(txid=txid_hex, verbose=True)

            height = None
            confirmations = raw_tx.get("confirmations", 0)
            if confirmations > 0:
                blockheader = await self.iface.getblockheader(block_hash=raw_tx["blockhash"], verbose=True)
                height = blockheader["height"]

            return TxMinedInfo(
                height=height,
                conf=confirmations,
                timestamp=raw_tx.get("blocktime", None),
                txpos=None,  # we don't have this info and don't need it
                header_hash=raw_tx.get("blockhash", None),
                wanted_height=raw_tx["locktime"] if raw_tx["locktime"] > 0 else None,
            )
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor get_tx_height: Could not get raw transaction {txid_hex}: {e}")

    async def get_transaction(self, txid_hex: str) -> Optional[Transaction]:
        """getrawtransaction into Transaction object"""
        self._logger.debug(f"ChainMonitor: get_transaction: {txid_hex}")
        if self._chain_lookup_mode == "esplora":
            raw = await self._esplora_get(f"/tx/{txid_hex}/hex")
            if raw is None:
                return None  # unknown tx — same contract as the -5 path below
            return Transaction(raw=raw)
        try:
            raw_tx = await self.iface.getrawtransaction(txid=txid_hex, verbose=False)
            return Transaction(raw=raw_tx)
        except BitcoinRPCError as e:
            if e.error["code"] == -5:  # No such mempool or blockchain transaction.
                return None
            raise BitcoinCoreRPCError(f"ChainMonitor get_transaction: Could not get raw transaction {txid_hex}: {e}")
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor get_transaction: Could not get raw transaction {txid_hex}: {e}")

    async def get_local_height(self) -> int:
        try:
            height = await self.iface.getblockcount()
            assert isinstance(height, int)
            assert height >= 10, f"ChainMonitor get_local_height: sanity check: Not enough blocks: {height}"
            return height
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor get_local_height: Could not get blockcount: {e}")

    async def get_addr_outputs(self, address: str) -> List[PartialTxInput]:
        """Getting utxos for the address in form of a PartialTxInput. The utxo will be marked spent
        if it has already been spent again"""
        funding_inputs: List[PartialTxInput] = []

        # get all transactions that spent to the address
        try:  # minconf, include_empty, include_watchonly, address_filter, include_immature_cb
            received = await self.iface.acall(method="listreceivedbyaddress",
                                              params=[0, True, True, address, False])
            utxos = await self.iface.acall(method="listunspent",
                                           params=[0, 9999999, [address]])
        except Exception:
            raise BitcoinCoreRPCError(f"ChainMonitor: get_addr_outputs call for {address} failed: {traceback.format_exc()}")
        if len(received) == 0:
            raise UnknownAddressError(f"ChainMonitor: get_addr_outputs: Address {address} hasn't been imported before")

        received_txids = received[0]['txids']  # all txids of transactions that spent to 'address'
        if len(received_txids) == 0:  # no txids, no utxos
            self._logger.debug(f"ChainMonitor: get_addr_outputs: Address {address} has no received txids")
            return funding_inputs

        for utxo in utxos:
            funding_inputs.append(await self._utxo_to_partial_txin(utxo))
        unspent_amount_sat = sum([utxo.value_sats() for utxo in funding_inputs])
        spent_amount = int(Decimal(str(received[0]['amount'])) * COIN) - unspent_amount_sat
        self._logger.debug(f"ChainMonitor: get_addr_outputs: Address {address} has "
                           f"{unspent_amount_sat} unspent sats and {spent_amount} spent sats")
        if spent_amount > 0:  # nothing received to the address has been spent yet
            # at least some utxos have been spent again already, so we have to fetch the spending txs
            spent_utxos = await self._fetch_spent_utxos(received_txids, spent_amount, address)
            if spent_amount - sum([utxo.value_sats() for utxo in spent_utxos]) > 0:
                raise UtxosNotFoundError(f"ChainMonitor: get_addr_outputs: "
                                           f"Could not find all spent utxos for {address}. "
                                         f"Found {sum([utxo.value_sats() for utxo in spent_utxos])} "
                                         f"out of {spent_amount}")
            funding_inputs.extend(spent_utxos)
        return funding_inputs

    async def _utxo_to_partial_txin(self, utxo: dict) -> PartialTxInput:
        """Convert a utxo dict to a PartialTxInput object"""
        future_prevout = TxOutpoint(txid=bytes.fromhex(utxo['txid']), out_idx=utxo['vout'])
        part_txin = PartialTxInput(prevout=future_prevout, is_coinbase_output=False)  # rpc call doesn't return coinbase outputs
        part_txin._trusted_address = utxo['address']
        part_txin._trusted_value_sats = int(Decimal(str(utxo['amount'])) * COIN)
        part_txin.block_height = await self.get_tx_height(utxo['txid'])
        part_txin.block_txpos = utxo.get('blockindex', None)
        part_txin.spent_height = utxo.get('spent_height', None)
        part_txin.spent_txid = utxo.get('spent_txid', None)
        return part_txin

    async def _fetch_spent_utxos(self, received_txids: List[str], spent_amount_sat: int,
                                 locking_addr: str) -> List[PartialTxInput]:
        skip_txs = 0  # amount of transactions to fetch
        spent_utxos = []

        # we look for the spending transactions and deduct the amount once found
        while spent_amount_sat > 0:
            try:
                wallet_txs = await self.iface.acall(method="listtransactions",
                                                    params=["*", 1 , skip_txs, True],
                                                    timeout=HttpxTimeout(5))
            except Exception as e:
                raise BitcoinCoreRPCError(f"ChainMonitor: _fetch_spent_utxos: Could not get wallet transactions: {e}")
            skip_txs += 1
            if len(wallet_txs) == 0 or skip_txs > 200:  # no more txs to fetch
                self._logger.debug(f"ChainMonitor: _fetch_spent_utxos: No more wallet txs to fetch "
                                   f"got {len(wallet_txs)} txs, fetched {skip_txs} txs")
                return spent_utxos
            wallet_send_tx = wallet_txs[0] if wallet_txs[0]["category"] == "send" else None
            if not wallet_send_tx:  # fetched tx was no outgoing tx, ignoring it
                continue
            full_spending_tx = await self.get_transaction(wallet_send_tx["txid"])
            for txin in full_spending_tx.inputs():
                if txin.prevout.txid.hex() in received_txids:
                    # the spending tx is spending an output of a transaction that also spent to our address
                    full_received_tx = await self.get_transaction(txin.prevout.txid.hex())  # tx we received to locking_addr
                    # now we have to find if the spent prevout was locked to our address
                    spent_output = full_received_tx.outputs()[txin.prevout.out_idx]
                    if spent_output.address == locking_addr:
                        # this is the utxo that has been spent again
                        utxo = {
                            "txid": txin.prevout.txid.hex(),
                            "vout": txin.prevout.out_idx,
                            "address": locking_addr,
                            "amount": spent_output.value,
                            "spent_height": wallet_send_tx.get("blockheight", 0),
                            "spent_txid": wallet_send_tx["txid"]
                        }
                        spent_utxos.append(await self._utxo_to_partial_txin(utxo))
                        spent_amount_sat -= spent_output.value
        return spent_utxos

    async def broadcast_raw_transaction(self, raw_tx: Union[bytes, str]) -> str:
        """Broadcast a raw transaction to the network"""
        raw_tx = bytes_to_hex(raw_tx)
        try:
            txid = await self.iface.acall(method="sendrawtransaction", params=[raw_tx], timeout=HttpxTimeout(5))
            return txid
        except BitcoinRPCError as e:
            raise BitcoinCoreRPCError(f"ChainMonitor: broadcast_raw_transaction: "
                                      f"Could not broadcast transaction {raw_tx}:\n{e}")


@attr.s(frozen=True, auto_attribs=True, kw_only=True)
class BitcoinRPCCredentials:
    """Credentials for Bitcoin Core RPC."""
    host: str
    port: int
    user: str
    password: str
    datadir: Optional[str] = None
    timeout: int = attr.ib(default=60, validator=attr.validators.instance_of(int))

    # CLN ≥24.11 omits default-valued configs from listconfigs entirely
    # (observed on v26.06: bitcoin-rpcport absent on regtest) — the
    # per-network default is used when the key is missing
    _NETWORK_DEFAULT_RPCPORT = {
        "bitcoin": 8332, "testnet": 18332, "signet": 38332, "regtest": 18443,
    }

    network: Optional[str] = None

    @classmethod
    def from_cln_config_dict(cls, cln_config: dict) -> "BitcoinRPCCredentials":
        """Load the credentials from the cln config dict fetched with lightning-listconfigs"""
        network = cln_config.get("network", {}).get("value_str", "bitcoin")
        rpcport_entry = cln_config.get("bitcoin-rpcport")
        port = (rpcport_entry or {}).get(
            "value_int", cls._NETWORK_DEFAULT_RPCPORT.get(network, 8332))
        return cls(
            host=cln_config["bitcoin-rpcconnect"]["value_str"],
            port=port,
            user=cln_config["bitcoin-rpcuser"]["value_str"],
            password=cln_config["bitcoin-rpcpassword"]["value_str"],
            datadir=cln_config.get("bitcoin-datadir", {}).get("value_str"),
            timeout=cln_config.get("bitcoin-rpcclienttimeout", {}).get("value_int", 60),
            network=network,
        )

    def __str__(self) -> str:
        """Return a string representation of the credentials for pretty debugging"""
        components = [
            f"Bitcoin RPC Credentials:",
            f"  URL: {self.url}",
            f"  User: {self.user}",
            f"  Password: {self.password}",
        ]
        if self.datadir:
            components.append(f"  Data Directory: {self.datadir}")
        components.append(f"  Timeout: {self.timeout}s")
        return '\n'.join(components)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def auth(self) -> Tuple[str, str]:
        """Auth format required for bitcoinrpc lib"""
        return self.user, self.password


class BitcoinCoreRPCError(Exception):
    pass

class WrongWalletLoadedError(Exception):
    pass

class BitcoinCoreNotConnectedError(Exception):
    pass

class UnknownAddressError(Exception):
    pass

class UtxosNotFoundError(Exception):
    pass
