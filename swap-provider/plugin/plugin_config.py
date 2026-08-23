import attr
import os
import electrum_ecc as ecc
from electrum_aionostr import Relay
from dotenv import load_dotenv
from typing import Optional

from .cln_plugin import CLNPlugin
from .lnutil import hex_to_bytes, bytes_to_hex
from .json_db import StoredObject
from .cln_logger import PluginLogger
from . import constants
from .constants import AbstractNet, BitcoinMainnet, BitcoinTestnet, BitcoinSignet, BitcoinRegtest, SWEEP_GRACE_BLOCKS_DEFAULT


class PluginConfig:

    """Simple configuration class for swap server"""
    def __init__(self, *, nostr_secret: bytes, cln_configuration: dict, logger: PluginLogger):
        # lazy: keeps this module importable without the bitcoinrpc fork
        # (config/PoW tests must not need a running node)
        from .bitcoin_core_rpc import BitcoinRPCCredentials
        self.nostr_keypair = Keypair.from_private_key(nostr_secret) # plugin.derive_secret("NOSTRSECRET"))
        self.cln_config: dict = cln_configuration
        self.bcore_rpc_credentials = BitcoinRPCCredentials.from_cln_config_dict(cln_configuration)
        self.network = self.__parse_network_type(cln_configuration["network"]["value_str"])  # type: Optional[AbstractNet]
        self.nostr_relays: [str] = []
        self.swapserver_fee_millionths: int = 10_000
        self.confirmation_speed_target_blocks: int = 10
        self.fallback_fee_sat_per_vb:int = 60
        self.sweep_grace_blocks: int = SWEEP_GRACE_BLOCKS_DEFAULT
        self.logger = logger  # PluginLogger("swap-provider", plugin, level="DEBUG")

    @classmethod
    def from_cln_and_env(cls, *, cln_plugin_handler: CLNPlugin, logger: PluginLogger) -> 'PluginConfig':
        """Load configuration from .env file or environment variables"""
        load_dotenv()
        if nostr_secret_hex := os.getenv("NOSTR_SECRET_HEX"):
            logger.info(f"Found NOSTR_SECRET_HEX in env. Using it as Nostr secret to publish offers.")
            nostr_secret = bytes.fromhex(nostr_secret_hex.strip())
        else:
            logger.info(f"No NOSTR_SECRET_HEX found in env. Deriving from cln seed.")
            nostr_secret = cln_plugin_handler.derive_secret("NOSTRSECRET")
        config = PluginConfig(nostr_secret=nostr_secret,
                            cln_configuration=cln_plugin_handler.fetch_cln_configuration(),
                            logger=logger)
        constants.net = config.network

        # electrum 4.8.1 announcement PoW: current clients discard offers
        # whose pow_nonce doesn't reach the target bits. ANN_POW_NONCE
        # pins a pre-mined nonce (30-bit targets: mine externally with
        # ../nostr-pow-bench, ~90s rust / ~1s cuda); ANN_POW_TARGET below
        # 24 bits is mined in-process at startup (regtest/tests).
        from .offer import mine_ann_pow_nonce, nostr_ann_pow_bits
        config.ann_pow_target_bits = int(os.getenv("ANN_POW_TARGET_BITS", "30").strip())
        if pinned := os.getenv("ANN_POW_NONCE"):
            config.ann_pow_nonce = int(pinned.strip(), 0)
            achieved = nostr_ann_pow_bits(config.nostr_keypair.pubkey.hex()[2:],
                                          config.ann_pow_nonce)
            if achieved < config.ann_pow_target_bits:
                raise Exception(f"pinned ANN_POW_NONCE reaches only {achieved} bits "
                                f"(< target {config.ann_pow_target_bits}); clients would "
                                f"discard the offer. Mine a nonce for THIS nostr pubkey "
                                f"with ../nostr-pow-bench, or lower ANN_POW_TARGET_BITS.")
        elif config.ann_pow_target_bits <= 24:
            mined = mine_ann_pow_nonce(config.nostr_keypair.pubkey.hex()[2:],
                                       config.ann_pow_target_bits, deadline_s=120)
            if mined is None:
                raise Exception(f"in-process PoW mining did not reach "
                                f"{config.ann_pow_target_bits} bits in 120s")
            config.ann_pow_nonce = mined
        else:
            raise Exception(f"ANN_POW_TARGET_BITS={config.ann_pow_target_bits} "
                            f"requires ANN_POW_NONCE (pin a nonce mined with "
                            f"../nostr-pow-bench for pubkey "
                            f"{config.nostr_keypair.pubkey.hex()[2:]})")
        config.net_name = config.network.NET_NAME
        # ANN_NET_NAME decouples the nostr announcement tag from CLN's network:
        # mutinynet nodes run network=signet (shared genesis) yet MUST announce
        # net:mutinynet — the tag is the only wrong-network discriminator
        # electrum clients and the bridge worker have.
        if ann_net := os.getenv("ANN_NET_NAME", "").strip():
            from .constants import NETS_LIST
            if not any(net.NET_NAME == ann_net for net in NETS_LIST):
                raise Exception(
                    f"ANN_NET_NAME={ann_net} is not a known network "
                    f"({', '.join(n.NET_NAME for n in NETS_LIST)}) — refusing "
                    f"to announce an ambiguous network tag")
            config.net_name = ann_net

        if relays := os.getenv("NOSTR_RELAYS"):
            config.nostr_relays.extend(url.strip() for url in relays.split(","))
        else:
            raise Exception("No Nostr relays found. Set NOSTR_RELAYS as csv in env.")

        if fee_str := os.getenv("SWAP_FEE_PPM"):
            config.swapserver_fee_millionths = int(fee_str.strip())
        else:
            config.logger.warning(f"No swap fee in env. Using default value: {config.swapserver_fee_millionths}")

        # R3: honest advertised cap — the offer must not promise capacity
        # the node cannot fund (clamped again at server_update_pairs time)
        if max_amt := os.getenv("MAX_SWAP_AMOUNT"):
            config.max_swap_amount = int(max_amt.strip())
        else:
            config.max_swap_amount = 10_000_000
            config.logger.warning(f"No MAX_SWAP_AMOUNT in env. Advertising default "
                                  f"{config.max_swap_amount} (clamped to real capacity).")

        # Chain lookups: 'txindex' (default) or 'esplora'.
        # txindex: bitcoind must run -txindex (NOT prunable; ~25-30GB on
        #   signet) — zero external deps, works for every lookup.
        # esplora: raw-tx/height lookups via an esplora-API endpoint
        #   (mempool.space/signet, self-hosted esplora, or the lab's
        #   mempool-shim). bitcoind stays PRUNED and wallet-watch-only
        #   (address detection is wallet-based and prune-safe: lockups
        #   are imported at swap creation, needing only recent blocks).
        #   TRADEOFF: a third party (or your esplora) learns swap txids
        #   — acceptable on signet, think twice on mainnet; and the
        #   endpoint becomes swap-critical infrastructure.
        config.chain_lookup_mode = os.getenv("CHAIN_LOOKUP_MODE", "txindex").strip()
        if config.chain_lookup_mode not in ("txindex", "esplora"):
            raise Exception(f"CHAIN_LOOKUP_MODE must be txindex|esplora, got "
                            f"'{config.chain_lookup_mode}'")
        # endpoint list with fallback — the trustedcoin pattern (the
        # reference CLN plugin for explorer backends): every lookup
        # iterates the list until one answers; signet default is
        # mempool.space/signet (trustedcoin's own entire signet list)
        urls_csv = os.getenv("ESPLORA_URLS", "").strip()
        single = os.getenv("ESPLORA_URL", "").strip()
        config.esplora_urls = [u.rstrip("/") for u in urls_csv.split(",") if u.strip()] \
            or ([single.rstrip("/")] if single else [])
        if config.chain_lookup_mode == "esplora" and not config.esplora_urls:
            raise Exception("CHAIN_LOOKUP_MODE=esplora requires ESPLORA_URLS "
                            "(csv, tried in order) or ESPLORA_URL")

        if block_target := os.getenv("CONFIRMATION_TARGET_BLOCKS"):
            block_target = int(block_target.strip())
            if not 0 < block_target < 200:
               raise Exception("Invalid Block target. Use value between 0 and 200")
            config.confirmation_speed_target_blocks = block_target
        else:
            config.logger.warning(f"No CONFIRMATON_TARGET_BLOCKS found in env. "
                           f"Using default of {config.confirmation_speed_target_blocks}")

        if fallback_fee := os.getenv("FALLBACK_FEE_SATVB"):
            fallback_fee = int(fallback_fee.strip())
            if not 10 <= fallback_fee <= 300:
                raise Exception("FALLBACK_FEE_SATSVB is out of allowed range [10;300] ")
            else:
                config.fallback_fee_sat_per_vb = fallback_fee
        else:
            config.logger.warning(f"No FALLBACK_FEE_SATSVB set in env. Using default of {config.fallback_fee_sat_per_vb}")

        # O4 feerate oracle (mempool-style /v1/fees/recommended): used
        # when CLN has no estimate (signet/mutinynet). FEE_ORACLE_URL
        # pins an endpoint (self-hosted esplora/mempool); default derives
        # from the network. "off" disables; regtest has no default.
        from . import fee_oracle
        if (oracle := os.getenv("FEE_ORACLE_URL", "").strip()):
            config.fee_oracle_url = None if oracle.lower() == "off" else oracle
        else:
            config.fee_oracle_url = fee_oracle.default_oracle_url(config.network)
        if config.fee_oracle_url:
            config.logger.info(f"fee oracle: {config.fee_oracle_url}")
        else:
            config.logger.info("fee oracle: disabled (CLN estimates + static fallback only)")

        # issue #10: blocks past locktime before a funded lockup with no
        # LN commitment may be claimed; env-overridable
        if grace_blocks := os.getenv("SWEEP_GRACE_BLOCKS"):
            grace_blocks = int(grace_blocks.strip())
            if not 0 <= grace_blocks <= 100_000:
                raise Exception("SWEEP_GRACE_BLOCKS is out of allowed range [0;100000]")
            config.sweep_grace_blocks = grace_blocks
        else:
            config.logger.warning(f"No SWEEP_GRACE_BLOCKS set in env. "
                                  f"Using default of {config.sweep_grace_blocks}")

        if log_level := os.getenv("PLUGIN_LOG_LEVEL"):
            config.logger.change_level(log_level.strip())

        config.logger.debug(f"Loaded configuration: {config}")
        return config

    @staticmethod
    def __parse_network_type(network_type: str) -> AbstractNet:
        if network_type == "mainnet":
            return BitcoinMainnet()
        elif network_type == "testnet":
            return BitcoinTestnet()
        elif network_type == "signet":
            return BitcoinSignet()
        elif network_type == "regtest":
            return BitcoinRegtest()
        else:
            raise Exception(f"Invalid network type: {network_type}")

    @property
    def cln_feerate_str(self) -> str:
        if self.confirmation_speed_target_blocks < 12:
            feerate = "urgent"
        elif self.confirmation_speed_target_blocks < 100:
            feerate = "normal"
        else:
            feerate = "slow"
        return feerate

    @property
    def nostr_relays_csv(self) -> str:
        return ",".join(self.nostr_relays)

    def __str__(self):
        return f"nostr_pubkey={self.nostr_keypair.pubkey.hex()}, " \
               f"nostr_relays={self.nostr_relays}, " \
               f"swapserver_fee_millionths={self.swapserver_fee_millionths}, " \
               f"confirmation_speed_target_blocks={self.confirmation_speed_target_blocks}, " \
               f"fallback_fee_sat_per_vb={self.fallback_fee_sat_per_vb}, " \
               f"sweep_grace_blocks={self.sweep_grace_blocks})"


@attr.s
class OnlyPubkeyKeypair(StoredObject):
    pubkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)


@attr.s
class Keypair(OnlyPubkeyKeypair):
    privkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)

    @classmethod
    def from_private_key(cls, privkey: bytes) -> 'Keypair':
        pubkey: bytes = ecc.ECPrivkey(privkey).get_public_key_bytes()
        return cls(pubkey=pubkey, privkey=privkey)
