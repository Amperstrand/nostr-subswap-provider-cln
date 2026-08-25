import math
import asyncio
from typing import Optional
from pyln.client import RpcError, LightningRpc

from .cln_logger import PluginLogger
from .plugin_config import PluginConfig
from .transaction import PartialTxOutput, PartialTransaction
from .utils import TxBroadcastError

class CLNChainWallet:
    def __init__(self, *, plugin_rpc: LightningRpc, config: PluginConfig, logger: PluginLogger):
        self.rpc = plugin_rpc
        self.config = config
        self.logger = logger
        self.logger.debug("CLNChainWallet initialized")

    def create_transaction(self, *, outputs_without_change: [PartialTxOutput], rbf: bool) -> Optional[PartialTransaction]:
        """Assembles a signed PSBT spending to the passed outputs from the CLN wallet. Automatically adds change output."""
        output_sum_sat: int = int(sum([o.value for o in outputs_without_change]))
        tx_core_weight = 42
        spk_weights: int = sum([(len(o.scriptpubkey) + 9) * 4 for o in outputs_without_change])
        startweight: int = tx_core_weight + spk_weights  # weight of the tx without any inputs (required for CLN)
        # get inpts from CLN wallet using fundpsbt rpc call
        # CHANGE-SLACK (+1000 sat over the output sum): with
        # excess_as_change=true and an exact-satoshi ask, CLN selects
        # inputs so excess lands at dust and DROPS the change output ->
        # 'tx needs to have at least 1 output' on a HEALTHY wallet
        # (earned: 277k free, excess_msat=0, every ln_to_onchain funding failed)
        # CHANGE-SLACK ESCALATION: CLN's minimal coin selection returns
        # excess_msat as low as 0 REGARDLESS of the ask (excess depends on
        # UTXO granularity, not the satoshi parameter) — a 0-value change
        # output then kills the funding tx downstream ("tx needs to have
        # at least 1 output", earned live 2026-08-23: wire proof passed
        # at 06:47 by granularity luck, three GUI swaps failed at 07:43+).
        # Escalate the ask until excess clears dust; each re-ask asks CLN
        # to select for a larger target so excess grows with granularity.
        DUST_SAT = 546
        fundpsbt_response = None
        for attempt in range(4):
            ask_sat = output_sum_sat + 1000 + attempt * 2500
            try:
                resp = self.rpc.fundpsbt(satoshi=ask_sat,
                                                feerate=self.config.cln_feerate_str,
                                                startweight=startweight,
                                                minconf=None,
                                                # reserve=12 blocks (~6 min on mutinynet):
                                                # signpsbt REFUSES unreserved inputs,
                                                # but the DEFAULT 253-block reservation
                                                # LEAKS on every abandoned ask — four
                                                # dusty retries once froze 737k sat in
                                                # reservations ("all 1 available UTXOs",
                                                # earned live 2026-08-23). Short expiry
                                                # self-heals; spend releases immediately.
                                                reserve=12,
                                                excess_as_change=True)
            except Exception as e:
                # PluginLogger.error takes ONE arg (printf-style args crash
                # it — earned: the crash message replaced the real error)
                self.logger.error(f"create_transaction failed to call fundpsbt rpc: {e}")
                return None
            excess_sat = int(resp.get("excess_msat", 0)) // 1000
            if excess_sat >= DUST_SAT or attempt == 3:
                fundpsbt_response = resp
                break
            # release the dusty ask's reservation before re-asking, or the
            # escalation starves the wallet one UTXO-granule per attempt
            try:
                self.rpc.unreserveinputs(resp['psbt'])
            except Exception:
                pass  # best-effort; reserve=12 bounds any leak
            self.logger.info(f"fundpsbt excess {excess_sat} sat < dust "
                             f"({DUST_SAT}) — unreserved + escalating ask "
                             f"({ask_sat} -> {ask_sat + 2500})")
        raw_inputs_only_psbt = fundpsbt_response['psbt']

        # add outputs to inputs_only_psbt
        complete_psbt = PartialTransaction().from_raw_psbt(raw_inputs_only_psbt)
        complete_psbt.add_outputs(outputs_without_change)
        complete_psbt.set_rbf(rbf)
        complete_psbt_b64 = complete_psbt._serialize_as_base64()

        # sign psbt using CLN rpc call
        try:
           signed_psbt = self.rpc.signpsbt(complete_psbt_b64)["signed_psbt"]
        except Exception as e:
            self.logger.error(f"create_transaction failed to call signpsbt rpc: {e}")
            return None

        signed_psbt = PartialTransaction().from_raw_psbt(signed_psbt)
        signed_psbt.finalize_psbt()

        return signed_psbt

    def broadcast_transaction(self, signed_psbt: PartialTransaction) -> None:
        """Broadcasts a signed transaction to the bitcoin network."""
        # psbt = PartialTransaction().from_tx(signed_tx)._serialize_as_base64()
        # broadcast psbt
        try:
            res = self.rpc.sendpsbt(signed_psbt._serialize_as_base64())
            self.logger.debug(f"broadcasted tx: {res}")
        except RpcError as e:
            raise TxBroadcastError(e)

    async def get_local_height(self, retries_30sec: int = 20) -> int:
        """Returns the current block height of the cln backend."""
        # we retry a couple of times as cln can be out of sync on new blocks or startup for some time
        while True:
            try:
                response = self.rpc.getinfo()
            except RpcError as e:
                raise e
            if ('warning_bitcoind_sync' in response
                or 'warning_lightningd_sync' in response
                or not 'blockheight' in response):
                self.logger.warning(f"get_local_height: cln backend is not synced, waiting, response: {response}")
                if retries_30sec <= 0:
                    raise Exception(f"get_local_height: cln backend is not synced, response: {response}")
                retries_30sec -= 1
                await asyncio.sleep(30)
            else:
                break
        blockheight = response['blockheight']
        if response['network'] == 'bitcoin':
            assert blockheight > 869000, "get_local_height: cln backend returns invalid height"
        return blockheight

    def get_chain_fee(self, *, size_vbyte: int) -> int:
        """Uses CLN lightning-feerates to get required fee for given size. Fees are very conservative due to bitcoin core
        fee estimation algorithm."""
        speed_target_blocks = self.config.confirmation_speed_target_blocks
        try:
            feerates = self.rpc.feerates("perkb")
            feerates = feerates['perkb']['estimates']
        except (RpcError, TimeoutError) as e:
            feerates = []
            self.logger.error(f"get_chain_fee failed to call feerates rpc: {e}. Using fallback feerate")

        prev_blockcount, feerate_pervb = 0, None
        for feerate in feerates:  # get feerate closest to confirmation target todo: we could also interpolate
            if speed_target_blocks >= feerate['blockcount'] > prev_blockcount:
                prev_blockcount = feerate['blockcount']
                feerate_pervb = feerate['smoothed_feerate'] / 1000
        if feerate_pervb is None:
            # O4: CLN had no estimate (signet/mutinynet garbage estimates)
            # — try the mempool-style oracle before the static fallback.
            # Fail-open: oracle errors fall through, claims never block (R3).
            from . import fee_oracle
            oracle_url = getattr(self.config, "fee_oracle_url", None)
            oracle_fee = (fee_oracle.fetch_fee_sat_vb(oracle_url)
                          if oracle_url else None)
            if oracle_fee is not None:
                feerate_pervb = oracle_fee
                self.logger.info(f"get_chain_fee using oracle feerate "
                                 f"{oracle_fee} sat/vB (cln estimates empty)")
            else:
                feerate_pervb = self.config.fallback_fee_sat_per_vb
                self.logger.warning(f"get_chain_fee using fallback fee rate of {feerate_pervb} sat/vbyte because result"
                                    f" from cln rpc call was {feerates}")
        return math.ceil(feerate_pervb * size_vbyte)

    def get_receiving_address(self) -> str:
        """Returns a new receiving address from the CLN wallet.
        addresstype MUST be explicit: bare newaddr on v26.06 returns only
        {'p2tr': …} — indexing ['bech32'] crashed every real swap creation
        (KeyError('bech32'), earned 2026-08-19: dryruns quote fine because
        they never touch the server; first funded swap hit the crash)."""
        try:
            address = self.rpc.newaddr('bech32')['bech32']
        except RpcError as e:
            raise Exception("get_receiving_address failed to call newaddr rpc: " + str(e))
        return address

    def balance_sat(self) -> int:
        try:
            outputs = self.rpc.listfunds()['outputs']
        except RpcError as e:
            raise Exception("CLNChainWallet: balance_sat failed to call listfunds rpc: " + str(e))
        balance = 0
        for output in outputs:
            if output['status'] == 'confirmed' and output['reserved'] == False:
                balance += output['amount_msat'] // 1000
        return int(balance * 0.9)
