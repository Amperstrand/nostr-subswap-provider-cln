import math
import asyncio
from typing import Optional
from pyln.client import RpcError, LightningRpc

from .cln_logger import PluginLogger
from .plugin_config import PluginConfig
from .transaction import PartialTxOutput, PartialTransaction
from .utils import TxBroadcastError

class CLNChainWallet:
    # issue #31: CLN refuses any wallet spend that would dip below the
    # min-emergency-msat reserve (utxopsbt error 313 "We would not have
    # enough left for min-emergency-msat", live 2026-08-28 15:26Z). This
    # is the fallback when listconfigs cannot be read; under-advertising
    # is the safe direction.
    MIN_EMERGENCY_FALLBACK_SAT = 25_000
    # upstream #9452 / plugin #35 (five lightningd cores on inr2
    # 2026-08-29 19:28-19:33Z): utxopsbt with excess_as_change=true
    # SIGABRTs the daemon in change_for_emergency when the unselected
    # wallet cannot cover the emergency reserve AND the change-from-excess
    # also cannot. The guard below refuses such fundings BEFORE the RPC;
    # this margin absorbs the tx fee + change fee + estimation drift at
    # the fallback feerate (60 sat/vB x ~250 vB). Conservative on
    # purpose — under-funding is a clean swap failure, over-funding is a
    # daemon crash-loop.
    FUNDING_FEE_MARGIN_SAT = 15_000

    def __init__(self, *, plugin_rpc: LightningRpc, config: PluginConfig, logger: PluginLogger):
        self.rpc = plugin_rpc
        self.config = config
        self.logger = logger
        self._min_emergency_sat = None
        self.logger.debug("CLNChainWallet initialized")

    @staticmethod
    def _is_plain_key_script(scriptpubkey_hex: str) -> bool:
        """True for plain wallet key scripts (P2WPKH 0014…/44, P2TR
        5120…/68). Everything else in the CLN wallet (P2WSH to_local /
        HTLC-timeout / anchor outputs, P2SH) is channel-close machinery
        with CSV/CLTV encumbrances — never valid funding input for a tx
        built at the current tip (issue #29)."""
        return ((len(scriptpubkey_hex) == 44 and scriptpubkey_hex[:4] == '0014')
                or (len(scriptpubkey_hex) == 68 and scriptpubkey_hex[:4] == '5120'))

    def create_transaction(self, *, outputs_without_change: [PartialTxOutput], rbf: bool) -> Optional[PartialTransaction]:
        """Assembles a signed PSBT spending to the passed outputs from the CLN wallet. Automatically adds change output."""
        output_sum_sat: int = int(sum([o.value for o in outputs_without_change]))
        tx_core_weight = 42
        spk_weights: int = sum([(len(o.scriptpubkey) + 9) * 4 for o in outputs_without_change])
        startweight: int = tx_core_weight + spk_weights  # weight of the tx without any inputs (required for CLN)
        # issue #29: select inputs ONLY from plain key-script outputs
        # (P2WPKH / P2TR of our keys) via an EXPLICIT utxo list. CLN's
        # fundpsbt pool includes the wallet's own channel-close machinery
        # outputs (to_local CSV, HTLC-timeout CLTV, anchors) — spendable
        # only under conditions a funding tx at the current tip does not
        # satisfy, so bitcoind rejects the whole tx at broadcast:
        #   sendpsbt -26 mandatory-script-verify-flag-failed
        #   (Locktime requirement not satisfied), input 0 …
        # (earned live 2026-08-26 19:31Z+, mutinynet 0be690ad…:4 /
        # 75829f98…:6 — deterministic whenever selection lands on them).
        # This CLN has no fundpsbt `exclusions` param (-32602,
        # live-probed), so we filter ourselves and hand the list to
        # utxopsbt. onchaind sweeps the machinery outputs into plain
        # wallet outputs on its own — excluding them loses nothing.
        # Stricter than the old fundpsbt minconf=None on purpose: only
        # confirmed+unreserved outputs are offered (no mempool-chain
        # funding of our own change).
        try:
            funds = self.rpc.listfunds()
        except Exception as e:
            self.logger.error(f"create_transaction failed to call listfunds rpc: {e}")
            return None
        free_utxos, excluded_utxos = [], []
        free_total_sat = 0
        for o in funds.get('outputs', []):
            selectable = (o.get('status') == 'confirmed'
                          and not o.get('reserved')
                          and self._is_plain_key_script(o.get('scriptpubkey', '')))
            if selectable:
                free_utxos.append(f"{o['txid']}:{o['output']}")
                free_total_sat += o['amount_msat'] // 1000
            else:
                excluded_utxos.append(f"{o['txid']}:{o['output']}")
        if excluded_utxos:
            self.logger.info(f"create_transaction: excluding {len(excluded_utxos)} "
                             "wallet output(s) from coin selection "
                             "(reserved/unconfirmed or channel-close machinery "
                             "with CSV/CLTV encumbrances — issue #29)")
        if not free_utxos:
            self.logger.error("create_transaction: no free plain-script utxos in "
                              f"the wallet ({len(excluded_utxos)} excluded, "
                              "issue #29) — cannot fund the lockup")
            return None
        # upstream #9452 crash-window guard: even selecting EVERYTHING
        # must leave the change above the emergency reserve + fee
        # headroom, else utxopsbt(excess_as_change=true) aborts
        # lightningd (assert only valid for entering change == 0 — our
        # excess IS the change). Refusing here converts a daemon
        # crash-loop into a clean swap failure. Evaluated at the MAX
        # escalation ask so every retry attempt stays inside the bound.
        ask_base_slack_sat, ask_step_sat, ask_attempts = 1000, 2500, 4
        max_ask_sat = output_sum_sat + ask_base_slack_sat + (ask_attempts - 1) * ask_step_sat
        headroom_needed = self.min_emergency_reserve_sat() + self.FUNDING_FEE_MARGIN_SAT
        if free_total_sat - max_ask_sat < headroom_needed:
            self.logger.error(
                f"create_transaction: refusing to fund — change would land in "
                f"the emergency-reserve crash window (upstream #9452): "
                f"{free_total_sat} sat free, max ask {max_ask_sat}, reserve "
                f"+ margin {headroom_needed}. Top up the wallet or lower "
                f"min-emergency-msat before this swap can fund.")
            return None
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
        funding_response = None
        for attempt in range(ask_attempts):
            ask_sat = output_sum_sat + ask_base_slack_sat + attempt * ask_step_sat
            try:
                resp = self.rpc.utxopsbt(satoshi=ask_sat,
                                                feerate=self.config.cln_feerate_str,
                                                startweight=startweight,
                                                utxos=free_utxos,
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
                self.logger.error(f"create_transaction failed to call utxopsbt rpc: {e}")
                return None
            excess_sat = int(resp.get("excess_msat", 0)) // 1000
            if excess_sat >= DUST_SAT or attempt == ask_attempts - 1:
                funding_response = resp
                break
            # release the dusty ask's reservation before re-asking, or the
            # escalation starves the wallet one UTXO-granule per attempt
            try:
                self.rpc.unreserveinputs(resp['psbt'])
            except Exception:
                pass  # best-effort; reserve=12 bounds any leak
            self.logger.info(f"utxopsbt excess {excess_sat} sat < dust "
                             f"({DUST_SAT}) — unreserved + escalating ask "
                             f"({ask_sat} -> {ask_sat + 2500})")
        raw_inputs_only_psbt = funding_response['psbt']

        # issue #30: utxopsbt RESERVED the selected inputs (reserve=12).
        # Every path below that abandons the ask WITHOUT spending them
        # must release the reservation, or failed funding rounds lock the
        # wallet until reservation expiry (live 2026-08-27/28: stale
        # reservations of 12,535 + 17,074 + 54,000 = 83,609 of 103,664
        # confirmed sat locked — a swap-dead provider until they aged out).
        try:
            # add outputs to inputs_only_psbt
            complete_psbt = PartialTransaction().from_raw_psbt(raw_inputs_only_psbt)
            complete_psbt.add_outputs(outputs_without_change)
            complete_psbt.set_rbf(rbf)
            complete_psbt_b64 = complete_psbt._serialize_as_base64()

            # sign psbt using CLN rpc call
            signed_psbt = self.rpc.signpsbt(complete_psbt_b64)["signed_psbt"]
        except Exception as e:
            self._unreserve_best_effort(raw_inputs_only_psbt)
            self.logger.error(f"create_transaction failed to assemble/sign the "
                              f"funding psbt (reserved inputs released): {e}")
            return None

        signed_psbt = PartialTransaction().from_raw_psbt(signed_psbt)
        signed_psbt.finalize_psbt()

        return signed_psbt

    def _unreserve_best_effort(self, psbt_b64: str) -> None:
        """issue #30: release a utxopsbt reservation on an abandoned ask.
        Must be the PSBT form — the bare-outpoint form was a live no-op on
        CLN v26.06 (issue #30 body); the reserve expiry bounds any failure
        of this call itself."""
        try:
            self.rpc.unreserveinputs(psbt_b64)
        except Exception as e:
            self.logger.warning(f"unreserveinputs failed (leak bounded by "
                                f"reservation expiry): {e}")

    def broadcast_transaction(self, signed_psbt: PartialTransaction) -> None:
        """Broadcasts a signed transaction to the bitcoin network."""
        # psbt = PartialTransaction().from_tx(signed_tx)._serialize_as_base64()
        # broadcast psbt
        try:
            res = self.rpc.sendpsbt(signed_psbt._serialize_as_base64())
            self.logger.debug(f"broadcasted tx: {res}")
        except RpcError as e:
            # issue #30: the tx never went out, so its inputs are not
            # spent — release their utxopsbt reservation now instead of
            # at expiry, or one failed broadcast per swap starves funding
            # rounds for the whole reserve window.
            self._unreserve_best_effort(signed_psbt._serialize_as_base64())
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

    def min_emergency_reserve_sat(self) -> int:
        """issue #31: CLN's min-emergency-msat — the floor no wallet
        spend may cross. Node config, so it is fetched once and cached.
        LIVE shape (2026-08-28, pyln socket RPC, CLN v26.06): the raw
        listconfigs result wraps every option under a 'configs' key —
        {'configs': {'min-emergency-msat': {'value_msat': 10000000,
        'source': …}}}. Probing the top level silently missed the key
        and fell back to 25,000 for three quotation ticks while the
        node was configured to 10,000 (live 2026-08-28 16:46-17:06Z:
        the accept gate rejected 20k swaps at '18,535 spendable' with
        true capacity 33,535)."""
        if self._min_emergency_sat is None:
            self._min_emergency_sat = self._read_min_emergency_sat()
        return self._min_emergency_sat

    def _read_min_emergency_sat(self) -> int:
        try:
            resp = self.rpc.listconfigs()
        except Exception as e:
            self.logger.warning(f"min_emergency_reserve_sat: listconfigs "
                                f"failed ({e}) — assuming CLN default "
                                f"{self.MIN_EMERGENCY_FALLBACK_SAT} sat")
            return self.MIN_EMERGENCY_FALLBACK_SAT
        # socket RPC wraps options under 'configs'; clnrest-style
        # renderings are flat — support both
        cfg = resp.get('configs', resp) if isinstance(resp, dict) else {}
        raw = cfg.get('min-emergency-msat') if isinstance(cfg, dict) else None
        msat = None
        if isinstance(raw, dict):
            msat = raw.get('value_msat')
        elif isinstance(raw, int):
            msat = raw
        elif isinstance(raw, str) and raw.endswith('msat'):
            msat = raw[:-len('msat')]
        if msat is None:
            # issue #31 follow-up (live-earned): the fallback direction is
            # SAFE (under-advertise) but silent-fallback hid a mis-parse
            # for 40 minutes — an unreadable reserve is ALWAYS loud
            self.logger.warning(f"min_emergency_reserve_sat: could not read "
                                f"min-emergency-msat (raw={raw!r}) — assuming "
                                f"CLN default {self.MIN_EMERGENCY_FALLBACK_SAT} sat")
            return self.MIN_EMERGENCY_FALLBACK_SAT
        return int(msat) // 1000

    def spendable_capacity_sat(self) -> int:
        """issue #31: what the wallet can actually fund — balance_sat()
        minus the emergency reserve. Advertising or accepting above this
        sells swaps CLN refuses to fund (live 2026-08-28: offer max
        67,475 vs a 44,232-sat swap refused at utxopsbt 313 with 43,954
        sat of payer HTLCs already parked)."""
        return int(self.balance_sat()) - self.min_emergency_reserve_sat()
