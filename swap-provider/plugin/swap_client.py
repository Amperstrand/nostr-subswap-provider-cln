"""swap_client.py -- CLIENT mode for the CLN swap plugin.

The provider plugin (server mode) serves electrum-protocol swaps over
nostr.  This module is the other half: a CLIENT of electrum-protocol
swap servers -- discover providers over nostr (kind 30315 offers +
PoW gate), run the reverse-swap lifecycle (pay Lightning, receive
onchain) with every validation the reference client performs, and
claim onchain once the provider's lockup confirms.

Pedigree: the 2026-08 clboss C++ client (../clboss branch
nostr-swaps, NOSTR-SWAP.md) proved this exact lifecycle end-to-end
on mutinynet -- and caught three bug classes that live in precisely
these checks (BE-vs-LE locktime forging, hash160 double-hashing,
underfunded-lockup claiming).  This module is that client's Python
twin: same decision table, same constants, and the SAME live e2e
values pin its tests (tests/test_swap_client.py).

DRY statement (designs 12/13): the electrum website, the C++ clboss
client, and this module implement ONE state machine; cli-swap.py
drives THIS implementation so the educational walkthrough can never
drift from the executable truth.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Optional

import electrum_aionostr as aionostr
from electrum_aionostr.key import PrivateKey
from electrum_ecc import ECPrivkey

from .bitcoin import script_to_p2wsh
from .constants import MAX_LOCKTIME_DELTA, MIN_LOCKTIME_DELTA
from .crypto import ripemd, sha256
from .offer import nostr_ann_pow_bits
from .submarine_swaps import (CLAIM_FEE_SIZE, NostrTransport, SwapData,
                              create_claim_tx)
from .utils import now as get_now


class SwapClientError(Exception):
    """A refused swap (validation gate, transport, or quote)."""


def decode_script_num(data: bytes) -> int:
    """CScriptNum decode -- verbatim Bitcoin Core semantics: minimal
    LITTLE-endian, sign bit in the top bit of the last byte.

    The live e2e claim witness (2026-08-25) proved the wire form:
    push bytes 1f 7c 33 == 3374111.  A big-endian reader here is the
    exact bug class (NOSTR-SWAP.md 14) that let a malicious provider
    forge an immediately-refundable locktime while the client
    validated an in-window one -- which is why every locktime check
    in this module goes through this decoder and nothing else.
    """
    if not data:
        return 0
    if data[-1] & 0x80:
        # negative CScriptNum: nonsense for a locktime
        return -1
    result = 0
    for i, b in enumerate(data):
        result |= b << (8 * i)
    return result


def encode_script_num(n: int) -> bytes:
    """CScriptNum encode (electrum add_number_to_script twin):
    minimal little-endian, high-zero byte appended when the top bit
    would read as the sign.  Used by tests to build scripts and by
    nothing on the money path (the client never constructs these
    scripts -- it only parses and compares)."""
    if n == 0:
        return b'\x00'
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    out = bytearray()
    v = n
    while v:
        out.append(v & 0xFF)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0x00)
    return bytes([len(out)]) + bytes(out)


def build_lockup_script(payment_hash: bytes, claim_pubkey: bytes,
                        locktime: int, refund_pubkey: bytes) -> bytes:
    """Build the electrum lockup script (test/helper twin of the
    C++ generator; the live witness pinned this exact layout).

    NOTE the hash slot: the IF branch hashes the PREIMAGE pushed in
    the spending witness, so the slot is HASH160(preimage) =
    ripemd160(payment_hash) -- payment_hash IS sha256(preimage).
    Feeding sha256(payment_hash) here double-hashes and produces a
    script nobody can spend (the exact bug the C++ twin's test
    caught once; pinned by test_swap_client.py)."""
    def push(b: bytes) -> bytes:
        assert len(b) < 0x4c
        return bytes([len(b)]) + b
    return (
        bytes.fromhex('8201208763a9')         # OP_SIZE PUSH1-32 OP_EQUAL OP_IF OP_HASH160
        + push(ripemd(payment_hash))
        + bytes.fromhex('88')                  # OP_EQUALVERIFY
        + push(claim_pubkey)
        + bytes.fromhex('6775')                # ELSE DROP
        + encode_script_num(locktime)
        + bytes.fromhex('b175')                # OP_CLTV OP_DROP
        + push(refund_pubkey)
        + bytes.fromhex('68ac')                # ENDIF CHECKSIG
    )


def parse_redeem_script(redeem_script: bytes) -> dict:
    """Byte-level parse of the electrum lockup template; returns
    {hash160, claim_pubkey, locktime, refund_pubkey}.  Raises
    SwapClientError on any shape mismatch (never return garbage).

    Layout (WITNESS_TEMPLATE_REVERSE_SWAP, live-witness verified):
      OP_SIZE PUSH1-32 OP_EQUAL OP_IF
        OP_HASH160 PUSH1-20 <hash160> OP_EQUALVERIFY
        PUSH1-33 <claim pubkey>        ; OURS on the preimage path
      OP_ELSE
        OP_DROP <CScriptNum locktime> OP_CLTV OP_DROP
        PUSH1-33 <refund pubkey>      ; provider, after locktime
      OP_ENDIF OP_CHECKSIG
    """
    def fail(why: str):
        raise SwapClientError(f'redeemScript malformed: {why}')

    if len(redeem_script) < 45:
        fail('too short')
    if redeem_script[:7] != bytes.fromhex('8201208763a914'):
        fail('prefix')
    h160 = redeem_script[7:27]
    if redeem_script[27:29] != bytes.fromhex('8821'):
        fail('EQUALVERIFY/PUSH33')
    claim_pubkey = redeem_script[29:62]
    if redeem_script[62:64] != bytes.fromhex('6775'):
        fail('ELSE/DROP')
    n = redeem_script[64]
    if n == 0x00 or 0x51 <= n <= 0x60:
        locktime_bytes = b'' if n == 0 else bytes([n])
        body = redeem_script[65:]
    elif 1 <= n <= 5:
        locktime_bytes = redeem_script[65:65 + n]
        body = redeem_script[65 + n:]
    else:
        fail(f'locktime push length {n}')
    if body[:3] != bytes.fromhex('b17521'):
        fail('CLTV/DROP/PUSH33')
    refund_pubkey = body[3:36]
    if body[36:38] != bytes.fromhex('68ac'):
        fail('ENDIF/CHECKSIG')
    locktime = decode_script_num(locktime_bytes)
    if locktime < 0:
        fail('negative locktime')
    return {'hash160': h160, 'claim_pubkey': claim_pubkey,
            'locktime': locktime, 'refund_pubkey': refund_pubkey}


def validate_reply(*, reply: dict, preimage: bytes, claim_pubkey: bytes,
                   height: int, expected_onchain: int, net) -> None:
    """Every gate between 'bytes arrived' and 'we may pay'.

    Each check exists because its absence cost funds or availability
    somewhere (NOSTR-SWAP.md 14 + the C++ client's bug ledger):
      1. script SHAPE parses (template exactness);
      2. hash160 slot == ripemd160(sha256(preimage)) -- the script
         must pay OUR hash, else the preimage we reveal onchain
         settles someone else's invoice;
      3. claim-key slot == OURS -- else we cannot spend the preimage
         path (the direction trap: our key on the refund branch
         instead lets the provider walk away with the lockup);
      4. script locktime == declared timeoutBlockHeight under the
         TRUE little-endian decoding -- a mismatch here is the
         forged-refund-window attack shape (advisory 14);
      5. lockupAddress == P2WSH(script);
      6. timeout within MIN..MAX locktime-delta of current height;
      7. onchain amount equals the quoted expectation (off-by-one
         tolerated, electrum parity).
    """
    redeem_script = bytes.fromhex(reply['redeemScript'])
    parsed = parse_redeem_script(redeem_script)

    if parsed['hash160'] != ripemd(sha256(preimage)):
        raise SwapClientError('script does not commit to our preimage hash')
    if parsed['claim_pubkey'] != claim_pubkey:
        raise SwapClientError('script claim key is not ours (direction trap)')
    declared = reply['timeoutBlockHeight']
    if parsed['locktime'] != declared:
        raise SwapClientError(
            f'script locktime {parsed["locktime"]} != declared {declared} '
            '(LE decode; mismatch == forged refund window)')
    if script_to_p2wsh(redeem_script, net=net) != reply['lockupAddress']:
        raise SwapClientError('lockupAddress does not match redeemScript')
    if not (MIN_LOCKTIME_DELTA <= declared - height <= MAX_LOCKTIME_DELTA):
        raise SwapClientError(
            f'timeout {declared} outside window '
            f'[{height + MIN_LOCKTIME_DELTA}, {height + MAX_LOCKTIME_DELTA}]')
    onchain = reply['onchainAmount']
    if not (expected_onchain - 1 <= onchain <= expected_onchain):
        raise SwapClientError(f'onchain {onchain} != quoted {expected_onchain}')


class ClientOffer:
    """A kind-30315 offer with electrum's gates applied (freshness,
    PoW) and the server's pricing."""

    def __init__(self, event, pow_target: int):
        content = json.loads(event.content)
        self.server_pubkey = event.pubkey
        self.timestamp = event.created_at
        self.percentage_fee = float(content['percentage_fee'])
        self.mining_fee = int(content['mining_fee'])
        self.min_amount = int(content['min_amount'])
        self.max_forward = int(content['max_forward_amount'])
        self.max_reverse = int(content['max_reverse_amount'])
        self.relays = [r for r in content.get('relays', '').split(',') if r]
        pow_nonce = int(content.get('pow_nonce', '0'), 16)
        now = get_now()
        if not (now - 3600 <= self.timestamp <= now + 3600):
            raise SwapClientError(
                f'stale/future offer {self.server_pubkey[:8]}')
        if nostr_ann_pow_bits(self.server_pubkey, pow_nonce) < pow_target:
            raise SwapClientError(
                f'PoW below target {self.server_pubkey[:8]}')

    def quote_onchain(self, lightning_amount_sat: int) -> Optional[int]:
        """Expected onchain sats for an LN amount -- the pricing the
        server itself applied when publishing the offer."""
        fee = int(lightning_amount_sat * self.percentage_fee / 100) \
            + self.mining_fee
        onchain = lightning_amount_sat - fee
        return onchain if onchain > 0 else None


class SwapClient:
    """Client-mode state machine (NOSTR-SWAP.md 8.1):

    Idle -> Solicit -> Quoted -> SwapSent -> Validating -> Paying ->
    LockupWait -> Claiming -> Claimed.  Any gate failure refuses the
    swap; parked HTLCs return to us at their own CLTV, so a refused
    or stalled swap costs at most the settled prepay.
    """

    def __init__(self, *, plugin_rpc, config, logger, chain_monitor,
                 wallet, db):
        self.plugin_rpc = plugin_rpc
        self.config = config
        self.logger = logger
        self.lnwatcher = chain_monitor
        self.wallet = wallet
        self.db = db
        # client swaps keyed by our payment_hash hex; SwapData reused
        # so the persisted shape matches the jsondb's stored rules
        self.swaps = self.db.get_dict('swap_client_swaps')
        self.offers: dict[str, ClientOffer] = {}
        self.transport: Optional[NostrTransport] = None

    # ---- nostr client half ----------------------------------------

    async def run(self):
        """Client loops: relay connection + offer polling + the DM
        demux (reused wholesale from the server transport -- its
        check_direct_messages resolves reply_to futures regardless of
        role, and sm.is_server=False simply means we never dispatch
        incoming requests; only the offer PUBLISHER is skipped)."""
        self.transport = NostrTransport(config=self.config,
                                         sm=self._server_view())
        await self.transport.relay_manager.connect()
        self.transport.is_connected.set()
        while True:
            try:
                await self._poll_offers_once()
            except Exception:
                import traceback
                self.logger.error(
                    f'offer poll failed: {traceback.format_exc()}')
            await asyncio.sleep(60)

    def _server_view(self):
        client = self

        class _SM:
            # the transport touches sm.db (processed-event ids),
            # sm.is_server (request dispatch) and sm.config
            is_server = False
            db = client.db
            config = client.config
        return _SM()

    async def _poll_offers_once(self):
        now = int(time.time())
        query = {
            'kinds': [NostrTransport.STATUS_NIP38], 'limit': 30,
            '#d': [f'electrum-swapserver-'
                   f'{NostrTransport.NOSTR_EVENT_VERSION}'],
            '#r': [f'net:{self.config.net_name}'],
            'since': now - 3600,
        }
        best: dict[str, ClientOffer] = {}
        async for ev in self.transport.relay_manager.get_events(
                query, single_event=False, only_stored=False):
            try:
                offer = ClientOffer(ev, self.config.ann_pow_target_bits)
            except SwapClientError as e:
                self.logger.info(f'offer rejected: {e}')
                continue
            old = best.get(offer.server_pubkey)
            if old is None or offer.timestamp > old.timestamp:
                best[offer.server_pubkey] = offer
        self.offers = best
        self.logger.info(f'client: {len(best)} eligible offers')

    async def send_request(self, server_pubkey: str, method: str,
                           request_data: dict, timeout: float = 60.0) -> dict:
        """Kind-25582 NIP-04 DM round trip with reply PINNING: the
        correlated reply must carry event_pubkey == the server we
        asked -- a relay-injected spoof quoting a stolen reply_to
        fails the pin even if decryption succeeds."""
        priv = PrivateKey(self.config.nostr_keypair.privkey)
        envelope = dict(request_data)
        envelope['method'] = method
        enc = priv.encrypt_message(json.dumps(envelope), server_pubkey)
        event_id = await aionostr._add_event(
            self.transport.relay_manager, kind=25582, content=enc,
            private_key=self.transport.nostr_private_key,
            tags=[['p', server_pubkey]])
        # single-keyed: the transport's DM loop resolves
        # dm_replies[reply_to] (its own shape)
        fut = asyncio.get_event_loop().create_future()
        self.transport.dm_replies[event_id] = fut
        try:
            reply = await asyncio.wait_for(fut, timeout)
        finally:
            self.transport.dm_replies.pop(event_id, None)
        if reply.get('event_pubkey') != server_pubkey:
            raise SwapClientError('reply sender != requested server (pin)')
        if 'error' in reply:
            raise SwapClientError(
                f'server error (DO NOT TRUST the text): '
                f'{reply["error"]!r}')
        return reply

    # ---- swap lifecycle -------------------------------------------

    def pick_provider(self, lightning_amount_sat: int,
                      provider: Optional[str] = None) -> ClientOffer:
        if provider is not None:
            offer = self.offers.get(provider)
            if offer is None:
                raise SwapClientError(
                    f'provider {provider[:8]} not discovered')
            if not (offer.min_amount <= lightning_amount_sat
                    <= offer.max_reverse):
                raise SwapClientError('amount outside provider window')
            return offer
        capable = [o for o in self.offers.values()
                   if o.min_amount <= lightning_amount_sat <= o.max_reverse]
        if not capable:
            raise SwapClientError(
                'no discovered provider covers the amount')
        # cheapest quote wins (largest onchain for the LN amount)
        capable.sort(key=lambda o: o.quote_onchain(lightning_amount_sat)
                     or 1 << 60, reverse=True)
        return capable[0]

    async def reverse_swap(self, *, lightning_amount_sat: int,
                           provider: Optional[str] = None) -> dict:
        """Pay LN, receive onchain: the full gated lifecycle."""
        offer = self.pick_provider(lightning_amount_sat, provider)
        server = offer.server_pubkey
        expected_onchain = offer.quote_onchain(lightning_amount_sat)
        if expected_onchain is None:
            raise SwapClientError('fee exceeds amount at this provider')

        privkey = os.urandom(32)
        claim_pubkey = ECPrivkey(privkey).get_public_key_bytes(
            compressed=True)
        preimage = os.urandom(32)
        payment_hash = sha256(preimage)
        height = (await self.plugin_rpc('getinfo'))['blockheight']

        reply = await self.send_request(server, 'createswap', {
            'type': 'reversesubmarine',
            'pairId': 'BTC/BTC',
            'invoiceAmount': lightning_amount_sat,
            'preimageHash': payment_hash.hex(),
            'claimPublicKey': claim_pubkey.hex(),
        })

        # every gate before any sats move
        validate_reply(reply=reply, preimage=preimage,
                       claim_pubkey=claim_pubkey, height=height,
                       expected_onchain=expected_onchain,
                       net=self.config.network)

        swap = SwapData(
            is_reverse=True,
            locktime=reply['timeoutBlockHeight'],
            onchain_amount=reply['onchainAmount'],
            lightning_amount=lightning_amount_sat,
            redeem_script=reply['redeemScript'],
            preimage=preimage.hex(),
            privkey=privkey.hex(),
            lockup_address=reply['lockupAddress'],
            payment_hash=payment_hash,
            is_redeemed=False,
            funding_txid=None,
            spending_txid=None,
        )
        swap._payment_hash = payment_hash.hex()
        # persist claim material BEFORE paying (crash safety)
        self.swaps[payment_hash.hex()] = swap
        self.db.write()

        # prepay first, then main: both park at the provider's hold
        # invoices and are bundled (R4) -- neither settles until the
        # preimage is public, so the order is cosmetic
        for field in ('minerFeeInvoice', 'invoice'):
            inv = reply.get(field)
            if inv:
                await self.plugin_rpc('pay', inv)

        # hand to the chain watcher: claims on >=1 confirmation with
        # the R2 amount gate inside
        self.lnwatcher.add_callback(
            swap.lockup_address,
            lambda: self.claim_swap(payment_hash.hex()))
        return {
            'payment_hash': payment_hash.hex(),
            'lockup_address': swap.lockup_address,
            'onchain_amount': swap.onchain_amount,
            'provider': server,
            'timeout': swap.locktime,
        }

    async def _height(self) -> int:
        return (await self.plugin_rpc('getinfo'))['blockheight']

    async def claim_swap(self, payment_hash_hex: str) -> Optional[str]:
        """Watch-and-claim pass for one swap (idempotent; the chain
        monitor re-invokes it on every lockup movement).  Gates,
        mirroring the validated C++ scanner (NOSTR-SWAP.md 10.8):
          R2  exact (or greater) onchain amount before the preimage
              is revealed -- underfunded lockups are skipped loudly;
          R1  >=1 confirmation on the lockup before spending;
              timeout >10 blocks out (near-expiry claims skipped).
        """
        swap = self.swaps.get(payment_hash_hex)
        if swap is None or swap.is_redeemed:
            return None
        redeem_script = bytes.fromhex(swap.redeem_script)
        preimage = bytes.fromhex(swap.preimage)
        claim_pubkey = ECPrivkey(bytes.fromhex(swap.privkey)) \
            .get_public_key_bytes(compressed=True)

        addr_infos = await self.lnwatcher.get_addr_outputs(
            swap.lockup_address)
        height = await self._height()
        for txin in addr_infos:
            if txin.value_sats() < swap.onchain_amount:
                self.logger.warning(
                    f'lockup underfunded ({txin.value_sats()} < '
                    f'{swap.onchain_amount}); NOT revealing preimage')
                continue
            txheight = await self.lnwatcher.get_tx_height(
                txin.prevout.txid.hex())
            if txheight.conf <= 0:
                continue
            if swap.locktime <= height + 10:
                self.logger.warning('timeout too near; not claiming')
                continue
            addr = await self.plugin_rpc('newaddr', addresstype='bech32')
            fee = self.wallet.get_chain_fee(size_vbyte=CLAIM_FEE_SIZE)
            tx = create_claim_tx(
                txin=txin, witness_script=redeem_script,
                address=addr['bech32'],
                amount_sat=txin.value_sats() - fee,
                locktime=height + 1)
            # P2WSH signing via the generic path: register our key,
            # let PartialTransaction.sign build sig+script witnesses
            txin.pubkeys = [claim_pubkey]
            txin.num_sig = 1
            tx.sign({claim_pubkey: bytes.fromhex(swap.privkey)})
            # preimage goes in the witness stack between sig & script
            tx.inputs()[0].witness.insert(1, preimage)
            self.wallet.broadcast_transaction(tx)
            swap.spending_txid = tx.txid()
            swap.is_redeemed = True
            self.db.write()
            self.logger.info(f'client claim broadcast: {swap.spending_txid}')
            return swap.spending_txid
        return None
