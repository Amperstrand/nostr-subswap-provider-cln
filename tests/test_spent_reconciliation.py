"""Spent-UTXO reconciliation must be immune to wallet-history
pagination exhaustion (security review 2026-08-31, hunter-3 F6).

Attack shape (d1): a client claims the lockup onchain (revealing the
preimage in the witness) and surrounds the claim with N > 200 dust
decoy outputs paid to the SAME lockup address. The legacy
reconciliation walks the WHOLE wallet's listtransactions ONE tx per
RPC (params ["*", 1, skip, True]) and bails after 200 pages — decoy
'receive' entries newer than the claim push the claim 'send' past the
bound, _fetch_spent_utxos returns short, get_addr_outputs raises
UtxosNotFoundError on every pass, extract_preimage never runs, the
hold invoices never settle, and the client's LN payment reverses at
CLTV while they keep the onchain claim.

The fix: outpoint-indexed reconciliation via gettxspendingprevout
(Core >= 24, batched — one RPC regardless of decoy count), with the
legacy walk kept verbatim as the fallback for older cores.
"""
import asyncio
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

PLUGIN_PARENT = Path(__file__).resolve().parent.parent / "swap-provider"
if str(PLUGIN_PARENT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_PARENT))
_stub = types.ModuleType("bitcoinrpc")
_stub.BitcoinRPC = object
_stub.RPCError = RuntimeError
sys.modules.setdefault("bitcoinrpc", _stub)

from plugin.bitcoin_core_rpc import (  # noqa: E402
    BitcoinCoreRPC, BitcoinCoreRPCError, UtxosNotFoundError)

ADDR = "tb1qfakefakefakefakefakefakefakefakefakeq"


class FakeLogger(SimpleNamespace):
    def __init__(self):
        super().__init__()
        self.lines = []

    def debug(self, msg, *a):
        self.lines.append(("debug", msg))

    def warning(self, msg, *a):
        self.lines.append(("warn", msg))

    def error(self, msg, *a):
        self.lines.append(("error", msg))

    def info(self, msg, *a):
        self.lines.append(("info", msg))


class FakeOutput:
    def __init__(self, address, value):
        self.address = address
        self.value = value


class FakeTx:
    def __init__(self, outputs, inputs=()):
        self._outputs = list(outputs)
        self._inputs = list(inputs)

    def outputs(self):
        return self._outputs

    def inputs(self):
        return self._inputs


class FakePrevout:
    def __init__(self, txid, out_idx):
        self.txid = bytes.fromhex(txid)
        self.out_idx = out_idx


class FakeTxin:
    def __init__(self, txid, vout):
        self.prevout = FakePrevout(txid, vout)


LOCKUP_TXID = "11" * 32
CLAIM_TXID = "22" * 32


def _raw_lockup_tx():
    return FakeTx([FakeOutput(ADDR, 20340)])


def _raw_claim_tx():
    return FakeTx([FakeOutput("tb1qotherotherotherotherotherotherothq", 20200)],
                  inputs=[FakeTxin(LOCKUP_TXID, 0)])


class FakeIface:
    """listtransactions yields `decoys` receive entries (newest first),
    then the claim 'send'. gettxspendingprevout is toggleable."""

    def __init__(self, decoys, support_prevout=True):
        self.decoys = decoys
        self.support_prevout = support_prevout
        self.calls = []          # (method, params) audit
        self.history = [{"category": "receive", "txid": f"{i:064x}"} for i in range(decoys)]
        self.history.append({"category": "send", "txid": CLAIM_TXID, "blockheight": 320100})

    async def acall(self, method, params=None, timeout=None):
        self.calls.append((method, params))
        if method == "listreceivedbyaddress":
            return [{"amount": 20340 / 1e8, "txids": [LOCKUP_TXID] + [f"{i:064x}" for i in range(self.decoys)]}]
        if method == "listunspent":
            return []
        if method == "listtransactions":
            skip = params[2]
            return self.history[skip:skip + 1]
        if method == "gettxspendingprevout":
            if not self.support_prevout:
                raise BitcoinCoreRPCError("Method not found")
            out = []
            for op in params[0]:
                if op["txid"] == LOCKUP_TXID:
                    out.append({"txid": CLAIM_TXID, "vin": 0, "height": 320100})
                else:
                    out.append({"txid": None})
            return out
        raise AssertionError(f"unexpected method {method}")

    async def getrawtransaction(self, txid, verbose=False):
        self.calls.append(("getrawtransaction", [txid]))
        if txid == LOCKUP_TXID:
            return _raw_lockup_tx()
        if txid == CLAIM_TXID:
            return _raw_claim_tx()
        # decoys: outputs to the same address (the attacker's dust)
        return FakeTx([FakeOutput(ADDR, 330)])


def _make_rpc(decoys, support_prevout=True):
    rpc = object.__new__(BitcoinCoreRPC)
    rpc._logger = FakeLogger()
    rpc.iface = FakeIface(decoys, support_prevout)
    rpc._chain_lookup_mode = "txindex"
    rpc._esplora_urls = []
    rpc._iface_fail_streak = 0
    rpc._addr_outpoint_cache = {}

    # route tx parsing around the real Transaction constructor: the unit
    # under test is the reconciliation logic, not tx deserialization
    async def _get_transaction(txid_hex):
        rpc.iface.calls.append(("getrawtransaction", [txid_hex]))
        if txid_hex == LOCKUP_TXID:
            return _raw_lockup_tx()
        if txid_hex == CLAIM_TXID:
            return _raw_claim_tx()
        return FakeTx([FakeOutput(ADDR, 330)])  # decoy dust

    async def _get_tx_height(txid_hex):
        return SimpleNamespace(height=320100, conf=1)

    rpc.get_transaction = _get_transaction
    rpc.get_tx_height = _get_tx_height
    return rpc


@pytest.mark.asyncio
async def test_dust_decoys_cannot_block_reconciliation():
    """250 decoys > the 200-page legacy bound; the prevout-indexed path
    must still find the claim spend (RED against the legacy-only code).
    """
    rpc = _make_rpc(decoys=250, support_prevout=True)
    result = await rpc.get_addr_outputs(ADDR)
    spent = [t for t in result if t.spent_txid == CLAIM_TXID]
    assert spent, "claim spend must be reconciled despite 250 dust decoys"
    assert spent[0].spent_height == 320100


@pytest.mark.asyncio
async def test_prevout_unavailable_falls_back_to_legacy_walk():
    """Core < 24 (method not found): the legacy walk still works when
    the decoy count is inside its bound."""
    rpc = _make_rpc(decoys=5, support_prevout=False)
    result = await rpc.get_addr_outputs(ADDR)
    assert any(t.spent_txid == CLAIM_TXID for t in result)


@pytest.mark.asyncio
async def test_mempool_spend_reports_spent_height_zero():
    """A spend still in mempool (height null) must report spent_height 0
    (mempool semantics preserved by the prevout path)."""
    rpc = _make_rpc(decoys=0, support_prevout=True)

    async def acall(method, params=None, timeout=None):
        if method == "listreceivedbyaddress":
            return [{"amount": 20340 / 1e8, "txids": [LOCKUP_TXID]}]
        if method == "listunspent":
            return []
        if method == "gettxspendingprevout":
            return [{"txid": CLAIM_TXID, "vin": 0, "height": None}]
        raise AssertionError(method)

    rpc.iface.acall = acall
    result = await rpc.get_addr_outputs(ADDR)
    spent = [t for t in result if t.spent_txid == CLAIM_TXID]
    assert spent and spent[0].spent_height == 0


@pytest.mark.asyncio
async def test_received_tx_outpoints_are_cached_across_passes():
    """Decoys must not become an RPC amplifier either: the received-tx
    parse is cached, so a second pass issues zero new getrawtransaction
    calls for known txids."""
    rpc = _make_rpc(decoys=3, support_prevout=True)
    await rpc.get_addr_outputs(ADDR)
    before = sum(1 for m, _ in rpc.iface.calls if m == "getrawtransaction")
    await rpc.get_addr_outputs(ADDR)
    after = sum(1 for m, _ in rpc.iface.calls if m == "getrawtransaction")
    assert after == before, "second pass must not re-fetch received txs"


@pytest.mark.asyncio
async def test_unresolvable_txid_is_not_cached_and_retries():
    """Re-review 2026-09-01 A1: a get_transaction None (esplora 404 for a
    wallet-known tx) must NOT poison the outpoint cache — the next pass
    retries it. (The old cache[txid] = [] permanently blinded the
    outpoint; once spent, UtxosNotFoundError every pass = the exhaustion
    class resurrected.)"""
    rpc = _make_rpc(decoys=0, support_prevout=True)
    state = {"fail_get": True}

    async def acall(method, params=None, timeout=None):
        if method == "listreceivedbyaddress":
            return [{"amount": 20340 / 1e8, "txids": [LOCKUP_TXID]}]
        if method == "listunspent":
            return []
        if method == "gettxspendingprevout":
            # once the funding resolves, the claim is visible to prevout
            return ([{"txid": CLAIM_TXID, "vin": 0, "height": 320100}]
                    if not state["fail_get"] else [{"txid": None}])
        raise AssertionError(method)

    async def get_tx(txid_hex):
        if txid_hex == LOCKUP_TXID and state["fail_get"]:
            return None  # esplora "unknown" for a tx the wallet knows
        if txid_hex == LOCKUP_TXID:
            return _raw_lockup_tx()
        if txid_hex == CLAIM_TXID:
            return _raw_claim_tx()
        return FakeTx([FakeOutput(ADDR, 330)])

    rpc.iface.acall = acall
    rpc.get_transaction = get_tx
    # first pass: the funding is spent-but-unresolvable -> fail LOUD
    # (retryable next pass) — and must not poison the cache
    with pytest.raises(UtxosNotFoundError):
        await rpc.get_addr_outputs(ADDR)
    assert LOCKUP_TXID not in rpc._addr_outpoint_cache[ADDR], \
        "negative result must never be cached"
    state["fail_get"] = False
    # next pass resolves it — the retry path the fix guarantees
    outs = await rpc.get_addr_outputs(ADDR)
    assert LOCKUP_TXID in rpc._addr_outpoint_cache[ADDR]
