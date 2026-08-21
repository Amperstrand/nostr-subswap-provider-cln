import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "swap-provider"))
_stub = types.ModuleType("bitcoinrpc")
_stub.BitcoinRPC = object
_stub.RPCError = RuntimeError
sys.modules.setdefault("bitcoinrpc", _stub)

from plugin.bitcoin_core_rpc import BitcoinCoreRPC  # noqa: E402


class _Iface:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def acall(self, method, params, timeout):
        self.calls.append((method, params))
        return self.result


class _Mon(BitcoinCoreRPC):
    def __init__(self, result):
        self.iface = _Iface(result)
        self._logger = type("L", (), {"debug": staticmethod(lambda *a, **k: None),
                                      "info": staticmethod(lambda *a, **k: None)})()


@pytest.mark.asyncio
async def test_register_address_omits_label():
    # Bitcoin Core v29+ (the mutinynet Inquisition fork, and future
    # mains) rejects importdescriptors carrying a label for watch-only
    # imports: "-8 Internal addresses should not have a label". The
    # label was cosmetic (nothing ever queried it back).
    mon = _Mon([{"success": True}])
    await mon.register_address("tb1qryyu9dfpg97234zx29p2weaguq78gq7dy4aa68")
    method, params = mon.iface.calls[0]
    assert method == "importdescriptors"
    # acall params wrap the import-descriptors array: [[request_dict]]
    req = params[0][0]
    assert "label" not in req
    assert req["internal"] is False
    assert req["active"] is False
    assert req["timestamp"] == "now"
    assert req["desc"].startswith("addr(")


@pytest.mark.asyncio
async def test_register_address_surfaces_import_error():
    mon = _Mon([{"success": False, "error": {"code": -8, "message": "boom"}}])
    with pytest.raises(Exception, match="Import failed"):
        await mon.register_address("tb1qryyu9dfpg97234zx29p2weaguq78gq7dy4aa68")
