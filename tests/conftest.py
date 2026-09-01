import importlib.util
import sys
from pathlib import Path

# Upstream tests import `plugin_src.plugin.…` (their docker-compose mounted
# swap-provider as plugin_src). Alias it to this repo's swap-provider/ so
# the suite runs from a plain checkout.
_swap_provider = Path(__file__).resolve().parent.parent / "swap-provider"
if (_swap_provider / "plugin" / "__init__.py").exists():
    _shim = importlib.util.module_from_spec(
        importlib.util.spec_from_file_location("plugin_src", _swap_provider / "plugin" / "__init__.py"))
    # not executed as a package init; just bind the search path:
    _shim.__path__ = [str(_swap_provider)]
    sys.modules.setdefault("plugin_src", _shim)

# python-bitcoinrpc is a runtime dependency (the plugin's bitcoind
# transport); individual tests stubbed it ad hoc — since
# submarine_swaps imports BitcoinCoreRPCError for its claim-broadcast
# catch (security review 2026-09-01 C1), stub it once for every
# importer instead of per-file.
import types as _types  # noqa: E402
if "bitcoinrpc" not in sys.modules:
    _btc = _types.ModuleType("bitcoinrpc")
    _btc.BitcoinRPC = object
    _btc.RPCError = RuntimeError
    sys.modules["bitcoinrpc"] = _btc
