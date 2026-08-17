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
