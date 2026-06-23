"""
Mock IDA modules for testing the Python worker without a real IDA Pro installation.

Install these mocks before importing ida_wrapper or connect_server:

    import tests.mocks as ida_mocks
    ida_mocks.install()

    # Now import worker modules — they'll use the mocks
    from worker.ida_wrapper import IDAWrapper
"""
import sys
from . import mock_idapro
from . import mock_ida_modules


_MOCK_MODULES = [
    "ida_auto", "ida_funcs", "ida_name", "ida_bytes", "ida_segment",
    "idautils", "idc", "ida_hexrays", "ida_ua", "idaapi", "ida_nalt",
    "ida_xref", "ida_typeinf", "ida_search",
]


def install():
    """Replace real IDA modules with mocks in sys.modules."""
    sys.modules["idapro"] = mock_idapro
    for mod in _MOCK_MODULES:
        sys.modules[mod] = mock_ida_modules


def uninstall():
    """Remove mocks from sys.modules (cleanup between tests)."""
    sys.modules.pop("idapro", None)
    for mod in _MOCK_MODULES:
        sys.modules.pop(mod, None)


def reset():
    """Reset all mock state."""
    mock_idapro.reset()
    mock_ida_modules.reset_all()
