"""
Mock idapro module — simulates the idapro package for testing without real IDA.
"""
import os

_console_enabled = True


def enable_console_messages(enabled: bool):
    global _console_enabled
    _console_enabled = enabled


class _MockDatabase:
    """Simulates an opened IDA database with in-memory state.

    The fields here are the ground truth that the ida_* mocks read from.
    Tests can mutate them directly (or via setter helpers) to drive the
    wrapper through specific paths.
    """

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.names: dict[int, str] = {}       # addr → name
        self.comments: dict[int, str] = {}    # addr → comment
        self.func_comments: dict[int, str] = {}
        self.decompiler_comments: dict[tuple[int, int], str] = {}  # (func_addr, addr) → comment
        self.types: dict[int, str] = {}       # addr → type string
        self.globals: dict[int, str] = {}     # addr → type
        # Type system: ordinal → struct/enum dict.
        # Struct: {"kind": "struct"|"union", "name": str, "size": int,
        #          "members": [{"name", "offset_bits", "size_bits", "type"}]}.
        # Enum: {"kind": "enum", "name": str, "members": [{"name", "value"}]}.
        self.types_by_ordinal: dict[int, dict] = {}
        # addr → type-info dict consumed by ida_nalt.get_tinfo's mock.
        # {"type": str, "size": int, "is_ptr": bool, "is_func": bool,
        #  "is_array": bool, "is_struct": bool, "is_union": bool,
        #  "is_enum": bool, "cc": int, "rettype": str, "nargs": int}
        self.tinfos: dict[int, dict] = {}
        # Function flags / frame sizes consumed by ida_funcs.get_func's mock.
        self.func_attrs: dict[int, dict] = {}  # addr → {"flags": int, "frsize": int}
        # ROM contents used by find_binary / find_text and get_byte. Keyed by
        # address. Missing addresses default to 0x90.
        self.memory: dict[int, int] = {}
        self.image_base = 0x1000
        self.bad_addr = 0xFFFFFFFFFFFFFFFF
        self.func_name_lookup: dict[int, str] = {}  # ida_funcs.get_func_name
        self._seed(binary_path)

    def _seed(self, path: str):
        base = os.path.basename(path)
        self.names[0x1000] = "main"
        self.names[0x1100] = "sub_1100"
        self.names[0x1200] = "init_runtime"
        self.names[0x2000] = "dword_2000"
        self.names[0x3000] = "g_config"
        # Seed a struct, a union, and an enum so type-system tests hit a
        # realistic mix without each test having to populate the DB by hand.
        self.types_by_ordinal[1] = {
            "kind": "struct",
            "name": "Point",
            "size": 8,
            "members": [
                {"name": "x", "offset_bits": 0, "size_bits": 32, "type": "int"},
                {"name": "y", "offset_bits": 32, "size_bits": 32, "type": "int"},
            ],
        }
        self.types_by_ordinal[2] = {
            "kind": "union",
            "name": "Variant",
            "size": 8,
            "members": [
                {"name": "i", "offset_bits": 0, "size_bits": 64, "type": "long"},
                {"name": "d", "offset_bits": 0, "size_bits": 64, "type": "double"},
            ],
        }
        self.types_by_ordinal[3] = {
            "kind": "enum",
            "name": "Color",
            "members": [
                {"name": "RED", "value": 0},
                {"name": "GREEN", "value": 1},
                {"name": "BLUE", "value": 2},
            ],
        }
        # Type at a code address — drives get_type_at and get_function_info.
        # CM_CC_FASTCALL == 0x40 in ida_typeinf (mirrored in the mock module).
        self.tinfos[0x1000] = {
            "type": "int __fastcall main(int argc, char **argv)",
            "size": 0,
            "is_ptr": False,
            "is_func": True,
            "is_array": False,
            "is_struct": False,
            "is_union": False,
            "is_enum": False,
            "cc": 0x40,
            "rettype": "int",
            "nargs": 2,
        }
        # Data-typed location for get_type_at.
        self.tinfos[0x3000] = {
            "type": "Point *",
            "size": 8,
            "is_ptr": True,
            "is_func": False,
            "is_array": False,
            "is_struct": False,
            "is_union": False,
            "is_enum": False,
            "cc": 0,
            "rettype": "",
            "nargs": 0,
        }
        self.func_attrs[0x1000] = {"flags": 0, "frsize": 16}
        self.func_attrs[0x1100] = {"flags": 0x40, "frsize": 0}  # FUNC_LIB
        self.func_attrs[0x1200] = {"flags": 0x80, "frsize": 0}  # FUNC_THUNK
        self.func_name_lookup[0x1000] = "main"
        self.func_name_lookup[0x1100] = "sub_1100"
        self.func_name_lookup[0x1200] = "init_runtime"
        # Memory pattern used by find_binary / find_text tests.
        for i, b in enumerate(b"hello\x00\x90\x90\x90\x90\x90world"):
            self.memory[0x1000 + i] = b
        # Strings drive get_strings tests; entries drive get_exports tests;
        # disasm drives get_disasm tests; insn_lengths drives get_instruction_length.
        self.strings: list[tuple[int, str]] = [
            (0x4000, "hello"),
            (0x4100, "%d items found"),
            (0x4200, "ERROR_FATAL"),
        ]
        self.entries: list[tuple[int, int, int, str]] = [
            (0, 1, 0x1000, "main"),
            (1, 2, 0x1200, "init_runtime"),
        ]
        # Per-address disasm; missing addresses fall back to "mov rax, rbx".
        self.disasm: dict[int, str] = {
            0x1000: "push rbp",
            0x1004: "mov rbp, rsp",
            0x1008: "call sub_1100",
        }
        self.insn_lengths: dict[int, int] = {0x1000: 1, 0x1004: 3, 0x1008: 5}


_db: _MockDatabase | None = None
_open_result: int = 0  # sticky override for testing error paths
_open_results: list[int] = []  # one-shot sequence; consumed left-to-right


def open_database(binary_path: str, auto_analyze: bool, flags: str = "") -> int:
    """Simulated idapro.open_database. Honors _open_results (a one-shot
    sequence drained per-call) before falling back to the sticky _open_result.
    The sequence shape lets tests assert behavior like "fail once, then
    succeed on retry" without juggling globals across calls."""
    global _db
    result = _open_results.pop(0) if _open_results else _open_result
    if result != 0:
        return result
    _db = _MockDatabase(binary_path)
    return 0


def get_db() -> _MockDatabase | None:
    return _db


def reset():
    global _db, _open_result
    _db = None
    _open_result = 0
    _open_results.clear()
