"""
Mock IDA modules — simulates ida_* modules for testing without real IDA.
Uses mock_idapro._db as the shared in-memory database state.
"""
import re
from .mock_idapro import get_db


# ── idautils ──


class _FunctionIterator:
    """Simulates idautils.Functions() iterator."""
    def __init__(self):
        db = get_db()
        self._addrs = sorted(k for k in db.names if k < 0x100000) if db else []
        self._idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self._idx >= len(self._addrs):
            raise StopIteration
        addr = self._addrs[self._idx]
        self._idx += 1
        return addr


def Functions():
    """Simulated idautils.Functions()."""
    return _FunctionIterator()


class _Xref:
    def __init__(self, frm, to_, type_):
        self.frm = frm
        self.to = to_
        self.type = type_


class _XrefsToIterator:
    """Simulated XrefsTo."""
    def __init__(self, addr, flags=0):
        self._xrefs = []
        if addr == 0x1100:
            self._xrefs.append(_Xref(0x1000, addr, 0x11))  # call from main
        self._idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self._idx >= len(self._xrefs):
            raise StopIteration
        xref = self._xrefs[self._idx]
        self._idx += 1
        return xref


class _XrefsFromIterator:
    """Simulated XrefsFrom."""
    def __init__(self, addr, flags=0):
        self._xrefs = []
        if addr == 0x1000:
            self._xrefs.append(_Xref(addr, 0x1100, 0x11))  # call to sub_1100
        self._idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self._idx >= len(self._xrefs):
            raise StopIteration
        xref = self._xrefs[self._idx]
        self._idx += 1
        return xref


def XrefsTo(addr, flags=0):
    return _XrefsToIterator(addr, flags)


def XrefsFrom(addr, flags=0):
    return _XrefsFromIterator(addr, flags)


def Segments():
    """Yield each segment's start_ea — the wrapper uses these to walk the
    segment list before resolving each via getseg()."""
    for seg in _segments:
        yield seg.start_ea


def FuncItems(start_ea):
    """Yield each instruction address inside the function at start_ea.
    Real IDA returns one address per instruction; the mock returns a fixed
    short sequence so disassembly tests are deterministic."""
    yield start_ea
    yield start_ea + 4
    yield start_ea + 8


def Entries():
    """Yield (index, ordinal, address, name) for each export."""
    db = get_db()
    if db:
        for entry in db.entries:
            yield entry


class _MockString:
    def __init__(self, ea, value):
        self.ea = ea
        self._value = value

    def __str__(self):
        return self._value


def Strings():
    """Iterable of mock string objects pulled from the DB."""
    db = get_db()
    if db:
        for ea, value in db.strings:
            yield _MockString(ea, value)


# ── ida_funcs ──


class _Func:
    def __init__(self, start_ea, flags=0, frsize=0):
        self.start_ea = start_ea
        self.end_ea = start_ea + 0x50
        self.flags = flags
        self.frsize = frsize


def get_func(addr):
    """Simulated ida_funcs.get_func."""
    db = get_db()
    if db and addr in db.names and addr < 0x100000:
        attrs = db.func_attrs.get(addr, {})
        return _Func(addr, flags=attrs.get("flags", 0), frsize=attrs.get("frsize", 0))
    return None


# ── ida_name ──


def get_name(addr):
    """Simulated ida_name.get_name."""
    db = get_db()
    if db and addr in db.names:
        return db.names[addr]
    return ""


# ── idc ──


SN_NOWARN = 0x80000000


def set_name(addr, name, flags=0):
    """Simulated idc.set_name."""
    db = get_db()
    if not db:
        return 0
    db.names[addr] = name
    return 1


def get_name_cached(addr):
    """Simulated idc.get_name (for rename_global)."""
    db = get_db()
    if db and addr in db.names:
        return db.names[addr]
    return ""


def set_cmt(addr, comment, repeatable=False):
    """Simulated idc.set_cmt."""
    db = get_db()
    if not db:
        return False
    db.comments[addr] = comment
    return True


def get_cmt(addr, repeatable=False):
    """Simulated idc.get_cmt."""
    db = get_db()
    if db:
        return db.comments.get(addr, "")
    return ""


def set_func_cmt(addr, comment, repeatable=False):
    """Simulated idc.set_func_cmt."""
    db = get_db()
    if not db:
        return False
    db.func_comments[addr] = comment
    return True


def get_func_cmt(addr, repeatable=False):
    """Simulated idc.get_func_cmt."""
    db = get_db()
    if db:
        return db.func_comments.get(addr, "")
    return ""


def apply_type(addr, decl, flags=0):
    """Simulated idc.apply_type."""
    db = get_db()
    if not db:
        return False
    db.types[addr] = decl
    return True


def del_name(addr):
    """Simulated idc.del_name."""
    db = get_db()
    if db and addr in db.names:
        del db.names[addr]
        return 1
    return 0


# ── ida_bytes ──


def get_bytes(addr, size):
    """Simulated ida_bytes.get_bytes — pulls bytes from db.memory when seeded.
    Missing addresses default to 0x90 so callers that only care about the size
    (e.g. fixture sanity checks) still get a non-empty buffer."""
    db = get_db()
    if not db:
        return b"\x90" * size
    return bytes(db.memory.get(addr + i, 0x90) for i in range(size))


def get_dword(addr):
    return 0xDEADBEEF


def get_qword(addr):
    return 0xDEADBEEFCAFEBABE


# ── ida_segment ──


class _Segment:
    def __init__(self, name, start, end, seg_class):
        self.name = name
        self.start_ea = start
        self.end_ea = end
        self.segclass = seg_class
        self.perm = 5  # R+X
        self.bitness = 64


_segments = [
    _Segment(".text", 0x1000, 0x2000, "CODE"),
    # .data spans 0x2000–0x4000 so the seeded globals at 0x2000 and 0x3000
    # both fall inside the DATA segment that get_globals walks.
    _Segment(".data", 0x2000, 0x4000, "DATA"),
]


def get_first_seg():
    return _segments[0]


def get_next_seg(ea):
    for seg in _segments:
        if seg.start_ea > ea:
            return seg
    return None


def getnseg(n):
    """Simulated ida_segment.getnseg (0-indexed)."""
    if 0 <= n < len(_segments):
        return _segments[n]
    return None


def get_segm_by_name(name):
    for seg in _segments:
        if seg.name == name:
            return seg
    return None


def get_segm_name(seg):
    """Simulated ida_segment.get_segm_name."""
    return seg.name if seg else ""


def get_segm_class(seg):
    """Simulated ida_segment.get_segm_class."""
    return seg.segclass if seg else ""


def getseg(addr):
    """Return the segment containing addr, or None."""
    for seg in _segments:
        if seg.start_ea <= addr < seg.end_ea:
            return seg
    return None


# ── ida_hexrays ──

_hexrays_available = True


def init_hexrays_plugin():
    return _hexrays_available


def set_hexrays_available(available: bool):
    global _hexrays_available
    _hexrays_available = available


class _DecompResult:
    def __init__(self, addr):
        db = get_db()
        name = db.names.get(addr, f"sub_{addr:X}") if db else f"sub_{addr:X}"
        self._text = f"// Decompiled from {hex(addr)}\nint {name}() {{\n    return sub_1100();\n}}"

    def __str__(self):
        return self._text


def decompile(ea):
    """Simulated ida_hexrays.decompile."""
    if not _hexrays_available:
        raise Exception("HexRaysError: decompiler not available")
    return _DecompResult(ea)


# ── ida_auto ──

_auto_running = False
_auto_state = "idle"


def get_auto_state():
    return _auto_state


def is_auto_enabled():
    return True


def auto_wait():
    global _auto_running, _auto_state
    _auto_running = False
    _auto_state = "idle"


def plan_and_wait(timeout=None):
    return True


# ── ida_ua ──


class insn_t:
    def __init__(self):
        self.size = 0


def decode_insn(insn, addr):
    db = get_db()
    if not db:
        return 0
    length = db.insn_lengths.get(addr, 0)
    insn.size = length
    return length


def get_insn_output(addr, flags=0):
    return "mov rax, rbx"


# ── idc (additions) ──


def generate_disasm_line(addr, flags):
    """Return per-address disassembly seeded in db.disasm; fall back to a
    generic instruction string for unseeded addresses."""
    db = get_db()
    if db and addr in db.disasm:
        return db.disasm[addr]
    return "mov rax, rbx"


def get_inf_attr(attr):
    """Mock idc.get_inf_attr — used by the entry-point fallback chain."""
    db = get_db()
    if db:
        return db.image_base
    return 0


INF_START_EA = 0  # Opaque attribute index — only used as a key, value unused.


# ── idaapi ──


def get_import_module_qty():
    return 2


def enum_import_names(mod_index, callback):
    """Simulated import enumeration."""
    if mod_index == 0:
        callback(0x4000, "printf", 0)
        callback(0x4008, "malloc", 0)
    elif mod_index == 1:
        callback(0x4010, "MessageBoxA", 0)


def get_import_module_name(mod_index):
    if mod_index == 0:
        return "libc"
    if mod_index == 1:
        return "user32"
    return ""


# ── ida_nalt ──


def get_import_module_name_by_index(mod_index):
    return get_import_module_name(mod_index)


# ── ida_xref ──

XREF_DATA = 1
XREF_ALL = 15


class xrefblk_t:
    def __init__(self):
        self.frm = 0
        self.to = 0
        self.type = 0
        self._count = 0
        self._items = []

    def first_to(self, addr, flags):
        self._count = 0
        if addr == 0x3000:
            self._items = [(0x1000, XREF_DATA), (0x1100, XREF_DATA)]
        else:
            self._items = []
        if self._items:
            self.frm, self.type = self._items[0]
            return True
        return False

    def next_to(self):
        self._count += 1
        if self._count < len(self._items):
            self.frm, self.type = self._items[self._count]
            return True
        return False


# ── ida_typeinf ──


# Constants the wrapper compares against. Values match real IDA where they
# matter for the test paths; CM_CC_* and PT_VAR are otherwise opaque.
CM_CC_CDECL = 0x10
CM_CC_STDCALL = 0x20
CM_CC_FASTCALL = 0x40
CM_CC_THISCALL = 0x60

PT_VAR = 0
TINFO_DEFINITE = 0


def get_type(addr):
    """Simulated ida_typeinf.get_type."""
    db = get_db()
    if db and addr in db.types:
        return db.types[addr]
    return ""


class _Til:
    """Opaque type-info library handle. get_idati() returns one of these."""


def get_idati():
    return _Til()


def get_ordinal_limit(ti):
    db = get_db()
    if not db or not db.types_by_ordinal:
        return 1
    return max(db.types_by_ordinal.keys()) + 1


class tinfo_t:
    """Minimal tinfo_t: state set by get_numbered_type / get_named_type from
    the DB's types_by_ordinal / tinfos dict, queried by the wrapper via the
    is_X / get_X methods."""

    def __init__(self):
        self._kind = None  # "struct" | "union" | "enum" | "func" | "ptr" | "array" | None
        self._name = ""
        self._size = 0
        self._ordinal = 0
        self._cc = 0
        self._rettype = ""
        self._nargs = 0
        self._dstr = ""
        self._struct_members = None  # list[dict] when kind in (struct, union)
        self._enum_members = None    # list[dict] when kind == enum

    # ── Fill from type-system DB ──

    def _load_from_struct_or_enum(self, entry, ordinal):
        self._kind = entry["kind"]
        self._name = entry["name"]
        self._size = entry.get("size", 0)
        self._ordinal = ordinal
        if entry["kind"] in ("struct", "union"):
            self._struct_members = entry.get("members", [])
        elif entry["kind"] == "enum":
            self._enum_members = entry.get("members", [])
        self._dstr = entry["name"]

    def _load_from_tinfo(self, info):
        self._dstr = info.get("type", "")
        self._size = info.get("size", 0)
        self._kind = (
            "func" if info.get("is_func") else
            "ptr" if info.get("is_ptr") else
            "array" if info.get("is_array") else
            "struct" if info.get("is_struct") else
            "union" if info.get("is_union") else
            "enum" if info.get("is_enum") else
            None
        )
        self._cc = info.get("cc", 0)
        self._rettype = info.get("rettype", "")
        self._nargs = info.get("nargs", 0)

    def get_numbered_type(self, ti, ordinal):
        db = get_db()
        if db and ordinal in db.types_by_ordinal:
            self._load_from_struct_or_enum(db.types_by_ordinal[ordinal], ordinal)
            return True
        return False

    def get_named_type(self, ti, name):
        db = get_db()
        if not db:
            return False
        for ordinal, entry in db.types_by_ordinal.items():
            if entry.get("name") == name:
                self._load_from_struct_or_enum(entry, ordinal)
                return True
        return False

    # ── Kind predicates ──

    def is_struct(self):
        return self._kind == "struct"

    def is_union(self):
        return self._kind == "union"

    def is_enum(self):
        return self._kind == "enum"

    def is_func(self):
        return self._kind == "func"

    def is_ptr(self):
        return self._kind == "ptr"

    def is_array(self):
        return self._kind == "array"

    # ── Accessors ──

    def get_type_name(self):
        return self._name

    def get_size(self):
        return self._size

    def get_ordinal(self):
        return self._ordinal

    def dstr(self):
        return self._dstr

    def get_cc(self):
        return self._cc

    def get_rettype(self):
        if not self._rettype:
            return None
        ret = tinfo_t()
        ret._dstr = self._rettype
        return ret

    def get_nargs(self):
        return self._nargs

    # ── UDT / Enum detail extraction ──

    def get_udt_details(self, udt_data):
        if self._struct_members is None:
            return False
        udt_data._load(self._struct_members)
        return True

    def get_enum_details(self, enum_data):
        if self._enum_members is None:
            return False
        enum_data._load(self._enum_members)
        return True


class _UdtMember:
    def __init__(self, raw):
        self.name = raw["name"]
        self.offset = raw["offset_bits"]
        self.size = raw["size_bits"]
        # The wrapper calls member.type.dstr(), so the type field must be a
        # tinfo_t-shaped object, not a bare string.
        self.type = tinfo_t()
        self.type._dstr = raw["type"]


class udt_type_data_t:
    def __init__(self):
        self._members = []

    def _load(self, raw_members):
        self._members = [_UdtMember(m) for m in raw_members]

    def size(self):
        return len(self._members)

    def __getitem__(self, i):
        return self._members[i]


class _EnumMember:
    def __init__(self, raw):
        self.name = raw["name"]
        self.value = raw["value"]


class enum_type_data_t:
    def __init__(self):
        self._members = []

    def _load(self, raw_members):
        self._members = [_EnumMember(m) for m in raw_members]

    def size(self):
        return len(self._members)

    def __getitem__(self, i):
        return self._members[i]


def parse_decl(*args):
    """Dual-shape mock — mock_ida_modules registers as both idc and
    ida_typeinf, so a single parse_decl must handle either calling shape:
      - idc.parse_decl(decl, flags) → returns the parsed decl string.
      - ida_typeinf.parse_decl(tinfo, til, decl, flags) → fills tinfo, bool.
    """
    if len(args) == 2:
        decl, _flags = args
        return decl  # idc.parse_decl: real returns a parsed-type token; the
                     # wrapper only checks truthiness, so the string suffices.
    if len(args) == 4:
        tinfo, _til, decl, _flags = args
        if not decl or not isinstance(decl, str):
            return False
        tinfo._dstr = decl
        return True
    raise TypeError(f"parse_decl called with {len(args)} positional args")


def apply_tinfo(addr, tinfo, flags):
    db = get_db()
    if not db:
        return False
    db.types[addr] = tinfo._dstr
    return True


# ── ida_nalt ──


def get_tinfo(tinfo, addr):
    """Populate tinfo with the type stored for addr; return False when absent."""
    db = get_db()
    if not db or addr not in db.tinfos:
        return False
    tinfo._load_from_tinfo(db.tinfos[addr])
    return True


# ── ida_bytes (additions) ──


BIN_SEARCH_FORWARD = 0
BIN_SEARCH_BACKWARD = 1


def get_byte(addr):
    db = get_db()
    if not db:
        return None
    return db.memory.get(addr, 0x90)


def get_full_flags(ea):
    """Return a flag word; we mark addresses listed in db.types as data."""
    db = get_db()
    if db and ea in db.types:
        return 0x400  # arbitrary "is_data" sentinel
    return 0


def is_data(flags):
    return bool(flags & 0x400)


def next_not_tail(ea):
    return ea + 4


class compiled_binpat_vec_t:
    """Holds the parsed pattern. parse_binpat_str fills _bytes."""

    def __init__(self):
        self._bytes = b""


def parse_binpat_str(compiled, ea, pattern, radix):
    """Parse a space-separated hex pattern. Returns falsy string ("") on
    success, truthy string on error — matching the wrapper's `if encoding_error`
    failure check."""
    if not pattern:
        return "empty"
    try:
        parts = pattern.split()
        compiled._bytes = bytes(int(p, radix) for p in parts)
    except (ValueError, TypeError):
        return f"bad pattern: {pattern}"
    return ""


def bin_search(start, end, compiled, direction):
    """Linear search of db.memory for the compiled pattern. Returns
    (addr, size) on hit and (BADADDR, 0) on miss, matching the wrapper's
    `result[0] if isinstance(result, tuple) else result` handling."""
    db = get_db()
    if not db or not compiled._bytes:
        return (db.bad_addr if db else 0xFFFFFFFFFFFFFFFF, 0)
    needle = compiled._bytes
    rng = range(start, end - len(needle) + 1) if direction == BIN_SEARCH_FORWARD \
        else range(start, max(end - len(needle), -1), -1)
    for addr in rng:
        if all(db.memory.get(addr + i, 0x90) == b for i, b in enumerate(needle)):
            return (addr, len(needle))
    return (db.bad_addr, 0)


# ── ida_search ──


SEARCH_DOWN = 1
SEARCH_CASE = 4


def find_text(ea, x, y, text, flags):
    """Linear text search across db.memory. Real find_text searches the
    listing; the mock interprets the search as a substring match against the
    byte stream starting at ea."""
    db = get_db()
    if not db or not text:
        return db.bad_addr if db else 0xFFFFFFFFFFFFFFFF
    case_sensitive = bool(flags & SEARCH_CASE)
    needle = text if case_sensitive else text.lower()
    encoded = needle.encode("utf-8", errors="replace")
    end = max(db.memory.keys(), default=ea) + 1
    for addr in range(ea, end - len(encoded) + 1):
        chunk = bytes(db.memory.get(addr + i, 0x90) for i in range(len(encoded)))
        if not case_sensitive:
            chunk = chunk.lower()
        if chunk == encoded:
            return addr
    return db.bad_addr


# ── ida_funcs (additions) ──


FUNC_LIB = 0x40
FUNC_THUNK = 0x80
FUNC_NORET = 0x01
FUNC_FAR = 0x02
FUNC_STATICDEF = 0x04


def get_func_name(addr):
    db = get_db()
    if db and addr in db.func_name_lookup:
        return db.func_name_lookup[addr]
    return ""


# ── idaapi (additions) ──


BADADDR = 0xFFFFFFFFFFFFFFFF
DBFL_KILL = 0x100


def get_imagebase():
    db = get_db()
    if db:
        return db.image_base
    return 0


def parse_decls(header, flags):
    """Real parse_decls returns the number of errors. Our mock accepts any
    non-empty string as a valid set of declarations."""
    return 0 if header else 1


def is_database_flag(flag):
    return False


class _Inf:
    def __init__(self):
        self.start_ea = 0x1000


class _Cvar:
    def __init__(self):
        self.inf = _Inf()


cvar = _Cvar()


def save_database(_path, _flags):
    return True


def get_next_func(addr):
    db = get_db()
    if not db:
        return BADADDR
    later = sorted(a for a in db.names if a > addr and a < 0x10000)
    return later[0] if later else BADADDR


def del_func(addr):
    return True


def add_func(start, end=None):
    """Real ida_funcs.add_func accepts (start) or (start, end); the wrapper
    uses both shapes (make_function: one arg, import_il2cpp: two args)."""
    db = get_db()
    if db:
        db.names.setdefault(start, f"sub_{start:X}")
    return True


# ── Reset helper for tests ──


def reset_all():
    """Reset all mock state between tests."""
    from .mock_idapro import reset as r
    r()
    global _hexrays_available, _auto_running, _auto_state
    _hexrays_available = True
    _auto_running = False
    _auto_state = "idle"
