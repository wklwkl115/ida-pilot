"""
Unit tests for ida_wrapper.IDAWrapper — runs without real IDA Pro.

Uses mock IDA modules to verify wrapper logic, error handling, and edge cases.
"""
import os
import sys
import time
from pathlib import Path

import pytest

# Setup: install mocks before importing the worker module
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "worker"))

from tests.mocks import install, uninstall, reset


@pytest.fixture(autouse=True)
def setup_mocks():
    """Install mocks before each test, clean up after."""
    install()
    from worker.ida_wrapper import IDAWrapper
    yield IDAWrapper
    reset()
    # Clear cached module imports in IDAWrapper's module scope
    uninstall()


@pytest.fixture
def wrapper(tmp_path, setup_mocks):
    """An opened IDAWrapper sharing the seeded mock DB. Cuts the four-line
    binary-create / wrapper / open_database preamble that every functional
    test would otherwise repeat."""
    IDAWrapper = setup_mocks
    binary = tmp_path / "test.bin"
    binary.write_bytes(b"\x90" * 1024)
    w = IDAWrapper(str(binary), "test-session")
    assert w.open_database(auto_analyze=False) is True
    return w


class TestOpenDatabase:
    """Tests for open_database method."""

    def test_successful_open(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        result = wrapper.open_database(auto_analyze=False)

        assert result is True
        assert wrapper.db_open is True
        assert wrapper.has_decompiler is True
        assert wrapper.ida_funcs is not None
        assert wrapper.idc is not None

    def test_missing_binary(self, setup_mocks):
        IDAWrapper = setup_mocks
        wrapper = IDAWrapper("/nonexistent/binary.elf", "test-session")
        result = wrapper.open_database(auto_analyze=False)

        assert result is False
        assert wrapper.db_open is False
        assert wrapper.last_error is not None
        assert "not found" in wrapper.last_error.lower()

    def test_open_error_code(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        from tests.mocks import mock_idapro
        mock_idapro._open_result = 1

        # Need a file that exists but triggers the error code path.
        binary = tmp_path / "test_err.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        result = wrapper.open_database(auto_analyze=False)

        assert result is False
        assert "Database format error" in (wrapper.last_error or "")
        mock_idapro._open_result = 0

    def test_no_hexrays(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        from tests.mocks import mock_ida_modules
        mock_ida_modules.set_hexrays_available(False)

        binary = tmp_path / "test_nohex.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        result = wrapper.open_database(auto_analyze=False)
        assert result is True
        assert wrapper.has_decompiler is False


class TestGetFunctions:
    """Tests for get_functions method."""

    def test_enumerates_functions(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        wrapper.open_database(auto_analyze=False)

        funcs = wrapper.get_functions()
        assert len(funcs) > 0
        assert any(f["name"] == "main" for f in funcs)
        assert any(f["name"] == "sub_1100" for f in funcs)


class TestGetDecompiled:
    """Tests for get_decompiled method."""

    def test_decompiles_function(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        wrapper.open_database(auto_analyze=False)

        code = wrapper.get_decompiled(0x1000)
        assert "main" in code
        assert "sub_1100" in code

    def test_no_function_at_address(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        wrapper.open_database(auto_analyze=False)

        with pytest.raises(Exception, match="No function at address"):
            wrapper.get_decompiled(0x9999)

    def test_no_decompiler_available(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        from tests.mocks import mock_ida_modules
        mock_ida_modules.set_hexrays_available(False)

        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        wrapper.open_database(auto_analyze=False)

        with pytest.raises(Exception, match="Decompiler not available"):
            wrapper.get_decompiled(0x1000)


class TestSetName:
    """Tests for set_name method."""

    def test_rename_function(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        wrapper.open_database(auto_analyze=False)

        result = wrapper.set_name(0x1100, "helper_func")
        assert result is True
        assert wrapper.get_name(0x1100) == "helper_func"

    def test_delete_name(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        wrapper.open_database(auto_analyze=False)

        result = wrapper.delete_name(0x1100)
        assert result is True


class TestGetImports:
    """Tests for get_imports method."""

    def test_enumerates_imports(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        wrapper.open_database(auto_analyze=False)

        imports = wrapper.get_imports()
        assert len(imports) > 0
        names = [i["name"] for i in imports]
        assert "printf" in names
        assert "MessageBoxA" in names


class TestGetSegments:
    """Tests for get_segments method."""

    def test_enumerates_segments(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        wrapper.open_database(auto_analyze=False)

        segs = wrapper.get_segments()
        assert len(segs) >= 2
        names = [s["name"] for s in segs]
        assert ".text" in names
        assert ".data" in names


class TestStatus:
    """Tests for status and touch."""

    def test_status_snapshot_updates(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        binary = tmp_path / "test_status.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        snap = wrapper.get_status_snapshot()
        assert snap["phase"] == "initializing"

        wrapper.open_database(auto_analyze=False)
        snap = wrapper.get_status_snapshot()
        # auto_analyze=False => phase is "loaded" not "ready"
        assert snap["phase"] == "loaded"
        assert snap["running"] is False


# ── B14: Type-system handlers ──


class TestListStructs:
    def test_lists_seeded_structs(self, wrapper):
        structs = wrapper.list_structs()
        names = [s["name"] for s in structs]
        assert "Point" in names
        assert "Variant" in names  # union is also reported by list_structs

    def test_regex_filter(self, wrapper):
        structs = wrapper.list_structs(regex="^Point$")
        assert [s["name"] for s in structs] == ["Point"]

    def test_filter_misses(self, wrapper):
        assert wrapper.list_structs(regex="^DoesNotExist$") == []


class TestGetStruct:
    def test_returns_members(self, wrapper):
        result = wrapper.get_struct("Point")
        assert result["name"] == "Point"
        assert result["size"] == 8
        assert result["is_union"] is False
        assert [m["name"] for m in result["members"]] == ["x", "y"]
        assert result["members"][1]["offset"] == 4  # 32 bits → 4 bytes
        assert result["members"][1]["size"] == 4
        assert result["members"][0]["type"] == "int"

    def test_union_is_flagged(self, wrapper):
        result = wrapper.get_struct("Variant")
        assert result["is_union"] is True
        assert {m["name"] for m in result["members"]} == {"i", "d"}

    def test_unknown_struct_raises(self, wrapper):
        with pytest.raises(ValueError, match="not found"):
            wrapper.get_struct("Missing")

    def test_enum_is_rejected(self, wrapper):
        # Color is in types_by_ordinal but is an enum — get_struct must refuse.
        with pytest.raises(ValueError, match="not a structure"):
            wrapper.get_struct("Color")

    def test_blank_name_raises(self, wrapper):
        with pytest.raises(ValueError, match="name is required"):
            wrapper.get_struct("")


class TestListEnums:
    def test_lists_seeded_enums(self, wrapper):
        enums = wrapper.list_enums()
        assert any(e["name"] == "Color" for e in enums)
        # list_enums must skip structs/unions.
        assert all(e["name"] != "Point" for e in enums)

    def test_regex_filter(self, wrapper):
        enums = wrapper.list_enums(regex="Color")
        assert [e["name"] for e in enums] == ["Color"]


class TestGetEnum:
    def test_returns_members(self, wrapper):
        result = wrapper.get_enum("Color")
        assert result["name"] == "Color"
        names = [m["name"] for m in result["members"]]
        values = [m["value"] for m in result["members"]]
        assert names == ["RED", "GREEN", "BLUE"]
        assert values == [0, 1, 2]

    def test_struct_is_rejected(self, wrapper):
        with pytest.raises(ValueError, match="not an enumeration"):
            wrapper.get_enum("Point")

    def test_unknown_enum_raises(self, wrapper):
        with pytest.raises(ValueError, match="not found"):
            wrapper.get_enum("Missing")


class TestGetTypeAt:
    def test_returns_typed_address(self, wrapper):
        info = wrapper.get_type_at(0x3000)
        assert info["has_type"] is True
        assert info["type"] == "Point *"
        assert info["is_ptr"] is True
        assert info["is_func"] is False
        assert info["size"] == 8

    def test_untyped_address_returns_empty(self, wrapper):
        info = wrapper.get_type_at(0x9999)
        assert info["has_type"] is False
        assert info["type"] == ""
        assert info["size"] == 0


class TestGetFunctionInfo:
    def test_returns_bounds_and_name(self, wrapper):
        info = wrapper.get_function_info(0x1000)
        assert info["name"] == "main"
        assert info["start"] == 0x1000
        assert info["end"] == 0x1000 + 0x50
        assert info["size"] == 0x50
        assert info["frame_size"] == 16

    def test_library_flag_is_surfaced(self, wrapper):
        info = wrapper.get_function_info(0x1100)
        assert info["flags"]["is_library"] is True
        assert info["flags"]["is_thunk"] is False

    def test_thunk_flag_is_surfaced(self, wrapper):
        info = wrapper.get_function_info(0x1200)
        assert info["flags"]["is_thunk"] is True
        assert info["flags"]["is_library"] is False

    def test_calling_convention_from_tinfo(self, wrapper):
        info = wrapper.get_function_info(0x1000)
        # 0x1000 has cc=0x40 (CM_CC_FASTCALL) and rettype=int / nargs=2 seeded.
        assert info["calling_convention"] == "fastcall"
        assert info["return_type"] == "int"
        assert info["num_args"] == 2

    def test_unknown_address_raises(self, wrapper):
        with pytest.raises(ValueError, match="No function at"):
            wrapper.get_function_info(0xDEAD)


# ── B15: Search / globals ──


class TestFindBinary:
    def test_finds_seeded_pattern(self, wrapper):
        # "hello" begins at 0x1000 in the seeded memory map.
        result = wrapper.find_binary(0, 0x2000, "68 65 6C 6C 6F")
        assert result == [0x1000]

    def test_default_start_uses_imagebase(self, wrapper):
        result = wrapper.find_binary(0, 0x2000, "68 65 6C 6C 6F")  # start=0 → image_base
        assert 0x1000 in result

    def test_blank_pattern_raises(self, wrapper):
        with pytest.raises(ValueError, match="pattern is required"):
            wrapper.find_binary(0x1000, 0x2000, "")

    def test_no_match_returns_empty(self, wrapper):
        assert wrapper.find_binary(0x1000, 0x2000, "DE AD BE EF") == []


class TestFindText:
    def test_finds_seeded_text(self, wrapper):
        result = wrapper.find_text(0x1000, 0x2000, "hello", False, False)
        assert 0x1000 in result

    def test_finds_other_seeded_text(self, wrapper):
        # "world" is at offset 11 of the seeded memory.
        result = wrapper.find_text(0x1000, 0x2000, "world", False, False)
        assert 0x100B in result

    def test_blank_text_raises(self, wrapper):
        with pytest.raises(ValueError, match="text is required"):
            wrapper.find_text(0x1000, 0x2000, "", False, False)


class TestGetGlobals:
    def test_enumerates_data_segment_names(self, wrapper):
        # Mark the seeded DATA-segment names as data via the type DB.
        from tests.mocks.mock_idapro import get_db
        db = get_db()
        db.types[0x2000] = "uint32_t"
        db.types[0x3000] = "Point *"
        globs = wrapper.get_globals()
        addrs = [g["address"] for g in globs]
        assert 0x2000 in addrs
        assert 0x3000 in addrs

    def test_regex_filter_narrows_results(self, wrapper):
        from tests.mocks.mock_idapro import get_db
        db = get_db()
        db.types[0x2000] = "uint32_t"
        db.types[0x3000] = "Point *"
        globs = wrapper.get_globals(regex="^g_")
        assert [g["name"] for g in globs] == ["g_config"]


# ── B16: Previously-coverable but untested methods ──


class TestGetDisasm:
    def test_returns_seeded_disasm(self, wrapper):
        assert wrapper.get_disasm(0x1000) == "push rbp"
        assert wrapper.get_disasm(0x1004) == "mov rbp, rsp"

    def test_unknown_addr_returns_fallback(self, wrapper):
        # generate_disasm_line's mock falls back to a generic instruction.
        assert wrapper.get_disasm(0xDEAD) == "mov rax, rbx"


class TestGetFunctionDisasm:
    def test_returns_multiline_listing(self, wrapper):
        text = wrapper.get_function_disasm(0x1000)
        # Three FuncItems x [addr]: line ⇒ 3 newline-joined entries.
        lines = text.splitlines()
        assert len(lines) == 3
        assert lines[0].startswith("00001000:")

    def test_unknown_function_raises(self, wrapper):
        with pytest.raises(ValueError, match="No function at"):
            wrapper.get_function_disasm(0xDEAD)


class TestGetEntryPoint:
    def test_returns_image_base(self, wrapper):
        # ida_ida is not in the mock install list, so the wrapper falls
        # through to idc.get_inf_attr which returns the seeded image_base.
        assert wrapper.get_entry_point() == 0x1000


class TestGetStrings:
    def test_returns_seeded_strings(self, wrapper):
        result = wrapper.get_strings()
        assert result["total"] == 3
        values = [s["value"] for s in result["strings"]]
        assert "hello" in values
        assert "ERROR_FATAL" in values

    def test_regex_filter(self, wrapper):
        result = wrapper.get_strings(regex="ERROR")
        assert [s["value"] for s in result["strings"]] == ["ERROR_FATAL"]

    def test_pagination(self, wrapper):
        first = wrapper.get_strings(offset=0, limit=2)
        assert first["count"] == 2
        assert first["offset"] == 0
        second = wrapper.get_strings(offset=2, limit=2)
        assert second["count"] == 1
        assert second["offset"] == 2


class TestGetExports:
    def test_returns_seeded_entries(self, wrapper):
        exports = wrapper.get_exports()
        names = [e["name"] for e in exports]
        assert "main" in names
        assert "init_runtime" in names


class TestXRefs:
    def test_xrefs_to_returns_call_site(self, wrapper):
        # Seeded: 0x1100 has one xref from 0x1000.
        xrefs = wrapper.get_xrefs_to(0x1100)
        assert len(xrefs) == 1
        assert xrefs[0]["from"] == 0x1000
        assert xrefs[0]["to"] == 0x1100

    def test_xrefs_from_returns_call_target(self, wrapper):
        # Seeded: 0x1000 has one xref to 0x1100.
        xrefs = wrapper.get_xrefs_from(0x1000)
        assert len(xrefs) == 1
        assert xrefs[0]["from"] == 0x1000
        assert xrefs[0]["to"] == 0x1100

    def test_no_xrefs_returns_empty(self, wrapper):
        assert wrapper.get_xrefs_to(0xDEAD) == []
        assert wrapper.get_xrefs_from(0xDEAD) == []


class TestDataAndStringRefs:
    def test_data_refs_returns_seeded_refs(self, wrapper):
        # xrefblk_t mock returns two refs when first_to(0x3000, …) is called.
        refs = wrapper.get_data_refs(0x3000)
        assert {r["from"] for r in refs} == {0x1000, 0x1100}

    def test_string_xrefs_adds_function_context(self, wrapper):
        refs = wrapper.get_string_xrefs(0x3000)
        assert len(refs) == 2
        # Both refs originate inside functions, so function metadata is
        # populated (main at 0x1000, sub_1100 at 0x1100).
        assert any(r["function_name"] == "main" for r in refs)
        assert any(r["function_name"] == "sub_1100" for r in refs)


class TestReadWords:
    def test_dword_qword_return_seeded_values(self, wrapper):
        assert wrapper.get_dword_at(0x1234) == 0xDEADBEEF
        assert wrapper.get_qword_at(0x1234) == 0xDEADBEEFCAFEBABE


class TestDataReadString:
    def test_reads_until_null(self, wrapper):
        # Memory map has "hello\x00" starting at 0x1000.
        assert wrapper.data_read_string(0x1000, 32) == "hello"


class TestDataReadByte:
    def test_returns_seeded_byte(self, wrapper):
        # 'h' = 0x68 at 0x1000 per the seeded memory map.
        assert wrapper.data_read_byte(0x1000) == 0x68


class TestCommentRoundtrip:
    def test_set_get_address_comment(self, wrapper):
        assert wrapper.set_comment(0x1000, "entry") is True
        assert wrapper.get_comment(0x1000) == "entry"

    def test_set_get_func_comment(self, wrapper):
        assert wrapper.set_func_comment(0x1000, "kickoff") is True
        assert wrapper.get_func_comment(0x1000) == "kickoff"

    def test_missing_address_returns_empty(self, wrapper):
        assert wrapper.get_comment(0xDEAD) == ""
        assert wrapper.get_func_comment(0xDEAD) == ""


class TestSetFunctionType:
    def test_apply_prototype(self, wrapper):
        assert wrapper.set_function_type(0x1000, "int main(int argc)") is True

    def test_blank_prototype_raises(self, wrapper):
        with pytest.raises(ValueError, match="prototype is required"):
            wrapper.set_function_type(0x1000, "")


class TestSetGlobalType:
    def test_applies_type_via_tinfo(self, wrapper):
        # set_global_type goes through ida_typeinf.parse_decl + apply_tinfo
        # rather than idc.parse_decl, so this exercises the new mocks.
        assert wrapper.set_global_type(0x3000, "Point *") is True
        from tests.mocks.mock_idapro import get_db
        # apply_tinfo writes db.types under the address.
        assert get_db().types[0x3000] != ""

    def test_blank_type_raises(self, wrapper):
        with pytest.raises(ValueError, match="type is required"):
            wrapper.set_global_type(0x3000, "")


class TestRenameGlobal:
    def test_changes_name(self, wrapper):
        assert wrapper.rename_global(0x3000, "g_renamed") is True
        assert wrapper.get_name(0x3000) == "g_renamed"

    def test_blank_name_raises(self, wrapper):
        with pytest.raises(ValueError, match="new_name is required"):
            wrapper.rename_global(0x3000, "")


class TestMakeFunction:
    def test_creates_function(self, wrapper):
        assert wrapper.make_function(0x5000) is True


class TestGetInstructionLength:
    def test_returns_seeded_length(self, wrapper):
        assert wrapper.get_instruction_length(0x1000) == 1
        assert wrapper.get_instruction_length(0x1004) == 3

    def test_unknown_addr_raises(self, wrapper):
        with pytest.raises(Exception, match="Failed to decode"):
            wrapper.get_instruction_length(0xDEAD)


class TestGetFunctionName:
    def test_returns_db_name(self, wrapper):
        assert wrapper.get_function_name(0x1100) == "sub_1100"


class TestOpenDatabaseRepair:
    """Tests for the corruption-repair path in _try_open_with_repair."""

    def test_corruption_repaired_on_retry(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        from tests.mocks import mock_idapro
        # First call returns 1 (format error → triggers repair); second call
        # (the retry after sidecar deletion) succeeds.
        mock_idapro._open_results.extend([1, 0])

        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 1024)
        # Seed a sidecar so _delete_ida_sidecars has something to remove.
        sidecar = tmp_path / "test.i64"
        sidecar.write_bytes(b"stale")

        wrapper = IDAWrapper(str(binary), "test-session")
        result = wrapper.open_database(auto_analyze=False)

        assert result is True
        assert wrapper.db_open is True
        assert not sidecar.exists()  # sidecar deleted before the retry
        assert wrapper.last_error is None

    def test_unrecoverable_error_skips_repair(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        from tests.mocks import mock_idapro
        # Code -1 isn't in the repair set (1, 4); it's terminal on the first try.
        mock_idapro._open_results.append(-1)

        binary = tmp_path / "test_err.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        result = wrapper.open_database(auto_analyze=False)
        assert result is False
        assert "File not found" in (wrapper.last_error or "")

    def test_repair_failure_surfaces_final_error(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        from tests.mocks import mock_idapro
        # Both attempts fail with code 4 ("already exists or corrupted").
        mock_idapro._open_results.extend([4, 4])

        binary = tmp_path / "test_repair_fail.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-session")
        result = wrapper.open_database(auto_analyze=False)
        assert result is False
        assert "already exists or corrupted" in (wrapper.last_error or "")


class TestDeleteIdaSidecars:
    """Direct test of the sidecar-cleanup helper."""

    def test_removes_each_extension(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        binary = tmp_path / "subject.bin"
        binary.write_bytes(b"\x90" * 16)

        sidecars = [tmp_path / f"subject.{ext}"
                    for ext in ("i64", "id0", "nam", "til")]
        for f in sidecars:
            f.write_bytes(b"stale")

        wrapper = IDAWrapper(str(binary), "test-session")
        deleted = wrapper._delete_ida_sidecars()
        assert {os.path.basename(p) for p in deleted} == {f.name for f in sidecars}
        for f in sidecars:
            assert not f.exists()
        # The binary itself is not a sidecar — must survive.
        assert binary.exists()

    def test_returns_empty_when_no_sidecars(self, tmp_path, setup_mocks):
        IDAWrapper = setup_mocks
        binary = tmp_path / "subject.bin"
        binary.write_bytes(b"\x90" * 16)

        wrapper = IDAWrapper(str(binary), "test-session")
        assert wrapper._delete_ida_sidecars() == []

    def test_ignores_glob_metacharacters_in_path(self, tmp_path, setup_mocks):
        """A binary_path with glob metacharacters must not expand to a wildcard.

        binary_path is agent-influenced. The old glob.glob approach treated base
        "pro[g]" as a character class matching the single char g, so a decoy
        "prog.i64" would be matched and wrongly deleted. The literal-name
        approach only ever touches the exact "pro[g].i64".
        """
        IDAWrapper = setup_mocks
        binary = tmp_path / "pro[g].bin"
        binary.write_bytes(b"\x90" * 16)
        literal_sidecar = tmp_path / "pro[g].i64"
        literal_sidecar.write_bytes(b"db")
        decoy = tmp_path / "prog.i64"  # glob [g] expansion would hit this
        decoy.write_bytes(b"keep")

        wrapper = IDAWrapper(str(binary), "test-session")
        deleted = wrapper._delete_ida_sidecars()

        assert [os.path.basename(p) for p in deleted] == ["pro[g].i64"]
        assert not literal_sidecar.exists()
        assert decoy.exists()  # never matched by a wildcard

    def test_skips_symlinked_sidecar(self, tmp_path, setup_mocks):
        """A symlinked sidecar is left alone so we never delete through a link
        to an unrelated file."""
        IDAWrapper = setup_mocks
        if sys.platform == "win32":
            pytest.skip("symlink creation requires elevation on Windows")
        binary = tmp_path / "subject.bin"
        binary.write_bytes(b"\x90" * 16)
        outside = tmp_path / "important.dat"
        outside.write_bytes(b"do-not-touch")
        link = tmp_path / "subject.i64"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("symlink unsupported in this environment")

        wrapper = IDAWrapper(str(binary), "test-session")
        deleted = wrapper._delete_ida_sidecars()

        assert deleted == []
        assert link.is_symlink()  # the link itself is left in place
        assert outside.exists() and outside.read_bytes() == b"do-not-touch"
