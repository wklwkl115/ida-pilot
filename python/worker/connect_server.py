"""
Connect RPC Server
Implements SessionControl, AnalysisTools, and Healthcheck services
"""

import json
import logging
import sys
import time
from pathlib import Path

# Add gen path for protobuf imports
sys.path.insert(0, str(Path(__file__).parent / "gen"))

from ida.worker.v1 import service_pb2 as pb


def _proto_handler(req_cls, resp_cls, ida_method, extract_args, build_response):
    """Build a Connect RPC handler closure.

    Each handler:
      1. Parses proto_body into req_cls (None for nullary methods).
      2. Calls self.ida.<ida_method>(*extract_args(req)).
      3. Constructs resp_cls and lets build_response(resp, result, req) fill it.

    Collapses the parse/call/build dance that every dispatch branch would
    otherwise duplicate. build_response receives req so handlers that fall back
    to a request field (e.g. xref.to defaulting to req.address) stay one line.
    """
    def handler(self, body):
        if req_cls is not None:
            req = req_cls()
            req.ParseFromString(body)
            args = extract_args(req) if extract_args else ()
        else:
            req = None
            args = ()
        result = getattr(self.ida, ida_method)(*args)
        resp = resp_cls()
        build_response(resp, result, req)
        return resp
    return handler


def _set_field(field):
    """Builder factory: copies the wrapper result into resp.<field>."""
    return lambda resp, val, req: setattr(resp, field, val)


def _set_success(resp, val, req):
    resp.success = val


def _set_bytes(field):
    """Builder for binary fields — coerces lists/iterables to bytes."""
    return lambda resp, val, req: setattr(resp, field, bytes(val))


def _build_segments(resp, result, req):
    for seg in result:
        seg_pb = resp.segments.add()
        seg_pb.start = seg["start"]
        seg_pb.end = seg["end"]
        seg_pb.name = seg["name"]
        seg_class = seg.get("seg_class", 0)
        seg_pb.seg_class = str(seg_class) if seg_class is not None else ""
        seg_pb.permissions = seg.get("permissions", 0)
        seg_pb.bitness = seg.get("bitness", 0)


def _build_functions(resp, result, req):
    for func in result:
        func_pb = resp.functions.add()
        func_pb.address = func["address"]
        func_pb.name = func["name"]


def _build_xrefs_to(resp, result, req):
    # GetXRefsTo: the wrapper may omit "to" when iterating xrefs that all
    # target the queried address; default to req.address in that case.
    for xref in result:
        xref_pb = resp.xrefs.add()
        setattr(xref_pb, "from", xref["from"])
        xref_pb.to = xref.get("to", req.address)
        xref_pb.type = xref["type"]


def _build_xrefs_from(resp, result, req):
    for xref in result:
        xref_pb = resp.xrefs.add()
        setattr(xref_pb, "from", xref["from"])
        xref_pb.to = xref["to"]
        xref_pb.type = xref["type"]


def _build_data_refs(resp, result, req):
    for ref in result:
        ref_pb = resp.refs.add()
        setattr(ref_pb, "from", ref["from"])
        ref_pb.type = ref["type"]


def _build_string_xrefs(resp, result, req):
    for ref in result:
        ref_pb = resp.refs.add()
        ref_pb.address = ref["address"]
        ref_pb.function_address = ref["function_address"]
        ref_pb.function_name = ref["function_name"]


def _build_imports(resp, result, req):
    for imp in result:
        imp_pb = resp.imports.add()
        imp_pb.module = imp.get("module", "")
        imp_pb.address = imp["address"]
        imp_pb.name = imp["name"]
        imp_pb.ordinal = imp.get("ordinal", 0)


def _build_exports(resp, result, req):
    for exp in result:
        exp_pb = resp.exports.add()
        exp_pb.index = exp.get("index", 0)
        exp_pb.ordinal = exp["ordinal"]
        exp_pb.address = exp["address"]
        exp_pb.name = exp["name"]


def _build_strings(resp, result, req):
    resp.total = result["total"]
    resp.offset = result["offset"]
    resp.count = result["count"]
    for s in result["strings"]:
        str_pb = resp.strings.add()
        str_pb.address = s["address"]
        str_pb.value = s["value"]


def _build_globals(resp, result, req):
    for g in result:
        glob_pb = resp.globals.add()
        glob_pb.address = g["address"]
        glob_pb.name = g["name"]
        glob_pb.type = g["type"]


def _build_addresses_extend(field):
    return lambda resp, val, req: getattr(resp, field).extend(val)


def _build_struct_summaries(resp, result, req):
    for item in result:
        summary = resp.structs.add()
        summary.name = item.get("name", "")
        summary.id = item.get("id", 0)
        summary.size = item.get("size", 0)


def _build_struct(resp, result, req):
    resp.name = result["name"]
    resp.id = result["id"]
    resp.size = result["size"]
    for member in result["members"]:
        mem = resp.members.add()
        mem.name = member.get("name", "")
        mem.offset = member.get("offset", 0)
        mem.size = member.get("size", 0)
        mem.type = member.get("type", "")


def _build_enum_summaries(resp, result, req):
    for item in result:
        summary = resp.enums.add()
        summary.name = item.get("name", "")
        summary.id = item.get("ordinal", 0)


def _build_enum(resp, result, req):
    resp.name = result["name"]
    resp.id = result["id"]
    for member in result["members"]:
        mem = resp.members.add()
        mem.name = member.get("name", "")
        mem.value = member.get("value", 0)


def _build_function_info(resp, result, req):
    resp.address = result["address"]
    resp.name = result["name"]
    resp.start = result["start"]
    resp.end = result["end"]
    resp.size = result["size"]
    resp.frame_size = result["frame_size"]
    resp.flags.is_library = result["flags"]["is_library"]
    resp.flags.is_thunk = result["flags"]["is_thunk"]
    resp.flags.no_return = result["flags"]["no_return"]
    resp.flags.has_farseg = result["flags"]["has_farseg"]
    resp.flags.is_static = result["flags"]["is_static"]
    if result["calling_convention"]:
        resp.calling_convention = result["calling_convention"]
    if result["return_type"]:
        resp.return_type = result["return_type"]
    resp.num_args = result["num_args"]


def _build_type_at(resp, result, req):
    resp.address = result["address"]
    resp.type = result["type"]
    resp.size = result["size"]
    resp.is_ptr = result["is_ptr"]
    resp.is_func = result["is_func"]
    resp.is_array = result["is_array"]
    resp.is_struct = result["is_struct"]
    resp.is_union = result["is_union"]
    resp.is_enum = result["is_enum"]
    resp.has_type = result["has_type"]


# Method → handler. Each entry replaces an ~8-line elif branch with one
# table row. Custom logic lives in named builders above; the factory pulls
# req fields via the lambda and routes the wrapper return through the
# builder. Methods needing pre/post wrapping that don't fit this shape
# (currently: ImportIl2Cpp, ImportFlutter — both do file IO outside the
# wrapper) keep dedicated handler functions defined below.
_ANALYSIS_HANDLERS = {
    "GetBytes": _proto_handler(pb.GetBytesRequest, pb.GetBytesResponse,
                               "get_bytes", lambda r: (r.address, r.size), _set_bytes("data")),
    "GetDisasm": _proto_handler(pb.GetDisasmRequest, pb.GetDisasmResponse,
                                "get_disasm", lambda r: (r.address,), _set_field("disasm")),
    "GetFunctionDisasm": _proto_handler(pb.GetFunctionDisasmRequest, pb.GetFunctionDisasmResponse,
                                        "get_function_disasm", lambda r: (r.address,), _set_field("disassembly")),
    "GetDecompiled": _proto_handler(pb.GetDecompiledRequest, pb.GetDecompiledResponse,
                                    "get_decompiled", lambda r: (r.address,), _set_field("code")),
    "GetFunctionName": _proto_handler(pb.GetFunctionNameRequest, pb.GetFunctionNameResponse,
                                      "get_function_name", lambda r: (r.address,), _set_field("name")),
    "GetSegments": _proto_handler(None, pb.GetSegmentsResponse,
                                  "get_segments", None, _build_segments),
    "GetFunctions": _proto_handler(None, pb.GetFunctionsResponse,
                                   "get_functions", None, _build_functions),
    "GetXRefsTo": _proto_handler(pb.GetXRefsToRequest, pb.GetXRefsToResponse,
                                 "get_xrefs_to", lambda r: (r.address,), _build_xrefs_to),
    "GetXRefsFrom": _proto_handler(pb.GetXRefsFromRequest, pb.GetXRefsFromResponse,
                                   "get_xrefs_from", lambda r: (r.address,), _build_xrefs_from),
    "GetDataRefs": _proto_handler(pb.GetDataRefsRequest, pb.GetDataRefsResponse,
                                  "get_data_refs", lambda r: (r.address,), _build_data_refs),
    "GetStringXRefs": _proto_handler(pb.GetStringXRefsRequest, pb.GetStringXRefsResponse,
                                     "get_string_xrefs", lambda r: (r.address,), _build_string_xrefs),
    "GetImports": _proto_handler(None, pb.GetImportsResponse,
                                 "get_imports", None, _build_imports),
    "GetExports": _proto_handler(None, pb.GetExportsResponse,
                                 "get_exports", None, _build_exports),
    "GetEntryPoint": _proto_handler(None, pb.GetEntryPointResponse,
                                    "get_entry_point", None, _set_field("address")),
    "GetStrings": _proto_handler(
        pb.GetStringsRequest, pb.GetStringsResponse, "get_strings",
        # offset defaults to 0; limit defaults to 1000 (proto default-zero is
        # not "no limit" here — the wrapper expects a positive page size).
        lambda r: (r.offset if r.offset > 0 else 0, r.limit if r.limit > 0 else 1000),
        _build_strings),
    "MakeFunction": _proto_handler(pb.MakeFunctionRequest, pb.MakeFunctionResponse,
                                   "make_function", lambda r: (r.address,), _set_success),
    "GetDwordAt": _proto_handler(pb.GetDwordAtRequest, pb.GetDwordAtResponse,
                                 "get_dword_at", lambda r: (r.address,), _set_field("value")),
    "GetQwordAt": _proto_handler(pb.GetQwordAtRequest, pb.GetQwordAtResponse,
                                 "get_qword_at", lambda r: (r.address,), _set_field("value")),
    "GetInstructionLength": _proto_handler(pb.GetInstructionLengthRequest, pb.GetInstructionLengthResponse,
                                           "get_instruction_length", lambda r: (r.address,), _set_field("length")),
    "SetComment": _proto_handler(pb.SetCommentRequest, pb.SetCommentResponse,
                                 "set_comment", lambda r: (r.address, r.comment, r.repeatable), _set_success),
    "GetComment": _proto_handler(pb.GetCommentRequest, pb.GetCommentResponse,
                                 "get_comment", lambda r: (r.address, r.repeatable), _set_field("comment")),
    "SetFuncComment": _proto_handler(pb.SetFuncCommentRequest, pb.SetFuncCommentResponse,
                                     "set_func_comment", lambda r: (r.address, r.comment), _set_success),
    "GetFuncComment": _proto_handler(pb.GetFuncCommentRequest, pb.GetFuncCommentResponse,
                                     "get_func_comment", lambda r: (r.address,), _set_field("comment")),
    "SetDecompilerComment": _proto_handler(pb.SetDecompilerCommentRequest, pb.SetDecompilerCommentResponse,
                                           "set_decompiler_comment",
                                           lambda r: (r.function_address, r.address, r.comment), _set_success),
    "SetName": _proto_handler(pb.SetNameRequest, pb.SetNameResponse,
                              "set_name", lambda r: (r.address, r.name), _set_success),
    "SetFunctionType": _proto_handler(pb.SetFunctionTypeRequest, pb.SetFunctionTypeResponse,
                                      "set_function_type", lambda r: (r.address, r.prototype), _set_success),
    "SetLvarType": _proto_handler(pb.SetLvarTypeRequest, pb.SetLvarTypeResponse,
                                  "set_lvar_type",
                                  lambda r: (r.function_address, r.lvar_name, r.lvar_type), _set_success),
    "RenameLvar": _proto_handler(pb.RenameLvarRequest, pb.RenameLvarResponse,
                                 "rename_lvar",
                                 lambda r: (r.function_address, r.lvar_name, r.new_name), _set_success),
    "GetGlobals": _proto_handler(pb.GetGlobalsRequest, pb.GetGlobalsResponse,
                                 "get_globals", lambda r: (r.regex or None, r.case_sensitive), _build_globals),
    "SetGlobalType": _proto_handler(pb.SetGlobalTypeRequest, pb.SetGlobalTypeResponse,
                                    "set_global_type", lambda r: (r.address, r.type), _set_success),
    "RenameGlobal": _proto_handler(pb.RenameGlobalRequest, pb.RenameGlobalResponse,
                                   "rename_global", lambda r: (r.address, r.new_name), _set_success),
    "DataReadString": _proto_handler(pb.DataReadStringRequest, pb.DataReadStringResponse,
                                     "data_read_string", lambda r: (r.address, r.max_length or 0), _set_field("value")),
    "DataReadByte": _proto_handler(pb.DataReadByteRequest, pb.DataReadByteResponse,
                                   "data_read_byte", lambda r: (r.address,), _set_field("value")),
    "FindBinary": _proto_handler(pb.FindBinaryRequest, pb.FindBinaryResponse,
                                 "find_binary",
                                 lambda r: (r.start, r.end, r.pattern, r.search_up),
                                 _build_addresses_extend("addresses")),
    "FindText": _proto_handler(pb.FindTextRequest, pb.FindTextResponse,
                               "find_text",
                               lambda r: (r.start, r.end, r.needle, r.case_sensitive, r.unicode),
                               _build_addresses_extend("addresses")),
    "ListStructs": _proto_handler(pb.ListStructsRequest, pb.ListStructsResponse,
                                  "list_structs", lambda r: (r.regex, r.case_sensitive), _build_struct_summaries),
    "GetStruct": _proto_handler(pb.GetStructRequest, pb.GetStructResponse,
                                "get_struct", lambda r: (r.name,), _build_struct),
    "ListEnums": _proto_handler(pb.ListEnumsRequest, pb.ListEnumsResponse,
                                "list_enums", lambda r: (r.regex, r.case_sensitive), _build_enum_summaries),
    "GetEnum": _proto_handler(pb.GetEnumRequest, pb.GetEnumResponse,
                              "get_enum", lambda r: (r.name,), _build_enum),
    "GetFunctionInfo": _proto_handler(pb.GetFunctionInfoRequest, pb.GetFunctionInfoResponse,
                                      "get_function_info", lambda r: (r.address,), _build_function_info),
    "GetTypeAt": _proto_handler(pb.GetTypeAtRequest, pb.GetTypeAtResponse,
                                "get_type_at", lambda r: (r.address,), _build_type_at),
    "GetName": _proto_handler(pb.GetNameRequest, pb.GetNameResponse,
                              "get_name", lambda r: (r.address,), _set_field("name")),
    "DeleteName": _proto_handler(pb.DeleteNameRequest, pb.DeleteNameResponse,
                                 "delete_name", lambda r: (r.address,), _set_success),
}


class ConnectServer:
    """Simple Connect RPC handler over HTTP"""

    def __init__(self, ida_wrapper, executor=None):
        self.ida = ida_wrapper
        # All IDA-entering work runs on this single executor thread because
        # idalib is not thread-safe and assumes the main thread. If no executor
        # is supplied, work runs inline on the calling thread (legacy/tests).
        self.executor = executor
        self.pending_requests = 0

    def _ensure_database_open(self, auto_analyze: bool) -> tuple[bool, str | None]:
        """Ensure the IDA database is open before servicing requests."""
        if self.ida.db_open:
            return True, None
        success = self.ida.open_database(auto_analyze)
        if success:
            return True, None
        return False, self.ida.last_error or "Failed to open IDA database"

    def _require_open_database(self):
        if self.ida.db_open:
            return
        success, error = self._ensure_database_open(auto_analyze=False)
        if not success:
            raise RuntimeError(error or "IDA database is not open. Call OpenBinary first.")

    def handle(self, method: str, path: str, data: bytes) -> bytes:
        """Handle Connect RPC request.

        The lightweight status endpoints (Healthcheck/* and
        SessionControl/GetSessionInfo) are answered inline on the calling
        connection thread so they stay responsive during a long load/analysis.
        Every other request enters idalib and is funneled to the single IDA
        thread via the executor, since idalib is not thread-safe.
        """
        try:
            self.pending_requests += 1

            parts = path.split("/")
            if len(parts) >= 3:
                service = parts[-2].split(".")[-1]
                rpc_method = parts[-1]
                # Status endpoints — no IDA access, answer inline.
                if service == "Healthcheck":
                    return self._success_response(
                        self._handle_healthcheck(rpc_method, self._extract_body(data)))
                if service == "SessionControl" and rpc_method == "GetSessionInfo":
                    return self._success_response(
                        self._handle_session_control(rpc_method, self._extract_body(data)))

            # Everything else enters IDA — run it on the single IDA thread.
            if self.executor is not None:
                return self.executor.submit(lambda: self._dispatch(method, path, data))
            return self._dispatch(method, path, data)

        except Exception as e:
            logging.error(f"Error handling request: {e}", exc_info=True)
            return self._error_response(500, str(e))
        finally:
            self.pending_requests -= 1

    def _dispatch(self, method: str, path: str, data: bytes) -> bytes:
        """Route an IDA-entering request to its handler. Runs on the IDA thread."""
        if path == "/py_eval":
            return self._handle_py_eval(data)
        if path == "/batch_annotate":
            return self._handle_batch_annotate(data)

        # Path format: /idagrpc.v1.ServiceName/MethodName
        parts = path.split("/")
        if len(parts) < 3:
            return self._error_response(400, "Invalid path")

        service = parts[-2].split(".")[-1]  # Extract ServiceName
        rpc_method = parts[-1]
        proto_body = self._extract_body(data)

        if service == "SessionControl":
            response_pb = self._handle_session_control(rpc_method, proto_body)
        elif service == "AnalysisTools":
            response_pb = self._handle_analysis_tools(rpc_method, proto_body)
        elif service == "Healthcheck":
            response_pb = self._handle_healthcheck(rpc_method, proto_body)
        else:
            return self._error_response(404, f"Unknown service: {service}")

        return self._success_response(response_pb)

    def _handle_session_control(self, method: str, proto_body: bytes):
        """Handle SessionControl RPC - returns protobuf message"""
        if method == "OpenBinary":
            req = pb.OpenBinaryRequest()
            req.ParseFromString(proto_body)
            resp = pb.OpenBinaryResponse()

            success, error = self._ensure_database_open(req.auto_analyze)
            resp.success = success
            resp.binary_path = self.ida.binary_path

            if success:
                resp.has_decompiler = self.ida.has_decompiler
            else:
                resp.error = error or "Failed to open IDA database"
            return resp

        elif method == "CloseSession":
            req = pb.CloseSessionRequest()
            req.ParseFromString(proto_body)
            if not self.ida.db_open:
                success = True
            else:
                success = self.ida.close_database(req.save)
            resp = pb.CloseSessionResponse()
            resp.success = success
            return resp

        elif method == "SaveDatabase":
            self._require_open_database()
            success, timestamp, dirty = self.ida.save_database()
            resp = pb.SaveDatabaseResponse()
            resp.success = success
            resp.timestamp = timestamp
            resp.dirty = dirty
            if not success:
                resp.error = "Failed to save database"
            return resp

        elif method == "PlanAndWait":
            self._require_open_database()
            success, duration, error = self.ida.plan_and_wait()
            resp = pb.PlanAndWaitResponse()
            resp.success = success
            resp.duration_seconds = duration
            if error:
                resp.error = error
            return resp

        elif method == "GetSessionInfo":
            resp = pb.GetSessionInfoResponse()
            resp.binary_path = self.ida.binary_path
            resp.opened_at = int(self.ida.opened_at or 0)
            resp.last_activity = int(self.ida.last_activity or 0)
            resp.has_decompiler = self.ida.has_decompiler
            auto_running, auto_state = self.ida.get_auto_status()
            resp.auto_running = auto_running
            resp.auto_state = auto_state
            return resp

        else:
            raise Exception(f"Unknown method: {method}")

    def _handle_analysis_tools(self, method: str, proto_body: bytes):
        """Handle AnalysisTools RPC - returns protobuf message.

        Dispatch lives in the module-level _ANALYSIS_HANDLERS table; this
        function only validates state and routes. Methods that do file IO
        or other pre-wrapper work outside the parse/call/build shape have
        dedicated _handle_* methods below.
        """
        self._require_open_database()

        if method == "ImportIl2Cpp":
            return self._handle_import_il2cpp(proto_body)
        if method == "ImportFlutter":
            return self._handle_import_flutter(proto_body)

        handler = _ANALYSIS_HANDLERS.get(method)
        if handler is None:
            raise Exception(f"Unknown method: {method}")
        try:
            return handler(self, proto_body)
        except Exception as e:
            logging.error(f"Analysis tool error: {e}")
            raise

    def _handle_import_il2cpp(self, proto_body: bytes):
        """Read Il2Cpp metadata (script.json + il2cpp.h) from disk and apply via the wrapper."""
        req = pb.ImportIl2CppRequest()
        req.ParseFromString(proto_body)
        if not req.script_path or not req.il2cpp_path:
            raise ValueError("script_path and il2cpp_path are required")
        with open(req.script_path, "r", encoding="utf-8") as f:
            script_json = f.read()
        with open(req.il2cpp_path, "r", encoding="utf-8") as f:
            header = f.read()
        result = self.ida.import_il2cpp(script_json, header, list(req.fields))
        resp = pb.ImportIl2CppResponse()
        resp.success = True
        resp.duration_seconds = result.get("duration_seconds", 0.0)
        resp.functions_defined = result.get("functions_defined", 0)
        resp.functions_named = result.get("functions_named", 0)
        resp.strings_named = result.get("strings_named", 0)
        resp.metadata_named = result.get("metadata_named", 0)
        resp.metadata_methods = result.get("metadata_methods", 0)
        resp.signatures_applied = result.get("signatures_applied", 0)
        if result.get("header_error"):
            resp.error = result["header_error"]
        return resp

    def _handle_import_flutter(self, proto_body: bytes):
        """Hand a Flutter/Dart metadata JSON path to the wrapper."""
        req = pb.ImportFlutterRequest()
        req.ParseFromString(proto_body)
        if not req.meta_json_path:
            raise ValueError("meta_json_path is required")
        result = self.ida.import_flutter_metadata(req.meta_json_path)
        resp = pb.ImportFlutterResponse()
        resp.success = True
        resp.duration_seconds = result.get("duration_seconds", 0.0)
        resp.functions_created = result.get("functions_created", 0)
        resp.functions_named = result.get("functions_named", 0)
        resp.structs_created = result.get("structs_created", 0)
        resp.signatures_applied = result.get("signatures_applied", 0)
        resp.comments_set = result.get("comments_set", 0)
        return resp

    def _handle_healthcheck(self, method: str, proto_body: bytes):
        """Handle Healthcheck RPC - returns protobuf message"""
        if method == "Ping":
            resp = pb.PingResponse()
            resp.alive = True
            return resp

        elif method == "StatusStream":
            # For now, return single status (streaming would need more work)
            resp = pb.WorkerStatus()
            resp.timestamp = int(time.time())
            resp.memory_bytes = 0  # TODO: implement
            resp.dirty = False
            resp.last_activity = int(self.ida.last_activity)
            resp.pending_requests = self.pending_requests
            return resp

        else:
            raise Exception(f"Unknown method: {method}")

    def _handle_batch_annotate(self, data: bytes) -> bytes:
        """Batch all annotation operations into a single call."""
        try:
            self._require_open_database()
            body = self._extract_body(data)
            req = json.loads(body)
            addr = req.get("address", 0)
            applied = []
            failed = []

            def run_op(label, op_name, fn):
                """Append to applied/failed based on fn() result, catching any wrapper exception."""
                try:
                    ok = fn()
                    if ok:
                        applied.append(label)
                    else:
                        failed.append(f"{label}: {op_name} returned false")
                except Exception as exc:
                    failed.append(f"{label}: {exc}")

            for rt in req.get("retypes", []):
                run_op(f"retype {rt['name']} → {rt['type']}", "set_lvar_type",
                       lambda rt=rt: self.ida.set_lvar_type(addr, rt["name"], rt["type"]))

            for rn in req.get("renames", []):
                run_op(f"rename {rn['current']} → {rn['new']}", "rename_lvar",
                       lambda rn=rn: self.ida.rename_lvar(addr, rn["current"], rn["new"]))

            name = req.get("name", "")
            if name:
                run_op(f"func_name → {name}", "set_name",
                       lambda: self.ida.set_name(addr, name))

            comment = req.get("comment", "")
            if comment:
                run_op("func_comment", "set_func_comment",
                       lambda: self.ida.set_func_comment(addr, comment))

            for dc in req.get("decompiler_comments", []):
                run_op(f"decompiler_comment@0x{dc['address']:x}", "set_decompiler_comment",
                       lambda dc=dc: self.ida.set_decompiler_comment(addr, dc["address"], dc["comment"]))

            decompilation = ""
            try:
                decompilation = self.ida.get_decompiled(addr)
            except Exception as e:
                decompilation = f"[decompilation error: {e}]"

            result = {
                "applied": applied,
                "applied_count": len(applied),
                "decompilation": decompilation,
            }
            if failed:
                result["failed"] = failed
                result["failed_count"] = len(failed)

            return self._json_response(200, result)
        except Exception as e:
            logging.error(f"batch_annotate error: {e}", exc_info=True)
            return self._json_response(500, {"error": str(e)})

    def _handle_py_eval(self, data: bytes) -> bytes:
        """Handle py_eval JSON endpoint"""
        try:
            self._require_open_database()
            body = self._extract_body(data)
            req = json.loads(body)
            code = req.get("code", "")
            if not code:
                return self._json_response(400, {"error": "code is required"})
            result = self.ida.py_eval(code)
            return self._json_response(200, result)
        except Exception as e:
            logging.error(f"py_eval error: {e}", exc_info=True)
            return self._json_response(500, {"error": str(e)})

    def _json_response(self, code: int, data: dict) -> bytes:
        """Build HTTP response with JSON body"""
        body = json.dumps(data, default=str).encode()
        status = "OK" if code == 200 else "Error"
        return (
            f"HTTP/1.1 {code} {status}\r\n".encode() +
            b"Content-Type: application/json\r\n"
            b"Connection: close\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )

    def _extract_body(self, data: bytes) -> bytes:
        """Extract protobuf body from HTTP request"""
        # Find body after headers
        if b"\r\n\r\n" in data:
            return data.split(b"\r\n\r\n", 1)[1]
        return b""

    def _success_response(self, proto_msg) -> bytes:
        """Build HTTP 200 response with protobuf body"""
        body = proto_msg.SerializeToString()
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/proto\r\n"
            b"Connection: close\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        return response

    def _error_response(self, code: int, message: str) -> bytes:
        """Build HTTP error response"""
        # Use plain text for errors
        body = message.encode()
        status_line = f"HTTP/1.1 {code} Error\r\n".encode()
        response = (
            status_line +
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        return response
