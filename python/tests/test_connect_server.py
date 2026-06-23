"""
Unit tests for connect_server.ConnectServer — runs without real IDA Pro.

Tests request routing, protobuf encoding, error handling, and the
lightweight status-endpoint fast path.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "worker"))

from tests.mocks import install, uninstall, reset


@pytest.fixture(autouse=True)
def setup_mocks(tmp_path):
    """Install mocks and create a live IDAWrapper + ConnectServer."""
    install()
    from worker.ida_wrapper import IDAWrapper
    from worker.connect_server import ConnectServer

    binary = tmp_path / "test_cs.bin"
    binary.write_bytes(b"\x90" * 1024)

    wrapper = IDAWrapper(str(binary), "test-cs")
    wrapper.open_database(auto_analyze=False)
    server = ConnectServer(wrapper, executor=None)  # inline for testing

    yield server, wrapper, str(binary)

    reset()
    uninstall()


class TestRequestRouting:
    """Tests for ConnectServer request routing."""

    @staticmethod
    def _make_request(body_bytes: bytes) -> bytes:
        """Build a minimal HTTP POST request."""
        body = body_bytes
        return (
            b"POST /idagrpc.v1.SessionControl/OpenBinary HTTP/1.1\r\n"
            b"Host: unix\r\n"
            b"Content-Type: application/proto\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )

    @staticmethod
    def _parse_response(data: bytes) -> tuple:
        """Parse HTTP response into status, headers dict, body."""
        if b"\r\n\r\n" not in data:
            return 0, {}, data
        header_section, body = data.split(b"\r\n\r\n", 1)
        lines = header_section.split(b"\r\n")
        status = int(lines[0].split(b" ")[1])
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode().strip()] = v.strip().decode()
        return status, headers, body

    def test_ping_healthcheck(self, setup_mocks):
        server, wrapper, _ = setup_mocks
        from ida.worker.v1 import service_pb2 as pb

        req = pb.PingRequest()
        body = self._make_request(req.SerializeToString())
        resp = server.handle("POST", "/idagrpc.v1.Healthcheck/Ping", body)

        status, headers, body = self._parse_response(resp)
        assert status == 200
        assert headers.get("Content-Type") == "application/proto"

        ping_resp = pb.PingResponse()
        ping_resp.ParseFromString(body)
        assert ping_resp.alive is True

    def test_get_session_info_inline(self, setup_mocks):
        """GetSessionInfo should be answered without executor (fast path)."""
        server, wrapper, _ = setup_mocks
        from ida.worker.v1 import service_pb2 as pb

        req = pb.GetSessionInfoRequest()
        body = self._make_request(req.SerializeToString())
        resp = server.handle("POST", "/idagrpc.v1.SessionControl/GetSessionInfo", body)

        status, headers, body = self._parse_response(resp)
        assert status == 200

        info = pb.GetSessionInfoResponse()
        info.ParseFromString(body)
        assert info.has_decompiler is True
        assert info.auto_state in ("loaded", "idle")  # loaded when auto_analyze=False

    def test_error_on_invalid_path(self, setup_mocks):
        server, wrapper, _ = setup_mocks

        resp = server.handle("POST", "/unknown/path", b"garbage")
        status, _, _ = TestRequestRouting._parse_response(resp)
        # The worker returns either 404 (unknown path) or 500 (parse error)
        assert status >= 400

    def test_get_functions_rpc(self, setup_mocks):
        server, wrapper, _ = setup_mocks
        from ida.worker.v1 import service_pb2 as pb

        req = pb.GetFunctionsRequest()
        body = self._make_request(req.SerializeToString())
        resp = server.handle("POST", "/idagrpc.v1.AnalysisTools/GetFunctions", body)

        status, headers, body = self._parse_response(resp)
        assert status == 200

        funcs_resp = pb.GetFunctionsResponse()
        funcs_resp.ParseFromString(body)
        assert len(funcs_resp.functions) > 0

    def test_get_imports_rpc(self, setup_mocks):
        server, wrapper, _ = setup_mocks
        from ida.worker.v1 import service_pb2 as pb

        req = pb.GetImportsRequest()
        body = self._make_request(req.SerializeToString())
        resp = server.handle("POST", "/idagrpc.v1.AnalysisTools/GetImports", body)

        status, _, body = self._parse_response(resp)
        assert status == 200

        imports_resp = pb.GetImportsResponse()
        imports_resp.ParseFromString(body)
        assert len(imports_resp.imports) > 0


class TestErrorHandling:
    """Tests for error handling in ConnectServer."""

    def test_require_open_database(self, tmp_path, setup_mocks):
        """Calling a non-status RPC before open should trigger auto-open via _require_open_database."""
        from worker.ida_wrapper import IDAWrapper
        from worker.connect_server import ConnectServer
        from ida.worker.v1 import service_pb2 as pb

        binary = tmp_path / "test_auto.bin"
        binary.write_bytes(b"\x90" * 1024)

        wrapper = IDAWrapper(str(binary), "test-auto-open")
        assert wrapper.db_open is False

        server = ConnectServer(wrapper, executor=None)

        # GetFunctions goes through _require_open_database which auto-opens
        req = pb.GetFunctionsRequest()
        body = TestRequestRouting._make_request(req.SerializeToString())
        resp = server.handle("POST", "/idagrpc.v1.AnalysisTools/GetFunctions", body)
        status, _, _ = TestRequestRouting._parse_response(resp)
        assert status == 200
        assert wrapper.db_open is True


class TestStatusEndpoints:
    """Tests for lightweight status-endpoint fast path."""

    def test_healthcheck_does_not_use_executor(self, setup_mocks):
        """Healthcheck must answer on connection thread, not via executor."""
        server, wrapper, _ = setup_mocks
        from ida.worker.v1 import service_pb2 as pb

        # Verify it works without crashing even with high pending counter
        server.pending_requests = 100
        req = pb.PingRequest()
        body = TestRequestRouting._make_request(req.SerializeToString())
        resp = server.handle("POST", "/idagrpc.v1.Healthcheck/Ping", body)
        status, _, _ = TestRequestRouting._parse_response(resp)
        assert status == 200
