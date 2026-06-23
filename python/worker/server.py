#!/usr/bin/env python3
"""
Python Connect RPC Worker for IDA Pilot
Serves Connect RPC over Unix domain socket
"""

import argparse
import logging
import os
import queue
import socket
import sys
import threading
import time
from pathlib import Path

# Add proto path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "proto"))

try:
    import idapro
except ImportError:
    print("Error: idapro module not found. Run: ./scripts/setup_idalib.sh")
    sys.exit(1)

from connect_server import ConnectServer
from ida_wrapper import IDAWrapper


class IDAExecutor:
    """Runs all idalib work on a single thread (the main thread).

    Connection threads submit a callable and block until it has run here.
    idalib is not thread-safe and assumes the main thread, so this is the only
    thread allowed to touch it. Lightweight status RPCs bypass the executor and
    are answered directly on the connection thread (see ConnectServer.handle).
    """

    def __init__(self):
        self._jobs = queue.Queue()

    def submit(self, fn):
        done = threading.Event()
        box = {}

        def task():
            try:
                box["result"] = fn()
            except BaseException as exc:  # propagate to the caller thread
                box["error"] = exc
            finally:
                done.set()

        self._jobs.put(task)
        done.wait()
        if "error" in box:
            raise box["error"]
        return box["result"]

    def run_forever(self):
        while True:
            task = self._jobs.get()
            if task is None:
                return
            task()

def serve_on_unix_socket(socket_path: str, handler, session_id: str):
    """Serve Connect RPC over Unix domain socket"""

    # Remove existing socket
    if os.path.exists(socket_path):
        os.remove(socket_path)

    # Create Unix socket
    server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_socket.bind(socket_path)
    server_socket.listen(64)

    logging.info(f"[Worker {session_id}] Listening on {socket_path}")

    try:
        while True:
            conn, _ = server_socket.accept()
            # Handle each connection on its own thread so lightweight status
            # requests stay responsive while a long IDA operation is in flight.
            # IDA access itself is serialized by a lock inside the handler.
            threading.Thread(
                target=handle_connection, args=(conn, handler), daemon=True
            ).start()
    finally:
        server_socket.close()
        if os.path.exists(socket_path):
            os.remove(socket_path)


def serve_on_tcp(port: int, handler, session_id: str, port_file: str = None):
    """Serve Connect RPC over TCP (Windows fallback)"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", port))
    server_socket.listen(64)

    actual_port = server_socket.getsockname()[1]
    logging.info(f"[Worker {session_id}] Listening on 127.0.0.1:{actual_port}")

    if port_file:
        with open(port_file, "w") as f:
            f.write(str(actual_port))

    try:
        while True:
            conn, _ = server_socket.accept()
            threading.Thread(
                target=handle_connection, args=(conn, handler), daemon=True
            ).start()
    finally:
        server_socket.close()

def handle_connection(conn: socket.socket, handler):
    """Handle single HTTP connection"""
    try:
        # Read HTTP request
        request_data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            request_data += chunk
            # Simple check for end of headers
            if b"\r\n\r\n" in request_data:
                # Check Content-Length to read body
                headers = request_data.split(b"\r\n\r\n")[0]
                if b"Content-Length:" in headers:
                    for line in headers.split(b"\r\n"):
                        if line.startswith(b"Content-Length:"):
                            content_length = int(line.split(b":")[1].strip())
                            body_start = request_data.find(b"\r\n\r\n") + 4
                            body_received = len(request_data) - body_start
                            while body_received < content_length:
                                chunk = conn.recv(content_length - body_received)
                                if not chunk:
                                    break
                                request_data += chunk
                                body_received += len(chunk)
                break

        if not request_data:
            return

        # Parse HTTP request (simplified)
        lines = request_data.split(b"\r\n")
        request_line = lines[0].decode('utf-8')
        method, path, _ = request_line.split()

        # Route to handler
        response = handler(method, path, request_data)

        # Send HTTP response
        conn.sendall(response.encode() if isinstance(response, str) else response)

    except Exception as e:
        logging.error(f"Connection error: {e}")
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="IDA Connect Worker")
    parser.add_argument("--socket", required=False, help="Unix socket path")
    parser.add_argument("--port", type=int, default=0, help="TCP port (0=auto, Windows fallback)")
    parser.add_argument("--port-file", required=False, help="File to write actual TCP port")
    parser.add_argument("--binary", required=True, help="Binary file path")
    parser.add_argument("--session-id", required=True, help="Session ID")
    parser.add_argument("--log-level", default="INFO", help="Log level")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format=f'[Worker {args.session_id}] %(asctime)s - %(levelname)s - %(message)s'
    )

    logging.info(f"Starting worker for binary: {args.binary}")
    logging.info("Initializing Connect server (IDA database will open on demand)")

    # Initialize IDA wrapper (database opens when OpenBinary is called)
    ida = IDAWrapper(args.binary, args.session_id)

    # All IDA work runs on this executor (the main thread); connection threads
    # submit jobs to it. idalib is single-threaded and assumes the main thread.
    executor = IDAExecutor()
    server = ConnectServer(ida, executor)

    # Simple HTTP handler
    def handle_request(method: str, path: str, data: bytes) -> bytes:
        return server.handle(method, path, data)

    # Run the socket accept loop on a background thread so the main thread is
    # free to own idalib. Accepted connections are handled on their own threads
    # (see serve_on_*), keeping status RPCs responsive during long analysis.
    if args.socket and hasattr(socket, 'AF_UNIX'):
        serve_target = lambda: serve_on_unix_socket(args.socket, handle_request, args.session_id)
    else:
        serve_target = lambda: serve_on_tcp(args.port, handle_request, args.session_id, args.port_file)
    threading.Thread(target=serve_target, daemon=True).start()

    try:
        executor.run_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        ida.close_database()
        logging.info("Worker terminated")


if __name__ == "__main__":
    main()
