#!/usr/bin/env python3
"""Black-box tests against real RVNX binaries. Requires the h2 package for independent HTTP/2 interoperability checks."""

import concurrent.futures
from contextlib import ExitStack
import json
import re
import http.client
import http.server

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import os
from pathlib import Path
import signal
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("RVNX_BIN_DIR", ROOT / "target" / "debug"))


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block:
            raise EOFError("connection closed before response completed")
        data.extend(block)
    return bytes(data)


def send_control(sock, control):
    data = b"\x01" + json.dumps(control).encode()
    sock.sendall(struct.pack("!I", len(data)) + data)


def read_control(sock):
    size = struct.unpack("!I", receive_exact(sock, 4))[0]
    frame = receive_exact(sock, size)
    if frame[0] != 1:
        raise ValueError("expected control frame")
    return json.loads(frame[1:])


class H2Tunnel:
    """Independent Python HTTP/2 client; speaks the Rust service's HTTPS transport."""
    def __init__(self, sock, token, port, path="/api/stream", payload=None, grpc=False):
        self.sock = sock
        self.connection = h2.connection.H2Connection(config=h2.config.H2Configuration(
            client_side=True, header_encoding="utf-8"))
        self.connection.initiate_connection()
        headers = [
            (":method", "POST"), (":scheme", "https"),
            (":authority", f"localhost:{port}"), (":path", path),
            ("content-type", "application/grpc+proto" if grpc else "application/octet-stream"),
            ("te", "trailers"),
        ]
        if token:
            headers.append(("authorization", f"Bearer {token}"))
        self.connection.send_headers(1, headers)
        if payload is not None:
            self.connection.send_data(1, payload, end_stream=True)
        self.buffer = bytearray()
        self.ended = False
        self.status = None
        self.trailers = {}
        self.sock.sendall(self.connection.data_to_send())
        while self.status is None:
            self.pump()

    def pump(self):
        data = self.sock.recv(65536)
        if not data:
            self.ended = True
            return
        for event in self.connection.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                self.status = int(dict(event.headers)[":status"])
            elif isinstance(event, h2.events.TrailersReceived):
                self.trailers = dict(event.headers)
            elif isinstance(event, h2.events.DataReceived):
                self.buffer.extend(event.data)
                self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, (h2.events.StreamEnded, h2.events.StreamReset)):
                self.ended = True
        outgoing = self.connection.data_to_send()
        if outgoing:
            self.sock.sendall(outgoing)

    def sendall(self, data):
        self.connection.send_data(1, data)
        self.sock.sendall(self.connection.data_to_send())

    def recv(self, size):
        while not self.buffer and not self.ended:
            self.pump()
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.sock.close()


class EchoTCP(socketserver.ThreadingTCPServer):
    daemon_threads = True


class EchoUDP(socketserver.ThreadingUDPServer):
    daemon_threads = True
    max_packet_size = 65535


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        # Respond only AFTER EOF to verify both halves of a TCP connection.
        chunks = []
        while block := self.request.recv(65536):
            chunks.append(block)
        try:
            self.request.sendall(b"".join(chunks))
        except (BrokenPipeError, ConnectionResetError):
            # The slow-reader test intentionally closes before draining its echo.
            pass


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class TransportRelayHandler(socketserver.BaseRequestHandler):
    """Opaque TCP relay used to break exactly one encrypted transport in a test."""
    def handle(self):
        with self.server.live_lock:
            if getattr(self.server, "reject_new", False):
                self.server.reject_count += 1
                return
        try:
            upstream = socket.create_connection(self.server.target, timeout=5)
        except OSError:
            return  # Upstream may already be stopped during teardown/fault injection.
        upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        pair = (self.request, upstream)
        with self.server.live_lock:
            self.server.live.add(pair)
        try:
            readable = list(pair)
            while readable:
                ready, _, _ = select.select(readable, [], [], 1)
                for source in ready:
                    destination = upstream if source is self.request else self.request
                    data = source.recv(65536)
                    if data:
                        if hasattr(self.server, "byte_counts"):
                            with self.server.live_lock:
                                self.server.byte_counts[pair] = self.server.byte_counts.get(pair, 0) + len(data)
                                delay = self.server.delays.get(pair, 0) if source is upstream else 0
                            if delay:
                                time.sleep(delay)
                        destination.sendall(data)
                    else:
                        readable.remove(source)
                        destination.shutdown(socket.SHUT_WR)
        except (OSError, ValueError):
            pass
        finally:
            with self.server.live_lock:
                self.server.live.discard(pair)
            upstream.close()


class InteractiveHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(90)
        try:
            while data := self.request.recv(4096):
                self.request.sendall(data)
        except (ConnectionError, TimeoutError):
            pass


class ModelHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.observed = (self.path, self.headers.get("Authorization"), json.loads(body))
        self.send_response(200)
        native = self.path == "/api/chat"
        self.send_header("Content-Type", "application/x-ndjson" if native else "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        time.sleep(self.server.prefill_delay)
        if native:
            first = '{"message":{"content":"你"},"done":false}\n'.encode()
            final = b'{"done":true}\n'
        elif self.path == "/v1/messages":
            first = ('event: content_block_delta\ndata: {"type":"content_block_delta",'
                     '"index":0,"delta":{"type":"text_delta","text":"你"}}\n\n').encode()
            final = b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
        else:
            first = 'data: {"choices":[{"delta":{"content":"你"}}]}\n\n'.encode()
            final = b'data: [DONE]\n\n'
        try:
            # Split a UTF-8 character across HTTP chunks to verify byte transparency.
            split = first.index("你".encode()) + 1
            for chunk in (first[:split], first[split:]):
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
            self.server.first_sent.set()
            if not self.server.continue_generation.wait(8):
                return
            self.wfile.write(f"{len(final):x}\r\n".encode() + final + b"\r\n0\r\n\r\n")
            self.wfile.flush()
        except (ConnectionError, TimeoutError):
            pass


class RVNXTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for name in ("rvnx-srv", "rvnx-clnt"):
            if not (BIN / name).exists():
                raise RuntimeError("Run cargo build --workspace first")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rvnx-e2e-")
        self.directory = Path(self.temp.name)
        self.processes = []
        self.logs = []
        self.echo_servers = []
        self.addCleanup(self.cleanup)
        self.tcp_echo = EchoTCP(("127.0.0.1", 0), TCPHandler)
        self.echo_servers.append(self.tcp_echo)
        self.udp_echo = EchoUDP(("127.0.0.1", 0), UDPHandler)
        self.echo_servers.append(self.udp_echo)
        for server in (self.tcp_echo, self.udp_echo):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        self.control_port = free_port()
        self.tcp_port = free_port()
        while self.tcp_port == self.control_port:
            self.tcp_port = free_port()
        self.udp_port = free_port(socket.SOCK_DGRAM)
        self.token = os.urandom(32).hex()
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
            "-nodes", "-days", "1", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-keyout", str(self.directory / "key.pem"),
            "-out", str(self.directory / "cert.pem"),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.write_configs()
        self.server = self.start("rvnx-srv", "srv.toml")
        self.wait_for(lambda: self.port_open(self.control_port))
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.port_open(self.tcp_port))
        self.wait_for(lambda: "proxy=udp" in self.log_text())

    def cleanup(self):
        errors = []
        for proc in self.processes:
            try:
                self.stop(proc)
            except AssertionError as error:
                errors.append(str(error))
        for log in self.logs:
            log.close()
        for server in self.echo_servers:
            server.shutdown()
            server.server_close()
        self.temp.cleanup()
        self.assertFalse(errors, "\n".join(errors))

    def log_text(self):
        return "\n".join(path.read_text() for path in self.directory.glob("*.log"))

    def write_configs(self):
        cert = json.dumps(str(self.directory / "cert.pem"))
        key = json.dumps(str(self.directory / "key.pem"))
        (self.directory / "srv.toml").write_text(f'''
bind = "127.0.0.1:{self.control_port}"
token = "{self.token}"
tls_cert = {cert}
tls_key = {key}
[[proxies]]
name = "tcp"
protocol = "tcp"
bind = "127.0.0.1:{self.tcp_port}"
[[proxies]]
name = "udp"
protocol = "udp"
bind = "127.0.0.1:{self.udp_port}"
udp_timeout_secs = 1
''')
        (self.directory / "clnt.toml").write_text(f'''
server = "127.0.0.1:{self.control_port}"
server_name = "localhost"
token = "{self.token}"
tls_ca = {cert}
reconnect_secs = 1
[[proxies]]
name = "tcp"
protocol = "tcp"
local = "127.0.0.1:{self.tcp_echo.server_address[1]}"
[[proxies]]
name = "udp"
protocol = "udp"
local = "127.0.0.1:{self.udp_echo.server_address[1]}"
udp_timeout_secs = 1
''')

    def start(self, binary, config):
        log = open(self.directory / f"{binary}-{len(self.processes)}.log", "w")
        self.logs.append(log)
        process = subprocess.Popen([
            str(BIN / binary), "--config", str(self.directory / config),
        ], stdout=log, stderr=log, env={**os.environ, "RUST_LOG": "debug", "NO_COLOR": "1"})
        self.processes.append(process)
        return process

    def stop(self, process):
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                self.fail(f"{Path(process.args[0]).name} did not exit within 5 seconds of SIGINT")
        self.assertEqual(process.returncode, 0, f"{process.args[0]} exited abnormally")

    def wait_for(self, predicate, seconds=8):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        self.fail("timed out\n" + self.log_text())

    @staticmethod
    def port_open(port):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except OSError:
            return False

    def tcp_round_trip(self, data):
        with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=10) as sock:
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
            actual = bytearray()
            while block := sock.recv(65536):
                actual.extend(block)
            self.assertEqual(bytes(actual), data)

    def tls_connection(self, token=None, path="/api/stream", payload=None, grpc=False):
        context = ssl.create_default_context(cafile=str(self.directory / "cert.pem"))
        context.set_alpn_protocols(["h2"])
        sock = context.wrap_socket(
            socket.create_connection(("127.0.0.1", self.control_port), timeout=5),
            server_hostname="localhost",
        )
        self.assertEqual(sock.selected_alpn_protocol(), "h2")
        return H2Tunnel(sock, self.token if token is None else token, self.control_port, path, payload, grpc)

    def enable_cf(self, extra="", candidate_port=None, target=0.01, slow=0.001):
        self.stop(self.client)
        self.stop(self.server)
        srv = self.directory / "srv.toml"
        srv.write_text('cf_probe_enabled = true\n' + srv.read_text().replace(
            'name = "tcp"', 'name = "tcp"\nconnection_wait_secs = 20'))
        clnt = self.directory / "clnt.toml"
        clnt.write_text(clnt.read_text().replace(
            f'server = "127.0.0.1:{self.control_port}"', f'server = "localhost:{self.control_port}"') + f'''
[cloudflare]
candidates = ["127.0.0.1:{candidate_port or self.control_port}"]
quick_download_mib = 1
final_download_mib = 1
refill_download_mib = 1
target_mbps = {target}
slow_mbps = {slow}
keepalive_secs = 1
queue_timeout_secs = 10
probe_timeout_secs = 10
{extra}
''')
        self.server = self.start("rvnx-srv", "srv.toml")
        self.wait_for(lambda: self.port_open(self.control_port))
        self.cf_log = self.directory / f"rvnx-clnt-{len(self.processes)}.log"
        self.client = self.start("rvnx-clnt", "clnt.toml")
        # Observing logs avoids opening a business TCP connection just to test readiness.
        self.wait_for(lambda: "proxy=tcp" in self.cf_log.read_text() and
                      "proxy=udp" in self.cf_log.read_text(), seconds=20)

    def cf_allocations(self):
        return [tuple(map(int, m)) for m in re.findall(
            r"CF TCP connection allocated connection=(\d+) opened=(\d+)", self.cf_log.read_text())]

    def cf_relay(self):
        relay = EchoTCP(("127.0.0.1", 0), TransportRelayHandler)
        relay.target = ("127.0.0.1", self.control_port)
        relay.live, relay.live_lock = set(), threading.Lock()
        relay.byte_counts, relay.delays = {}, {}
        relay.reject_new, relay.reject_count = False, 0
        self.echo_servers.append(relay)
        threading.Thread(target=relay.serve_forever, daemon=True).start()
        return relay

    def cf_primary_socket(self, relay):
        with relay.live_lock:
            before = dict(relay.byte_counts)
        self.tcp_round_trip(os.urandom(512*1024))
        with relay.live_lock:
            active = [pair for pair in relay.live if relay.byte_counts.get(pair, 0)-before.get(pair, 0) > 512*1024]
        self.assertEqual(len(active), 1, "identify the active connection by real business traffic")
        return active[0]

    def test_cf_failure_promotes_standby_without_score_preemption(self):
        relay = self.cf_relay()
        self.enable_cf("retry_secs = 1", candidate_port=relay.server_address[1])
        primary = self.cf_primary_socket(relay)
        for transport in primary:
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            transport.close()
        self.wait_for(lambda: self.cf_log.read_text().count("CF primary selected") == 2)
        # The broken primary carried control streams, so mappings re-register.
        self.wait_for(lambda: self.cf_log.read_text().count("mapping connected proxy=tcp") >= 2)
        self.tcp_round_trip(b"traffic on promoted standby")
        self.wait_for(lambda: self.cf_log.read_text().count("CF candidate measured") >= 3, seconds=15)
        time.sleep(0.3)
        self.assertEqual(self.cf_log.read_text().count("CF primary selected"), 2)
        self.assertNotEqual(self.cf_allocations()[0][0], self.cf_allocations()[-1][0])

    def test_cf_two_low_measurements_rotate_without_cutting_control(self):
        relay = self.cf_relay()
        self.enable_cf("retry_secs = 1\nhealth_interval_secs = 3\nhealth_download_mib = 1",
                       candidate_port=relay.server_address[1], target=25.0, slow=20.0)
        primary = self.cf_primary_socket(relay)
        with relay.live_lock:
            relay.delays[primary] = 0.12
        self.wait_for(lambda: "consecutive_low=1" in self.cf_log.read_text(), seconds=18)
        self.assertEqual(self.cf_log.read_text().count("CF primary selected"), 1)
        self.wait_for(lambda: "consecutive_low=2" in self.cf_log.read_text(), seconds=18)
        self.wait_for(lambda: self.cf_log.read_text().count("CF primary selected") >= 2)
        with relay.live_lock:
            relay.delays[primary] = 0
        self.tcp_round_trip(b"new primary after two slow checks")
        # Low speed requests a rotation; it does not close the old control stream.
        self.assertEqual(self.cf_log.read_text().count("mapping connected proxy=tcp"), 1)

    def test_cf_grpc_download_authentication_and_wire_format(self):
        # The endpoint is invisible while disabled, even with a valid token.
        request = b"\x00\x00\x00\x00\x06\x0a\x04" + struct.pack("!I", 1024*1024)
        with self.tls_connection(path="/rvnx.Tunnel/Download", payload=request, grpc=True) as tunnel:
            self.assertEqual(tunnel.status, 404)
        self.enable_cf()
        with self.tls_connection(token="incorrect", path="/rvnx.Tunnel/Download", payload=request, grpc=True) as tunnel:
            self.assertEqual(tunnel.status, 404)
        # Decode using independent Python HTTP/2 and protobuf wire parsing.
        with self.tls_connection(path="/rvnx.Tunnel/Download", payload=request, grpc=True) as tunnel:
            self.assertEqual(tunnel.status, 200)
            total = 0
            while header := tunnel.recv(5):
                header += receive_exact(tunnel, 5-len(header))
                self.assertEqual(header[0], 0)
                body = receive_exact(tunnel, struct.unpack("!I",header[1:])[0])
                self.assertEqual(body[0], 10)
                length, shift, index = 0, 0, 1
                while True:
                    byte = body[index]; index += 1
                    length |= (byte & 127) << shift
                    if byte < 128: break
                    shift += 7
                self.assertEqual(length, len(body)-index)
                total += length
            self.assertEqual(total, 1024*1024)
            self.assertEqual(tunnel.trailers.get("grpc-status"), "0")

    def test_cf_sticky_rotation_preserves_stream_and_udp(self):
        self.enable_cf("rotate_after = 3\nhard_budget = 4\nretry_secs = 1\nhealth_interval_secs = 2\nhealth_download_mib = 1")
        with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=10) as held:
            held.sendall(b"held across rotation")
            self.wait_for(lambda: len(self.cf_allocations()) == 1)
            for _ in range(6):
                self.tcp_round_trip(os.urandom(32768))
            held.shutdown(socket.SHUT_WR)
            self.assertEqual(receive_exact(held, 20), b"held across rotation")
            self.assertEqual(held.recv(1), b"")
        allocations = self.cf_allocations()
        self.assertEqual([x[0] for x in allocations[:3]], [allocations[0][0]]*3)
        self.assertNotEqual(allocations[0][0], allocations[3][0])
        self.assertTrue(all(count <= 4 for _, count in allocations))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(3)
            for data in (b"", b"udp over grpc", os.urandom(60000)):
                udp.sendto(data, ("127.0.0.1", self.udp_port))
                self.assertEqual(udp.recv(65535), data)
        self.wait_for(lambda: "CF health measurement" in self.cf_log.read_text())

    def test_cf_streaming_http_keepalive_and_ssh_survive_rotation(self):
        model, model_port, maintenance_port = self.configure_model_and_maintenance()
        self.stop(self.client)
        clnt = self.directory / "clnt.toml"
        clnt.write_text(re.sub(r"dedicated_pool_size = \d+\n", "", clnt.read_text()))
        self.enable_cf("rotate_after = 3\nhard_budget = 4\nretry_secs = 1")
        with socket.create_connection(("127.0.0.1", maintenance_port), timeout=5) as ssh:
            ssh.sendall(b"interactive")
            self.assertEqual(receive_exact(ssh, 11), b"interactive")
            conn = http.client.HTTPConnection("127.0.0.1", model_port, timeout=5)
            try:
                for i in range(2):
                    model.continue_generation.clear()
                    conn.request("POST", "/v1/chat/completions", '{"stream":true}')
                    response = conn.getresponse()
                    self.assertIn("你".encode(), response.readline())
                    if i == 0:
                        self.tcp_round_trip(b"trigger a planned rotation")
                        self.wait_for(lambda: self.cf_log.read_text().count("CF primary selected") >= 2)
                    ssh.sendall(b"still interactive")
                    self.assertEqual(receive_exact(ssh, 17), b"still interactive")
                    model.continue_generation.set()
                    self.assertIn(b"[DONE]", response.read())
                # Two requests on the same HTTP TCP connection count once.
                self.assertEqual(len(self.cf_allocations()), 3)
            finally:
                model.continue_generation.set()
                conn.close()

    def test_cf_failed_refills_back_off_without_continuous_probes(self):
        relay = self.cf_relay()
        self.enable_cf("rotate_after = 2\nhard_budget = 3\nretry_secs = 4\nhealth_interval_secs = 1\nhealth_download_mib = 1", candidate_port=relay.server_address[1])
        with relay.live_lock:
            relay.reject_new = True
        self.tcp_round_trip(b"first")
        self.tcp_round_trip(b"promote standby")
        self.wait_for(lambda: "CF standby refill failed" in self.cf_log.read_text())
        # Failed standby recovery must not suppress health checks on the live primary.
        self.wait_for(lambda: "CF health measurement" in self.cf_log.read_text())
        with relay.live_lock:
            self.assertEqual(relay.reject_count, 2, "one bounded refill attempt set, then backoff")
            relay.reject_new = False
        self.wait_for(lambda: "CF standby refill complete" in self.cf_log.read_text())
        self.tcp_round_trip(b"recovered after retry")

    def test_cf_successful_refill_does_not_wait_for_failure_retry_interval(self):
        self.enable_cf("rotate_after = 3\nhard_budget = 4\nretry_secs = 60")
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
            list(workers.map(self.tcp_round_trip, [os.urandom(4096) for _ in range(30)]))
        self.assertLess(time.monotonic()-start, 8)
        self.assertTrue(all(count <= 4 for _, count in self.cf_allocations()))
        text = self.cf_log.read_text()
        self.assertGreaterEqual(text.count("CF standby refill complete"), 6)
        # Startup: 6x1 + 2x2x1 = 10 MiB. Each normal refill: 2x1 = 2 MiB.
        charged = re.findall(r"CF probe budget charged .*purpose=\"([^\"]+)\" bytes=(\d+)", text)
        self.assertEqual(sum(int(n) for purpose,n in charged if purpose.startswith("selection_")), 10*1024*1024)
        self.assertTrue(any(purpose == "refill" for purpose,_ in charged))
        self.assertNotIn("CF standby refill failed", text)

    def test_cf_hard_budget_waits_and_existing_stream_survives(self):
        self.enable_cf("rotate_after = 1\nhard_budget = 2\nprobe_budget_mib_per_minute = 60\nprobe_burst_mib = 10\nhealth_download_mib = 1")
        # A deliberately tight probe budget delays refill; hard caps must still hold.
        # First connection consumes the original primary; its standby is promoted.
        self.tcp_round_trip(b"first")
        self.tcp_round_trip(b"second")
        with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=10) as held:
            held.sendall(b"old transfer")
            self.wait_for(lambda: len(self.cf_allocations()) == 3)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.tcp_round_trip, b"waited for measured standby")
                time.sleep(0.3)
                self.assertFalse(pending.done(), "must wait at hard budget while standby is missing")
                held.shutdown(socket.SHUT_WR)
                self.assertEqual(receive_exact(held, 12), b"old transfer")
                pending.result(timeout=15)
        self.assertTrue(all(count <= 2 for _, count in self.cf_allocations()))

    def policy_server_text(self, policies, probes=False, connection_wait_secs=10):
        text = f'''bind = "127.0.0.1:{self.control_port}"
tls_cert = {json.dumps(str(self.directory / "cert.pem"))}
tls_key = {json.dumps(str(self.directory / "key.pem"))}
cf_probe_enabled = {str(probes).lower()}
connection_wait_secs = {connection_wait_secs}
'''
        for token, policy in policies:
            text += f'''\n[[policies]]
token = {json.dumps(token)}
[policies.policy]
bind_ip = "127.0.0.1"
allowed_ports = {json.dumps(policy.get("allowed_ports", [{"start": 1024, "end": 65535}])).replace(':', ' =')}
protocols = {json.dumps(policy.get("protocols", ["tcp", "udp"]))}
max_mappings = {policy.get("max_mappings", 8)}
'''
        # JSON inline object keys are valid TOML quoted keys; separators are '='.
        return text.replace("cf_probe_enabled = false\n", "")

    def enable_policy(self, policies=None, probes=False, connection_wait_secs=10):
        self.stop(self.client)
        self.stop(self.server)
        self.policy_other_token = "other-policy-identity-" * 3
        if policies is None:
            policies = [(self.token, {}), (self.policy_other_token, {})]
        (self.directory / "srv.toml").write_text(self.policy_server_text(policies, probes, connection_wait_secs))
        self.server = self.start("rvnx-srv", "srv.toml")
        self.wait_for(lambda: self.port_open(self.control_port))

    def policy_tunnel(self, token=None):
        tunnel = self.tls_connection(token)
        self.assertEqual(tunnel.status, 200)
        send_control(tunnel, {"type": "get_policy", "version": 3})
        response = read_control(tunnel)
        self.assertEqual(response["type"], "policy")
        self.assertEqual(response["version"], 3)
        self.assertNotIn(self.token, json.dumps(response))
        self.assertNotIn(self.policy_other_token, json.dumps(response))
        return tunnel, response["policy"]

    def policy_register(self, tunnel, name, port, protocol="tcp", expected="registered"):
        send_control(tunnel, {"type": "register_policy", "version": 3,
                              "proxy": name, "protocol": protocol, "remote_port": port})
        response = read_control(tunnel)
        self.assertEqual(response["type"], expected, response)
        for key, value in [("proxy", name), ("protocol", protocol), ("remote_port", port)]:
            self.assertEqual(response[key], value)
        if expected == "mapping_error":
            self.assertTrue(response["code"])
            self.assertTrue(response["reason"])
        return response

    def write_policy_client(self, mappings, token=None):
        text = f'''server = "127.0.0.1:{self.control_port}"
server_name = "localhost"
token = {json.dumps(token or self.token)}
tls_ca = {json.dumps(str(self.directory / "cert.pem"))}
reconnect_secs = 1
policy_mode = true
'''
        for name, protocol, port in mappings:
            local_port = (self.tcp_echo if protocol == "tcp" else self.udp_echo).server_address[1]
            text += f'''\n[[proxies]]
name = {json.dumps(name)}
protocol = {json.dumps(protocol)}
remote_port = {port}
local = "127.0.0.1:{local_port}"
'''
        (self.directory / "clnt.toml").write_text(text)

    def test_policy_is_private_and_no_legacy_or_version_fallback(self):
        own = {"allowed_ports": [{"start": self.tcp_port, "end": self.tcp_port}],
               "protocols": ["tcp"], "max_mappings": 1}
        other = "other-policy-identity-" * 3
        self.enable_policy([(self.token, own), (other, {"max_mappings": 3})])
        tunnel, policy = self.policy_tunnel()
        with tunnel:
            self.assertEqual(policy["allowed_ports"], own["allowed_ports"])
            self.assertEqual(policy["protocols"], ["tcp"])
            self.assertEqual(policy["max_mappings"], 1)
            error = self.policy_register(tunnel, "denied-protocol", self.tcp_port, "udp", "mapping_error")
            self.assertEqual(error["code"], "policy_denied")
        with self.tls_connection() as tunnel:
            send_control(tunnel, {"type": "register", "version": 2, "proxy": "tcp", "protocol": "tcp"})
            self.assertEqual(read_control(tunnel)["type"], "error")
        with self.tls_connection() as tunnel:
            send_control(tunnel, {"type": "get_policy", "version": 2})
            self.assertEqual(read_control(tunnel)["type"], "error")
        with self.tls_connection() as tunnel:
            error = self.policy_register(tunnel, "no-policy-handshake", self.tcp_port, expected="mapping_error")
            self.assertEqual(error["code"], "mode_mismatch")
        denied, _ = self.policy_tunnel()
        with denied:
            denied_port = self.tcp_port + 1 if self.tcp_port < 65535 else self.tcp_port - 1
            error = self.policy_register(denied, "denied-port", denied_port, expected="mapping_error")
            self.assertEqual(error["code"], "policy_denied")
        tunnel, _ = self.policy_tunnel()
        with tunnel:
            self.policy_register(tunnel, "allowed", self.tcp_port)
        self.wait_for(lambda: not self.port_open(self.tcp_port))

    def test_policy_names_ports_and_protocol_namespaces(self):
        self.enable_policy()
        second_port = free_port()
        while second_port in (self.tcp_port, self.control_port):
            second_port = free_port()
        with ExitStack() as stack:
            owner, _ = self.policy_tunnel()
            stack.enter_context(owner)
            self.policy_register(owner, "shared-name", self.tcp_port)
            other, _ = self.policy_tunnel(self.policy_other_token)
            stack.enter_context(other)
            self.policy_register(other, "shared-name", second_port)
            duplicate, _ = self.policy_tunnel()
            with duplicate:
                self.policy_register(duplicate, "shared-name", free_port(), expected="mapping_error")
            conflict, _ = self.policy_tunnel(self.policy_other_token)
            with conflict:
                self.policy_register(conflict, "different-name", self.tcp_port, expected="mapping_error")
            udp, _ = self.policy_tunnel()
            stack.enter_context(udp)
            self.policy_register(udp, "udp-same-number", self.tcp_port, "udp")
        self.wait_for(lambda: not self.port_open(self.tcp_port) and not self.port_open(second_port))
        retry, _ = self.policy_tunnel()
        with retry:
            self.policy_register(retry, "shared-name", self.tcp_port)

    def test_policy_quota_and_bind_failure_release_reservations(self):
        self.enable_policy([(self.token, {"max_mappings": 1})])
        with socket.socket() as blocker:
            blocker.bind(("127.0.0.1", 0))
            blocker.listen()
            occupied = blocker.getsockname()[1]
            denied, _ = self.policy_tunnel()
            with denied:
                error = self.policy_register(denied, "reusable", occupied, expected="mapping_error")
                self.assertEqual(error["code"], "bind_failed")
        owner, _ = self.policy_tunnel()
        with owner:
            self.policy_register(owner, "reusable", occupied)
            denied, _ = self.policy_tunnel()
            with denied:
                error = self.policy_register(denied, "over-quota", self.tcp_port, expected="mapping_error")
                self.assertEqual(error["code"], "quota_exceeded")
        self.wait_for(lambda: not self.port_open(occupied))
        retry, _ = self.policy_tunnel()
        with retry:
            self.policy_register(retry, "over-quota", self.tcp_port)

    def test_policy_concurrent_registrations_cannot_exceed_quota(self):
        self.enable_policy([(self.token, {"max_mappings": 1})])
        first, _ = self.policy_tunnel()
        second, _ = self.policy_tunnel()
        barrier = threading.Barrier(2)
        ports = [self.tcp_port, free_port()]
        while ports[1] in (ports[0], self.control_port):
            ports[1] = free_port()
        def register(index, tunnel):
            barrier.wait(timeout=5)
            send_control(tunnel, {"type": "register_policy", "version": 3,
                                  "proxy": f"racer-{index}", "protocol": "tcp", "remote_port": ports[index]})
            return read_control(tunnel)
        with first, second, concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(register, i, tunnel) for i, tunnel in enumerate([first, second])]
            replies = [f.result(timeout=5) for f in futures]
            self.assertEqual(sorted(r["type"] for r in replies), ["mapping_error", "registered"])
            self.assertEqual(sum(self.port_open(port) for port in ports), 1)
        self.wait_for(lambda: not any(self.port_open(port) for port in ports))

    def test_policy_tcp_setup_budget_expires_ticket_but_not_established_stream(self):
        self.enable_policy(connection_wait_secs=1)
        owner, _ = self.policy_tunnel()
        with owner:
            self.policy_register(owner, "budget", self.tcp_port)
            with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=5) as expired:
                opened = read_control(owner)
                self.assertEqual(opened["type"], "open")
                self.assertGreater(opened["timeout_ms"], 0)
                self.assertLessEqual(opened["timeout_ms"], 1000)
                # The server's monotonic deadline, not a late Attach, wins.
                self.assertEqual(expired.recv(1), b"")
                with self.tls_connection() as late:
                    send_control(late, {"type": "attach", "ticket": opened["ticket"]})
                    self.assertEqual(read_control(late)["type"], "error")
            send_control(owner, {"type": "ping"})
            reply = read_control(owner)
            if reply["type"] == "cancel":
                self.assertEqual(reply["ticket"], opened["ticket"])
                reply = read_control(owner)
            self.assertEqual(reply["type"], "pong")
            with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=5) as public:
                opened = read_control(owner)
                with self.tls_connection() as attached:
                    send_control(attached, {"type": "attach", "ticket": opened["ticket"]})
                    self.assertEqual(read_control(attached)["type"], "ready")
                    time.sleep(1.2)
                    public.sendall(b"after setup deadline")
                    self.assertEqual(receive_exact(attached, 20), b"after setup deadline")
                    attached.sendall(b"still alive")
                    self.assertEqual(receive_exact(public, 11), b"still alive")
            send_control(owner, {"type": "ping"})
            self.assertEqual(read_control(owner)["type"], "pong")
        self.wait_for(lambda: not self.port_open(self.tcp_port))
        retry, _ = self.policy_tunnel()
        with retry:
            self.policy_register(retry, "budget", self.tcp_port)

    def policy_scripted_peer(self, malformed):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.directory / "cert.pem"), str(self.directory / "key.pem"))
        context.set_alpn_protocols(["h2"])
        class MalformedHandler(socketserver.BaseRequestHandler):
            def handle(handler):
                try:
                    with context.wrap_socket(handler.request, server_side=True) as sock:
                        sock.settimeout(5)
                        connection = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
                        connection.initiate_connection()
                        sock.sendall(connection.data_to_send())
                        healthy = {}
                        def respond(stream_id, message):
                            frame = b"\x01" + json.dumps(message).encode()
                            connection.send_data(stream_id, struct.pack("!I", len(frame)) + frame)
                        while data := sock.recv(65536):
                            for event in connection.receive_data(data):
                                if isinstance(event, h2.events.RequestReceived):
                                    with handler.server.request_lock:
                                        handler.server.requests += 1
                                        malformed_response = handler.server.requests == 1
                                    connection.send_headers(event.stream_id,
                                        [(":status", "200"), ("content-type", "application/octet-stream")])
                                    if malformed_response:
                                        connection.send_data(event.stream_id, handler.server.malformed)
                                    else:
                                        healthy[event.stream_id] = bytearray()
                                elif isinstance(event, h2.events.DataReceived) and event.stream_id in healthy:
                                    buffer = healthy[event.stream_id]
                                    buffer.extend(event.data)
                                    connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                                    while len(buffer) >= 4:
                                        length = struct.unpack("!I", buffer[:4])[0]
                                        if len(buffer) < length + 4:
                                            break
                                        message = json.loads(bytes(buffer[5:4+length]))
                                        del buffer[:4+length]
                                        if message["type"] == "get_policy":
                                            respond(event.stream_id, {"type": "policy", "version": 3,
                                                "policy": {"bind_ip": "127.0.0.1", "protocols": ["tcp"],
                                                    "allowed_ports": [{"start": 1, "end": 65535}], "max_mappings": 4}})
                                        elif message["type"] == "register_policy":
                                            respond(event.stream_id, {"type": "registered", "proxy": message["proxy"],
                                                "protocol": message["protocol"], "remote_port": message["remote_port"]})
                                        elif message["type"] == "ping":
                                            respond(event.stream_id, {"type": "pong"})
                            sock.sendall(connection.data_to_send())
                except (OSError, ssl.SSLError, h2.exceptions.H2Error):
                    pass
        peer = EchoTCP(("127.0.0.1", 0), MalformedHandler)
        peer.malformed = malformed
        peer.requests, peer.request_lock = 0, threading.Lock()
        self.echo_servers.append(peer)
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        return peer

    def test_policy_malformed_control_response_is_terminal_not_network_retry(self):
        self.stop(self.client)
        for malformed in (struct.pack("!I", 1) + b"\x7f",
                          struct.pack("!I", 2) + b"\x01{"):
            with self.subTest(malformed=malformed):
                peer = self.policy_scripted_peer(malformed=malformed)
                self.write_policy_client([("first", "tcp", self.tcp_port), ("second", "tcp", self.tcp_port)])
                config = self.directory / "clnt.toml"
                config.write_text(config.read_text().replace(
                    f'server = "127.0.0.1:{self.control_port}"',
                    f'server = "127.0.0.1:{peer.server_address[1]}"'))
                log = self.directory / f"rvnx-clnt-{len(self.processes)}.log"
                self.client = self.start("rvnx-clnt", "clnt.toml")
                self.wait_for(lambda: "mapping stopped; configuration must be corrected" in log.read_text()
                              and "mapping connected" in log.read_text())
                time.sleep(1.2)
                self.assertIsNone(self.client.poll(), "one malformed response must not stop another mapping")
                self.assertEqual(log.read_text().count("mapping stopped; configuration must be corrected"), 1)
                self.assertEqual(peer.requests, 2, "malformed data must not cause a reconnect loop")
                self.stop(self.client)

    def test_policy_ticket_owner_cancel_scope_and_disconnect_cleanup(self):
        self.enable_policy()
        other_port = free_port()
        while other_port in (self.tcp_port, self.control_port):
            other_port = free_port()
        owner, _ = self.policy_tunnel()
        other, _ = self.policy_tunnel(self.policy_other_token)
        with owner, other:
            self.policy_register(owner, "owned", self.tcp_port)
            self.policy_register(other, "other", other_port)
            with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=5) as public:
                opened = read_control(owner)
                self.assertEqual(opened["type"], "open")
                ticket = opened["ticket"]
                with self.tls_connection(self.policy_other_token) as wrong:
                    send_control(wrong, {"type": "attach", "ticket": ticket})
                    self.assertEqual(read_control(wrong)["type"], "error")
                sibling, _ = self.policy_tunnel()
                with sibling:
                    sibling_port = free_port()
                    while sibling_port in (self.tcp_port, other_port, self.control_port):
                        sibling_port = free_port()
                    self.policy_register(sibling, "sibling", sibling_port)
                    send_control(sibling, {"type": "cancel", "ticket": ticket})
                    send_control(sibling, {"type": "ping"})
                    self.assertEqual(read_control(sibling)["type"], "pong")
                send_control(other, {"type": "cancel", "ticket": ticket})
                send_control(other, {"type": "ping"})
                self.assertEqual(read_control(other)["type"], "pong")
                with self.tls_connection() as attached:
                    send_control(attached, {"type": "attach", "ticket": ticket})
                    self.assertEqual(read_control(attached)["type"], "ready")
                    public.sendall(b"ownership survived")
                    self.assertEqual(receive_exact(attached, 18), b"ownership survived")
                    attached.sendall(b"returned")
                    self.assertEqual(receive_exact(public, 8), b"returned")
                    with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=5):
                        pending = read_control(owner)["ticket"]
                        owner.sock.close()
                        self.wait_for(lambda: not self.port_open(self.tcp_port))
                        self.assertEqual(public.recv(1), b"", "mapping teardown must stop existing transfers")
            with self.tls_connection() as stale:
                send_control(stale, {"type": "attach", "ticket": pending})
                self.assertEqual(read_control(stale)["type"], "error")

    def test_policy_client_terminal_mapping_isolation_and_reconnect_policy_refresh(self):
        own = {"allowed_ports": [{"start": self.tcp_port, "end": self.tcp_port}]}
        self.enable_policy([(self.token, own)])
        denied_port = free_port()
        while denied_port in (self.tcp_port, self.control_port):
            denied_port = free_port()
        self.write_policy_client([("tcp", "tcp", self.tcp_port), ("denied", "tcp", denied_port)])
        log = self.directory / f"rvnx-clnt-{len(self.processes)}.log"
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.port_open(self.tcp_port))
        self.wait_for(lambda: "mapping stopped; configuration must be corrected" in log.read_text())
        self.tcp_round_trip(b"healthy mapping survives policy denial")
        self.assertFalse(self.port_open(denied_port))
        time.sleep(2.2)
        self.assertIsNone(self.client.poll())
        self.assertEqual(log.read_text().count("mapping stopped; configuration must be corrected"), 1)
        before = log.read_text().count("mapping connected")
        self.stop(self.server)
        self.server = self.start("rvnx-srv", "srv.toml")
        self.wait_for(lambda: log.read_text().count("mapping connected") > before)
        self.tcp_round_trip(b"same requested port after network reconnect")
        self.stop(self.server)
        changed = {"allowed_ports": [{"start": denied_port, "end": denied_port}]}
        (self.directory / "srv.toml").write_text(self.policy_server_text([(self.token, changed)]))
        self.server = self.start("rvnx-srv", "srv.toml")
        self.wait_for(lambda: self.port_open(self.control_port))
        self.wait_for(lambda: self.client.poll() is not None)
        self.assertEqual(self.client.returncode, 1)
        self.processes.remove(self.client)  # Expected all-mappings-failed exit, not graceful shutdown.
        self.assertEqual(log.read_text().count("mapping stopped; configuration must be corrected"), 2)
        self.assertFalse(self.port_open(self.tcp_port))
        self.assertFalse(self.port_open(denied_port), "must not silently pick a new remote port")
        self.assertNotIn(self.token, log.read_text())
        self.assertFalse(any(self.directory.glob("*policy*.toml")), "fetched policy is memory-only")

    def test_policy_client_authentication_rejection_is_terminal(self):
        self.enable_policy()
        self.write_policy_client([("tcp", "tcp", self.tcp_port)], token="unknown-policy-identity-" * 3)
        log = self.directory / f"rvnx-clnt-{len(self.processes)}.log"
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.client.poll() is not None)
        self.assertEqual(self.client.returncode, 1)
        self.processes.remove(self.client)
        self.assertEqual(log.read_text().count("mapping stopped; configuration must be corrected"), 1)
        self.assertFalse(self.port_open(self.tcp_port))

    def test_policy_client_cloudflare_grpc_and_udp(self):
        self.enable_policy()
        self.write_policy_client([("tcp", "tcp", self.tcp_port), ("udp", "udp", self.udp_port)])
        self.enable_cf()
        self.wait_for(lambda: self.port_open(self.tcp_port))
        self.tcp_round_trip(b"policy registration over CF gRPC")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(b"policy UDP", ("127.0.0.1", self.udp_port))
            self.assertEqual(sock.recv(65535), b"policy UDP")

    def test_multiple_server_tokens_and_revocation_after_restart(self):
        self.stop(self.client)
        self.stop(self.server)
        second = "second-test-token-" * 4
        path = self.directory / "srv.toml"
        original = path.read_text()
        path.write_text(original.replace(f'token = "{self.token}"',
            f'tokens = ["{self.token}", "{second}"]\ncf_probe_enabled = true'))
        self.server = self.start("rvnx-srv", "srv.toml")
        self.wait_for(lambda: self.port_open(self.control_port))
        for token in [self.token, second]:
            for route, grpc in [("/api/stream", False), ("/rvnx.Tunnel/Connect", True)]:
                with self.tls_connection(token, path=route, grpc=grpc) as tunnel:
                    self.assertEqual(tunnel.status, 200)
                    if not grpc:
                        send_control(tunnel, {"type": "attach", "ticket": "not-a-real-ticket"})
                        self.assertIn("invalid or expired ticket", read_control(tunnel)["message"])
            request = b"\x00\x00\x00\x00\x06\x0a\x04" + struct.pack("!I", 0)
            with self.tls_connection(token, path="/rvnx.Tunnel/Download", payload=request, grpc=True) as tunnel:
                self.assertEqual(tunnel.status, 200)
                self.assertEqual(tunnel.recv(1), b"")
                self.assertEqual(tunnel.trailers.get("grpc-status"), "0")
        client_path = self.directory / "clnt.toml"
        client_path.write_text(client_path.read_text().replace(self.token, second))
        udp_registrations = self.log_text().count("mapping connected proxy=udp")
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.port_open(self.tcp_port))
        self.tcp_round_trip(b"second credential forwards traffic")
        self.wait_for(lambda: self.log_text().count("mapping connected proxy=udp") > udp_registrations)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(b"second credential UDP", ("127.0.0.1", self.udp_port))
            self.assertEqual(sock.recv(65535), b"second credential UDP")
        self.stop(self.client)
        self.stop(self.server)
        path.write_text(original.replace(f'token = "{self.token}"', f'tokens = ["{second}"]\ncf_probe_enabled = true'))
        self.server = self.start("rvnx-srv", "srv.toml")
        self.wait_for(lambda: self.port_open(self.control_port))
        for route, grpc in [("/api/stream", False), ("/rvnx.Tunnel/Connect", True), ("/rvnx.Tunnel/Download", True)]:
            for token in [self.token, "", "wrong"]:
                with self.tls_connection(token, path=route, grpc=grpc) as tunnel:
                    self.assertEqual(tunnel.status, 404)
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.port_open(self.tcp_port))
        self.tcp_round_trip(b"retained credential still works")
        self.assertNotIn(self.token, self.log_text())
        self.assertNotIn(second, self.log_text())

    def test_unauthenticated_http_responses(self):
        probe = b'\x01{"type":"attach","ticket":"not-a-real-ticket"}'
        probe = struct.pack("!I", len(probe)) + probe
        with self.tls_connection("wrong", payload=probe) as stream:
            self.assertEqual(stream.status, 404)
            self.assertEqual(receive_exact(stream, 10), b"Not Found\n")
        for token, path in [("wrong", "/api/stream"), ("", "/api/stream"), ("wrong", "/missing")]:
            with self.tls_connection(token, path) as stream:
                self.assertEqual(stream.status, 404)
                self.assertEqual(receive_exact(stream, 10), b"Not Found\n")
        context = ssl.create_default_context(cafile=str(self.directory / "cert.pem"))
        for method, path in [("GET", "/"), ("POST", "/api/stream"), ("GET", "/missing")]:
            conn = http.client.HTTPSConnection("localhost", self.control_port, context=context, timeout=5)
            try:
                conn.request(method, path)
                response = conn.getresponse()
                self.assertEqual(response.status, 404)
                self.assertEqual(response.read(), b"Not Found\n")
                self.assertIsNone(response.getheader("server"))
            finally:
                conn.close()

    def established_transport_connections(self):
        # Linux-only observation: count the service's established transport sockets.
        rows = Path("/proc/net/tcp").read_text().splitlines()[1:]
        return sum(int(row.split()[1].split(":")[1], 16) == self.control_port
                   and row.split()[3] == "01" for row in rows)

    def enable_multiplexing(self, pool_size=4):
        self.stop(self.client)
        self.wait_for(lambda: not self.port_open(self.tcp_port))
        path = self.directory / "clnt.toml"
        path.write_text(path.read_text().replace('reconnect_secs = 1',
            f'reconnect_secs = 1\nmultiplex = true\npool_size = {pool_size}'))
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.port_open(self.tcp_port))

    @unittest.skipUnless(Path("/proc/net/tcp").exists(), "requires Linux socket counters")
    def test_default_connection_isolation_and_cleanup(self):
        self.wait_for(lambda: self.established_transport_connections() == 2)
        with ExitStack() as stack:
            sockets = [stack.enter_context(socket.create_connection(
                ("127.0.0.1", self.tcp_port), timeout=5)) for _ in range(3)]
            for sock in sockets:
                sock.sendall(b"separate transport")
            self.wait_for(lambda: self.established_transport_connections() == 5)
            sockets[0].close()
            self.wait_for(lambda: self.established_transport_connections() == 4)
            for sock in sockets[1:]:
                sock.shutdown(socket.SHUT_WR)
                self.assertEqual(receive_exact(sock, 18), b"separate transport")
                self.assertEqual(sock.recv(1), b"")
        self.wait_for(lambda: self.established_transport_connections() == 2)

    def test_transport_failure_is_isolated_to_one_business_connection(self):
        self.stop(self.client)
        self.wait_for(lambda: not self.port_open(self.tcp_port))
        relay = EchoTCP(("127.0.0.1", 0), TransportRelayHandler)
        relay.target = ("127.0.0.1", self.control_port)
        relay.live, relay.live_lock = set(), threading.Lock()
        self.echo_servers.append(relay)
        threading.Thread(target=relay.serve_forever, daemon=True).start()
        path = self.directory / "clnt.toml"
        path.write_text(path.read_text().replace(f'server = "127.0.0.1:{self.control_port}"',
                         f'server = "127.0.0.1:{relay.server_address[1]}"'))
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.port_open(self.tcp_port))

        def connections():
            with relay.live_lock:
                return set(relay.live)

        self.wait_for(lambda: len(connections()) == 2)
        controls = connections()
        with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=5) as first:
            first.sendall(b"first")
            self.wait_for(lambda: len(connections()) == 3)
            broken = next(iter(connections() - controls))
            with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=5) as second:
                second.sendall(b"surviving business")
                self.wait_for(lambda: len(connections()) == 4)
                # Terminate both sides of ONLY the first TLS transport.
                for transport in broken:
                    try:
                        transport.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    transport.close()
                try:
                    self.assertEqual(first.recv(1), b"")
                except ConnectionResetError:
                    pass
                second.shutdown(socket.SHUT_WR)
                self.assertEqual(receive_exact(second, 18), b"surviving business")
                self.assertEqual(second.recv(1), b"")
        self.tcp_round_trip(b"mapping is still usable")
        self.wait_for(lambda: len(connections()) == 2)

    @unittest.skipUnless(Path("/proc/net/tcp").exists(), "requires Linux socket counters")
    def test_per_mapping_opt_out_of_multiplexing(self):
        self.stop(self.client)
        self.wait_for(lambda: not self.port_open(self.tcp_port))
        path = self.directory / "clnt.toml"
        path.write_text(path.read_text().replace('name = "tcp"',
                        'name = "tcp"\nmultiplex = false'))
        self.enable_multiplexing(pool_size=1)
        # One shared connection for UDP; one private TCP control connection.
        self.wait_for(lambda: self.established_transport_connections() == 2)
        with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=5) as sock:
            sock.sendall(b"override")
            self.wait_for(lambda: self.established_transport_connections() == 3)
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(receive_exact(sock, 8), b"override")
        self.wait_for(lambda: self.established_transport_connections() == 2)

    @unittest.skipUnless(Path("/proc/net/tcp").exists(), "requires Linux socket counters")
    def test_connection_pool_reuse(self):
        self.enable_multiplexing()
        self.assertEqual(self.established_transport_connections(), 4)
        for _ in range(30):
            self.tcp_round_trip(b"short connection")
        self.assertEqual(self.established_transport_connections(), 4)

    def test_slow_stream_does_not_block_shared_connection(self):
        self.stop(self.client)
        self.wait_for(lambda: not self.port_open(self.tcp_port))
        config_path = self.directory / "clnt.toml"
        config_path.write_text(config_path.read_text().replace('reconnect_secs = 1', 'reconnect_secs = 1\nmultiplex = true\npool_size = 1'))
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.port_open(self.tcp_port))
        with socket.socket() as stalled:
            stalled.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            stalled.settimeout(10)
            stalled.connect(("127.0.0.1", self.tcp_port))
            stalled.sendall(b"x" * (4 * 1024 * 1024))
            stalled.shutdown(socket.SHUT_WR)
            time.sleep(0.1)
            # All streams share ONE H2 connection, including the control stream.
            self.tcp_round_trip(b"independent short request")

    def test_unavailable_backend_fails_promptly(self):
        self.tcp_echo.shutdown()
        self.tcp_echo.server_close()
        with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=2) as sock:
            sock.sendall(b"backend is unavailable")
            try:
                self.assertEqual(sock.recv(1), b"")
            except ConnectionResetError:
                pass

    def configure_model_and_maintenance(self):
        self.stop(self.client)
        self.stop(self.server)
        model = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ModelHandler)
        model.first_sent = threading.Event()
        model.continue_generation = threading.Event()
        model.prefill_delay = 0
        maintenance = EchoTCP(("127.0.0.1", 0), InteractiveHandler)
        for backend in (model, maintenance):
            self.echo_servers.append(backend)
            threading.Thread(target=backend.serve_forever, daemon=True).start()
        model_port, maintenance_port = free_port(), free_port()
        while maintenance_port == model_port:
            maintenance_port = free_port()
        srv_path = self.directory / "srv.toml"
        srv_path.write_text(srv_path.read_text() + f'''
[[proxies]]
name = "model"
protocol = "tcp"
bind = "127.0.0.1:{model_port}"
[[proxies]]
name = "maintenance"
protocol = "tcp"
bind = "127.0.0.1:{maintenance_port}"
''')
        clnt_path = self.directory / "clnt.toml"
        clnt_path.write_text(clnt_path.read_text() + f'''
[[proxies]]
name = "model"
protocol = "tcp"
local = "127.0.0.1:{model.server_address[1]}"
dedicated_pool_size = 2
[[proxies]]
name = "maintenance"
protocol = "tcp"
local = "127.0.0.1:{maintenance.server_address[1]}"
dedicated_pool_size = 1
''')
        self.server = self.start("rvnx-srv", "srv.toml")
        self.wait_for(lambda: self.port_open(self.control_port))
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.port_open(model_port) and self.port_open(maintenance_port))
        return model, model_port, maintenance_port

    @unittest.skipUnless(Path("/proc/net/tcp").exists(), "requires Linux socket counters")
    def test_dedicated_only_does_not_create_shared_pool(self):
        self.stop(self.client)
        self.wait_for(lambda: not self.port_open(self.tcp_port))
        path = self.directory / "clnt.toml"
        config = path.read_text().replace('reconnect_secs = 1', 'reconnect_secs = 1\nmultiplex = true\npool_size = 32')
        config = config.replace('name = "tcp"', 'name = "tcp"\ndedicated_pool_size = 2')
        config = config.replace('name = "udp"', 'name = "udp"\ndedicated_pool_size = 1')
        path.write_text(config)
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.port_open(self.tcp_port))
        self.assertEqual(self.established_transport_connections(), 3)
        self.tcp_round_trip(b"isolated pool works")

    def test_model_streams_with_independent_connections(self):
        model, model_port, maintenance_port = self.configure_model_and_maintenance()
        if Path("/proc/net/tcp").exists():
            # Four control/mapping connections; pool sizes alone never enable reuse.
            self.wait_for(lambda: self.established_transport_connections() == 4)
        with socket.create_connection(("127.0.0.1", maintenance_port), timeout=3) as terminal:
            for path in ("/v1/chat/completions", "/v1/messages", "/api/chat"):
                model.first_sent.clear()
                model.continue_generation.clear()
                conn = http.client.HTTPConnection("127.0.0.1", model_port, timeout=3)
                try:
                    payload = {"model": "test", "messages": [], "stream": True}
                    conn.request("POST", path, json.dumps(payload), {
                        "Content-Type": "application/json", "Authorization": "Bearer model-test-key"})
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    first = response.readline()
                    if path != "/api/chat":
                        while not first.endswith(b"\n\n"):
                            line = response.readline()
                            self.assertTrue(line, "stream ended before first event")
                            first += line
                    self.assertIn("你".encode(), first)
                    # Producer cannot finish until the test observes the FIRST event.
                    # A buffering proxy deadlocks here and fails the socket timeout.
                    self.assertFalse(model.continue_generation.is_set())
                    if Path("/proc/net/tcp").exists():
                        self.wait_for(lambda: self.established_transport_connections() == 6)
                    self.assertEqual(model.observed, (path, "Bearer model-test-key", payload))
                    terminal.sendall(b"maintenance remains interactive")
                    self.assertEqual(receive_exact(terminal, 31), b"maintenance remains interactive")
                    model.continue_generation.set()
                    rest = response.read()
                    end = {"/api/chat": b'"done":true', "/v1/messages": b"message_stop",
                           "/v1/chat/completions": b"[DONE]"}[path]
                    self.assertIn(end, rest)
                finally:
                    model.continue_generation.set()
                    conn.close()

    @unittest.skipUnless(os.environ.get("RVNX_LONG_TESTS") == "1", "set RVNX_LONG_TESTS=1 for 65-second prefill test")
    def test_model_prefill_longer_than_control_timeout(self):
        model, model_port, _ = self.configure_model_and_maintenance()
        model.prefill_delay = 65
        conn = http.client.HTTPConnection("127.0.0.1", model_port, timeout=75)
        try:
            conn.request("POST", "/v1/chat/completions", '{"stream":true}')
            response = conn.getresponse()
            self.assertIn("你".encode(), response.readline())
            model.continue_generation.set()
            self.assertIn(b"[DONE]", response.read())
        finally:
            model.continue_generation.set()
            conn.close()

    def test_shutdown_releases_active_http1_and_tcp_connections(self):
        context = ssl.create_default_context(cafile=str(self.directory / "cert.pem"))
        conn = http.client.HTTPSConnection("localhost", self.control_port, context=context, timeout=5)
        try:
            conn.request("GET", "/")
            response = conn.getresponse()
            self.assertEqual(response.status, 404)
            self.assertEqual(response.read(), b"Not Found\n")
            with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=5) as stream:
                stream.sendall(b"still active during shutdown")
                self.wait_for(lambda: self.established_transport_connections() >= 4)
                self.stop(self.server)
                try:
                    self.assertEqual(stream.recv(1), b"")
                except ConnectionResetError:
                    pass
        finally:
            conn.close()

    def test_tls_without_h2_is_rejected_and_pool_warmup_failure_retries(self):
        self.stop(self.client)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.directory / "cert.pem"), str(self.directory / "key.pem"))
        context.set_alpn_protocols(["http/1.1"])
        class NoH2Handler(socketserver.BaseRequestHandler):
            def handle(handler):
                try:
                    with context.wrap_socket(handler.request, server_side=True) as stream:
                        stream.settimeout(3)
                        stream.recv(1)
                except (OSError, ssl.SSLError):
                    pass
        peer = EchoTCP(("127.0.0.1", 0), NoH2Handler)
        self.echo_servers.append(peer)
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        config = self.directory / "clnt.toml"
        config.write_text('multiplex = true\npool_size = 1\n' + config.read_text().replace(
            f'server = "127.0.0.1:{self.control_port}"', f'server = "127.0.0.1:{peer.server_address[1]}"'))
        log = self.directory / f"rvnx-clnt-{len(self.processes)}.log"
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: "pool warm-up failed" in log.read_text() and
                      log.read_text().count("server did not negotiate HTTP/2") >= 3)
        self.assertIsNone(self.client.poll())

    def test_cli_check_validates_without_starting_another_listener(self):
        for binary, config in (("rvnx-srv", "srv.toml"), ("rvnx-clnt", "clnt.toml")):
            with self.subTest(binary=binary):
                result = subprocess.run([str(BIN / binary), "--config", str(self.directory / config), "--check"],
                                        capture_output=True, text=True, timeout=5, env={**os.environ, "RUST_LOG": "info"})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("configuration is valid", result.stdout + result.stderr)
        invalid = self.directory / "invalid.toml"
        invalid.write_text((self.directory / "clnt.toml").read_text().replace('server_name = "localhost"', 'server_name = "invalid name"'))
        result = subprocess.run([str(BIN / "rvnx-clnt"), "--config", str(invalid), "--check"],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.tcp_round_trip(b"check left existing service running")

    def test_startup_errors_do_not_disturb_the_existing_service(self):
        invalid_ca = self.directory / "invalid-ca.pem"
        invalid_ca.write_text("not a certificate")
        cases = [
            ("rvnx-clnt", None, "cannot read config"),
            ("rvnx-srv", None, "cannot read config"),
            ("rvnx-clnt", (self.directory / "clnt.toml").read_text().replace(self.token, "short"), "token"),
            ("rvnx-srv", (self.directory / "srv.toml").read_text().replace(self.token, "short"), "token"),
            ("rvnx-clnt", (self.directory / "clnt.toml").read_text().replace(str(self.directory / "cert.pem"), str(invalid_ca)), "TLS configuration failed"),
            ("rvnx-srv", (self.directory / "srv.toml").read_text().replace(str(self.directory / "key.pem"), str(self.directory / "missing-key.pem")), "TLS configuration failed"),
        ]
        for index, (binary, content, expected) in enumerate(cases):
            with self.subTest(binary=binary, case=index):
                config = self.directory / f"invalid-startup-{index}.toml"
                if content is not None:
                    config.write_text(content)
                result = subprocess.run([str(BIN / binary), "--config", str(config), "--check"],
                                        capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stdout + result.stderr)
        conflict = subprocess.run([str(BIN / "rvnx-srv"), "--config", str(self.directory / "srv.toml")],
                                  capture_output=True, text=True, timeout=5)
        self.assertNotEqual(conflict.returncode, 0)
        self.tcp_round_trip(b"startup failure did not disturb active service")

    def test_logging_falls_back_for_missing_or_invalid_environment_filter(self):
        for value in (None, "rvnx[=debug"):
            for binary, config in (("rvnx-srv", "srv.toml"), ("rvnx-clnt", "clnt.toml")):
                with self.subTest(filter=value, binary=binary):
                    env = {**os.environ, "NO_COLOR": "1"}
                    env.pop("RUST_LOG", None)
                    if value is not None:
                        env["RUST_LOG"] = value
                    result = subprocess.run([str(BIN / binary), "--config", str(self.directory / config), "--check"],
                                            capture_output=True, text=True, timeout=5, env=env)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("configuration is valid", result.stdout + result.stderr)

    def test_client_and_server_mapping_capacity_reject_and_recover(self):
        self.tcp_echo.RequestHandlerClass = InteractiveHandler
        originals = {name: (self.directory / name).read_text() for name in ("clnt.toml", "srv.toml")}
        for limited, message in (("clnt.toml", "local TCP connection limit reached"),
                                 ("srv.toml", "TCP mapping connection limit reached")):
            with self.subTest(limited=limited):
                self.stop(self.client)
                self.stop(self.server)
                for name, content in originals.items():
                    if name == limited:
                        content = content.replace('name = "tcp"', 'name = "tcp"\nmax_connections = 1')
                    (self.directory / name).write_text(content)
                self.server = self.start("rvnx-srv", "srv.toml")
                self.wait_for(lambda: self.port_open(self.control_port))
                client_log = self.directory / f"rvnx-clnt-{len(self.processes)}.log"
                self.client = self.start("rvnx-clnt", "clnt.toml")
                self.wait_for(lambda: "proxy=tcp" in client_log.read_text() and "proxy=udp" in client_log.read_text())
                self.wait_for(lambda: self.established_transport_connections() == 2)
                with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=5) as first:
                    first.sendall(b"held")
                    self.assertEqual(receive_exact(first, 4), b"held")
                    with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=5) as second:
                        try:
                            second.sendall(b"rejected")
                            self.assertEqual(second.recv(1), b"")
                        except ConnectionResetError:
                            pass
                    self.wait_for(lambda: message in self.log_text())
                    first.sendall(b" survives")
                    first.shutdown(socket.SHUT_WR)
                    self.assertEqual(receive_exact(first, 9), b" survives")
                    self.assertEqual(first.recv(1), b"")
                self.wait_for(lambda: self.established_transport_connections() == 2)
                self.tcp_round_trip(b"capacity recovered")

    def test_global_https_connection_capacity_recovers_after_peers_close(self):
        self.stop(self.client)
        with ExitStack() as stack:
            for _ in range(520):
                stack.enter_context(socket.create_connection(("127.0.0.1", self.control_port), timeout=3))
            self.wait_for(lambda: "connection limit reached" in self.log_text(), seconds=3)
        # Every held connection closes before the TLS handshake timeout; releases
        # must make room for fresh authenticated control and business streams.
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.port_open(self.tcp_port))
        self.tcp_round_trip(b"global capacity recovered")

    def test_tcp_large_half_close_and_concurrency(self):
        self.tcp_round_trip(os.urandom(2 * 1024 * 1024))
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(self.tcp_round_trip, [os.urandom(65536) for _ in range(24)]))

    def test_udp_multiple_peers_empty_large_and_idle(self):
        def exchange(index):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                for data in (f"peer-{index}".encode(), b"", os.urandom(1024)):
                    sock.sendto(data, ("127.0.0.1", self.udp_port))
                    self.assertEqual(sock.recv(65535), data)
                time.sleep(1.2)
                data = f"after-idle-{index}".encode()
                sock.sendto(data, ("127.0.0.1", self.udp_port))
                self.assertEqual(sock.recv(65535), data)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(exchange, range(8)))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            data = os.urandom(65507)
            sock.sendto(data, ("127.0.0.1", self.udp_port))
            self.assertEqual(sock.recv(65535), data)

    def test_authentication_registration_and_ticket_rejection(self):
        for changes, expected in (
            ({"version": 99}, "unsupported protocol version"),
            ({"proxy": "missing"}, "proxy is not configured"),
            ({"protocol": "udp"}, "protocol mismatch"),
            ({}, "already connected"),
        ):
            with self.subTest(expected=expected), self.tls_connection() as sock:
                send_control(sock, {
                    "type": "register", "version": 2,
                    "proxy": "tcp", "protocol": "tcp", **changes,
                })
                reply = read_control(sock)
                self.assertEqual(reply["type"], "error")
                self.assertIn(expected, reply["message"])
        with self.tls_connection() as sock:
            send_control(sock, {"type": "attach", "ticket": "not-a-real-ticket"})
            self.assertIn("invalid or expired ticket", read_control(sock)["message"])
        self.tcp_round_trip(b"valid mapping survived rejected requests")
        self.assertNotIn(self.token, self.log_text())

    def test_client_and_server_reconnect(self):
        self.stop(self.client)
        self.wait_for(lambda: not self.port_open(self.tcp_port))
        self.client = self.start("rvnx-clnt", "clnt.toml")
        self.wait_for(lambda: self.port_open(self.tcp_port))
        self.tcp_round_trip(b"client restarted")
        self.stop(self.server)
        self.server = self.start("rvnx-srv", "srv.toml")
        self.wait_for(lambda: self.port_open(self.tcp_port))
        self.tcp_round_trip(b"server restarted; client reconnected")

    def test_certificate_hostname_verification(self):
        config = (self.directory / "clnt.toml").read_text()
        (self.directory / "wrong-name.toml").write_text(config.replace(
            'server_name = "localhost"', 'server_name = "wrong.example"'))
        self.start("rvnx-clnt", "wrong-name.toml")
        self.wait_for(lambda: 'certificate not valid for name "wrong.example"' in self.log_text())
        self.tcp_round_trip(b"healthy mapping unaffected")


if __name__ == "__main__":
    unittest.main(verbosity=2)
