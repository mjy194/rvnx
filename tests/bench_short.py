#!/usr/bin/env python3
"""Loopback short-connection benchmark; reports whole-tunnel cost, not TLS alone.

Use release binaries and repeat runs. Each request opens a fresh public TCP
connection, sends a fixed payload and waits for the complete echo response.
Multiplexing is opt-in; each sample otherwise uses an independent HTTPS connection.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import tempfile
import time


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def process_cpu(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


async def run_samples(port_number, samples, concurrency, payload):
    latencies = []
    count = 0

    async def worker():
        nonlocal count
        while count < samples:
            count += 1
            start = time.perf_counter()
            reader, writer = await asyncio.open_connection("127.0.0.1", port_number)
            try:
                writer.write(payload)
                await writer.drain()
                response = await asyncio.wait_for(reader.readexactly(len(payload)), 10)
                if response != payload:
                    raise AssertionError("payload mismatch")
                latencies.append((time.perf_counter() - start) * 1000)
            finally:
                writer.close()
                await writer.wait_closed()

    start = time.perf_counter()
    await asyncio.gather(*(worker() for _ in range(concurrency)))
    elapsed = time.perf_counter() - start
    values = sorted(latencies)
    return {
        "samples": len(values), "concurrency": concurrency,
        "requests_per_second": round(len(values) / elapsed, 1),
        **{f"p{p}_ms": round(values[min(len(values)-1, int(len(values)*p/100))], 3)
           for p in (50, 95, 99)},
    }


async def benchmark(args):
    payload = b"x" * args.bytes
    backend_tasks = set()

    async def echo(reader, writer):
        task = asyncio.current_task()
        backend_tasks.add(task)
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            backend_tasks.discard(task)

    backend = await asyncio.start_server(echo, "127.0.0.1", 0)
    backend_port = backend.sockets[0].getsockname()[1]
    control, public = port(), port()
    while public == control:
        public = port()
    processes, logs = [], []
    report = {
        "platform": platform.platform(), "cpu_count": os.cpu_count(),
        "binary_directory": str(args.bin_dir.resolve()), "worker_threads_per_process": 4,
        "payload_bytes": args.bytes, "multiplex": args.multiplex, "scope": "loopback; fresh TCP per request; warmed transport; complete echo latency",
        "results": [],
    }
    with tempfile.TemporaryDirectory(prefix="rvnx-bench-") as directory:
        root = Path(directory)
        token = os.urandom(32).hex()
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", str(root / "key.pem"),
            "-out", str(root / "cert.pem"),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cert, key = json.dumps(str(root / "cert.pem")), json.dumps(str(root / "key.pem"))
        (root / "srv.toml").write_text(f'''
bind = "127.0.0.1:{control}"
token = "{token}"
tls_cert = {cert}
tls_key = {key}
[[proxies]]
name = "bench"
protocol = "tcp"
bind = "127.0.0.1:{public}"
max_connections = 1024
''')
        (root / "clnt.toml").write_text(f'''
server = "127.0.0.1:{control}"
server_name = "localhost"
token = "{token}"
tls_ca = {cert}
reconnect_secs = 1
multiplex = {str(args.multiplex).lower()}
[[proxies]]
name = "bench"
protocol = "tcp"
local = "127.0.0.1:{backend_port}"
max_connections = 1024
''')
        try:
            for binary, config in (("rvnx-srv", "srv.toml"), ("rvnx-clnt", "clnt.toml")):
                log = open(root / f"{binary}.log", "w")
                logs.append(log)
                processes.append(subprocess.Popen([
                    str(args.bin_dir.resolve() / binary), "--config", str(root / config),
                ], stdout=log, stderr=log, env={**os.environ, "RUST_LOG": "warn", "TOKIO_WORKER_THREADS": "4"}))
            for _ in range(200):
                try:
                    await run_samples(public, 1, 1, payload)
                    break
                except (OSError, asyncio.IncompleteReadError):
                    await asyncio.sleep(0.05)
            else:
                raise RuntimeError("mapping did not start: " + "\n".join(p.read_text() for p in root.glob("*.log")))
            for repetition in range(args.repeats):
                for concurrency in args.concurrency:
                    for mode, destination in (("direct_tcp", backend_port), ("rvnx", public)):
                        await run_samples(destination, 64, concurrency, payload)
                        before = sum(process_cpu(p.pid) for p in processes)
                        result = await run_samples(destination, args.samples, concurrency, payload)
                        result.update(mode=mode, repetition=repetition + 1,
                                      proxy_cpu_seconds=round(sum(process_cpu(p.pid) for p in processes) - before, 3))
                        report["results"].append(result)
                        print(json.dumps(result), flush=True)
        finally:
            for proc in processes:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
            for proc in processes:
                try:
                    await asyncio.to_thread(proc.wait, 5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    await asyncio.to_thread(proc.wait)
            for log in logs:
                log.close()
            backend.close()
            await backend.wait_closed()
            for task in list(backend_tasks):
                task.cancel()
            await asyncio.gather(*backend_tasks, return_exceptions=True)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=Path("target/release"))
    parser.add_argument("--multiplex", action="store_true", help="Opt in to HTTP/2 connection pooling")
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 32])
    parser.add_argument("--bytes", type=int, default=1024)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if min(args.samples, args.bytes, args.repeats, *args.concurrency) < 1:
        parser.error("counts and sizes must be positive")
    asyncio.run(benchmark(args))
