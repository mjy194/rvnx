#!/usr/bin/env python3
"""Local release-mode comparison: independent TLS vs CF gRPC multiplexing.

Runs a deterministic SSE backend and a temporary real OpenSSH server. No external
Cloudflare traffic, system SSH changes, or actual model inference are involved.
Raw samples, binary hashes, policy events and generator lag are saved in JSON.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import pwd
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone


def percentile(values, percent):
    values = sorted(values)
    return round(values[max(0, math.ceil(len(values) * percent / 100) - 1)], 3) if values else None


def summary(values):
    return {"samples": len(values), **{f"p{p}_ms": percentile(values, p) for p in (50, 95, 99)},
            "max_ms": round(max(values), 3) if values else None,
            "over_50ms": sum(v > 50 for v in values),
            "over_100ms": sum(v > 100 for v in values), "over_250ms": sum(v > 250 for v in values)}


def free_ports(count):
    sockets = [socket.socket() for _ in range(count)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def cpu_seconds(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


async def close_writer(writer):
    writer.close()
    with contextlib.suppress(ConnectionError, asyncio.TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), 2)


async def backend_main(prefill_ms, token_gap_ms):
    block = os.urandom(65536)
    tasks = set()

    async def model(reader, writer):
        tasks.add(asyncio.current_task())
        try:
            while True:
                header = await reader.readuntil(b"\r\n\r\n")
                size = next(int(line.split(b":", 1)[1]) for line in header.split(b"\r\n")
                            if line.lower().startswith(b"content-length:"))
                await reader.readexactly(size)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
                await writer.drain()
                await asyncio.sleep(prefill_ms / 1000)
                for index in range(3):
                    event = b"data: " + json.dumps({"index": index, "sent_ns": time.perf_counter_ns(),
                        "choices": [{"delta": {"content": "stream-token"}}]}).encode() + b"\n\n"
                    writer.write(f"{len(event):x}\r\n".encode() + event + b"\r\n")
                    await writer.drain()
                    if index < 2:
                        await asyncio.sleep(token_gap_ms / 1000)
                end = b"data: [DONE]\n\n"
                writer.write(f"{len(end):x}\r\n".encode() + end + b"\r\n0\r\n\r\n")
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
            pass
        finally:
            await close_writer(writer)
            tasks.discard(asyncio.current_task())

    async def bulk(reader, writer):
        tasks.add(asyncio.current_task())
        try:
            # D + optional byte/sec budget, or U for an upload acknowledged at EOF.
            command = await reader.readline()
            if command.startswith(b"D "):
                rate = float(command[2:])
                sent, start = 0, time.perf_counter()
                while True:
                    writer.write(block)
                    await writer.drain()
                    sent += len(block)
                    if rate:
                        await asyncio.sleep(max(0, start + sent/rate - time.perf_counter()))
            elif command == b"U\n":
                total = 0
                while data := await reader.read(262144):
                    total += len(data)
                writer.write(total.to_bytes(8, "big"))
                await writer.drain()
            else:
                raise ValueError("unknown bulk command")
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            await close_writer(writer)
            tasks.discard(asyncio.current_task())

    servers = [await asyncio.start_server(handler, "127.0.0.1", 0) for handler in (model, bulk)]
    print(json.dumps({"model": servers[0].sockets[0].getsockname()[1],
                      "bulk": servers[1].sockets[0].getsockname()[1]}), flush=True)
    stop = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stop.set)
    await stop.wait()
    for server in servers:
        server.close()
        await server.wait_closed()
    active = list(tasks)
    for task in active:
        task.cancel()
    await asyncio.gather(*active, return_exceptions=True)


async def wait_log(path, predicate, processes, seconds=60):
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        text = path.read_text() if path.exists() else ""
        if predicate(text):
            return
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("process exited during startup: " + text[-6000:])
        await asyncio.sleep(0.05)
    raise RuntimeError("startup timeout: " + text[-6000:])


async def model_request(destination, connection=None):
    start = time.perf_counter_ns()
    fresh = connection is None
    if fresh:
        connection = await asyncio.open_connection("127.0.0.1", destination)
    reader, writer = connection
    try:
        writer.write(b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"stream\":true}")
        await writer.drain()
        headers = await reader.readuntil(b"\r\n\r\n")
        if not headers.startswith(b"HTTP/1.1 200"):
            raise RuntimeError("bad model response")
        headers_ms = (time.perf_counter_ns() - start) / 1e6
        first_ms, delivery_ms, arrivals = None, None, []
        while True:
            length = int((await reader.readline()).strip(), 16)
            if length == 0:
                if await reader.readexactly(2) != b"\r\n":
                    raise RuntimeError("bad HTTP termination")
                break
            data = await reader.readexactly(length)
            if await reader.readexactly(2) != b"\r\n":
                raise RuntimeError("bad HTTP chunk")
            now = time.perf_counter_ns()
            if data == b"data: [DONE]\n\n":
                continue
            item = json.loads(data.removeprefix(b"data: ").strip())
            arrivals.append(now)
            if first_ms is None:
                first_ms = (now - start)/1e6
                delivery_ms = (now - item["sent_ns"])/1e6
        if len(arrivals) != 3:
            raise RuntimeError("incomplete SSE stream")
        return {"ttft_ms": first_ms, "headers_ms": headers_ms, "first_event_delivery_ms": delivery_ms,
                "token_gaps_ms": [(b-a)/1e6 for a,b in zip(arrivals, arrivals[1:])]}
    finally:
        if fresh:
            await close_writer(writer)


async def stop_process(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            await asyncio.to_thread(process.wait, 5)
        except subprocess.TimeoutExpired:
            process.kill()
            await asyncio.to_thread(process.wait)


async def run_case(args, root, repetition, mode, scenario, backend_ports, ssh_port):
    control, model_port, public_ssh, bulk_port = free_ports(4)
    case = root / f"{repetition}-{mode}-{scenario}"
    case.mkdir()
    cert, key = json.dumps(str(root / "cert.pem")), json.dumps(str(root / "key.pem"))
    token = os.urandom(32).hex()
    server = f'bind = "127.0.0.1:{control}"\ntoken = "{token}"\ntls_cert = {cert}\ntls_key = {key}\ncf_probe_enabled = true\n'
    client = f'server = "localhost:{control}"\nserver_name = "localhost"\ntoken = "{token}"\ntls_ca = {cert}\n'
    if mode == "cf":
        # Keep the production selection/rotation/health defaults. Warm-up is outside timing.
        client += f'\n[cloudflare]\ncandidates = ["127.0.0.1:{control}"]\n'
    for name, public, local in (("model", model_port, backend_ports["model"]),
                                ("ssh", public_ssh, ssh_port), ("bulk", bulk_port, backend_ports["bulk"])):
        server += f'\n[[proxies]]\nname = "{name}"\nprotocol = "tcp"\nbind = "127.0.0.1:{public}"\nconnection_wait_secs = 120\n'
        client += f'\n[[proxies]]\nname = "{name}"\nprotocol = "tcp"\nlocal = "127.0.0.1:{local}"\n'
    (case / "srv.toml").write_text(server)
    (case / "clnt.toml").write_text(client)
    processes, logs, tasks = [], [], []
    ssh = None
    stop = asyncio.Event()
    bulk_bytes = {"download": 0, "upload": 0}
    errors, acknowledgments = [], []
    try:
        for binary, config in (("rvnx-srv", "srv.toml"), ("rvnx-clnt", "clnt.toml")):
            log = open(case / f"{binary}.log", "w")
            logs.append(log)
            processes.append(subprocess.Popen([str(args.bin_dir.resolve()/binary), "--config", str(case/config)],
                stdout=log, stderr=log, env={**os.environ, "NO_COLOR": "1", "RUST_LOG": "info", "TOKIO_WORKER_THREADS": "4"}))
            if binary == "rvnx-srv":
                # A cold CF dial before listen() triggers the production retry
                # backoff. Measure warmed transport only after the server is ready.
                await wait_log(case / "rvnx-srv.log", lambda s: "RVNX server listening" in s, processes)
        client_log = case / "rvnx-clnt.log"
        await wait_log(client_log, lambda s: all(f"proxy={name}" in s for name in ("model", "ssh", "bulk")), processes)
        for _ in range(3):
            await asyncio.wait_for(model_request(model_port), 10)
        ssh = await asyncio.create_subprocess_exec("ssh", "-F", "/dev/null", "-T", "-p", str(public_ssh),
            "-i", str(root/"client_key"), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={root/'known_hosts'}",
            "-o", "HostKeyAlias=rvnx-benchmark", "-o", "LogLevel=ERROR", "-o", "Compression=no",
            f"{pwd.getpwuid(os.getuid()).pw_name}@127.0.0.1", "cat",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        ssh.stdin.write(b"ready\n")
        await ssh.stdin.drain()
        if await asyncio.wait_for(ssh.stdout.readline(), 10) != b"ready\n":
            raise RuntimeError("SSH startup: " + (await ssh.stderr.read()).decode())
        persistent = await asyncio.open_connection("127.0.0.1", model_port)
        await model_request(model_port, persistent)

        async def bulk_worker(direction, rate):
            writer = None
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", bulk_port)
                writer.write(f"D {rate}\n".encode() if direction == "download" else b"U\n")
                await writer.drain()
                block, sent, started = os.urandom(65536), 0, time.perf_counter()
                while not stop.is_set():
                    if direction == "download":
                        data = await reader.read(262144)
                        if not data:
                            raise EOFError("bulk stream ended early")
                        bulk_bytes[direction] += len(data)
                    else:
                        writer.write(block)
                        await writer.drain()
                        sent += len(block)
                        bulk_bytes[direction] += len(block)
                        if rate:
                            await asyncio.sleep(max(0, started + sent/rate - time.perf_counter()))
                if direction == "upload":
                    writer.write_eof()
                    actual = int.from_bytes(await asyncio.wait_for(reader.readexactly(8), 10), "big")
                    if actual != sent:
                        raise RuntimeError(f"upload delivery mismatch {actual} != {sent}")
                    acknowledgments.append(actual)
            except Exception as error:
                errors.append({"kind": f"bulk_{direction}", "error": repr(error)})
            finally:
                if writer:
                    await close_writer(writer)

        directions = {"idle": [], "download": ["download"], "upload": ["upload"],
                      "duplex": ["download", "upload"], "duplex_200mbps": ["download", "upload"]}[scenario]
        for direction in directions:
            rate = 200_000_000 / 8 / args.bulk_streams if scenario == "duplex_200mbps" else 0
            for _ in range(args.bulk_streams):
                tasks.append(asyncio.create_task(bulk_worker(direction, rate)))
        await asyncio.sleep(args.settle_seconds)
        start = time.perf_counter()
        end = start + args.seconds
        before_bytes = bulk_bytes.copy()
        cpu_before = sum(cpu_seconds(p.pid) for p in processes)
        fresh_samples, keep_samples, ssh_samples, lag = [], [], [], []

        async def model_worker(keep):
            target = keep_samples if keep else fresh_samples
            next_at = start
            while time.perf_counter() < end:
                try:
                    sample = await asyncio.wait_for(model_request(model_port, persistent if keep else None), args.model_timeout)
                    sample["offset_s"] = time.perf_counter()-start
                    target.append(sample)
                except Exception as error:
                    errors.append({"kind": "model_keepalive" if keep else "model_fresh", "error": repr(error)})
                    break
                next_at = max(next_at + 1/args.model_hz, time.perf_counter())
                await asyncio.sleep(max(0, next_at-time.perf_counter()))

        async def ssh_worker():
            sequence, next_at = 0, start
            while time.perf_counter() < end:
                message = f"{sequence:08d}:interactive-ssh-echo\n".encode()
                t0 = time.perf_counter()
                try:
                    ssh.stdin.write(message)
                    await ssh.stdin.drain()
                    actual = await asyncio.wait_for(ssh.stdout.readexactly(len(message)), 5)
                    if actual != message:
                        raise RuntimeError("SSH echo mismatch")
                    ssh_samples.append((time.perf_counter()-t0)*1000)
                except Exception as error:
                    errors.append({"kind": "ssh", "error": repr(error)})
                    break
                sequence += 1
                next_at = max(next_at + args.ssh_interval_ms/1000, time.perf_counter())
                await asyncio.sleep(max(0, next_at-time.perf_counter()))

        async def lag_worker():
            while time.perf_counter() < end:
                target = time.perf_counter() + 0.01
                await asyncio.sleep(0.01)
                lag.append(max(0, time.perf_counter()-target)*1000)

        await asyncio.gather(model_worker(False), model_worker(True), ssh_worker(), lag_worker())
        elapsed = time.perf_counter()-start
        cpu_used = sum(cpu_seconds(p.pid) for p in processes)-cpu_before
        measured_bytes = {k: bulk_bytes[k]-before_bytes[k] for k in bulk_bytes}
        stop.set()
        await asyncio.wait_for(asyncio.gather(*tasks), 15)
        await close_writer(persistent[1])
        log_text = client_log.read_text()
        result = {"mode": mode, "scenario": scenario, "repetition": repetition,
            "elapsed_seconds": elapsed, "proxy_cpu_seconds": cpu_used,
            "bulk_mbps": {k: round(v*8/elapsed/1e6, 2) for k,v in measured_bytes.items()},
            "upload_acked_bytes_including_settle": acknowledgments,
            "ssh_rtt": summary(ssh_samples), "generator_lag": summary(lag), "errors": errors,
            "cf_primary_selections": log_text.count("CF primary selected"),
            "cf_candidate_measurements": log_text.count("CF candidate measured"),
            "cf_tcp_allocations": log_text.count("CF TCP connection allocated"),
            "cf_probe_charged_bytes": sum(int(n) for n in re.findall(r"CF probe budget charged .*? bytes=(\d+) ", log_text)),
            "cf_standby_refills": log_text.count("CF standby refill complete"),
            "cf_events": [line for line in log_text.splitlines() if any(label in line for label in
                          ("CF primary selected", "CF candidate measured", "CF TCP connection allocated", "CF health measurement", "CF probe budget charged", "CF standby refill complete"))],
            "model_fresh": summary([s["ttft_ms"] for s in fresh_samples]),
            "model_keepalive": summary([s["ttft_ms"] for s in keep_samples]),
            "raw": {"fresh": fresh_samples, "keepalive": keep_samples, "ssh_ms": ssh_samples, "generator_lag_ms": lag}}
        print(json.dumps({k:v for k,v in result.items() if k != "raw"}), flush=True)
        return result
    finally:
        stop.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if ssh and ssh.returncode is None:
            ssh.terminate()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(ssh.wait(), 3)
            if ssh.returncode is None:
                ssh.kill()
                await ssh.wait()
        for process in reversed(processes):
            await stop_process(process)
        for log in logs:
            log.close()


async def benchmark(args):
    # Guard against quietly benchmarking queue exhaustion instead of warm transport.
    # Each cell uses a new client and stays below the default 80-connection rotation.
    if not args.allow_rotation and math.ceil(args.seconds*args.model_hz) + 8 + 2*args.bulk_streams >= 80:
        raise ValueError("reduce seconds/model-hz/streams or use --allow-rotation for a policy stress test")
    report = {"created_utc": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
        "cpu": next((s.split(":",1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines()
                     if s.startswith('model name')), 'unknown'), "cpu_count": os.cpu_count(),
        "settings": {k:str(v) if isinstance(v,Path) else v for k,v in vars(args).items()},
        "scope": "loopback, real OpenSSH cat channel, synthetic SSE, release binaries; no real Cloudflare edge",
        "tokio_worker_threads_per_process": 4,
        "binary_sha256": {n:hashlib.sha256((args.bin_dir/n).read_bytes()).hexdigest() for n in ('rvnx-clnt','rvnx-srv')},
        "results": []}
    processes, logs = [], []
    backend = None
    with tempfile.TemporaryDirectory(prefix="rvnx-stream-bench-") as directory:
        root = Path(directory)
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE",
                "-keyout", str(root/'key.pem'), "-out", str(root/'cert.pem')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for name in ('host_key','client_key'):
                subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/name)],check=True)
            (root/'authorized_keys').write_text('restrict '+(root/'client_key.pub').read_text())
            (root/'known_hosts').write_text('rvnx-benchmark '+(root/'host_key.pub').read_text())
            ssh_port = free_ports(1)[0]
            (root/'sshd_config').write_text(f'''Port {ssh_port}
ListenAddress 127.0.0.1
HostKey {root/'host_key'}
PidFile {root/'sshd.pid'}
AuthorizedKeysFile {root/'authorized_keys'}
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin prohibit-password
AllowUsers {pwd.getpwuid(os.getuid()).pw_name}
AllowTcpForwarding no
X11Forwarding no
PermitTTY no
ForceCommand /usr/bin/cat
LogLevel ERROR
''')
            ssh_log = open(root/'sshd.log','w'); logs.append(ssh_log)
            processes.append(subprocess.Popen(['/usr/bin/sshd','-D','-e','-f',str(root/'sshd_config')],stdout=ssh_log,stderr=ssh_log))
            backend = await asyncio.create_subprocess_exec(sys.executable, str(Path(__file__).resolve()), '--backend',
                '--prefill-ms',str(args.prefill_ms),'--token-gap-ms',str(args.token_gap_ms),stdout=asyncio.subprocess.PIPE)
            backend_ports = json.loads(await asyncio.wait_for(backend.stdout.readline(), 10))
            await asyncio.sleep(0.1)
            if processes[0].poll() is not None:
                raise RuntimeError('temporary sshd failed: '+(root/'sshd.log').read_text())
            for repetition in range(1,args.repeats+1):
                for index, scenario in enumerate(args.scenarios):
                    # Alternate mode ordering to reduce warm-cache and thermal order bias.
                    modes = ('independent','cf') if (repetition+index)%2 else ('cf','independent')
                    for mode in modes:
                        if mode not in args.modes:
                            continue
                        report['results'].append(await run_case(args,root,repetition,mode,scenario,backend_ports,ssh_port))
                        args.output.parent.mkdir(parents=True,exist_ok=True)
                        args.output.write_text(json.dumps(report,indent=2)+'\n')
        except BaseException:
            for log in root.rglob('*.log'):
                print(f'{log.name}:\n{log.read_text()[-4000:]}',file=sys.stderr)
            raise
        finally:
            if backend and backend.returncode is None:
                backend.terminate()
                await backend.wait()
            for process in processes:
                await stop_process(process)
            for log in logs:
                log.close()
    if any(r['errors'] for r in report['results']):
        raise RuntimeError('benchmark contains failures; inspect raw report')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--bin-dir',type=Path,default=Path('target/release'))
    parser.add_argument('--modes',nargs='+',choices=['independent','cf'],default=['independent','cf'])
    parser.add_argument('--allow-rotation',action='store_true',help='Include default soft/hard connection budgets in the measurement')
    parser.add_argument('--model-timeout',type=float,default=10)
    parser.add_argument('--seconds',type=float,default=10)
    parser.add_argument('--settle-seconds',type=float,default=1)
    parser.add_argument('--repeats',type=int,default=3)
    parser.add_argument('--bulk-streams',type=int,default=4)
    parser.add_argument('--model-hz',type=float,default=4)
    parser.add_argument('--ssh-interval-ms',type=float,default=50)
    parser.add_argument('--prefill-ms',type=float,default=25)
    parser.add_argument('--token-gap-ms',type=float,default=20)
    parser.add_argument('--scenarios',nargs='+',choices=['idle','download','upload','duplex','duplex_200mbps'],
                        default=['idle','download','upload','duplex_200mbps','duplex'])
    parser.add_argument('--output',type=Path,default=Path('/tmp/rvnx-streaming.json'))
    args = parser.parse_args()
    if min(args.seconds,args.repeats,args.bulk_streams,args.model_hz,args.ssh_interval_ms,args.model_timeout) <= 0 or min(args.settle_seconds,args.prefill_ms,args.token_gap_ms)<0:
        parser.error('invalid benchmark parameters')
    asyncio.run(backend_main(args.prefill_ms,args.token_gap_ms) if args.backend else benchmark(args))
