#!/usr/bin/env python3
"""LLVM source coverage for production Rust files: unit-only and unit + full E2E.

Requires `rustup component add llvm-tools-preview`, Python h2 and OpenSSL.
Uses an isolated target directory. Does not replace debug/release application binaries.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "target" / "coverage"
BUILD = Path(os.environ.get("RVNX_COVERAGE_BUILD_DIR", str(Path(tempfile.gettempdir()) / ("rvnx-coverage-build-" + hashlib.sha256(str(ROOT).encode()).hexdigest()[:12]))))
SOURCES = sorted(p for folder in ("common/src", "clnt/src", "srv/src")
                 for p in (ROOT / folder).glob("*.rs"))


def run(command, env=None, output=None):
    if output:
        with output.open("w") as stream:
            subprocess.run(list(map(str, command)), cwd=ROOT, env=env, stdout=stream, check=True)
    else:
        subprocess.run(list(map(str, command)), cwd=ROOT, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit-only", action="store_true", help="Skip E2E for an intermediate coverage audit")
    args = parser.parse_args()
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    version = subprocess.check_output(["rustc", "-vV"], text=True)
    host = next(line.split(": ", 1)[1] for line in version.splitlines() if line.startswith("host:"))
    tool_dir = sysroot / "lib" / "rustlib" / host / "bin"
    cov, profdata = tool_dir / "llvm-cov", tool_dir / "llvm-profdata"
    if not cov.exists() or not profdata.exists():
        raise SystemExit("Install matching tools first: rustup component add llvm-tools-preview")
    BASE.mkdir(parents=True, exist_ok=True)
    for name in ("profiles", "unit", "combined"):
        path = BASE / name
        if path.exists():
            shutil.rmtree(path)
    unit_profiles, e2e_profiles = BASE / "profiles" / "unit", BASE / "profiles" / "e2e"
    unit_profiles.mkdir(parents=True)
    e2e_profiles.mkdir()
    env = {**os.environ, "CARGO_TARGET_DIR": str(BUILD), "RUSTFLAGS": "-C instrument-coverage",
           "RUSTDOCFLAGS": "-C instrument-coverage", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "1", "CARGO_PROFILE_TEST_DEBUG": "1",
           "LLVM_PROFILE_FILE": str(unit_profiles / "%p-%m.profraw")}
    print("Building and running unit tests with coverage instrumentation", flush=True)
    metadata = BASE / "cargo-tests.jsonl"
    run(["cargo", "test", "--workspace", "--locked", "--offline", "--message-format=json"], env, metadata)
    objects = []
    for line in metadata.read_text().splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") == "compiler-artifact" and record.get("executable") and record["profile"].get("test"):
            objects.append(Path(record["executable"]))
    if not objects:
        raise RuntimeError("no test executables found")
    run(["cargo", "build", "--workspace", "--bins", "--locked", "--offline"], env)
    objects.extend(BUILD / "debug" / name for name in ("rvnx-clnt", "rvnx-srv"))
    objects = sorted(set(objects))
    # Explicit file list prevents test fixtures, dependencies and generated
    # harnesses from inflating the production-code percentages.
    common_args = [objects[0]]
    for obj in objects[1:]:
        common_args.extend(["-object", obj])
    common_args.extend(["-ignore-filename-regex", r"/tests/|/\.cargo/|/rustc/", *SOURCES])

    def report(name, profiles):
        directory = BASE / name
        directory.mkdir()
        profile = directory / "coverage.profdata"
        raw = [path for folder in profiles for path in sorted(folder.glob("*.profraw"))]
        if not raw:
            raise RuntimeError("no coverage profiles produced")
        run([profdata, "merge", "-sparse", *raw, "-o", profile])
        profile_args = ["-instr-profile", profile, *common_args]
        run([cov, "report", *profile_args], output=directory / "report.txt")
        run([cov, "export", "-summary-only", *profile_args], output=directory / "summary.json")
        run([cov, "export", *profile_args], output=directory / "coverage.json")
        run([cov, "show", "-format=html", "-show-line-counts-or-regions", "-show-instantiations=false",
             "-output-dir", directory / "html", *profile_args])
        print(f"{name} production-code coverage:\n{(directory / 'report.txt').read_text()}", flush=True)
        return json.loads((directory / "summary.json").read_text())["data"][0]

    unit = report("unit", [unit_profiles])
    combined = None
    if not args.unit_only:
        print("Running full E2E, including 65-second model prefill", flush=True)
        env.update(LLVM_PROFILE_FILE=str(e2e_profiles / "%p-%m.profraw"),
                   RVNX_BIN_DIR=str(BUILD / "debug"), RVNX_LONG_TESTS="1")
        run([sys.executable, "tests/e2e.py"], env)
        combined = report("combined", [unit_profiles, e2e_profiles])
    summary = {"rustc": version, "scope": "production Rust files only; tests, generated harnesses and dependencies excluded",
        "metric_note": "LLVM line/region/function coverage; not branch coverage or proof of race freedom",
        "full_e2e_included": combined is not None,
        "sources_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCES},
        "unit": unit, "combined": combined}
    # Absolute checkout paths are useful to LLVM HTML, but should not pollute the portable summary.
    for result in (unit, combined):
        if result:
            for item in result["files"]:
                item["filename"] = str(Path(item["filename"]).relative_to(ROOT))
    (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Coverage summary: {BASE / 'summary.json'}", flush=True)


if __name__ == "__main__":
    main()
