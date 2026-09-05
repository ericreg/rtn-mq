#!/usr/bin/env python3
"""Regenerate the small loopback smoke matrix; no third-party Python packages."""
import datetime
import json
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    subprocess.run(
        ["cargo", "build", "--locked", "--release", "--example", "benchmark"],
        cwd=ROOT, check=True,
    )
    metadata = json.loads(run("cargo", "metadata", "--no-deps", "--format-version", "1"))
    binary = Path(metadata["target_directory"]) / "release" / "examples" / (
        "benchmark.exe" if platform.system() == "Windows" else "benchmark"
    )
    rows = []
    for fanout in (1, 10, 100):
        for size in (128, 1024, 65536, 1048576):
            lines = run(str(binary), "5", str(fanout), str(size)).splitlines()
            if len(lines) != 2:
                raise RuntimeError(f"Unexpected benchmark output: {lines!r}")
            if not rows:
                rows.append(lines[0])
            elif rows[0] != lines[0]:
                raise RuntimeError("Benchmark CSV header changed")
            rows.append(lines[1])
            print(lines[1], flush=True)
    out = ROOT / "benchmarks"
    out.mkdir(exist_ok=True)
    (out / "smoke.csv").write_text("\n".join(rows) + "\n")
    details = [
        f"Date: {datetime.date.today().isoformat()}",
        "Profile: release, no optional features",
        "Network: direct IPv4 loopback, all endpoints in one process; no fault injection",
        "Iterations: 5 per case; no warmup; smoke checks only, not statistically robust capacity estimates",
        "Latency: sender monotonic publish admission through all recipient processing ACKs",
        "Memory: conservative sender library charges; excludes process RSS and Iroh/runtime overhead",
        f"Platform: {platform.platform()}",
    ]
    if platform.system() == "Darwin":
        details += [f"CPU: {run('sysctl', '-n', 'machdep.cpu.brand_string')}",
                    f"RAM bytes: {run('sysctl', '-n', 'hw.memsize')}"]
    details += [run("rustc", "--version"), "Dependencies: Cargo.lock"]
    (out / "environment.txt").write_text("\n".join(details) + "\n")


if __name__ == "__main__":
    main()
