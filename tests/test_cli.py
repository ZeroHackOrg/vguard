import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vguard.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]
ENV = {"PYTHONPATH": str(ROOT / "src"), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp"}


def _run(args, cwd):
    return subprocess.run(
        [sys.executable, "-m", "vguard.cli", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        env=ENV,
        timeout=60,
    )


def test_cli_verify(tmp_path):
    proc = _run(["verify"], cwd=str(tmp_path))
    assert "verify complete" in proc.stdout


def test_cli_guard_allows_safe(tmp_path):
    proc = _run(["guard", "--json", json.dumps([0.15, 0.45, 0.85])], cwd=str(tmp_path))
    assert json.loads(proc.stdout.strip())["allowed"] is True


def test_cli_guard_blocks_attack(tmp_path):
    proc = _run(["guard", "--json", json.dumps([4.5, -6.2, 8.1])], cwd=str(tmp_path))
    assert json.loads(proc.stdout.strip())["allowed"] is False


def test_cli_benchmark_smoke(tmp_path):
    proc = _run(["benchmark", "--dimension", "8", "--queries", "50"], cwd=str(tmp_path))
    assert "| p50 latency" in proc.stdout


def test_cli_scan_pii():
    proc = subprocess.run(
        [sys.executable, "-m", "vguard.cli", "scan"],
        input="email a@b.com",
        capture_output=True,
        text=True,
        env=ENV,
    )
    findings = json.loads(proc.stdout)
    assert any(f["category"] == "email" for f in findings)


def test_parser_subcommands():
    parser = build_parser()
    for name in ("verify", "web", "proxy", "guard", "report", "benchmark", "scan"):
        assert parser.parse_args([name]).command == name


def test_cli_main_unknown():
    with pytest.raises(SystemExit):
        main(["not-a-command"])