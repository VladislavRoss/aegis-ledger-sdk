#!/usr/bin/env python3
"""
Release Gate — runs in a FRESH venv against the built wheel.
This is the ONLY valid proof that the package works for end users.

Usage:
    python scripts/release_gate.py dist/aegis_ledger_sdk-*.whl

Exit 0 = all gates pass, safe to upload to PyPI.
Exit 1 = at least one gate failed, DO NOT release.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

WHEEL = sys.argv[1] if len(sys.argv) > 1 else None
if not WHEEL or not Path(WHEEL).exists():
    print("Usage: python scripts/release_gate.py <path-to-wheel>")
    sys.exit(1)

WHEEL = str(Path(WHEEL).resolve())
VENV_DIR = Path(tempfile.mkdtemp(prefix="aegis-release-gate-"))
IS_WINDOWS = sys.platform == "win32"
PYTHON = str(VENV_DIR / ("Scripts" if IS_WINDOWS else "bin") / "python")
AEGIS = [PYTHON, "-m", "aegis"]

passed = 0
failed = 0
errors: list[str] = []


def gate(name: str, cmd: list[str], timeout: int = 60,
         expect_in_stdout: str = "") -> bool:
    """Run a single gate check."""
    global passed, failed
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ok = r.returncode == 0
        if ok and expect_in_stdout:
            ok = expect_in_stdout in r.stdout
        if ok:
            print(f"  PASS  {name}")
            passed += 1
            return True
        else:
            out = (r.stdout + r.stderr).strip()[-200:]
            print(f"  FAIL  {name}: exit={r.returncode}")
            if out:
                print(f"        {out}")
            errors.append(name)
            failed += 1
            return False
    except subprocess.TimeoutExpired:
        print(f"  FAIL  {name}: timeout ({timeout}s)")
        errors.append(f"{name} (timeout)")
        failed += 1
        return False
    except Exception as e:
        print(f"  FAIL  {name}: {e}")
        errors.append(f"{name} ({e})")
        failed += 1
        return False


print(f"\n=== Aegis Release Gate ===")
print(f"Wheel: {WHEEL}")
print(f"Venv:  {VENV_DIR}\n")

# Step 0: Create venv + install
print("[0/6] Creating fresh venv...")
subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)],
               check=True, capture_output=True)
subprocess.run([PYTHON, "-m", "pip", "install", "-q",
                f"{WHEEL}[mcp,icp,pq,all]"],
               check=True, capture_output=True)
print(f"  OK   Installed in {VENV_DIR}\n")

# Gate 1: Wheel contents
print("[1/6] Wheel contents...")
gate("mcp_queue.py in wheel",
     [PYTHON, "-c",
      "import zipfile; z=zipfile.ZipFile(r'" + WHEEL + "'); "
      "names=[n for n in z.namelist() if n.endswith('.py')]; "
      "assert any('mcp_queue' in n for n in names), 'mcp_queue.py missing'; "
      "assert any('candid_builder' in n for n in names), 'candid_builder.py missing'; "
      "print(f'{len(names)} .py files OK')"])

# Gate 2: All module imports
print("\n[2/6] Module imports...")
MODULES = {
    "mcp_server": "mcp", "mcp_queue": "ensure_bg_worker",
    "langchain": "AegisCallbackHandler", "crewai": "AegisCrewCallback",
    "openai_agents": "AegisAgentTracer", "autogen": "AegisAutoGenHook",
    "anthropic_sdk": "AegisAnthropicTracer", "mcp_proxy": "run_proxy",
    "auto": "auto", "monitor": "HealthMonitor", "alerting": "create_alerter",
    "otel_exporter": "AegisOTelExporter", "verify": "verify_chain",
    "candid_builder": "_build_add_ledger_entry_v2_args",
    "client": "AegisClient", "transport": "CanisterTransport",
}
for mod, cls in MODULES.items():
    gate(f"import aegis.{mod}.{cls}",
         [PYTHON, "-c",
          f"from aegis.{mod} import {cls}; print('OK')"])

# Gate 3: CLI commands (no network needed)
print("\n[3/6] CLI commands...")
gate("aegis version", [*AEGIS, "version"], expect_in_stdout="aegis-ledger-sdk")
gate("aegis spill-status", [*AEGIS, "spill-status"])
gate("aegis queue-status", [*AEGIS, "queue-status"])
gate("aegis profiles", [*AEGIS, "profiles"])

# Gate 4: Live canister (requires ~/.aegis/config.toml)
config_exists = (Path.home() / ".aegis" / "config.toml").exists()
print(f"\n[4/6] Live canister tests "
      f"{'(config found)' if config_exists else '(SKIPPED — no config)'}...")
if config_exists:
    gate("aegis status", [*AEGIS, "status"], timeout=30)
    gate("aegis doctor", [*AEGIS, "doctor"], timeout=30)
    gate("aegis test", [*AEGIS, "test"], timeout=60,
         expect_in_stdout="VERIFIED")
    gate("aegis deploy-check", [*AEGIS, "deploy-check"], timeout=60,
         expect_in_stdout="Deploy check passed")
    gate("aegis monitor --once", [*AEGIS, "monitor", "--once"], timeout=30)
    gate("SDK log_tool_call",
         [PYTHON, "-c",
          "from aegis import AegisClient; "
          "c=AegisClient.from_config(); "
          "aid=c.log_tool_call('release-gate','test','ok',10); "
          "print(f'OK: {aid}'); c.close()"],
         timeout=60)
    gate("MCP server starts",
         [PYTHON, "-c",
          "from aegis.mcp_server import mcp; "
          f"print(f'OK: {{len(mcp._tool_manager._tools)}} tools')"],
         expect_in_stdout="tools")
else:
    print("  SKIP  No ~/.aegis/config.toml — live tests skipped")
    print("        (These MUST pass on the release machine)")

# Gate 5: Keygen (no network)
print("\n[5/6] Keygen...")
tmp_key = VENV_DIR / "test_key.pem"
gate("aegis keygen ed25519",
     [*AEGIS, "keygen", str(tmp_key)],
     expect_in_stdout="Ed25519")
tmp_key_pq = VENV_DIR / "test_key_pq.pem"
gate("aegis keygen ml-dsa-65",
     [*AEGIS, "keygen", str(tmp_key_pq), "--algorithm", "ml-dsa-65"],
     expect_in_stdout="ML-DSA-65")

# Gate 6: Summary
print(f"\n[6/6] Summary")
print(f"  {passed} passed, {failed} failed")
if errors:
    print(f"  BLOCKED: {', '.join(errors)}")
    print(f"\n  DO NOT RELEASE.\n")
    sys.exit(1)
else:
    print(f"\n  ALL GATES PASS — safe to release.\n")
    sys.exit(0)
