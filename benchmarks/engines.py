"""Definitions for external SAST engines used in the benchmark.
Each engine implementation must expose:
    async def run(target_dir: Path, output_dir: Path) -> Path
which returns the path to the SARIF (or JSON) output file produced.
The benchmark harness will import these engines dynamically.
"""
from __future__ import annotations

import asyncio
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Callable, Awaitable, Any

__all__ = [
    "ENGINE_REGISTRY",
]

ENGINE_REGISTRY: Dict[str, Callable[[Path, Path], Awaitable[Path]]] = {}

def register(name: str):
    """Decorator to register a new engine implementation."""
    def _wrap(fn: Callable[[Path, Path], Awaitable[Path]]):
        ENGINE_REGISTRY[name] = fn
        return fn
    return _wrap

async def _run_cmd(cmd: list[str], cwd: Path, timeout: int = 600) -> None:
    """Utility: run command and raise if fails."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError(f"Command timed out: {' '.join(cmd)}")
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\nSTDERR:\n{stderr.decode()}\nSTDOUT:\n{stdout.decode()}"
        )

# -------------------- ENGINE IMPLEMENTATIONS --------------------

@register("llm_sast")
async def run_llm_sast(target_dir: Path, output_dir: Path) -> Path:
    out_path = output_dir / "llm_sast.sarif"
    cmd = [
        "python3",
        "main.py",
        "-t",
        str(target_dir),
        "-o",
        str(output_dir),
        "--sarif",  # assume scanner supports SARIF flag; if not, adjust accordingly
    ]
    await _run_cmd(cmd, cwd=Path(__file__).resolve().parent.parent)
    if not out_path.exists():
        # fallback: use generic json if sarif not produced
        out_path = next(output_dir.glob("*.sarif"), None) or next(output_dir.glob("*.json"))
    return out_path

@register("semgrep")
async def run_semgrep(target_dir: Path, output_dir: Path) -> Path:
    if shutil.which("semgrep") is None:
        raise RuntimeError("semgrep executable not found. Install with `pip install semgrep`. ")
    out_path = output_dir / "semgrep.sarif"
    cmd = [
        "semgrep",
        "--config",
        "auto",
        "--sarif",
        "--output",
        str(out_path),
        str(target_dir),
    ]
    await _run_cmd(cmd, cwd=target_dir)
    return out_path

@register("bandit")
async def run_bandit(target_dir: Path, output_dir: Path) -> Path:
    """Run Bandit and convert its JSON output to SARIF-lite format for comparison."""
    if shutil.which("bandit") is None:
        raise RuntimeError("bandit executable not found. Install with `pip install bandit`. ")

    json_path = output_dir / "bandit.json"
    cmd = [
        "bandit",
        "-r",
        str(target_dir),
        "-f",
        "json",
        "-o",
        str(json_path),
    ]
    await _run_cmd(cmd, cwd=target_dir)

    # Convert minimal fields to SARIF structure consumed by benchmark
    import json as _json
    sarif_path = output_dir / "bandit.sarif"
    with json_path.open() as f:
        data = _json.load(f)

    results = []
    for issue in data.get("results", []):
        rule_id = issue.get("test_id", "BANDIT")
        file_path = issue.get("filename")
        line = issue.get("line_number", 0)
        sev = issue.get("issue_severity", "LOW").upper()
        results.append({
            "ruleId": rule_id,
            "level": sev.lower(),
            "message": {"text": issue.get("issue_text", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": line, "endLine": line}
                }
            }],
            "properties": {"severity": sev}
        })
    sarif_doc = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Bandit"}},
            "results": results
        }]
    }
    with sarif_path.open("w") as f:
        _json.dump(sarif_doc, f)
    return sarif_path
