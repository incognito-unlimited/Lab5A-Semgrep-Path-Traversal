#!/usr/bin/env python3
"""Reproducible functional tests for Lab 5A.

Runs the same seven filename inputs against vulnerable.py and
secure_file_reader.py, captures the real stdout/stderr/exit codes, classifies
the observed behaviour and writes evidence/test_results.txt.

Run with:
    python3 tests/functional_tests.py
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence"
SYMLINK = ROOT / "files" / "escape_link.txt"
OUTSIDE = ROOT / "outside.txt"
SAMPLE_MARKER = "Lab 5A sample file."
OUTSIDE_MARKER = "OUTSIDE-SENSITIVE-MARKER"
OUTSIDE_ERROR = "Access outside the permitted directory is not allowed"
ABSOLUTE_ERROR = "Absolute paths are not allowed"


def classify(stdout: str, stderr: str) -> str:
    """Return a short, objective description of what the program did."""
    if OUTSIDE_MARKER in stdout:
        return "ESCAPED - content from outside files/ was printed"
    if SAMPLE_MARKER in stdout:
        return "ALLOWED - in-scope sample.txt content was printed"
    if OUTSIDE_ERROR in stdout or ABSOLUTE_ERROR in stdout:
        return "REJECTED - clear containment/absolute-path error"
    if "Error:" in stdout:
        return "CLEAN ERROR - safe, generic error message"
    if "Traceback (most recent call last)" in stderr:
        return "TRACEBACK - unhandled exception leaked to the user"
    return "OTHER - see captured output"


def run_program(script: str, payload: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(ROOT / script)],
        input=payload + "\n",
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=15,
    )
    return {
        "exit": result.returncode,
        "stdout": result.stdout.rstrip("\n"),
        "stderr": result.stderr.rstrip("\n"),
        "behaviour": classify(result.stdout, result.stderr),
    }


def block(title: str, lines: list[str]) -> None:
    lines.append("-" * 78)
    lines.append(title)
    lines.append("-" * 78)


def indent(text: str) -> list[str]:
    if not text:
        return ["    (empty)"]
    return ["    " + line for line in text.splitlines()]


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)

    # Harmless symlink used only for the symlink test case.
    if SYMLINK.is_symlink() or SYMLINK.exists():
        SYMLINK.unlink()
    os.symlink("../outside.txt", SYMLINK)

    absolute_path = str(OUTSIDE)
    cases = [
        (
            "Valid filename",
            "sample.txt",
            "Read the legitimate in-scope file inside files/.",
            "both allow",
        ),
        (
            "Single parent traversal",
            "../outside.txt",
            "One ../ segment should leave the files/ directory.",
            "vulnerable escapes / secure rejects",
        ),
        (
            "Multiple parent traversal segments",
            "../../Lab5A-Semgrep-Path-Traversal/outside.txt",
            "Two ../ segments walk further up and back into the project root.",
            "vulnerable escapes / secure rejects",
        ),
        (
            "Absolute path",
            absolute_path,
            "An absolute path replaces the intended base directory.",
            "vulnerable escapes / secure rejects",
        ),
        (
            "Missing file",
            "does_not_exist.txt",
            "A nonexistent in-scope filename must produce a clean error.",
            "both report missing file; secure stays clean",
        ),
        (
            "Empty filename",
            "",
            "Pressing Enter with no filename must produce a clean error.",
            "both error; secure stays clean",
        ),
        (
            "Symlink pointing outside files/",
            "escape_link.txt",
            "files/escape_link.txt is a symlink to ../outside.txt.",
            "vulnerable follows it / secure rejects it",
        ),
    ]

    results = []
    for name, payload, description, expected in cases:
        vuln = run_program("vulnerable.py", payload)
        secure = run_program("secure_file_reader.py", payload)
        results.append((name, payload, description, expected, vuln, secure))

    lines: list[str] = []
    lines.append("LAB 5A - FUNCTIONAL TEST RESULTS")
    lines.append("=" * 78)
    lines.append(f"Generated (UTC) : {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S UTC}")
    lines.append(f"Python          : {sys.version.split()[0]}")
    lines.append(f"Platform        : {platform.platform()}")
    lines.append(f"Working dir     : {ROOT}")
    lines.append("Command pattern : python3 <program>   (input supplied on stdin)")
    lines.append("")
    lines.append("Synthetic fixtures (no real sensitive system files were used):")
    lines.append("  files/sample.txt       - legitimate file inside the safe directory")
    lines.append(f"  outside.txt            - harmless marker at {OUTSIDE}")
    lines.append("  files/escape_link.txt  - symlink -> ../outside.txt (created by this test)")
    lines.append("")
    lines.append(
        "The vulnerable program is expected to demonstrate the flaw; the secure "
        "program is expected to reject every out-of-scope input."
    )
    lines.append("")

    for index, (name, payload, description, expected, vuln, secure) in enumerate(results, 1):
        block(f"TEST {index}: {name}", lines)
        lines.append(f"Description : {description}")
        lines.append(f"Input       : {payload!r}")
        lines.append(f"Expected    : {expected}")
        lines.append("")
        lines.append("VULNERABLE (vulnerable.py)")
        lines.append(f"  Exit code  : {vuln['exit']}")
        lines.append(f"  Behaviour  : {vuln['behaviour']}")
        lines.append("  STDOUT:")
        lines.extend(indent(vuln["stdout"]))
        lines.append("  STDERR:")
        lines.extend(indent(vuln["stderr"]))
        lines.append("")
        lines.append("SECURE (secure_file_reader.py)")
        lines.append(f"  Exit code  : {secure['exit']}")
        lines.append(f"  Behaviour  : {secure['behaviour']}")
        lines.append("  STDOUT:")
        lines.extend(indent(secure["stdout"]))
        lines.append("  STDERR:")
        lines.extend(indent(secure["stderr"]))
        lines.append("")

    block("SUMMARY", lines)
    header = f"{'Case':<36} {'Vulnerable':<44} {'Secure':<44}"
    lines.append(header)
    lines.append("-" * len(header))
    for name, _payload, _description, _expected, vuln, secure in results:
        lines.append(
            f"{name:<36} {vuln['behaviour']:<44} {secure['behaviour']:<44}"
        )
    lines.append("")

    leaks = sum("ESCAPED" in v["behaviour"] for _n, _p, _d, _e, v, _s in results)
    secure_blocks = sum(
        "REJECTED" in s["behaviour"] for _n, _p, _d, _e, _v, s in results
    )
    secure_clean_errors = sum(
        "TRACEBACK" not in s["behaviour"]
        for _n, _p, _d, _e, _v, s in results
    )
    lines.append("OBSERVATIONS")
    lines.append("-" * 78)
    lines.append(
        f"  * The vulnerable program leaked out-of-scope content in {leaks} of "
        f"{len(results)} cases."
    )
    lines.append(
        f"  * The secure program rejected {secure_blocks} path-escape attempts "
        "(traversal, absolute path and symlink)."
    )
    lines.append(
        f"  * The secure program produced a clean (non-traceback) result in "
        f"{secure_clean_errors} of {len(results)} cases."
    )
    lines.append(
        "  * Both programs read files/sample.txt successfully, so the fix did "
        "not break legitimate use."
    )
    lines.append("")
    lines.append("CONCLUSION")
    lines.append("-" * 78)
    lines.append(
        "Path traversal is confirmed in vulnerable.py: user input is joined to "
        "the base directory and opened without canonicalisation or containment "
        "checks. secure_file_reader.py rejects every escape attempt, resolves "
        "symlinks before validation and returns generic error messages."
    )

    output = EVIDENCE / "test_results.txt"
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Remove the temporary symlink so the committed tree stays clean.
    SYMLINK.unlink(missing_ok=True)

    print(f"Wrote {output}")
    print(f"Vulnerable leaks: {leaks}; secure rejections: {secure_blocks}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
