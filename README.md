# Lab 5A — Semgrep: Detection and Remediation of Path Traversal

**Student:** Aditey Mehra (2301730266)  
**University:** K.R. Mangalam University  
**Programme:** B.Tech CSE (AI & ML) — Section D — Semester 7  
**Subject:** Secure Coding and Vulnerabilities  
**Repository:** https://github.com/incognito-unlimited/Lab5A-Semgrep-Path-Traversal

---

## 1. Aim

To build a Python file reader that accepts a user-supplied filename, detect its path-traversal flaw with Semgrep, remediate it with canonical path resolution and containment checks, rescan with the identical toolchain, verify the fix functionally, and publish the evidence and report.

## 2. Objectives

- Implement an intentionally vulnerable file reader with no filename validation.
- Scan it with Semgrep (`p/python` registry ruleset) and interpret the findings.
- Document a custom Semgrep rule when the registry ruleset misses the exact flaw.
- Implement a hardened reader that rejects traversal, absolute paths and symlink escapes.
- Rerun the same scans and compare the results.
- Test seven input classes against both implementations.
- Capture genuine screenshots, publish everything to GitHub, and produce DOCX/PDF reports.

## 3. Project structure

```
Lab5A-Semgrep-Path-Traversal/
├── vulnerable.py                     # intentionally vulnerable implementation
├── secure_file_reader.py             # remediated implementation
├── outside.txt                       # harmless marker OUTSIDE files/ (test fixture)
├── files/
│   └── sample.txt                    # legitimate file INSIDE the safe directory
├── rules/
│   └── path_traversal_unvalidated.yml  # documented custom Semgrep rule
├── tests/
│   └── functional_tests.py           # reproducible 7-case test harness
├── evidence/
│   ├── semgrep_before.txt            # before: registry + custom rule (text)
│   ├── semgrep_before.json           # before: custom rule (machine-readable)
│   ├── semgrep_registry_before.json  # before: p/python JSON
│   ├── semgrep_after.txt             # after: registry + custom rule (text)
│   ├── semgrep_after.json            # after: custom rule JSON
│   ├── semgrep_registry_after.json   # after: p/python JSON
│   ├── semgrep_comparison.txt        # generated before/after comparison
│   ├── semgrep_tool_info.txt         # version and environment
│   ├── test_results.txt              # complete real functional-test output
│   ├── valid_access_console.txt      # verbatim console transcript (valid access)
│   ├── rejected_traversal_console.txt# verbatim console transcript (rejections)
│   └── screenshots/                  # 7 genuine screenshots
├── report/
│   ├── Lab5A_Report.md
│   ├── Lab_5A_Semgrep_Path_Traversal_Aditey_Mehra.docx
│   └── Lab_5A_Semgrep_Path_Traversal_Aditey_Mehra.pdf
├── README.md
└── .gitignore
```

## 4. Toolchain

Semgrep was installed in a WSL Ubuntu virtual environment:

```bash
python3 -m venv /home/aditey/semgrep-venv
/home/aditey/semgrep-venv/bin/pip install semgrep
/home/aditey/semgrep-venv/bin/semgrep --version
# 1.185.0
```

Environment: Ubuntu 26.04.1 LTS, Linux 6.18.58.1-microsoft-standard-WSL2, Python 3.14.4 (WSL) / 3.11.9 (Windows).

## 5. Vulnerable implementation

`vulnerable.py` takes the filename directly from `input()`, joins it to `Path("files")` and opens it. There is no validation, canonicalisation or containment check:

```python
from pathlib import Path

BASE_DIR = Path("files")

filename = input("Enter filename: ")
target = BASE_DIR / filename

with target.open("r", encoding="utf-8") as file:
    print(file.read())
```

`Path.joinpath` discards the left operand when the right operand is absolute, and `..` segments are interpreted by the filesystem. Therefore `../outside.txt`, repeated parent segments, an absolute path, or a symlink inside `files/` can all reach a file outside the intended directory.

## 6. Semgrep analysis — before remediation

Commands actually run (from the project root):

```bash
semgrep scan --config p/python vulnerable.py
semgrep scan --config p/python --json --output evidence/semgrep_registry_before.json vulnerable.py
semgrep scan --config rules/path_traversal_unvalidated.yml vulnerable.py
semgrep scan --config rules/path_traversal_unvalidated.yml --json --output evidence/semgrep_before.json vulnerable.py
```

**Result:** the 151-rule `p/python` registry set reported **0 findings** — it does not model this `input() → path join → open()` data flow. As the lab brief directs, a documented custom rule was created and applied to both versions.

**Custom-rule finding:**

| Field | Value |
|---|---|
| Rule ID | `rules.python-path-traversal-unvalidated-filename` |
| Severity | `ERROR` |
| Confidence | `HIGH` (declared in the YAML; Semgrep OSS does not emit it in JSON `extra`) |
| Source line | 5 (matched region 5–9) |
| Vulnerable construct | `filename = input(...)` → `target = BASE_DIR / filename` → `with target.open(...) as file:` |

The OSS JSON fields `lines` and `fingerprint` report `requires login`; the real matched source lines are preserved in `evidence/semgrep_before.txt`.

**Security implications:** an attacker-controlled filename can escape `files/` and disclose arbitrary readable files, including credentials or application source, depending on process privileges. The same primitive can be extended to overwrite or delete files when the sink writes instead of reads. The program also leaks absolute paths and exception details through unhandled tracebacks.

## 7. Remediation

`secure_file_reader.py` applies defence in depth:

- `BASE_DIR` is anchored to the script location: `Path(__file__).resolve().parent / "files"`.
- Input is checked for emptiness, excessive length and null bytes.
- Absolute paths (POSIX, Windows drive letters, UNC) are rejected.
- `Path.resolve()` canonicalises the candidate, collapsing `..` and following symlinks.
- `candidate.relative_to(safe_root)` enforces containment — no string-prefix comparison.
- On POSIX, `os.open()` uses `O_NOFOLLOW`, and `/proc/self/fd/<fd>` is re-resolved and re-checked to reduce TOCTOU risk if the filesystem is modified concurrently.
- Exceptions are caught and converted into short, generic messages that reveal no system paths.
- `O_CLOEXEC` is set so the descriptor is not inherited by child processes.

## 8. Semgrep analysis — after remediation

The exact same version, rulesets and options were rerun against `secure_file_reader.py`:

```bash
semgrep scan --config p/python secure_file_reader.py
semgrep scan --config rules/path_traversal_unvalidated.yml secure_file_reader.py
```

| Ruleset | Findings before | Findings after |
|---|---:|---:|
| `p/python` (151 rules) | 0 | 0 |
| Custom rule | 1 (`ERROR`, `vulnerable.py:5`) | 0 |

No path-traversal findings remain. A clean static result is not treated as proof on its own; the functional tests below provide the runtime check.

## 9. Functional testing

Run:

```bash
python3 tests/functional_tests.py
```

The harness creates a temporary `files/escape_link.txt → ../outside.txt` symlink, runs all seven inputs against both programs, records real stdout/stderr/exit codes, classifies the behaviour, writes `evidence/test_results.txt` and removes the symlink.

| # | Input | vulnerable.py | secure_file_reader.py |
|---|---|---|---|
| 1 | `sample.txt` | allowed | allowed |
| 2 | `../outside.txt` | **escaped** | rejected |
| 3 | `../../Lab5A-Semgrep-Path-Traversal/outside.txt` | **escaped** | rejected |
| 4 | absolute path to `outside.txt` | **escaped** | rejected |
| 5 | `does_not_exist.txt` | unhandled traceback | clean error |
| 6 | empty filename | unhandled traceback | clean error |
| 7 | `escape_link.txt` (symlink) | **escaped** | rejected |

**Result:** the vulnerable program leaked out-of-scope content in 4 of 7 cases. The secure program rejected all 4 escape attempts and produced a clean, non-traceback result in 7 of 7 cases while still reading the valid file.

## 10. Evidence and screenshots

- `evidence/semgrep_before.txt`, `evidence/semgrep_after.txt` — complete text scans (both rulesets).
- `evidence/semgrep_before.json`, `evidence/semgrep_after.json` — custom-rule JSON.
- `evidence/semgrep_registry_before.json`, `evidence/semgrep_registry_after.json` — registry JSON.
- `evidence/semgrep_comparison.txt` — generated comparison and finding detail.
- `evidence/test_results.txt` — full functional-test transcript.
- `evidence/valid_access_console.txt`, `evidence/rejected_traversal_console.txt` — verbatim console transcripts used for screenshots 5 and 6.

Genuine screenshots in `evidence/screenshots/`:

1. `01_vulnerable_source.png` — vulnerable source in VS Code.
2. `02_semgrep_before.png` — 1 finding from the custom rule, with source lines.
3. `03_secure_source.png` — remediated source showing validation logic.
4. `04_semgrep_after.png` — 0 findings from both rulesets.
5. `05_valid_file_access.png` — real console transcript for the valid filename.
6. `06_rejected_traversal.png` — real console transcript for all rejected paths.
7. `07_github_repository.png` — the published GitHub repository.

## 11. Result and conclusion

Path traversal was reproduced and demonstrated against a harmless synthetic marker file. The default `p/python` ruleset produced no findings, so a narrowly scoped custom rule was documented and applied identically to both programs: 1 finding before, 0 after. The remediated reader combines input validation, absolute-path rejection, canonical resolution, resolved-path containment, symlink handling and TOCTOU hardening, and it passed all seven functional cases without leaking an out-of-scope file or exposing a traceback. The experiment confirms that static analysis must be supplemented with an appropriate rule and runtime tests when a generic ruleset does not cover the vulnerable data flow.

---

**GitHub URL:** https://github.com/incognito-unlimited/Lab5A-Semgrep-Path-Traversal
