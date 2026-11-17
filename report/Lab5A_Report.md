# LAB 5A — Semgrep-Based Detection and Remediation of Path Traversal

| Detail | Value |
|---|---|
| Name | Aditey Mehra |
| Roll Number | 2301730266 |
| University | K.R. Mangalam University |
| Programme | B.Tech CSE (AI & ML) |
| Section | D |
| Semester | 7 |
| Subject | Secure Coding and Vulnerabilities |
| Lab | 5A |
| GitHub Repository | https://github.com/incognito-unlimited/Lab5A-Semgrep-Path-Traversal |

---

## 1. Aim

To develop a Python program that reads a user-specified filename from a designated folder, identify insecure file-access and path-traversal risks using Semgrep, remediate the program with robust path validation, compare static-analysis findings before and after the security fix, and publish the source, evidence and report to GitHub.

## 2. Objectives

1. Implement an initial Python file-reading program without filename validation.
2. Scan the initial implementation using Semgrep and record relevant findings.
3. Explain how path traversal can allow access outside the intended directory.
4. Restrict file access to a predefined safe directory using canonical path resolution and containment checks.
5. Rescan the corrected program and compare actual findings.
6. Publish source files, Semgrep outputs, screenshots and documentation to GitHub.

## 3. Introduction

Path traversal (CWE-22) occurs when an application constructs a filesystem path from untrusted input without verifying that the resulting path remains inside an authorised directory. File-separator sequences such as `../` are interpreted by the operating system, so a name that looks like a simple filename can navigate out of the intended folder. Python's `pathlib` makes this especially easy to overlook: `Path("files") / "/etc/passwd"` discards the base directory entirely because the right-hand operand is absolute, and `Path.resolve()` will happily collapse `..` segments to a location elsewhere on disk.

If the application opens the resulting path, an attacker can read configuration files, credentials, source code or other sensitive data that the process can access. Where the sink is a write operation, the same flaw can lead to arbitrary file modification. Symlinks add a second bypass: a file name inside the safe directory may point to a target outside it.

Static application security testing (SAST) with Semgrep can identify such patterns before deployment, but ruleset coverage varies. This experiment therefore records both the registry scan and a documented custom rule, then confirms the result with functional tests.

## 4. Vulnerable code

File: `vulnerable.py`

```python
from pathlib import Path

BASE_DIR = Path("files")

filename = input("Enter filename: ")
target = BASE_DIR / filename

with target.open("r", encoding="utf-8") as file:
    print(file.read())
```

The user-controlled `filename` flows directly into the path join and then into `open()`. There is no validation, no canonicalisation and no containment check. A harmless synthetic marker file, `outside.txt`, was placed at the project root to demonstrate the escape without touching real sensitive files.

## 5. Semgrep findings — before remediation

Environment and toolchain:

```
Semgrep version: 1.185.0 (OSS engine)
Platform: Ubuntu 26.04.1 LTS (Linux 6.18.58.1-microsoft-standard-WSL2)
Rulesets: p/python (151 rules) and rules/path_traversal_unvalidated.yml
```

Commands executed:

```bash
semgrep --version
semgrep scan --config p/python vulnerable.py
semgrep scan --config p/python --json --output evidence/semgrep_registry_before.json vulnerable.py
semgrep scan --config rules/path_traversal_unvalidated.yml vulnerable.py
semgrep scan --config rules/path_traversal_unvalidated.yml --json --output evidence/semgrep_before.json vulnerable.py
```

The `p/python` registry ruleset reported **0 findings** (151 rules, 1 target). It does not model this `input() → path join → open()` flow. In accordance with the lab brief, a custom rule was therefore created at `rules/path_traversal_unvalidated.yml` and applied to both programs. Its multi-line pattern matches the complete data flow:

```yaml
pattern: |
  $FILENAME = input(...)
  ...
  $TARGET = $BASE / $FILENAME
  ...
  with $TARGET.open(...) as $F:
    ...
```

**Finding from the custom rule (verbatim details from the scan):**

| Field | Value |
|---|---|
| Rule ID | `rules.python-path-traversal-unvalidated-filename` |
| Severity | `ERROR` |
| Confidence | `HIGH` (declared in the YAML; Semgrep OSS does not include it in JSON `extra`) |
| File and source line | `vulnerable.py`, line 5 (matched region 5–9) |
| Validation state | `NO_VALIDATOR` |
| Vulnerable construct | `filename = input(...)` → `target = BASE_DIR / filename` → `with target.open(...) as file:` |

Matched source as shown in the text output:

```
   5┆ filename = input("Enter filename: ")
   6┆ target = BASE_DIR / filename
   7┆
   8┆ with target.open("r", encoding="utf-8") as file:
   9┆     print(file.read())
```

Note: Semgrep OSS returns `requires login` for the JSON `lines` and `fingerprint` fields. The genuine matched source is preserved in `evidence/semgrep_before.txt`.

## 6. Security implications

A malicious filename such as `../outside.txt` escapes `files/` because the filesystem resolves `..` after the join. Multiple segments, an absolute path, or a symlink placed inside the safe directory achieve the same result. The displayed output in this lab is a harmless marker, but in a real application the same primitive could disclose secrets, source code or configuration. The vulnerable program additionally leaks absolute filesystem paths and Python tracebacks for error cases, giving an attacker useful reconnaissance information.

## 7. Corrected code

File: `secure_file_reader.py` (key sections)

```python
BASE_DIR = Path(__file__).resolve().parent / "files"

def _validate_filename(filename: str) -> None:
    if not isinstance(filename, str) or not filename.strip():
        raise InvalidFilenameError("Filename must be a non-empty string")
    if len(filename) > MAX_FILENAME_LENGTH:
        raise InvalidFilenameError("Filename is too long")
    if "\x00" in filename:
        raise InvalidFilenameError("Filename contains a null byte")
    candidate = Path(filename)
    if candidate.is_absolute() or candidate.drive or filename.startswith(("/", "\\")):
        raise InvalidFilenameError("Absolute paths are not allowed")

def resolve_within_directory(filename: str, base_dir: Path = BASE_DIR):
    _validate_filename(filename)
    safe_root = base_dir.resolve()
    candidate = (safe_root / filename).resolve()
    try:
        candidate.relative_to(safe_root)
    except ValueError:
        raise OutsideDirectoryError(
            "Access outside the permitted directory is not allowed"
        ) from None
    return safe_root, candidate
```

`read_user_file()` additionally checks that the candidate is a regular file, opens it with `O_NOFOLLOW | O_CLOEXEC`, and on Linux re-verifies the descriptor's real target through `/proc/self/fd/<fd>` before reading — a TOCTOU hardening step for environments where the filesystem may be modified concurrently. `main()` catches the safe exception types and prints short, generic errors without absolute paths or stack traces. No string-prefix comparison is used anywhere.

## 8. Semgrep comparison — after remediation

The same Semgrep version, rulesets and options were run against `secure_file_reader.py`.

```bash
semgrep scan --config p/python secure_file_reader.py
semgrep scan --config rules/path_traversal_unvalidated.yml secure_file_reader.py
```

| Ruleset | Before | After | Rule ID / severity | Resolved |
|---|---:|---:|---|---|
| `p/python` (151 rules) | 0 | 0 | none | no finding existed |
| Custom rule | 1 | 0 | `rules.python-path-traversal-unvalidated-filename` / `ERROR` | yes |
| Path-traversal findings | 1 | 0 | as above | yes |
| Remaining warnings | 0 | 0 | none | — |

The custom rule's single `ERROR` finding at `vulnerable.py:5-9` was resolved. Both scans completed without errors. A clean static result is supported by the functional tests below.

## 9. Functional testing

Command: `python3 tests/functional_tests.py` (real output saved to `evidence/test_results.txt`).

| # | Test input | vulnerable.py | secure_file_reader.py | Expected |
|---|---|---|---|---|
| 1 | `sample.txt` | ALLOWED | ALLOWED | allow |
| 2 | `../outside.txt` | ESCAPED (marker leaked) | REJECTED | block |
| 3 | `../../Lab5A-Semgrep-Path-Traversal/outside.txt` | ESCAPED | REJECTED | block |
| 4 | `/mnt/d/Projects/Lab5A-Semgrep-Path-Traversal/outside.txt` | ESCAPED | REJECTED | block |
| 5 | `does_not_exist.txt` | TRACEBACK | CLEAN ERROR | clean error |
| 6 | empty filename | TRACEBACK (`IsADirectoryError`) | CLEAN ERROR | clean error |
| 7 | `escape_link.txt` → `../outside.txt` | ESCAPED | REJECTED | block |

Summary of actual observations:

* The vulnerable program leaked out-of-scope content in 4 of 7 cases.
* The secure program rejected all 4 path-escape attempts (single traversal, multiple segments, absolute path and symlink).
* The secure program produced a clean, non-traceback result in 7 of 7 cases.
* Both programs read `files/sample.txt` successfully, so the fix did not break legitimate use.

The temporary symlink used for test 7 was removed by the harness after the run.

## 10. Screenshots

All screenshots are genuine captures of real files, scan output and program output:

1. `evidence/screenshots/01_vulnerable_source.png`
2. `evidence/screenshots/02_semgrep_before.png`
3. `evidence/screenshots/03_secure_source.png`
4. `evidence/screenshots/04_semgrep_after.png`
5. `evidence/screenshots/05_valid_file_access.png`
6. `evidence/screenshots/06_rejected_traversal.png`
7. `evidence/screenshots/07_github_repository.png`

Screenshots 5 and 6 show verbatim console transcripts captured from the actual program runs (`evidence/valid_access_console.txt` and `evidence/rejected_traversal_console.txt`).

## 11. GitHub URL

https://github.com/incognito-unlimited/Lab5A-Semgrep-Path-Traversal

## 12. Result and conclusion

The vulnerable implementation demonstrably read a file outside its permitted directory using a harmless synthetic marker. The default registry ruleset did not flag the flaw, so a narrowly scoped custom rule was documented and applied to both versions, producing 1 finding before remediation and 0 after. The hardened implementation passed all seven functional cases: it preserved valid access, rejected every traversal, absolute-path and symlink attempt, and returned safe error messages without tracebacks. The experiment demonstrates that effective path-traversal defence requires canonical resolution and containment verification — not string-prefix checks — and that static analysis should be complemented by an accurately targeted rule and runtime testing when generic rulesets miss the vulnerable data flow.
