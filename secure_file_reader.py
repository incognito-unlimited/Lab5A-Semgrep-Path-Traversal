"""Secure file reader: restricts access to a predefined safe directory.

Lab 5A remediation for the path-traversal vulnerability demonstrated in
vulnerable.py.  The design uses canonical path resolution and a resolved-path
containment check rather than a string-prefix comparison.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent / "files"
MAX_FILENAME_LENGTH = 200


class FileAccessError(Exception):
    """Base class for errors that are safe to display to a user."""


class InvalidFilenameError(FileAccessError):
    """The supplied filename is malformed or absolute."""


class OutsideDirectoryError(FileAccessError):
    """The resolved path is outside the permitted directory."""


def _validate_filename(filename: str) -> None:
    """Apply input-level checks before any filesystem operation."""
    if not isinstance(filename, str) or not filename.strip():
        raise InvalidFilenameError("Filename must be a non-empty string")
    if len(filename) > MAX_FILENAME_LENGTH:
        raise InvalidFilenameError("Filename is too long")
    if "\x00" in filename:
        raise InvalidFilenameError("Filename contains a null byte")

    candidate = Path(filename)
    # Covers POSIX absolute paths, Windows drive letters and UNC paths.
    if candidate.is_absolute() or candidate.drive or filename.startswith(("/", "\\")):
        raise InvalidFilenameError("Absolute paths are not allowed")


def resolve_within_directory(filename: str, base_dir: Path = BASE_DIR):
    """Return (safe_root, candidate) only when the candidate is contained.

    Path.resolve() collapses '..' segments and follows symlinks, so the
    containment test observes the real location rather than the textual path.
    """
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


def read_user_file(filename: str) -> str:
    """Read a file after enforcing directory containment and safe opening."""
    safe_root, candidate = resolve_within_directory(filename)

    if not candidate.is_file():
        raise FileNotFoundError("Requested file does not exist")

    # TOCTOU hardening on POSIX: O_NOFOLLOW prevents a last-component symlink
    # that is swapped after the containment check from being followed.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(candidate, flags)
    except FileNotFoundError:
        raise FileNotFoundError("Requested file does not exist") from None
    except OSError:
        raise FileAccessError("Unable to open the requested file") from None

    try:
        # On Linux, re-verify the descriptor's real target so a replaced
        # intermediate symlink cannot redirect the open after resolution.
        if sys.platform.startswith("linux"):
            try:
                opened_path = Path(os.readlink(f"/proc/self/fd/{fd}")).resolve()
                opened_path.relative_to(safe_root)
            except (OSError, ValueError):
                raise OutsideDirectoryError(
                    "Access outside the permitted directory is not allowed"
                ) from None

        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def main() -> None:
    """Prompt for a filename and print content or a safe error message."""
    filename = input("Enter filename: ").strip()
    try:
        print(read_user_file(filename))
    except (FileAccessError, FileNotFoundError) as exc:
        # Deliberately generic: no absolute paths, stack traces or OS details.
        print(f"Error: {exc}")
    except OSError:
        print("Error: Unable to read the requested file")


if __name__ == "__main__":
    main()
