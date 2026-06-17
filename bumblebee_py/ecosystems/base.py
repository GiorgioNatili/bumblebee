"""
Base scanner with bounded file reading helpers.

All ecosystem scanners share this pattern: a MaxFileSize cap,
read_bounded() for opening and sized reading, and optional
read_optional() for best-effort sibling file reads.
"""

import os
import stat
from typing import Optional


class BaseScanner:
    """Base class for ecosystem scanners.

    Subclasses set ``self.emit`` (callable taking a model.Record) and
    ``self.diag`` (callable taking level, path, msg).
    """

    def __init__(self, max_file_size: int = 5 * 1024 * 1024,
                 emit=None, diag=None):
        self.max_file_size = max_file_size
        self.emit = emit
        self.diag = diag

    def read_bounded(self, path: str) -> Optional[bytes]:
        """Read *path* up to max_file_size bytes.

        Returns bytes on success, None on error (diagnostics emitted
        via self.diag).
        """
        try:
            info = os.stat(path)
            if not stat.S_ISREG(info.st_mode):
                return None
            if self.max_file_size > 0 and info.st_size > self.max_file_size:
                if self.diag:
                    self.diag("warn", path,
                              f"skipping: size {info.st_size} exceeds max {self.max_file_size}")
                return None
            with open(path, "rb") as f:
                return f.read()
        except OSError as e:
            return None

    def read_optional(self, path: str) -> Optional[bytes]:
        """Read a best-effort optional sibling file.

        Returns bytes or None (silently). No diagnostics emitted for
        missing or oversized files.
        """
        try:
            info = os.stat(path)
            if not stat.S_ISREG(info.st_mode):
                return None
            if self.max_file_size > 0 and info.st_size > self.max_file_size:
                return None
            with open(path, "rb") as f:
                return f.read()
        except OSError:
            return None
