"""
Ecosystem-specific package name normalization.

Mirrors the Go normalize package exactly.
"""

import re
import string


def npm(name: str) -> str:
    """Normalize an npm package name: lowercase, strip whitespace.

    Scoped names (``@scope/pkg``) retain the leading ``@`` and ``/`` separator.
    """
    return name.strip().lower()


def pypi(name: str) -> str:
    """Normalize a PyPI package name per PEP 503.

    Lowercase, then collapse any run of ``-``, ``_``, ``.`` or whitespace
    into a single ``-``.
    """
    name = name.strip().lower()
    result = []
    prev_sep = False
    for ch in name:
        if ch in ("-", "_", ".") or ch.isspace():
            if not prev_sep:
                result.append("-")
                prev_sep = True
        else:
            result.append(ch)
            prev_sep = False
    return "".join(result).strip("-")
