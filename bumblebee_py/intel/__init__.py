"""Bumblebee threat-intel submodule (legacy — wraps bumblebee_py.catalogs)."""
import sys as _sys, os as _os
# Re-export from catalogs module
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(__file__)))
from bumblebee_py.catalogs import *  # noqa: F401, F403
