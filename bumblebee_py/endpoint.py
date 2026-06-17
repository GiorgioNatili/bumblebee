"""
Host identity collection.

Populates the Endpoint struct with hostname, OS, architecture, username,
UID, and optional device ID.
"""

import getpass
import os
import platform
import socket

from bumblebee_py.model import Endpoint


def current(device_id: str = "") -> Endpoint:
    """Return the endpoint identity for the current host.

    Args:
        device_id: Optional opaque device identifier from an external source
                   (e.g. MDM/EDR). Already trimmed.

    Returns:
        An Endpoint dataclass populated with runtime values.
    """
    hostname = ""
    try:
        hostname = socket.gethostname()
    except OSError:
        pass

    username = ""
    try:
        username = os.getlogin()
    except OSError:
        username = getpass.getuser()

    uid = ""
    try:
        uid = str(os.getuid())
    except AttributeError:
        pass

    return Endpoint(
        hostname=hostname,
        os=platform.system().lower(),
        arch=platform.machine().lower(),
        username=username,
        uid=uid,
        device_id=device_id,
    )
