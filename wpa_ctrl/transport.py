## @package wpa_ctrl.transport
#
# Socket mechanics for the wpa_supplicant control interface.
#
# The interface is a UNIX *datagram* socket, not a stream: the client binds
# its own socket, connects to wpa_supplicant's, and every command and reply
# is one datagram. That is why the client needs a writable directory of its
# own - there is nowhere else for its address to live.
#
# This layer knows nothing about the commands themselves. It exists apart
# from the client so the same protocol handling can later be driven by an
# asyncio transport without touching the command surface.
#
# @file transport.py

import logging
import os
import select
import socket
import time
from typing import Optional

from .errors import WpaCtrlConnectionError, WpaCtrlTimeout

logger = logging.getLogger(__name__)

## Where wpa_supplicant keeps its per-interface sockets by default, per
#  CONFIG_CTRL_IFACE_DIR in wpa_cli.c
DEFAULT_CTRL_DIR = "/var/run/wpa_supplicant"
## The same for hostapd, per CONFIG_CTRL_IFACE_DIR in hostapd_cli.c and the
#  ctrl_interface line in the shipped hostapd.conf. The protocol either side
#  of the socket is identical - upstream serves both from one wpa_ctrl.c
HOSTAPD_CTRL_DIR = "/var/run/hostapd"
## Where this client puts its own socket. Needs to be writable and is
#  deliberately not the control directory, which may be root-only
DEFAULT_CLIENT_DIR = "/tmp"
## Long enough for a busy supplicant to answer a scan, short enough that a
#  caller blocked on a dead daemon notices
DEFAULT_TIMEOUT = 5.0
## One datagram. Scan results on a crowded band are the big ones;
#  wpa_supplicant itself caps replies well below this
RECV_BUFFER = 65536


## Build the socket path for an interface
# @param ifname interface name, e.g. wlan0
# @param ctrl_dir directory wpa_supplicant was told to use
# @return the path to that interface's control socket
def interface_path(ifname: str, ctrl_dir: str = DEFAULT_CTRL_DIR) -> str:
    return os.path.join(ctrl_dir, ifname)


## A datagram connection to one wpa_supplicant control socket.
#
#  Not thread safe: one connection serves one caller. Use two connections
#  where commands and unsolicited events are both wanted - it is what the
#  interface documentation recommends, and it keeps a command's reply from
#  being interleaved with events.
class CtrlTransport:

    ## @param path control socket to talk to (an interface socket, or the
    #         global socket wpa_supplicant was started with via -g)
    #  @param client_dir writable directory for this client's own socket
    #  @param timeout default seconds to wait for a reply
    def __init__(self, path: str, client_dir: str = DEFAULT_CLIENT_DIR,
                 timeout: float = DEFAULT_TIMEOUT):
        self._path = path
        self._client_dir = client_dir
        self._timeout = timeout
        self._socket: Optional[socket.socket] = None
        self._client_path: Optional[str] = None

    @property
    def path(self) -> str:
        return self._path

    @property
    def connected(self) -> bool:
        return self._socket is not None

    ## Bind our own socket and connect it to wpa_supplicant's
    def open(self):
        if self._socket is not None:
            return

        # Unique per process and per connection: a process may hold several
        # (one for commands, one attached for events)
        client_path = os.path.join(
            self._client_dir, f"wpa_ctrl_{os.getpid()}-{id(self)}")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            # A crashed predecessor can leave its address behind
            self._unlink(client_path)
            sock.bind(client_path)
            sock.connect(self._path)
        except OSError as ex:
            sock.close()
            self._unlink(client_path)
            raise WpaCtrlConnectionError(f"{self._path}: {ex}") from ex

        sock.settimeout(self._timeout)
        self._socket = sock
        self._client_path = client_path
        logger.debug(f"Opened {self._path} as {client_path}")

    ## Close the connection and remove our socket from the filesystem
    def close(self):
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        self._unlink(self._client_path)
        self._client_path = None

    def __enter__(self) -> 'CtrlTransport':
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    ## Send one command. No terminator: the datagram boundary is the frame
    # @param command the command text
    def send(self, command: str):
        sock = self._require_socket()
        try:
            sock.send(command.encode())
        except OSError as ex:
            raise WpaCtrlConnectionError(f"send on {self._path}: {ex}") from ex

    ## Receive one datagram
    #  @param timeout seconds to wait, or the connection default
    #  @return the message, decoded
    def receive(self, timeout: Optional[float] = None) -> str:
        sock = self._require_socket()
        sock.settimeout(self._timeout if timeout is None else timeout)
        try:
            data = sock.recv(RECV_BUFFER)
        except socket.timeout as ex:
            raise WpaCtrlTimeout(f"no reply from {self._path}") from ex
        except OSError as ex:
            raise WpaCtrlConnectionError(f"recv on {self._path}: {ex}") from ex
        # errors=replace: SSIDs are arbitrary bytes and are not always UTF-8.
        # Losing a byte of an access point name must not lose the message
        return data.decode(errors="replace")

    ## The underlying socket's file descriptor, for handing to an event
    #  loop - asyncio's add_reader, a Qt notifier, a bare select.
    #
    #  Remove it from the loop before close(): the descriptor is closed with
    #  the socket, and a loop still watching it will either spin or raise
    # @return the descriptor
    def fileno(self) -> int:
        return self._require_socket().fileno()

    ## True if a datagram is already waiting, without consuming it
    # @param timeout seconds to wait for one to arrive
    def pending(self, timeout: float = 0.0) -> bool:
        sock = self._require_socket()
        try:
            readable, _, _ = select.select([sock], [], [], timeout)
        except OSError as ex:
            raise WpaCtrlConnectionError(f"select on {self._path}: {ex}") from ex
        return bool(readable)

    def _require_socket(self) -> socket.socket:
        if self._socket is None:
            raise WpaCtrlConnectionError(f"{self._path} is not open")
        return self._socket

    @staticmethod
    def _unlink(path: Optional[str]):
        if not path:
            return
        try:
            os.unlink(path)
        except OSError:
            # Never existed, or someone else cleaned up - either is fine
            pass


## Seconds remaining until a deadline, never negative
def remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())
