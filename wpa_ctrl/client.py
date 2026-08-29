## @package wpa_ctrl.client
#
# The wpa_supplicant control interface, as documented in
# doc/ctrl_iface.doxygen, spoken directly over its UNIX datagram socket.
#
# Stdlib only: no third-party dependencies, and nothing to build.
#
# @file client.py

import logging
import time
from typing import Dict, List, NamedTuple, Optional

from .errors import WpaCtrlCommandFailed, WpaCtrlTimeout
from .events import Event, is_event, parse_event
from .transport import (
    DEFAULT_CLIENT_DIR,
    DEFAULT_CTRL_DIR,
    DEFAULT_TIMEOUT,
    CtrlTransport,
    interface_path,
    remaining,
)

logger = logging.getLogger(__name__)

## Replies that mean "did as asked" and "would not"
REPLY_OK = "OK"
REPLY_FAIL = "FAIL"
REPLY_PONG = "PONG"
REPLY_UNKNOWN = "UNKNOWN COMMAND"


## One row of LIST_NETWORKS
class Network(NamedTuple):
    id: int
    ssid: str
    bssid: str
    flags: str

    ## True for the network wpa_supplicant is currently associated with
    @property
    def current(self) -> bool:
        return "[CURRENT]" in self.flags

    ## True for a network that has been administratively disabled
    @property
    def disabled(self) -> bool:
        return "[DISABLED]" in self.flags


## One row of SCAN_RESULTS
class ScanResult(NamedTuple):
    bssid: str
    frequency: int
    signal_level: int
    flags: str
    ssid: str


## One row of the PMKSA cache
class PmksaEntry(NamedTuple):
    index: int
    aa: str
    pmkid: str
    expiration: int
    opportunistic: int


## Wrap a value in the quotes wpa_supplicant expects for string network
#  variables (ssid, psk, identity, ...), escaping what it cannot take raw
# @param value the string to quote
# @return the quoted form, ready for SET_NETWORK
def quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


## Parse a variable=value block (STATUS, MIB, BSS, ...) into a dict.
#  Lines without an "=" are skipped rather than guessed at
# @param reply the raw reply text
# @return the parsed pairs, in the order wpa_supplicant sent them
def parse_variables(reply: str) -> Dict[str, str]:
    variables = {}
    for line in reply.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            variables[key] = value
    return variables


## Parse a tab-separated table with a header line (LIST_NETWORKS,
#  SCAN_RESULTS). The header is discarded: the column order is fixed by the
#  interface, and the header text has changed between releases
# @param reply the raw reply text
# @param columns how many fields each row must have
# @return one list of fields per row
def parse_table(reply: str, columns: int) -> List[List[str]]:
    rows = []
    for line in reply.splitlines()[1:]:
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < columns:
            logger.debug(f"Ignoring short row: {line!r}")
            continue
        # wpa_supplicant escapes control characters on the way out, so a
        # separator inside the last field should not reach us - but if one
        # does, rejoining it costs nothing and truncating a name is worse
        rows.append(fields[:columns - 1] + ["\t".join(fields[columns - 1:])])
    return rows


## A connection to one wpa_supplicant (or hostapd) control socket.
#
#  Every documented command has a method. Anything not covered - a newer
#  command, or a hostapd-only one - goes through request().
#
#  Commands that answer OK/FAIL raise WpaCtrlCommandFailed when refused;
#  use try_command() where a refusal is an expected outcome rather than an
#  error. Nothing here retries: the caller knows whether a repeat is safe.
class WpaCtrl:

    ## @param ifname interface to talk to, e.g. wlan0. Ignored when path is
    #         given
    #  @param ctrl_dir where wpa_supplicant keeps its interface sockets
    #  @param path a control socket path, for the global socket (-g) or a
    #         non-standard location
    #  @param client_dir writable directory for this client's own socket
    #  @param timeout default seconds to wait for a reply
    def __init__(self, ifname: str = None, ctrl_dir: str = DEFAULT_CTRL_DIR,
                 path: str = None, client_dir: str = DEFAULT_CLIENT_DIR,
                 timeout: float = DEFAULT_TIMEOUT):
        if path is None:
            if ifname is None:
                raise ValueError("one of ifname or path is required")
            path = interface_path(ifname, ctrl_dir)
        self._transport = CtrlTransport(path, client_dir=client_dir, timeout=timeout)
        self._timeout = timeout
        self._attached = False
        self._events: List[Event] = []

    @property
    def path(self) -> str:
        return self._transport.path

    @property
    def attached(self) -> bool:
        return self._attached

    def open(self) -> 'WpaCtrl':
        self._transport.open()
        return self

    def close(self):
        self._transport.close()
        self._attached = False
        self._events = []

    def __enter__(self) -> 'WpaCtrl':
        return self.open()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    # ------------------------------------------------------------------
    # Sending commands
    # ------------------------------------------------------------------

    ## Send a command and return its reply verbatim.
    #
    #  Unsolicited events arriving while we wait are set aside for
    #  next_event() rather than mistaken for the reply - which is what
    #  makes a single attached connection usable for both, as wpa_cli does.
    # @param command the command text
    # @param timeout seconds to wait, or the connection default
    # @return the reply, trailing newline removed
    def request(self, command: str, timeout: float = None) -> str:
        if timeout is None:
            timeout = self._timeout
        self._transport.open()
        self._transport.send(command)
        deadline = time.monotonic() + timeout
        while True:
            reply = self._transport.receive(remaining(deadline))
            if not is_event(reply):
                return reply.rstrip("\n")
            self._events.append(parse_event(reply))
            if remaining(deadline) <= 0:
                raise WpaCtrlTimeout(f"{command!r}: only events arrived")

    ## Send a command that answers OK or FAIL
    # @param command the command text
    # @return None
    def command(self, command: str, timeout: float = None):
        reply = self.request(command, timeout)
        if reply.strip() != REPLY_OK:
            raise WpaCtrlCommandFailed(command, reply)

    ## Send a command that answers OK or FAIL, where FAIL is an answer
    # @param command the command text
    # @return True if the reply was OK
    def try_command(self, command: str, timeout: float = None) -> bool:
        return self.request(command, timeout).strip() == REPLY_OK

    # ------------------------------------------------------------------
    # Unsolicited events
    # ------------------------------------------------------------------

    ## Ask to receive unsolicited event messages on this connection
    def attach(self):
        self.command("ATTACH")
        self._attached = True

    ## Stop receiving unsolicited event messages
    def detach(self):
        self.command("DETACH")
        self._attached = False

    ## True if an event is already waiting
    # @param timeout seconds to wait for one
    def pending(self, timeout: float = 0.0) -> bool:
        return bool(self._events) or self._transport.pending(timeout)

    ## Take the next event
    # @param timeout seconds to wait for one to arrive
    # @return the event, or None if none arrived in time
    def next_event(self, timeout: float = 0.0) -> Optional[Event]:
        if self._events:
            return self._events.pop(0)
        deadline = time.monotonic() + timeout
        while True:
            if not self._transport.pending(remaining(deadline)):
                return None
            message = self._transport.receive(remaining(deadline))
            if is_event(message):
                return parse_event(message)
            # A reply with no outstanding request: nothing sane to do with
            # it, and dropping it keeps the event stream honest
            logger.debug(f"Discarding unsolicited reply: {message!r}")
            if remaining(deadline) <= 0:
                return None

    # ------------------------------------------------------------------
    # Status and control
    # ------------------------------------------------------------------

    ## Check the daemon is answering
    # @return True if it replied PONG
    def ping(self) -> bool:
        return self.request("PING").strip() == REPLY_PONG

    ## Request the dot1x/dot11 MIB variables
    def mib(self) -> Dict[str, str]:
        return parse_variables(self.request("MIB"))

    ## Current WPA/EAPOL/EAP status
    # @param verbose ask for STATUS-VERBOSE, which adds more variables
    def status(self, verbose: bool = False) -> Dict[str, str]:
        return parse_variables(self.request("STATUS-VERBOSE" if verbose else "STATUS"))

    ## The PMKSA cache
    def pmksa(self) -> List[PmksaEntry]:
        entries = []
        for line in self.request("PMKSA").splitlines()[1:]:
            fields = [field.strip() for field in line.split("/")]
            if len(fields) < 5:
                continue
            entries.append(PmksaEntry(int(fields[0]), fields[1], fields[2],
                                      int(fields[3]), int(fields[4])))
        return entries

    ## Set a global variable, e.g. EAPOL::heldPeriod
    def set(self, variable: str, value: str):
        self.command(f"SET {variable} {value}")

    ## IEEE 802.1X EAPOL state machine logon
    def logon(self):
        self.command("LOGON")

    ## IEEE 802.1X EAPOL state machine logoff
    def logoff(self):
        self.command("LOGOFF")

    ## Force reassociation
    def reassociate(self):
        self.command("REASSOCIATE")

    ## Connect if currently disconnected
    def reconnect(self):
        self.command("RECONNECT")

    ## Start pre-authentication with a BSSID
    def preauth(self, bssid: str):
        self.command(f"PREAUTH {bssid}")

    ## Change the daemon's debug level
    def level(self, debug_level: int):
        self.command(f"LEVEL {debug_level}")

    ## Make wpa_supplicant re-read its configuration file
    def reconfigure(self):
        self.command("RECONFIGURE")

    ## Terminate the wpa_supplicant process
    def terminate(self):
        self.command("TERMINATE")

    ## Disconnect and stay disconnected until reassociate() or reconnect()
    def disconnect(self):
        self.command("DISCONNECT")

    ## Request a new scan. The results arrive later - wait for a
    #  CTRL-EVENT-SCAN-RESULTS event, or poll scan_results()
    def scan(self):
        self.command("SCAN")

    ## The latest scan results
    def scan_results(self) -> List[ScanResult]:
        results = []
        for row in parse_table(self.request("SCAN_RESULTS"), 5):
            try:
                results.append(ScanResult(row[0], int(row[1]), int(row[2]),
                                          row[3], row[4]))
            except ValueError:
                logger.debug(f"Ignoring unparsable scan row: {row!r}")
        return results

    ## Detailed results for one BSS.
    # @param selector a BSSID, an index, FIRST, or NEXT-<bssid>
    # @return the BSS variables, empty if there is no such BSS
    def bss(self, selector) -> Dict[str, str]:
        return parse_variables(self.request(f"BSS {selector}"))

    ## Set the interface's scanning mode
    def ap_scan(self, value: int):
        self.command(f"AP_SCAN {value}")

    ## Driver capabilities for one option (eap, pairwise, group, key_mgmt,
    #  proto, auth_alg, ...)
    # @param option which capability to report
    # @param strict list only what the driver actually reports
    # @return the capability values
    def get_capability(self, option: str, strict: bool = False) -> List[str]:
        command = f"GET_CAPABILITY {option}"
        if strict:
            command += " strict"
        return self.request(command).split()

    ## Interfaces this wpa_supplicant has. Most useful on the global socket
    def interfaces(self) -> List[str]:
        return [line for line in self.request("INTERFACES").splitlines() if line]

    # ------------------------------------------------------------------
    # Networks
    # ------------------------------------------------------------------

    ## The configured networks
    def list_networks(self) -> List[Network]:
        networks = []
        for row in parse_table(self.request("LIST_NETWORKS"), 4):
            try:
                networks.append(Network(int(row[0]), row[1], row[2], row[3]))
            except ValueError:
                logger.debug(f"Ignoring unparsable network row: {row!r}")
        return networks

    ## Create a new, empty, disabled network
    # @return the new network's id
    def add_network(self) -> int:
        reply = self.request("ADD_NETWORK").strip()
        try:
            return int(reply)
        except ValueError:
            # from None: the ValueError is an implementation detail of
            # parsing, and the reply it choked on is already in the message
            raise WpaCtrlCommandFailed("ADD_NETWORK", reply) from None

    ## Remove a network, or "all"
    def remove_network(self, network_id):
        self.command(f"REMOVE_NETWORK {network_id}")

    ## Set one variable on a network
    # @param network_id which network
    # @param variable the variable name, e.g. ssid or psk
    # @param value the value
    # @param quoted wrap the value in quotes, as string variables need
    def set_network(self, network_id, variable: str, value: str,
                    quoted: bool = False):
        self.command(f"SET_NETWORK {network_id} {variable} "
                     f"{quote(value) if quoted else value}")

    ## Read one variable back from a network
    def get_network(self, network_id, variable: str) -> str:
        return self.request(f"GET_NETWORK {network_id} {variable}").strip()

    ## Enable a network, or "all"
    def enable_network(self, network_id):
        self.command(f"ENABLE_NETWORK {network_id}")

    ## Disable a network, or "all"
    def disable_network(self, network_id):
        self.command(f"DISABLE_NETWORK {network_id}")

    ## Select a network, disabling the others
    def select_network(self, network_id):
        self.command(f"SELECT_NETWORK {network_id}")

    ## Set the preferred BSSID for a network
    def bssid(self, network_id, bssid: str):
        self.command(f"BSSID {network_id} {bssid}")

    ## Write the running configuration back to the config file
    def save_config(self):
        self.command("SAVE_CONFIG")

    # ------------------------------------------------------------------
    # Wi-Fi Direct (P2P)
    # ------------------------------------------------------------------

    ## Start P2P device discovery
    # @param duration seconds to search for, or indefinitely if omitted
    # @param type_ "social" or "progressive" to limit the channels searched
    def p2p_find(self, duration: int = None, type_: str = None):
        command = "P2P_FIND"
        if duration is not None:
            command += f" {duration}"
        if type_ is not None:
            command += f" type={type_}"
        self.command(command)

    ## Stop an ongoing P2P discovery
    def p2p_stop_find(self):
        self.command("P2P_STOP_FIND")

    ## Start group formation with a discovered peer
    # @param address the peer's P2P device address
    # @param method pbc, or the PIN to use
    # @param extra further arguments, e.g. display, keypad, persistent, join
    # @return the interface the group will use, per the reply
    def p2p_connect(self, address: str, method: str, *extra) -> str:
        command = " ".join(["P2P_CONNECT", address, method] + list(extra))
        return self.request(command).strip()

    ## Listen for P2P peers
    # @param duration seconds to listen for
    def p2p_listen(self, duration: int = None):
        command = "P2P_LISTEN"
        if duration is not None:
            command += f" {duration}"
        self.command(command)

    ## Tear down a P2P group
    # @param ifname the group interface
    def p2p_group_remove(self, ifname: str):
        self.command(f"P2P_GROUP_REMOVE {ifname}")

    ## Become a group owner without negotiating with a peer
    # @param persistent restart this persistent group's network id
    # @param freq the frequency to operate on
    def p2p_group_add(self, persistent=None, freq: int = None):
        command = "P2P_GROUP_ADD"
        if persistent is not None:
            command += " persistent" if persistent is True else f" persistent={persistent}"
        if freq is not None:
            command += f" freq={freq}"
        self.command(command)

    ## Ask a peer which configuration method it wants
    # @param address the peer's P2P device address
    # @param method display, keypad or pbc
    def p2p_prov_disc(self, address: str, method: str):
        self.command(f"P2P_PROV_DISC {address} {method}")

    ## The passphrase of the group this device owns
    def p2p_get_passphrase(self) -> str:
        return self.request("P2P_GET_PASSPHRASE").strip()

    ## Schedule a service discovery request
    # @param address the peer, or 00:00:00:00:00:00 to ask every peer
    # @param query the Service Query TLVs as a hexdump, or "upnp <version>
    #        <search target>"
    # @return the identifier for cancelling the request
    def p2p_serv_disc_req(self, address: str, query: str) -> str:
        return self.request(f"P2P_SERV_DISC_REQ {address} {query}").strip()

    ## Cancel a pending service discovery request
    def p2p_serv_disc_cancel_req(self, request_id: str):
        self.command(f"P2P_SERV_DISC_CANCEL_REQ {request_id}")

    ## Reply to a service discovery request
    def p2p_serv_disc_resp(self, freq: int, address: str, dialog_token: str,
                           tlvs: str):
        self.command(f"P2P_SERV_DISC_RESP {freq} {address} {dialog_token} {tlvs}")

    ## Note that the local service database has changed
    def p2p_service_update(self):
        self.command("P2P_SERVICE_UPDATE")

    ## Hand service discovery over to an external program, or take it back
    # @param external 1 to hand over, 0 to handle it internally
    def p2p_serv_disc_external(self, external: int):
        self.command(f"P2P_SERV_DISC_EXTERNAL {external}")

    ## Reject and block a peer's connection attempts
    def p2p_reject(self, address: str):
        self.command(f"P2P_REJECT {address}")

    ## Invite a peer to a group, or restart a persistent group
    # @param group the group interface to invite to
    # @param peer the peer to invite
    # @param persistent the persistent group's network id to restart
    def p2p_invite(self, group: str = None, peer: str = None, persistent=None):
        command = "P2P_INVITE"
        if persistent is not None:
            command += f" persistent={persistent}"
        if group is not None:
            command += f" group={group}"
        if peer is not None:
            command += f" peer={peer}"
        self.command(command)

    ## Information about a discovered peer
    # @param selector the peer's address, FIRST, or NEXT-<address>
    # @return the peer's variables, empty if there is no such peer
    def p2p_peer(self, selector: str) -> Dict[str, str]:
        return parse_variables(self.request(f"P2P_PEER {selector}"))

    ## Extended listen timing. Called with neither argument, it turns the
    #  extended listen state off
    # @param period milliseconds to listen for in each interval
    # @param interval milliseconds between listen periods
    def p2p_ext_listen(self, period: int = None, interval: int = None):
        command = "P2P_EXT_LISTEN"
        if period is not None and interval is not None:
            command += f" {period} {interval}"
        self.command(command)

    # ------------------------------------------------------------------
    # Present in wpa_supplicant, absent from ctrl_iface.doxygen. Widely
    # used, and the document has not kept pace with the daemon
    # ------------------------------------------------------------------

    ## Signal strength of the current connection
    def signal_poll(self) -> Dict[str, str]:
        return parse_variables(self.request("SIGNAL_POLL"))

    ## How many scans a BSS may go unseen before it is dropped from the
    #  scan results cache
    def bss_expire_count(self, count: int):
        self.command(f"BSS_EXPIRE_COUNT {count}")
