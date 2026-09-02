## @package wpa_ctrl.client
#
# The wpa_supplicant control interface, as documented in
# doc/ctrl_iface.doxygen, spoken directly over its UNIX datagram socket.
#
# Stdlib only: no third-party dependencies, and nothing to build.
#
# The vocabulary this surface speaks lives in modules of its own - the
# reply types in replies, the flags reading in security, octet spelling in
# ssid, DPP parameter building in dpp - and the package re-exports all of
# it: import from wpa_ctrl, not from here. This module holds the
# connection and the commands.
#
# @file client.py

import logging
import time
from typing import Dict, Iterator, List, Optional

from .dpp import format_params
from .errors import WpaCtrlCommandFailed, WpaCtrlTimeout
from .events import Event, is_event, parse_event
from .replies import (
    Bss,
    BssMask,
    Network,
    P2pPeer,
    PmksaEntry,
    ScanResult,
    SignalPoll,
    Station,
    Status,
    _addressed_variables,
    parse_table,
    parse_variables,
)
from .ssid import quote
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

    ## The control socket's file descriptor, for driving this connection
    #  from an event loop instead of polling it.
    #
    #  Register it for read, and call next_event() when it fires, draining
    #  while pending() stays true - one readable socket can hold more than
    #  one datagram. Use a connection that is attached and does nothing
    #  else, so everything arriving is an event and nothing can be mistaken
    #  for a command's reply.
    #
    #  Unregister before close(), which closes the descriptor underneath a
    #  loop that is still watching it
    # @return the descriptor
    def fileno(self) -> int:
        return self._transport.fileno()

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
    def status(self, verbose: bool = False) -> Status:
        return Status(parse_variables(
            self.request("STATUS-VERBOSE" if verbose else "STATUS")))

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
    #
    #  The documented selectors are a BSSID and an index into the scan
    #  results; the daemon also takes ID-<id>, FIRST, LAST, NEXT-<id>,
    #  CURRENT and p2p_dev_addr=<addr>. Its RANGE= forms answer with
    #  several BSSes concatenated, which parse_variables would fold into
    #  one - use iter_bss() for the table, or request() for the raw text
    # @param selector which BSS
    # @param mask BssMask bits selecting the fields wanted; every field
    #        when omitted, and the daemon reads an explicit 0 the same way
    # @return the BSS variables, empty if there is no such BSS
    def bss(self, selector, mask: Optional[int] = None) -> Bss:
        command = f"BSS {selector}"
        if mask is not None:
            command += f" MASK={mask:#x}"
        return Bss(parse_variables(self.request(command)))

    ## Every BSS the daemon holds, in full - the iteration wpa_cli's
    #  all_bss performs: BSS FIRST, then BSS NEXT-<id> until the reply is
    #  empty.
    #
    #  Iterating is the point, not a convenience. A reply is one datagram,
    #  so asking for the whole table at once (BSS RANGE=ALL) is answered
    #  with as many BSSes as fit and no sign that the rest exist; walking
    #  by id gives each BSS a datagram of its own. Walking by id also
    #  holds the place properly - an index would slip when the table
    #  changes underneath the walk. What an expiry mid-walk costs instead
    #  is the tail: NEXT-<id> on an id that has just been dropped answers
    #  empty, indistinguishable from the end of the table.
    #
    #  A generator, because each BSS is a round trip of its own: a caller
    #  that finds what it wanted stops the commands too, and one that wants
    #  the whole table says list(wpa.iter_bss()). Nothing is sent until
    #  iteration begins, and nothing is held on the connection between
    #  steps, so other commands can run mid-walk
    # @param mask BssMask bits selecting the fields wanted; every field
    #        when omitted. ID is added when missing, since the walk is
    #        keyed on it
    # @return one Bss per BSS, in the daemon's id order
    def iter_bss(self, mask: Optional[int] = None) -> Iterator[Bss]:
        if mask is not None:
            mask |= BssMask.ID
        seen = set()
        selector = "FIRST"
        while True:
            info = self.bss(selector, mask=mask)
            bss_id = info.get("id")
            # An id seen twice would walk forever; a daemon answering NEXT
            # with the same BSS is broken, but looping on it is worse
            if bss_id is None or bss_id in seen:
                return
            seen.add(bss_id)
            yield info
            selector = f"NEXT-{bss_id}"

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

    ## Whether the build and driver can do one key management suite, e.g.
    #  before offering SAE on a device whose wpa_supplicant may predate it.
    #
    #  GET_CAPABILITY reports what is compiled in and what the driver admits
    #  to, which is the only honest answer available short of trying to
    #  associate
    # @param name the suite, as KeyMgmt spells it
    # @return True if it is on offer
    def supports_key_mgmt(self, name: str) -> bool:
        return name in self.get_capability("key_mgmt")

    ## Interfaces this wpa_supplicant has. Most useful on the global socket
    def interfaces(self) -> List[str]:
        return [line for line in self.request("INTERFACES").splitlines() if line]

    # ------------------------------------------------------------------
    # Networks
    # ------------------------------------------------------------------

    ## Parse LIST_NETWORKS rows, dropping what does not parse
    @staticmethod
    def _parse_networks(reply: str) -> List[Network]:
        networks = []
        for row in parse_table(reply, 4):
            try:
                networks.append(Network(int(row[0]), row[1], row[2], row[3]))
            except ValueError:
                logger.debug(f"Ignoring unparsable network row: {row!r}")
        return networks

    ## The configured networks - as many as fit one reply. A reply is one
    #  datagram, so a long list is cut short with no sign the rest exist;
    #  iter_networks() walks past that
    def list_networks(self) -> List[Network]:
        return self._parse_networks(self.request("LIST_NETWORKS"))

    ## Every configured network, however many there are.
    #
    #  The daemon's LAST_ID= continuation exists for exactly the truncation
    #  list_networks() suffers: ask again from the last id seen until a
    #  page brings nothing new. wpa_cli itself never continues - the
    #  feature is there for clients that do.
    #
    #  A generator like iter_bss(), and with the same guards: a page that
    #  brings no id not already seen ends the walk, which also covers a
    #  daemon old enough to answer the continuation with UNKNOWN COMMAND -
    #  such a daemon simply yields its first page and stops, which is
    #  every network it was ever going to show
    def iter_networks(self) -> Iterator[Network]:
        seen = set()
        command = "LIST_NETWORKS"
        while True:
            new = [network
                   for network in self._parse_networks(self.request(command))
                   if network.id not in seen]
            if not new:
                return
            for network in new:
                seen.add(network.id)
                yield network
            command = f"LIST_NETWORKS LAST_ID={new[-1].id}"

    ## One associated station, by MAC address. hostapd's command first,
    #  but wpa_supplicant answers it too in AP and mesh modes
    # @param address the station's MAC
    # @return the station, or None if no such station is associated
    def sta(self, address: str) -> Optional[Station]:
        found, variables = _addressed_variables(self.request(f"STA {address}"))
        return None if found is None else Station(found, variables)

    ## Every associated station - the iteration hostapd_cli's all_sta
    #  performs: STA-FIRST, then STA-NEXT <address> until the reply is
    #  empty. A generator like iter_bss(), with the same guards, one
    #  station per round trip
    def iter_stations(self) -> Iterator[Station]:
        seen = set()
        command = "STA-FIRST"
        while True:
            address, variables = _addressed_variables(self.request(command))
            if address is None or address in seen:
                return
            seen.add(address)
            yield Station(address, variables)
            command = f"STA-NEXT {address}"

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
    # @return the peer, or None if there is no such peer. The address is
    #         the reply's first line, which a plain variable parse would
    #         silently drop - it has no "=" - so this returns a P2pPeer
    #         that carries it
    def p2p_peer(self, selector: str) -> Optional[P2pPeer]:
        address, variables = _addressed_variables(
            self.request(f"P2P_PEER {selector}"))
        return None if address is None else P2pPeer(address, variables)

    ## Every P2P peer the device knows - the iteration wpa_cli's
    #  p2p_peers performs: P2P_PEER FIRST, then P2P_PEER NEXT-<address>
    #  until the daemon answers FAIL. A generator like iter_bss(), with
    #  the same guards, one peer per round trip
    def iter_p2p_peers(self) -> Iterator[P2pPeer]:
        seen = set()
        command = "P2P_PEER FIRST"
        while True:
            address, variables = _addressed_variables(self.request(command))
            if address is None or address in seen:
                return
            seen.add(address)
            yield P2pPeer(address, variables)
            command = f"P2P_PEER NEXT-{address}"

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
    # Device Provisioning Protocol, also known as Wi-Fi Easy Connect.
    #
    # The onboarding flow - configurator, bootstrap, listen, QR code,
    # authentication - is described in wpa_supplicant/README-DPP. The rest
    # of these are in the daemons' control interface command tables and
    # nowhere else; the README documents the happy path and not the
    # lifecycle, so stopping a listen or removing a bootstrap record is
    # taken from the source.
    #
    # Both daemons implement DPP. A few commands exist on only one side:
    # RECONFIG, CA_SET and CONF_SET are wpa_supplicant's, and the relay
    # controller pair is hostapd's.
    # ------------------------------------------------------------------

    ## Create a Configurator - the role that hands out credentials
    #  @param params curve, key, ... as DPP key=value parameters
    #  @return the new configurator's id
    def dpp_configurator_add(self, **params) -> int:
        return self._dpp_id("DPP_CONFIGURATOR_ADD", format_params(**params))

    ## The private key of a Configurator, for saving and restoring it
    def dpp_configurator_get_key(self, configurator_id) -> str:
        return self.request(f"DPP_CONFIGURATOR_GET_KEY {configurator_id}").strip()

    ## Change a Configurator's parameters
    def dpp_configurator_set(self, configurator_id, **params):
        self.command(f"DPP_CONFIGURATOR_SET {configurator_id} "
                     f"{format_params(**params)}")

    ## Remove a Configurator, or "all"
    def dpp_configurator_remove(self, configurator_id):
        self.command(f"DPP_CONFIGURATOR_REMOVE {configurator_id}")

    ## Configure this device using its own Configurator, rather than
    #  provisioning a separate Enrollee
    #  @param params conf, configurator and ssid, as DPP key=value
    #         parameters. ssid is a hexdump, not a quoted string
    def dpp_configurator_sign(self, **params):
        self.command(f"DPP_CONFIGURATOR_SIGN {format_params(**params)}")

    ## Generate a bootstrapping key and the information to publish it,
    #  typically as a QR code
    #  @param params type (qrcode, pkex, nfc-uri), mac, chan, key, ...
    #  @return the new bootstrap record's id
    def dpp_bootstrap_gen(self, **params) -> int:
        return self._dpp_id("DPP_BOOTSTRAP_GEN", format_params(**params))

    ## The URI to put in a QR code, for a bootstrap record we generated
    def dpp_bootstrap_get_uri(self, bootstrap_id) -> str:
        return self.request(f"DPP_BOOTSTRAP_GET_URI {bootstrap_id}").strip()

    ## What is known about a bootstrap record
    def dpp_bootstrap_info(self, bootstrap_id) -> Dict[str, str]:
        return parse_variables(self.request(f"DPP_BOOTSTRAP_INFO {bootstrap_id}"))

    ## Change a bootstrap record's parameters
    def dpp_bootstrap_set(self, bootstrap_id, **params):
        self.command(f"DPP_BOOTSTRAP_SET {bootstrap_id} {format_params(**params)}")

    ## Remove a bootstrap record, or "all"
    def dpp_bootstrap_remove(self, bootstrap_id):
        self.command(f"DPP_BOOTSTRAP_REMOVE {bootstrap_id}")

    ## Take in a peer's bootstrapping URI, as read from its QR code
    #  @param uri the URI, verbatim
    #  @return the id of the bootstrap record created for that peer
    def dpp_qr_code(self, uri: str) -> int:
        return self._dpp_id("DPP_QR_CODE", uri)

    ## Take in a peer's bootstrapping URI read over NFC
    def dpp_nfc_uri(self, uri: str) -> int:
        return self._dpp_id("DPP_NFC_URI", uri)

    ## NFC negotiated handover, request side
    def dpp_nfc_handover_req(self, uri: str) -> int:
        return self._dpp_id("DPP_NFC_HANDOVER_REQ", uri)

    ## NFC negotiated handover, select side
    def dpp_nfc_handover_sel(self, uri: str) -> int:
        return self._dpp_id("DPP_NFC_HANDOVER_SEL", uri)

    ## Wait on a frequency for a Configurator to start authentication.
    #  An Enrollee does this; the frequency is in MHz, so 2412 for 2.4 GHz
    #  channel 1
    #  @param freq the frequency to listen on, in MHz
    #  @param params role, netrole, qr, ... as DPP key=value parameters
    def dpp_listen(self, freq: int, **params):
        command = f"DPP_LISTEN {freq}"
        arguments = format_params(**params)
        self.command(f"{command} {arguments}" if arguments else command)

    ## Stop listening
    def dpp_stop_listen(self):
        self.command("DPP_STOP_LISTEN")

    ## Start authentication with a peer whose bootstrapping information we
    #  already have
    #  @param params peer, conf, ssid, configurator, pass_, ... as DPP
    #         key=value parameters. ssid and pass_ are hexdumps
    def dpp_auth_init(self, **params):
        self.command(f"DPP_AUTH_INIT {format_params(**params)}")

    ## Announce presence to a Configurator that is listening for chirps
    def dpp_chirp(self, **params):
        self.command(f"DPP_CHIRP {format_params(**params)}")

    ## Stop chirping
    def dpp_stop_chirp(self):
        self.command("DPP_STOP_CHIRP")

    ## Push-button bootstrapping, where the pairing is authorised by
    #  pressing a button on both devices at once
    def dpp_push_button(self, **params):
        arguments = format_params(**params)
        self.command(f"DPP_PUSH_BUTTON {arguments}" if arguments
                     else "DPP_PUSH_BUTTON")

    ## Ask for new credentials for a network already configured by DPP
    #  @param arguments the network id, and any parameters the daemon takes
    def dpp_reconfig(self, arguments: str):
        self.command(f"DPP_RECONFIG {arguments}")

    ## Add a PKEX bootstrapping record - the password-based alternative to
    #  scanning a QR code
    #  @param params own, identifier, init, code, ... as key=value
    #  @return the new bootstrap record's id
    def dpp_pkex_add(self, **params) -> int:
        return self._dpp_id("DPP_PKEX_ADD", format_params(**params))

    ## Remove a PKEX record, or "all"
    def dpp_pkex_remove(self, pkex_id):
        self.command(f"DPP_PKEX_REMOVE {pkex_id}")

    ## Listen for DPP over TCP rather than over the air
    def dpp_controller_start(self, **params):
        arguments = format_params(**params)
        self.command(f"DPP_CONTROLLER_START {arguments}" if arguments
                     else "DPP_CONTROLLER_START")

    ## Stop the TCP controller
    def dpp_controller_stop(self):
        self.command("DPP_CONTROLLER_STOP")

    ## Relay DPP frames to a Controller reached over TCP (hostapd)
    #  @param arguments the controller address, and its public key hash
    def dpp_relay_add_controller(self, arguments: str):
        self.command(f"DPP_RELAY_ADD_CONTROLLER {arguments}")

    ## Stop relaying to a Controller (hostapd)
    def dpp_relay_remove_controller(self, arguments: str):
        self.command(f"DPP_RELAY_REMOVE_CONTROLLER {arguments}")

    ## Set the certificate authority parameters used for DPP over TCP
    def dpp_ca_set(self, **params):
        self.command(f"DPP_CA_SET {format_params(**params)}")

    ## Set configuration parameters used when acting as a Configurator
    def dpp_conf_set(self, **params):
        self.command(f"DPP_CONF_SET {format_params(**params)}")

    ## Send a DPP command whose reply is an identifier, and return it.
    #  A refusal comes back as FAIL rather than a number
    def _dpp_id(self, command: str, arguments: str) -> int:
        full = f"{command} {arguments}" if arguments else command
        reply = self.request(full).strip()
        try:
            return int(reply)
        except ValueError:
            raise WpaCtrlCommandFailed(full, reply) from None

    # ------------------------------------------------------------------
    # Present in wpa_supplicant, absent from ctrl_iface.doxygen. Widely
    # used, and the document has not kept pace with the daemon
    # ------------------------------------------------------------------

    ## Signal strength of the current connection. Not associated answers
    #  FAIL, which parses to an empty SignalPoll - every property None
    def signal_poll(self) -> SignalPoll:
        return SignalPoll(parse_variables(self.request("SIGNAL_POLL")))

    ## How many scans a BSS may go unseen before it is dropped from the
    #  scan results cache
    def bss_expire_count(self, count: int):
        self.command(f"BSS_EXPIRE_COUNT {count}")
