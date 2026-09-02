## @package wpa_ctrl.replies
#
# What the daemon's replies parse into: the row and block types, and the
# two parsers that read them.
#
# The types keep everything the daemon sent - the dict subclasses stay
# dicts, unknown fields included - with typed properties over the fields
# worth typing, so a field added upstream is visible rather than discarded.
#
# @file replies.py

import logging
from typing import Dict, List, NamedTuple, Optional

from .security import Security, parse_security
from .ssid import _HEX_DIGITS, Ssid

logger = logging.getLogger(__name__)


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

    ## The SSID as the octet string it configures. LIST_NETWORKS prints
    #  the name printf-escaped like a scan result does, so ssid holds the
    #  wire's escaped ASCII - and matching a configured network against a
    #  scanned or associated one is an octets comparison, not a text one
    @property
    def ssid_bytes(self) -> 'Ssid':
        return Ssid.from_printf(self.ssid)

    ## The SSID as text when its bytes are UTF-8, None when they are
    #  not - see Ssid.text
    @property
    def ssid_text(self) -> Optional[str]:
        return self.ssid_bytes.text

## Field-selection bits for the BSS command's MASK= argument.
#
#  The values come from src/common/wpa_ctrl.h in hostap, like the event
#  names, and for the same reason: they are what the daemon reads off the
#  wire, so no other values would work. hostap's notice is in NOTICE.
#
#  Generated from hostap 2_12-bp-305-g168f9755d9d0. A daemon ignores bits
#  it does not know, so a stale list costs a caller a constant rather than
#  a wrong reply
class BssMask:
    ID = 0x00000001
    BSSID = 0x00000002
    FREQ = 0x00000004
    BEACON_INT = 0x00000008
    CAPABILITIES = 0x00000010
    QUAL = 0x00000020
    NOISE = 0x00000040
    LEVEL = 0x00000080
    TSF = 0x00000100
    AGE = 0x00000200
    IE = 0x00000400
    FLAGS = 0x00000800
    SSID = 0x00001000
    WPS_SCAN = 0x00002000
    P2P_SCAN = 0x00004000
    INTERNETW = 0x00008000
    WIFI_DISPLAY = 0x00010000
    ## Not a field: asks for "====" between entries in a multi-BSS reply,
    #  which is why ALL leaves it out
    DELIM = 0x00020000
    MESH_SCAN = 0x00040000
    SNR = 0x00080000
    EST_THROUGHPUT = 0x00100000
    FST = 0x00200000
    UPDATE_IDX = 0x00400000
    BEACON_IE = 0x00800000
    FILS_INDICATION = 0x01000000
    RNR = 0x02000000
    ML = 0x04000000
    AP_MLD_ADDR = 0x08000000
    ## Every field bit, as wpa_ctrl.h spells it: everything except DELIM.
    #  The daemon also reads a mask of 0 as this
    ALL = 0xFFFDFFFF

## One row of SCAN_RESULTS
class ScanResult(NamedTuple):
    bssid: str
    frequency: int
    signal_level: int
    flags: str
    ssid: str

    ## What this BSS advertises, parsed from flags
    @property
    def security(self) -> Security:
        return parse_security(self.flags)

    ## The SSID as the octet string the air carried. ssid holds the wire's
    #  escaped ASCII, which matches against itself and nothing else
    @property
    def ssid_bytes(self) -> Ssid:
        return Ssid.from_printf(self.ssid)

    ## The SSID as text when its bytes are UTF-8, None when they are
    #  not - see Ssid.text
    @property
    def ssid_text(self) -> Optional[str]:
        return self.ssid_bytes.text


## Shared base of the variable-block types - the replies (Status, Bss,
#  SignalPoll) and the typed event views: a dict of exactly what the
#  daemon sent, with the int parsing the typed properties share. A
#  property answers None for a field that was not reported, and raises
#  ValueError for one that is present but not in the daemon's own format
class _Variables(Dict[str, str]):

    def _int(self, key: str, base: int = 10) -> Optional[int]:
        value = self.get(key)
        return None if value is None else int(value, base)


## The daemon's "no reading" sentinel: WPA_INVALID_NOISE in driver.h.
#  SIGNAL_POLL spells an unknown noise floor as NOISE=9999 and an unknown
#  RSSI as RSSI=-9999, neither being a level any radio could report
_INVALID_NOISE = 9999


## The SIGNAL_POLL reply: the current association's signal, typed.
#
#  RSSI, LINKSPEED, NOISE and FREQUENCY are always present in a
#  successful reply - the daemon prints all four in one block - so a
#  caller never sees some of them missing. What it sees instead, when
#  there is no association to measure, is FAIL for the whole command,
#  which parses to an empty SignalPoll whose every property is None.
#  WIDTH, the center frequencies and the averages are genuinely
#  conditional: absent when the driver does not report them
class SignalPoll(_Variables):

    ## dBm. None for the daemon's -9999, which means "no reading", not a
    #  signal 9999 dB below a milliwatt
    @property
    def rssi(self) -> Optional[int]:
        value = self._int("RSSI")
        return None if value == -_INVALID_NOISE else value

    ## Mbps
    @property
    def linkspeed(self) -> Optional[int]:
        return self._int("LINKSPEED")

    ## dBm. None for the daemon's 9999, which means the driver cannot
    #  measure the noise floor, not a floor of +9999 dBm
    @property
    def noise(self) -> Optional[int]:
        value = self._int("NOISE")
        return None if value == _INVALID_NOISE else value

    ## MHz
    @property
    def frequency(self) -> Optional[int]:
        return self._int("FREQUENCY")

    ## The channel width as the daemon spells it, e.g. "80 MHz"
    @property
    def width(self) -> Optional[str]:
        return self.get("WIDTH")

    ## MHz
    @property
    def center_frq1(self) -> Optional[int]:
        return self._int("CENTER_FRQ1")

    ## MHz
    @property
    def center_frq2(self) -> Optional[int]:
        return self._int("CENTER_FRQ2")

    ## dBm
    @property
    def avg_rssi(self) -> Optional[int]:
        return self._int("AVG_RSSI")

    ## dBm
    @property
    def avg_beacon_rssi(self) -> Optional[int]:
        return self._int("AVG_BEACON_RSSI")


## The STATUS reply: the variable=value block as a dict, with the SSID
#  octet accessors.
#
#  A dict subclass like Bss and for the same reason - the block is
#  open-ended, and what STATUS-VERBOSE or a newer daemon adds should be
#  visible rather than discarded. The ssid field is printed through
#  wpa_ssid_txt() like everything else's, so it is the wire's escaped
#  ASCII; matching it against a config file's ssid= is an octets
#  comparison, Ssid.from_printf() against Ssid.from_config()
class Status(_Variables):

    ## The SSID as the octet string the air carried - see
    #  ScanResult.ssid_bytes. None when there is no ssid field, i.e. not
    #  associated
    @property
    def ssid_bytes(self) -> Optional[Ssid]:
        value = self.get("ssid")
        return None if value is None else Ssid.from_printf(value)

    ## The SSID as text when its bytes are UTF-8, None when they are
    #  not - see Ssid.text
    @property
    def ssid_text(self) -> Optional[str]:
        value = self.ssid_bytes
        return None if value is None else value.text


## One BSS, as the BSS command reports it.
#
#  A dict rather than a fixed record, because the block is open-ended: the
#  MASK= argument decides which fields are present, and upstream adds
#  fields without ceremony, so a fixed shape would either discard the
#  unknown ones or forever chase them. Every field the daemon sent is here
#  under its wire name; the properties type the ones worth typing, spelled
#  as ScanResult spells them - frequency and signal_level, not the wire's
#  freq and level - so the two report the same thing under the same name.
#
#  A property answers None for a field that was not reported. Absent
#  means "not asked for" or "daemon predates it", and must not read as a
#  value - the mask decides what is present, so with anything but ALL most
#  of these are None by construction. A field that is present but not in
#  the daemon's own format raises ValueError instead: that is not a BSS
#  variation, it is a reply this parser does not understand.
#
#  Deliberately without properties: the anqp_* and hs20_* fields, which are
#  hexdumps like ie (bytes.fromhex applies) but Interworking-specialist and
#  partly dynamically named - anqp[<info-id>] cannot be a property at all.
#  The wps_* fields are already the strings they look like. The RNR and ML
#  masks produce prose lines rather than variables; they land in the dict
#  under whatever precedes their first "=", unlovely but not lost
class Bss(_Variables):

    ## The daemon's id for this entry, stable while the entry lives -
    #  which is what iter_bss() walks on
    @property
    def id(self) -> Optional[int]:
        return self._int("id")

    @property
    def bssid(self) -> Optional[str]:
        return self.get("bssid")

    ## MHz, from the wire's freq field
    @property
    def frequency(self) -> Optional[int]:
        return self._int("freq")

    ## dBm, from the wire's level field
    @property
    def signal_level(self) -> Optional[int]:
        return self._int("level")

    @property
    def noise(self) -> Optional[int]:
        return self._int("noise")

    @property
    def snr(self) -> Optional[int]:
        return self._int("snr")

    @property
    def qual(self) -> Optional[int]:
        return self._int("qual")

    ## Seconds since the daemon last saw this BSS
    @property
    def age(self) -> Optional[int]:
        return self._int("age")

    ## TUs, from the beacon_int field
    @property
    def beacon_interval(self) -> Optional[int]:
        return self._int("beacon_int")

    ## The 802.11 capability field, reported as hex on the wire
    @property
    def capabilities(self) -> Optional[int]:
        return self._int("capabilities", 16)

    @property
    def tsf(self) -> Optional[int]:
        return self._int("tsf")

    ## kbps, from the est_throughput field
    @property
    def est_throughput(self) -> Optional[int]:
        return self._int("est_throughput")

    ## The BSS table's update counter when this entry last changed -
    #  compare across fetches to see whether an entry moved
    @property
    def update_idx(self) -> Optional[int]:
        return self._int("update_idx")

    ## The AP MLD address, present when the BSS is a link of an 802.11be
    #  multi-link device
    @property
    def ap_mld_addr(self) -> Optional[str]:
        return self.get("ap_mld_addr")

    @property
    def ssid(self) -> Optional[str]:
        return self.get("ssid")

    ## The SSID as the octet string the air carried - see
    #  ScanResult.ssid_bytes
    @property
    def ssid_bytes(self) -> Optional[Ssid]:
        value = self.get("ssid")
        return None if value is None else Ssid.from_printf(value)

    ## The SSID as text when its bytes are UTF-8, None when they are not -
    #  see Ssid.text
    @property
    def ssid_text(self) -> Optional[str]:
        value = self.ssid_bytes
        return None if value is None else value.text

    @property
    def flags(self) -> Optional[str]:
        return self.get("flags")

    ## What this BSS advertises, parsed from flags - None when flags was
    #  not reported, because "not asked" must not read as "open network"
    @property
    def security(self) -> Optional[Security]:
        flags = self.get("flags")
        return None if flags is None else parse_security(flags)

    ## The probe response / beacon information elements, from their hexdump
    @property
    def ie(self) -> Optional[bytes]:
        value = self.get("ie")
        return None if value is None else bytes.fromhex(value)

    @property
    def beacon_ie(self) -> Optional[bytes]:
        value = self.get("beacon_ie")
        return None if value is None else bytes.fromhex(value)

    ## The concatenated Wi-Fi Display subelements, from their hexdump
    @property
    def wfd_subelems(self) -> Optional[bytes]:
        value = self.get("wfd_subelems")
        return None if value is None else bytes.fromhex(value)


## Whether text is a MAC address as the control interface spells one
def _is_address(text: str) -> bool:
    parts = text.split(":")
    return (len(parts) == 6
            and all(len(part) == 2 and part[0] in _HEX_DIGITS
                    and part[1] in _HEX_DIGITS for part in parts))


## Split an address-headed reply (STA, P2P_PEER): the daemon puts the MAC
#  alone on the first line and the variables under it. FAIL, UNKNOWN
#  COMMAND and an empty reply all mean "no such entry", and none of them
#  parse as an address, which is the one check that covers them all
# @param reply the raw reply text
# @return (address, variables), or (None, {}) when there is no entry
def _addressed_variables(reply: str):
    line, _, rest = reply.partition("\n")
    address = line.strip()
    if _is_address(address):
        return address, parse_variables(rest)
    return None, {}


## One station, as the STA commands report it - hostapd's bread and
#  butter, and wpa_supplicant answers the same commands in AP and mesh
#  modes.
#
#  A dict of whatever the daemon sent, like Bss and for the same reason.
#  The address rides as an attribute because the daemon does not send it
#  as a variable - it is the first line of the reply, alone - and
#  inventing an address= the wire never carried would misdescribe the
#  reply. Note the flags variable here speaks hostapd's station
#  vocabulary ([AUTH][ASSOC][AUTHORIZED]...), not the BSS one, so
#  parse_security does not apply
class Station(Dict[str, str]):

    def __init__(self, address: str, variables: Dict[str, str]):
        super().__init__(variables)
        self.address = address


## One P2P peer, as P2P_PEER reports it: the device address alone on the
#  first line, then variables (device_name, config_methods, ...). The
#  address rides as an attribute for the same reason as Station's
class P2pPeer(Dict[str, str]):

    def __init__(self, address: str, variables: Dict[str, str]):
        super().__init__(variables)
        self.address = address


## One row of the PMKSA cache
class PmksaEntry(NamedTuple):
    index: int
    aa: str
    pmkid: str
    expiration: int
    opportunistic: int
