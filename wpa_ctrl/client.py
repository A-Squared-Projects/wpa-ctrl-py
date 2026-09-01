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
from typing import Dict, FrozenSet, Iterator, List, NamedTuple, Optional

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


## Key management suites, spelled the way the key_mgmt network variable and
#  GET_CAPABILITY key_mgmt spell them.
#
#  Scan results use a different, shorter vocabulary for the same things - an
#  AP offering WPA-PSK advertises it as PSK - so these are not the names
#  Security.key_mgmt reports. Use these when configuring a network, and the
#  Security predicates when reading what an AP offers
class KeyMgmt:
    NONE = "NONE"
    WPA_PSK = "WPA-PSK"
    WPA_EAP = "WPA-EAP"
    IEEE8021X = "IEEE8021X"
    SAE = "SAE"
    FT_PSK = "FT-PSK"
    FT_EAP = "FT-EAP"
    FT_SAE = "FT-SAE"
    OWE = "OWE"
    DPP = "DPP"


## The kind of network a DPP Configurator hands to an Enrollee, i.e. the
#  conf= parameter of DPP_CONFIGURATOR_PARAMS and DPP_PKEX_ADD.
#
#  The choice decides which AKMs the provisioned network offers, and a
#  wrong one is not reported anywhere: an Enrollee given sta-psk simply
#  associates over WPA2 against an access point that would have offered
#  SAE, and stays there, because a stored network is never rewritten
class DppConf:
    STA_PSK = "sta-psk"
    STA_SAE = "sta-sae"
    ## Both, for an access point in transition mode - and for one that is
    ## not, since the Enrollee uses whichever is offered
    STA_PSK_SAE = "sta-psk-sae"
    STA_DPP = "sta-dpp"
    STA_SAE_DPP = "sta-sae-dpp"
    STA_PSK_SAE_DPP = "sta-psk-sae-dpp"
    STA_DOT1X = "sta-dot1x"
    AP_PSK = "ap-psk"
    AP_SAE = "ap-sae"
    AP_PSK_SAE = "ap-psk-sae"
    AP_DPP = "ap-dpp"


## Hex-encode a string the way DPP carries SSIDs and passphrases.
#
#  Not a convenience. The control interface takes these fields as hex, and
#  supplying anything else fails silently in the worst way: the command is
#  accepted, and the exchange is built and torn down later with no event and
#  no log line to say why
# @param text the value to encode
# @return its hex encoding
# @raises ValueError if there is nothing to encode, since an empty field is
#         accepted by the daemon and produces exactly that silent failure
def dpp_hex(text: str) -> str:
    if not text:
        raise ValueError("DPP fields cannot be empty; an empty one is "
                         "accepted and then fails silently")
    return text.encode().hex()


## The global operating classes for 5 GHz, as (class, first channel, last)
#
#  Only the global classes are listed. A URI is read by whatever scans it,
#  which may be in another regulatory domain, so a class that means
#  different things in different places would be worse than none
_FIVE_GHZ_CLASSES = ((115, 36, 48), (118, 52, 64), (121, 100, 144),
                     (125, 149, 177))


## The channel a DPP bootstrapping URI advertises, as "operating-class/channel".
#
#  A peer announces itself on the channel its own URI names, so a listener
#  anywhere else hears nothing at all - a failure indistinguishable from a
#  peer that never announced
# @param frequency in MHz
# @return the channel spec, or None for a frequency that has no global
#         operating class here
def dpp_channel(frequency: int) -> Optional[str]:
    if 2412 <= frequency <= 2472 and (frequency - 2412) % 5 == 0:
        return f"81/{(frequency - 2412) // 5 + 1}"
    if frequency == 2484:
        return "82/14"
    if 5180 <= frequency <= 5885 and (frequency - 5180) % 5 == 0:
        channel = (frequency - 5000) // 5
        for operating_class, low, high in _FIVE_GHZ_CLASSES:
            if low <= channel <= high:
                return f"{operating_class}/{channel}"
    return None


## Build the parameters describing the network to hand over.
#
#  Used both as the value of the dpp_configurator_params variable and as
#  part of DPP_PKEX_ADD, which is why it is a string rather than a call.
#
#  The passphrase and psk arguments are not interchangeable. SAE derives
#  from the passphrase itself, so a passphrase can serve WPA2 and WPA3
#  while a derived 64-character key can only ever serve WPA2 - and only the
#  passphrase is hex-encoded, the key being hex already
# @param conf one of DppConf
# @param ssid the network name, encoded here
# @param passphrase the passphrase, encoded here
# @param psk a 64-character hex key, passed through
# @param configurator the configurator id to sign with
# @param extra any further parameters, e.g. expiry or a group id
# @return the parameter string
# @raises ValueError if neither or both secrets are given, or if a psk is
#         not a plausible derived key
def dpp_configurator_params(conf: str, ssid: str, passphrase: str = None,
                            psk: str = None, configurator=None,
                            **extra) -> str:
    if (passphrase is None) == (psk is None):
        raise ValueError("supply exactly one of passphrase or psk")
    if psk is not None and (len(psk) != 64
                            or any(c not in "0123456789abcdefABCDEF"
                                   for c in psk)):
        raise ValueError("psk must be 64 hex characters; pass a passphrase "
                         "as passphrase=")
    secret = {"pass": dpp_hex(passphrase)} if passphrase else {"psk": psk}
    return format_params(conf=conf, ssid=dpp_hex(ssid), **secret,
                         configurator=configurator, **extra)


## Values for the ieee80211w network variable, which selects management frame
#  protection. SAE requires it, and WPA2 predates it, so a network that has to
#  work with both wants OPTIONAL rather than either extreme
class Pmf:
    DISABLED = "0"
    OPTIONAL = "1"
    REQUIRED = "2"


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


## The protocol names a scan-result flag group can start with. WPA2 before WPA
#  so the longer one wins when both would match
_PROTOCOLS = ("WPA2", "WPA", "RSN", "OSEN")

## Key management names as they appear inside a scan-result flag group, i.e.
#  what wpa_supplicant_ie_txt() prints. Matched longest first, so PSK-SHA256
#  is not read as PSK followed by a cipher called SHA256
_SCAN_KEY_MGMT = tuple(sorted((
    "EAP", "PSK", "SAE", "OWE", "DPP", "None", "?",
    "FT/EAP", "FT/PSK", "FT/SAE",
    "EAP-SHA256", "PSK-SHA256", "EAP-SHA384",
    "EAP-SUITE-B", "EAP-SUITE-B-192",
    "SAE-EXT-KEY", "FT/SAE-EXT-KEY",
    "FILS-SHA256", "FILS-SHA384",
    "FT/FILS-SHA256", "FT/FILS-SHA384",
), key=len, reverse=True))


## Read the key management names off the front of a flag group's body, i.e.
#  the part after the protocol. The names run until the first token that is
#  not one, which is where the cipher list starts - and since a key
#  management name can itself contain a dash (PSK-SHA256) and so can a cipher
#  (CCMP-256), splitting on punctuation cannot tell the two apart
# @param body the group body, e.g. "PSK+SAE-CCMP"
# @return the key management names found, in the order advertised
def _scan_key_mgmt(body: str) -> List[str]:
    names = []
    index = 0
    while index < len(body):
        for name in _SCAN_KEY_MGMT:
            end = index + len(name)
            # A name only counts if what follows it is a separator: "PSK" must
            # not match the first three characters of a longer word
            if body[index:end] == name and (end == len(body) or body[end] in "+-"):
                names.append(name)
                index = end
                break
        else:
            # Not a key management name, so the ciphers begin here
            break
        if index < len(body) and body[index] == "+":
            index += 1
            continue
        break
    return names


## What an AP advertises, parsed from the flags column of a scan result.
#
#  The predicates are what callers normally want: whether a passphrase will
#  do, whether SAE is on offer, and whether the AP is running both at once.
#  key_mgmt and protocols are there for anything the predicates do not cover
class Security(NamedTuple):
    ## Key management names as the scan result spelled them: PSK, SAE, EAP,
    ## OWE, DPP, FT/PSK, PSK-SHA256, ...
    key_mgmt: FrozenSet[str]
    ## Protocols offered: WPA, WPA2, RSN, OSEN
    protocols: FrozenSet[str]
    ## Every other flag, unparsed: ESS, MFPR, MFPC, WPS, WEP, HS20, ...
    flags: FrozenSet[str]

    ## No encryption at all.
    #
    #  DO NOT SIMPLIFY THE protocols CLAUSE AWAY. It looks redundant next to
    #  the key_mgmt one and is not: a BSS advertising a WPA/RSN protocol
    #  whose only key management suite is one this code cannot name parses
    #  to an empty key_mgmt set, and without the protocols check it would
    #  report as open. "No key needed" is the single worst wrong answer this
    #  class can give - a caller acting on it would configure key_mgmt NONE
    #  against a secured network - and a suite added upstream is exactly how
    #  that arises. There is a test for it.
    #
    #  WEP is not open either, though it is not usable here in any case
    @property
    def open(self) -> bool:
        return not self.key_mgmt and not self.protocols and not self.wep

    ## Offers WPA/WPA2 Personal, i.e. a passphrase in the psk variable
    @property
    def psk(self) -> bool:
        return any(name == "PSK" or name.endswith("/PSK") or
                   name.startswith("PSK-") for name in self.key_mgmt)

    ## Offers WPA3 Personal
    @property
    def sae(self) -> bool:
        return any(name == "SAE" or name.endswith("/SAE") or
                   name.startswith("SAE-") for name in self.key_mgmt)

    ## Offers 802.1X, which needs credentials a passphrase cannot express
    @property
    def enterprise(self) -> bool:
        return any(name == "EAP" or "/EAP" in name or name.startswith("EAP-")
                   for name in self.key_mgmt)

    ## Offers Opportunistic Wireless Encryption, i.e. encrypted but keyless
    @property
    def owe(self) -> bool:
        return "OWE" in self.key_mgmt

    ## WPA2/WPA3 transition mode: one BSS running PSK and SAE together, so
    ## older clients keep working while newer ones get SAE
    @property
    def transition_mode(self) -> bool:
        return self.psk and self.sae

    ## SAE and nothing older, so a WPA2-only client cannot associate
    @property
    def sae_only(self) -> bool:
        return self.sae and not self.psk

    ## Management frame protection is required, which SAE always implies
    @property
    def pmf_required(self) -> bool:
        return "MFPR" in self.flags

    ## Management frame protection is supported but not insisted on
    @property
    def pmf_capable(self) -> bool:
        return "MFPC" in self.flags

    @property
    def wep(self) -> bool:
        return "WEP" in self.flags


## Parse the flags column of a scan result.
#
#  Unknown groups are kept verbatim in Security.flags rather than dropped:
#  this runs against whatever wpa_supplicant is on the device, and a name
#  added upstream should not turn into silence here
# @param flags the flags text, e.g. "[WPA2-PSK+SAE-CCMP][MFPC][ESS]"
# @return what the AP offers
def parse_security(flags: str) -> Security:
    key_mgmt = set()
    protocols = set()
    others = set()
    for group in (flags or "").split("]"):
        group = group.partition("[")[2]
        if not group:
            continue
        for protocol in _PROTOCOLS:
            if group.startswith(protocol + "-"):
                protocols.add(protocol)
                key_mgmt.update(_scan_key_mgmt(group[len(protocol) + 1:]))
                break
        else:
            others.add(group)
    return Security(frozenset(key_mgmt), frozenset(protocols), frozenset(others))


## The named escapes of the daemon's printf-style encoding
_PRINTF_ESCAPES = {"\\": b"\\", '"': b'"', "n": b"\n", "r": b"\r", "t": b"\t",
                   "e": b"\x1b"}


## Decode the printf-style escaping wpa_supplicant applies to octet strings
#  on their way out - SSIDs above all. The daemon keeps printable ASCII and
#  escapes everything else, so the wire form is pure ASCII and every byte
#  outside it arrives as \xNN - whether it is half of a UTF-8 character or
#  arbitrary binary. Undoing that yields bytes, not text: which bytes they
#  are is only known once decoded, so decoding straight to characters would
#  turn UTF-8 into mojibake.
#
#  The dialect is printf_encode()/printf_decode() in hostap's
#  src/utils/common.c, including what the encoder never emits but the
#  decoder accepts - a single-digit \xN, octal escapes, an unknown escape
#  standing for its character, a \x with no digits or a trailing backslash
#  dropped - so both ends read the wire the same way
# @param text the escaped text
# @return the octet string it encodes
def printf_decode(text: str) -> bytes:
    result = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        index += 1
        if char != "\\":
            result += char.encode()
            continue
        if index >= len(text):
            break
        escape = text[index]
        if escape in _PRINTF_ESCAPES:
            result += _PRINTF_ESCAPES[escape]
            index += 1
        elif escape == "x":
            index += 1
            digits = ""
            while (index < len(text) and len(digits) < 2
                   and text[index] in _HEX_DIGITS):
                digits += text[index]
                index += 1
            if digits:
                result.append(int(digits, 16))
        elif "0" <= escape <= "7":
            value = 0
            digits = 0
            while (index < len(text) and digits < 3
                   and "0" <= text[index] <= "7"):
                value = value * 8 + int(text[index])
                index += 1
                digits += 1
            result.append(value & 0xFF)
        else:
            result += escape.encode()
            index += 1
    return bytes(result)


## An SSID: the 0-32 octets the air carries, as a bytes subclass.
#
#  Its own type because the octets have one identity and several wire
#  spellings - the daemon prints them printf-escaped, DPP takes a hexdump,
#  a config file quotes them - and because what the octets mean is not the
#  type's to decide: a person's SSID is almost always UTF-8, an embedded
#  system's can be any bytes at all. Being bytes, it compares and hashes
#  as the octets do, which is the only identity two spellings share
class Ssid(bytes):

    ## Parse the printf-escaped spelling the daemon uses on the way out,
    #  e.g. the ssid field of a BSS reply or a SCAN_RESULTS row
    # @param text the escaped text
    # @return the SSID it spells
    @classmethod
    def from_printf(cls, text: str) -> 'Ssid':
        return cls(printf_decode(text))

    ## Parse the spelling a configuration file, a GET_NETWORK reply or a
    #  SET_NETWORK value uses for a string network variable. Three forms,
    #  per wpa_config_parse_string() in hostap's src/utils/common.c:
    #  "..." is the literal bytes between the first quote and the last,
    #  with no escape processing at all; P"..." is the same with the
    #  printf escapes; anything else is read as hex.
    #
    #  This is a different spelling from the one status() and scan
    #  results use - the config side quotes, the event side escapes - and
    #  comparing the two as text is the classic mistake this type exists
    #  to end: go through octets instead,
    #
    #      Ssid.from_printf(status["ssid"]) == Ssid.from_config(value)
    # @param value the text right of ssid=, as the file or reply holds it
    # @return the SSID it spells
    # @raises ValueError where the daemon's parser would refuse: an
    #         unterminated quoted form, or hex of odd length or with a
    #         character that is not hex
    @classmethod
    def from_config(cls, value: str) -> 'Ssid':
        for prefix, decode in (('"', lambda body: body.encode()),
                               ('P"', printf_decode)):
            if value.startswith(prefix):
                body, quote, tail = value[len(prefix):].rpartition('"')
                if not quote or tail:
                    raise ValueError(f"unterminated quoted string: {value!r}")
                return cls(decode(body))
        if len(value) % 2 or not all(c in _HEX_DIGITS for c in value):
            raise ValueError(f"neither a quoted string nor hex: {value!r}")
        return cls(bytes.fromhex(value))

    ## The UTF-8 reading, when there is one - a person's SSID almost
    #  always is UTF-8, but 802.11 promises nothing. None otherwise,
    #  rather than a replacement-character rendering under which two
    #  different networks could look identical; the octets are always
    #  the truth
    @property
    def text(self) -> Optional[str]:
        try:
            return self.decode()
        except UnicodeDecodeError:
            return None

    ## The spelling for a configuration file or SET_NETWORK, chosen by the
    #  daemon's own rule when it writes a config out: the quoted literal
    #  when every octet is printable ASCII, hex for anything else -
    #  wpa_config_write_string() hexes any octet below 32 or above 126,
    #  UTF-8 included. Hex is never wrong; the quoted form is offered only
    #  where it reads back to exactly these octets
    # @return the value to put right of ssid=
    def config_value(self) -> str:
        if all(32 <= byte <= 126 for byte in self):
            return f'"{self.decode("ascii")}"'
        return self.hex()


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
class Bss(Dict[str, str]):

    def _int(self, key: str, base: int = 10) -> Optional[int]:
        value = self.get(key)
        return None if value is None else int(value, base)

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


## The lengths WPA2 accepts for a psk passphrase. SAE has no such limit -
#  it derives its key from the password whatever the length - so a secret
#  outside this range can still serve a WPA3 network, just not a WPA2 one
PASSPHRASE_MIN_LENGTH = 8
PASSPHRASE_MAX_LENGTH = 63

## Spelled out rather than taken from string.hexdigits, to keep this package
#  on the standard library imports its packaging already declares
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


## Whether a secret can serve as a WPA2 passphrase
# @param secret the passphrase to check
# @return True if wpa_supplicant will accept it as one
def is_passphrase(secret: str) -> bool:
    return PASSPHRASE_MIN_LENGTH <= len(secret) <= PASSPHRASE_MAX_LENGTH


## Whether a secret is a raw 256-bit key rather than a passphrase.
#
#  The psk network variable takes either: a passphrase in quotes, or the key
#  itself as 64 hex digits, unquoted. The distinction decides more than
#  quoting - SAE derives its key from the password, so a raw key can only
#  ever serve WPA2, and offering it to SAE advertises something the station
#  cannot do
# @param secret the value destined for psk
# @return True if it is a key rather than a passphrase
def is_raw_psk(secret: str) -> bool:
    return len(secret) == 64 and all(c in _HEX_DIGITS for c in secret)


## The wire form of a secret for the psk network variable: a raw key
#  unquoted, anything else quoted. Quoting a raw key gets it refused as an
#  over-long passphrase, which is the mistake this exists to prevent
# @param secret the passphrase or raw key
# @return the value to send
def psk_value(secret: str) -> str:
    return secret if is_raw_psk(secret) else quote(secret)


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


## Format the key=value parameters most DPP commands take.
#
#  A trailing underscore is stripped from the name, so pass_="..." expresses
#  DPP's pass=, which Python will not accept as a keyword. Values are used
#  verbatim: a key, an SSID hexdump or a passphrase hexdump means exactly
#  what its bytes say, and quoting or case-folding one would corrupt it
# @param params the parameters to format
# @return them as a single space-separated string
def format_params(**params) -> str:
    return " ".join(f"{name.rstrip('_')}={value}"
                    for name, value in params.items() if value is not None)


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

    ## Signal strength of the current connection
    def signal_poll(self) -> Dict[str, str]:
        return parse_variables(self.request("SIGNAL_POLL"))

    ## How many scans a BSS may go unseen before it is dropped from the
    #  scan results cache
    def bss_expire_count(self, count: int):
        self.command(f"BSS_EXPIRE_COUNT {count}")
