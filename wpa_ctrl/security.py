## @package wpa_ctrl.security
#
# What an AP offers, read from the flags column a scan result or a BSS
# advertises - and the other vocabulary, the one used when configuring the
# answer, which spells the same ideas differently.
#
# @file security.py

from typing import FrozenSet, List, NamedTuple


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

## Values for the ieee80211w network variable, which selects management frame
#  protection. SAE requires it, and WPA2 predates it, so a network that has to
#  work with both wants OPTIONAL rather than either extreme
class Pmf:
    DISABLED = "0"
    OPTIONAL = "1"
    REQUIRED = "2"

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
