## @package wpa_ctrl.ssid
#
# The spelling of octet strings and secrets on the wire.
#
# An SSID is 0-32 octets that the daemon spells several ways - printf-escaped
# on its way out, quoted literal, P"..." or hex in configuration - and a psk
# is a secret whose quoting decides its meaning. This module holds those
# spellings and nothing else; what the octets mean is the caller's business.
#
# @file ssid.py

from typing import Optional

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
