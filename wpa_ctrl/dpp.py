## @package wpa_ctrl.dpp
#
# DPP (Wi-Fi Easy Connect) parameter building: the conf= vocabulary, the
# encodings, and the channel spelling a bootstrapping URI carries. The
# DPP_* commands themselves are methods on WpaCtrl; what lives here is
# everything that gets a string right before it is sent.
#
# @file dpp.py

from typing import Optional


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


## Hex-encode a value the way DPP carries SSIDs and passphrases.
#
#  Not a convenience. The control interface takes these fields as hex, and
#  supplying anything else fails silently in the worst way: the command is
#  accepted, and the exchange is built and torn down later with no event and
#  no log line to say why
# @param text the value to encode - text, or the octets themselves (an
#        Ssid included), since an SSID need not be text at all
# @return its hex encoding
# @raises ValueError if there is nothing to encode, since an empty field is
#         accepted by the daemon and produces exactly that silent failure
def dpp_hex(text) -> str:
    if not text:
        raise ValueError("DPP fields cannot be empty; an empty one is "
                         "accepted and then fails silently")
    return text.hex() if isinstance(text, bytes) else text.encode().hex()


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
    # 6 GHz: class 131 holds the 20 MHz primaries, channels 1, 5, 9 ...
    # 233 on a 20 MHz grid from 5955 - a frequency between those centres
    # is not a channel a peer can announce on, so it is refused rather
    # than rounded. 5935 sits outside the grid and the table gives it a
    # class of its own
    if frequency == 5935:
        return "136/2"
    if 5955 <= frequency <= 7115 and (frequency - 5955) % 20 == 0:
        return f"131/{(frequency - 5950) // 5}"
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
# @param ssid the network name - text or octets - encoded here
# @param passphrase the passphrase, encoded here
# @param psk a 64-character hex key, passed through
# @param configurator the configurator id to sign with
# @param extra any further parameters, e.g. expiry or a group id
# @return the parameter string
# @raises ValueError if neither or both secrets are given, or if a psk is
#         not a plausible derived key
def dpp_configurator_params(conf: str, ssid, passphrase: str = None,
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
