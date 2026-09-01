## @package wpa_ctrl
#
# A pure-Python client for the wpa_supplicant/hostapd control interface,
# speaking its UNIX datagram protocol directly rather than shelling out to
# wpa_cli or linking the wpa_ctrl C library.
#
# One protocol serves both daemons - upstream implements it once, in
# src/common/wpa_ctrl.c, which is what hostapd_cli and wpa_cli both link.
# Point the client at hostapd's socket directory and everything here works
# the same way:
#
#     WpaCtrl("wlan0", ctrl_dir=HOSTAPD_CTRL_DIR)
#
# Stdlib only, with no dependencies of any kind:
#
#     from wpa_ctrl import WpaCtrl, find_interfaces
#
#     for ifname in find_interfaces():
#         ...
#
#     with WpaCtrl("wlan0") as wpa:
#         print(wpa.status()["wpa_state"])
#         for network in wpa.list_networks():
#             print(network.id, network.ssid, network.current)
#
# Events need a connection of their own, attached:
#
#     with WpaCtrl("wlan0") as monitor:
#         monitor.attach()
#         event = monitor.next_event(timeout=10)
#
# @file __init__.py

from .client import (
                     PASSPHRASE_MAX_LENGTH,
                     PASSPHRASE_MIN_LENGTH,
                     Bss,
                     BssMask,
                     DppConf,
                     KeyMgmt,
                     Network,
                     Pmf,
                     PmksaEntry,
                     ScanResult,
                     Security,
                     Ssid,
                     Status,
                     WpaCtrl,
                     dpp_channel,
                     dpp_configurator_params,
                     dpp_hex,
                     format_params,
                     is_passphrase,
                     is_raw_psk,
                     parse_security,
                     parse_table,
                     parse_variables,
                     printf_decode,
                     psk_value,
                     quote,
)
from .discovery import (
                     SYS_CLASS_NET,
                     control_sockets,
                     find_interfaces,
                     have_sysfs,
                     is_wireless,
                     wireless_interfaces,
)
from .errors import WpaCtrlCommandFailed, WpaCtrlConnectionError, WpaCtrlError, WpaCtrlTimeout
from .events import Event, is_event, parse_event
from .transport import (
                     DEFAULT_CLIENT_DIR,
                     DEFAULT_CTRL_DIR,
                     DEFAULT_TIMEOUT,
                     HOSTAPD_CTRL_DIR,
                     CtrlTransport,
                     interface_path,
)

__all__ = [
    "Bss",
    "BssMask",
    "CtrlTransport",
    "DppConf",
    "SYS_CLASS_NET",
    "DEFAULT_CLIENT_DIR",
    "DEFAULT_CTRL_DIR",
    "DEFAULT_TIMEOUT",
    "Event",
    "HOSTAPD_CTRL_DIR",
    "KeyMgmt",
    "Network",
    "PASSPHRASE_MAX_LENGTH",
    "PASSPHRASE_MIN_LENGTH",
    "Pmf",
    "PmksaEntry",
    "ScanResult",
    "Security",
    "Ssid",
    "Status",
    "WpaCtrl",
    "WpaCtrlCommandFailed",
    "WpaCtrlConnectionError",
    "WpaCtrlError",
    "WpaCtrlTimeout",
    "control_sockets",
    "dpp_channel",
    "dpp_configurator_params",
    "dpp_hex",
    "format_params",
    "find_interfaces",
    "have_sysfs",
    "interface_path",
    "is_passphrase",
    "is_raw_psk",
    "is_wireless",
    "is_event",
    "parse_event",
    "parse_security",
    "parse_table",
    "parse_variables",
    "printf_decode",
    "psk_value",
    "quote",
    "wireless_interfaces",
]
