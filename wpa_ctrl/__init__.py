## @package wpa_ctrl
#
# A pure-Python client for the wpa_supplicant/hostapd control interface,
# speaking its UNIX datagram protocol directly rather than shelling out to
# wpa_cli or linking the wpa_ctrl C library.
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

from .client import Network, PmksaEntry, ScanResult, WpaCtrl, parse_table, parse_variables, quote
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
                     CtrlTransport,
                     interface_path,
)

__all__ = [
    "CtrlTransport",
    "SYS_CLASS_NET",
    "DEFAULT_CLIENT_DIR",
    "DEFAULT_CTRL_DIR",
    "DEFAULT_TIMEOUT",
    "Event",
    "Network",
    "PmksaEntry",
    "ScanResult",
    "WpaCtrl",
    "WpaCtrlCommandFailed",
    "WpaCtrlConnectionError",
    "WpaCtrlError",
    "WpaCtrlTimeout",
    "control_sockets",
    "find_interfaces",
    "have_sysfs",
    "interface_path",
    "is_wireless",
    "is_event",
    "parse_event",
    "parse_table",
    "parse_variables",
    "quote",
    "wireless_interfaces",
]
