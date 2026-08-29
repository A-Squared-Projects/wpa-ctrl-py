## @package wpa_ctrl.events
#
# Unsolicited event messages from wpa_supplicant.
#
# A connection only receives these after ATTACH. Each message arrives as its
# own datagram, prefixed with a syslog-style priority in angle brackets:
#
#     <3>CTRL-EVENT-CONNECTED - Connection to 00:11:22:33:44:55 completed
#
# @file events.py

from typing import NamedTuple

## Priority prefix on an event message. wpa_supplicant uses the syslog
#  levels; anything at or below MSGDUMP is debug chatter
MSG_EXCESSIVE = 0
MSG_MSGDUMP = 1
MSG_DEBUG = 2
MSG_INFO = 3
MSG_WARNING = 4
MSG_ERROR = 5

## Event name prefixes, as documented in ctrl_iface.doxygen. A request for
#  information from the user (identity, password, ...) is the one family
#  that uses a trailing dash and a field name rather than a fixed string
CTRL_REQ = "CTRL-REQ-"
CTRL_EVENT_CONNECTED = "CTRL-EVENT-CONNECTED"
CTRL_EVENT_DISCONNECTED = "CTRL-EVENT-DISCONNECTED"
CTRL_EVENT_TERMINATING = "CTRL-EVENT-TERMINATING"
CTRL_EVENT_PASSWORD_CHANGED = "CTRL-EVENT-PASSWORD-CHANGED"
CTRL_EVENT_EAP_NOTIFICATION = "CTRL-EVENT-EAP-NOTIFICATION"
CTRL_EVENT_EAP_STARTED = "CTRL-EVENT-EAP-STARTED"
CTRL_EVENT_EAP_METHOD = "CTRL-EVENT-EAP-METHOD"
CTRL_EVENT_EAP_SUCCESS = "CTRL-EVENT-EAP-SUCCESS"
CTRL_EVENT_EAP_FAILURE = "CTRL-EVENT-EAP-FAILURE"
CTRL_EVENT_SCAN_RESULTS = "CTRL-EVENT-SCAN-RESULTS"
CTRL_EVENT_BSS_ADDED = "CTRL-EVENT-BSS-ADDED"
CTRL_EVENT_BSS_REMOVED = "CTRL-EVENT-BSS-REMOVED"

WPS_OVERLAP_DETECTED = "WPS-OVERLAP-DETECTED"
WPS_AP_AVAILABLE_PBC = "WPS-AP-AVAILABLE-PBC"
WPS_AP_AVAILABLE_PIN = "WPS-AP-AVAILABLE-PIN"
WPS_AP_AVAILABLE = "WPS-AP-AVAILABLE"
WPS_CRED_RECEIVED = "WPS-CRED-RECEIVED"
WPS_M2D = "WPS-M2D"
WPS_FAIL = "WPS-FAIL"
WPS_SUCCESS = "WPS-SUCCESS"
WPS_TIMEOUT = "WPS-TIMEOUT"
WPS_ENROLLEE_SEEN = "WPS-ENROLLEE-SEEN"
WPS_ER_AP_ADD = "WPS-ER-AP-ADD"
WPS_ER_AP_REMOVE = "WPS-ER-AP-REMOVE"
WPS_ER_ENROLLEE_ADD = "WPS-ER-ENROLLEE-ADD"
WPS_ER_ENROLLEE_REMOVE = "WPS-ER-ENROLLEE-REMOVE"
WPS_PIN_NEEDED = "WPS-PIN-NEEDED"
WPS_NEW_AP_SETTINGS = "WPS-NEW-AP-SETTINGS"
WPS_REG_SUCCESS = "WPS-REG-SUCCESS"
WPS_AP_SETUP_LOCKED = "WPS-AP-SETUP-LOCKED"

AP_STA_CONNECTED = "AP-STA-CONNECTED"
AP_STA_DISCONNECTED = "AP-STA-DISCONNECTED"

P2P_DEVICE_FOUND = "P2P-DEVICE-FOUND"
P2P_GO_NEG_REQUEST = "P2P-GO-NEG-REQUEST"
P2P_GO_NEG_SUCCESS = "P2P-GO-NEG-SUCCESS"
P2P_GO_NEG_FAILURE = "P2P-GO-NEG-FAILURE"
P2P_GROUP_FORMATION_SUCCESS = "P2P-GROUP-FORMATION-SUCCESS"
P2P_GROUP_FORMATION_FAILURE = "P2P-GROUP-FORMATION-FAILURE"
P2P_GROUP_STARTED = "P2P-GROUP-STARTED"
P2P_GROUP_REMOVED = "P2P-GROUP-REMOVED"
P2P_PROV_DISC_SHOW_PIN = "P2P-PROV-DISC-SHOW-PIN"
P2P_PROV_DISC_ENTER_PIN = "P2P-PROV-DISC-ENTER-PIN"
P2P_PROV_DISC_PBC_REQ = "P2P-PROV-DISC-PBC-REQ"
P2P_PROV_DISC_PBC_RESP = "P2P-PROV-DISC-PBC-RESP"
P2P_SERV_DISC_REQ = "P2P-SERV-DISC-REQ"
P2P_SERV_DISC_RESP = "P2P-SERV-DISC-RESP"
P2P_INVITATION_RECEIVED = "P2P-INVITATION-RECEIVED"
P2P_INVITATION_RESULT = "P2P-INVITATION-RESULT"


## One unsolicited message.
#  @param priority syslog-style level from the <n> prefix, MSG_INFO when the
#         message carried no prefix
#  @param name the event name, e.g. CTRL-EVENT-CONNECTED
#  @param params whatever followed the name, unparsed
#  @param raw the message exactly as received, prefix included
class Event(NamedTuple):
    priority: int
    name: str
    params: str
    raw: str

    ## True if this is a request for information from the user, e.g.
    #  CTRL-REQ-PASSWORD-1:Password needed for SSID foo
    @property
    def is_request(self) -> bool:
        return self.name.startswith(CTRL_REQ)


## Parse one event message off the wire.
#  Anything unrecognised still comes back as an Event rather than being
#  dropped: this interface gains messages between releases, and a caller
#  filtering on name is better placed to ignore them than we are
# @param message the datagram, decoded
# @return the parsed event
def parse_event(message: str) -> Event:
    raw = message
    priority = MSG_INFO
    body = message
    if message.startswith("<"):
        end = message.find(">")
        if end != -1:
            try:
                priority = int(message[1:end])
                body = message[end + 1:]
            except ValueError:
                # Not a priority prefix after all - leave the body alone
                pass
    body = body.rstrip("\n")
    name, _, params = body.partition(" ")
    return Event(priority, name, params, raw)


## True if a received datagram is an unsolicited event rather than a reply
#  to a command. Replies never carry the priority prefix
# @param message the datagram, decoded
def is_event(message: str) -> bool:
    return message.startswith("<")
