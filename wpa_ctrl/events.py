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

from typing import Dict, List, NamedTuple, Optional

from .replies import _Variables
from .ssid import Ssid

## Priority prefix on an event message. wpa_supplicant uses the syslog
#  levels; anything at or below MSGDUMP is debug chatter
MSG_EXCESSIVE = 0
MSG_MSGDUMP = 1
MSG_DEBUG = 2
MSG_INFO = 3
MSG_WARNING = 4
MSG_ERROR = 5

## Event names, taken from src/common/wpa_ctrl.h in hostap - the header both
#  daemons' CLIs compile against, and the only complete list there is. The
#  doxygen documentation covers a fraction of them and has not kept pace:
#  CTRL-EVENT-SCAN-STARTED, to pick one seen on a live device, appears in
#  neither ctrl_iface.doxygen nor hostapd_ctrl_iface.doxygen.
#
#  hostap is BSD-3-Clause; its notice is reproduced in NOTICE, since these
#  names come from it.
#
#  Generated from hostap 2_12-bp-305-g168f9755d9d0. Regenerate when that
#  moves: parse_event() copes with names it has never seen, so a stale list
#  costs a caller a constant rather than a missed event.
#
#  Names here follow the event string rather than the C macro, which is not
#  always the same - WPA_EVENT_CONNECTED is CTRL-EVENT-CONNECTED - so that
#  what a caller writes matches what arrives on the wire.

## wpa_supplicant's own state changes, and its requests for
#  information from the user
CTRL_REQ = "CTRL-REQ-"
CTRL_RSP = "CTRL-RSP-"
CTRL_EVENT_CONNECTED = "CTRL-EVENT-CONNECTED"
CTRL_EVENT_DISCONNECTED = "CTRL-EVENT-DISCONNECTED"
CTRL_EVENT_ASSOC_REJECT = "CTRL-EVENT-ASSOC-REJECT"
CTRL_EVENT_AUTH_REJECT = "CTRL-EVENT-AUTH-REJECT"
CTRL_EVENT_TERMINATING = "CTRL-EVENT-TERMINATING"
CTRL_EVENT_PASSWORD_CHANGED = "CTRL-EVENT-PASSWORD-CHANGED"
CTRL_EVENT_EAP_NOTIFICATION = "CTRL-EVENT-EAP-NOTIFICATION"
CTRL_EVENT_EAP_STARTED = "CTRL-EVENT-EAP-STARTED"
CTRL_EVENT_EAP_PROPOSED_METHOD = "CTRL-EVENT-EAP-PROPOSED-METHOD"
CTRL_EVENT_EAP_METHOD = "CTRL-EVENT-EAP-METHOD"
CTRL_EVENT_EAP_PEER_CERT = "CTRL-EVENT-EAP-PEER-CERT"
CTRL_EVENT_EAP_PEER_ALT = "CTRL-EVENT-EAP-PEER-ALT"
CTRL_EVENT_EAP_TLS_CERT_ERROR = "CTRL-EVENT-EAP-TLS-CERT-ERROR"
CTRL_EVENT_EAP_STATUS = "CTRL-EVENT-EAP-STATUS"
CTRL_EVENT_EAP_RETRANSMIT = "CTRL-EVENT-EAP-RETRANSMIT"
CTRL_EVENT_EAP_RETRANSMIT2 = "CTRL-EVENT-EAP-RETRANSMIT2"
CTRL_EVENT_EAP_SUCCESS = "CTRL-EVENT-EAP-SUCCESS"
CTRL_EVENT_EAP_SUCCESS2 = "CTRL-EVENT-EAP-SUCCESS2"
CTRL_EVENT_EAP_FAILURE = "CTRL-EVENT-EAP-FAILURE"
CTRL_EVENT_EAP_FAILURE2 = "CTRL-EVENT-EAP-FAILURE2"
CTRL_EVENT_EAP_TIMEOUT_FAILURE = "CTRL-EVENT-EAP-TIMEOUT-FAILURE"
CTRL_EVENT_EAP_TIMEOUT_FAILURE2 = "CTRL-EVENT-EAP-TIMEOUT-FAILURE2"
CTRL_EVENT_SSID_TEMP_DISABLED = "CTRL-EVENT-SSID-TEMP-DISABLED"
CTRL_EVENT_SSID_REENABLED = "CTRL-EVENT-SSID-REENABLED"
CTRL_EVENT_SCAN_STARTED = "CTRL-EVENT-SCAN-STARTED"
CTRL_EVENT_SCAN_RESULTS = "CTRL-EVENT-SCAN-RESULTS"
CTRL_EVENT_SCAN_FAILED = "CTRL-EVENT-SCAN-FAILED"
CTRL_EVENT_STATE_CHANGE = "CTRL-EVENT-STATE-CHANGE"
CTRL_EVENT_BSS_ADDED = "CTRL-EVENT-BSS-ADDED"
CTRL_EVENT_BSS_REMOVED = "CTRL-EVENT-BSS-REMOVED"
CTRL_EVENT_NETWORK_NOT_FOUND = "CTRL-EVENT-NETWORK-NOT-FOUND"
CTRL_EVENT_SIGNAL_CHANGE = "CTRL-EVENT-SIGNAL-CHANGE"
CTRL_EVENT_BEACON_LOSS = "CTRL-EVENT-BEACON-LOSS"
CTRL_EVENT_REGDOM_CHANGE = "CTRL-EVENT-REGDOM-CHANGE"
CTRL_EVENT_REGDOM_BEACON_HINT = "CTRL-EVENT-REGDOM-BEACON-HINT"
CTRL_EVENT_STARTED_CHANNEL_SWITCH = "CTRL-EVENT-STARTED-CHANNEL-SWITCH"
CTRL_EVENT_CHANNEL_SWITCH = "CTRL-EVENT-CHANNEL-SWITCH"
CTRL_EVENT_LINK_CHANNEL_SWITCH = "CTRL-EVENT-LINK-CHANNEL-SWITCH"
CTRL_EVENT_UNPROT_BEACON = "CTRL-EVENT-UNPROT-BEACON"
CTRL_EVENT_DO_ROAM = "CTRL-EVENT-DO-ROAM"
CTRL_EVENT_SKIP_ROAM = "CTRL-EVENT-SKIP-ROAM"
CTRL_EVENT_T2LM_UPDATE = "CTRL-EVENT-T2LM-UPDATE"
CTRL_EVENT_LINK_RECONFIG = "CTRL-EVENT-LINK-RECONFIG"
CTRL_EVENT_LINK_STA_REMOVED = "CTRL-EVENT-LINK-STA-REMOVED"
CTRL_EVENT_LINK_STA_ADDED = "CTRL-EVENT-LINK-STA-ADDED"
CTRL_EVENT_SUBNET_STATUS_UPDATE = "CTRL-EVENT-SUBNET-STATUS-UPDATE"
CTRL_EVENT_FREQ_CONFLICT = "CTRL-EVENT-FREQ-CONFLICT"
CTRL_EVENT_AVOID_FREQ = "CTRL-EVENT-AVOID-FREQ"
CTRL_EVENT_NETWORK_ADDED = "CTRL-EVENT-NETWORK-ADDED"
CTRL_EVENT_NETWORK_REMOVED = "CTRL-EVENT-NETWORK-REMOVED"
CTRL_EVENT_MSCS_RESULT = "CTRL-EVENT-MSCS-RESULT"
CTRL_EVENT_SCS_RESULT = "CTRL-EVENT-SCS-RESULT"
CTRL_EVENT_DSCP_POLICY = "CTRL-EVENT-DSCP-POLICY"

## Wi-Fi Protected Setup
WPS_OVERLAP_DETECTED = "WPS-OVERLAP-DETECTED"
WPS_AP_AVAILABLE_PBC = "WPS-AP-AVAILABLE-PBC"
WPS_AP_AVAILABLE_AUTH = "WPS-AP-AVAILABLE-AUTH"
WPS_AP_AVAILABLE_PIN = "WPS-AP-AVAILABLE-PIN"
WPS_AP_AVAILABLE = "WPS-AP-AVAILABLE"
WPS_CRED_RECEIVED = "WPS-CRED-RECEIVED"
WPS_M2D = "WPS-M2D"
WPS_FAIL = "WPS-FAIL"
WPS_SUCCESS = "WPS-SUCCESS"
WPS_TIMEOUT = "WPS-TIMEOUT"
WPS_PBC_ACTIVE = "WPS-PBC-ACTIVE"
WPS_PBC_DISABLE = "WPS-PBC-DISABLE"
WPS_ENROLLEE_SEEN = "WPS-ENROLLEE-SEEN"
WPS_OPEN_NETWORK = "WPS-OPEN-NETWORK"
WPS_ER_AP_ADD = "WPS-ER-AP-ADD"
WPS_ER_AP_REMOVE = "WPS-ER-AP-REMOVE"
WPS_ER_ENROLLEE_ADD = "WPS-ER-ENROLLEE-ADD"
WPS_ER_ENROLLEE_REMOVE = "WPS-ER-ENROLLEE-REMOVE"
WPS_ER_AP_SETTINGS = "WPS-ER-AP-SETTINGS"
WPS_ER_AP_SET_SEL_REG = "WPS-ER-AP-SET-SEL-REG"
WPS_PIN_NEEDED = "WPS-PIN-NEEDED"
WPS_NEW_AP_SETTINGS = "WPS-NEW-AP-SETTINGS"
WPS_REG_SUCCESS = "WPS-REG-SUCCESS"
WPS_AP_SETUP_LOCKED = "WPS-AP-SETUP-LOCKED"
WPS_AP_SETUP_UNLOCKED = "WPS-AP-SETUP-UNLOCKED"
WPS_AP_PIN_ENABLED = "WPS-AP-PIN-ENABLED"
WPS_AP_PIN_DISABLED = "WPS-AP-PIN-DISABLED"
WPS_PIN_ACTIVE = "WPS-PIN-ACTIVE"
WPS_CANCEL = "WPS-CANCEL"

## hostapd, and wpa_supplicant acting as an AP
AP_STA_CONNECTED = "AP-STA-CONNECTED"
AP_STA_DISCONNECTED = "AP-STA-DISCONNECTED"
AP_STA_POSSIBLE_PSK_MISMATCH = "AP-STA-POSSIBLE-PSK-MISMATCH"
AP_STA_POLL_OK = "AP-STA-POLL-OK"
AP_REJECTED_MAX_STA = "AP-REJECTED-MAX-STA"
AP_REJECTED_BLOCKED_STA = "AP-REJECTED-BLOCKED-STA"
AP_ENABLED = "AP-ENABLED"
AP_DISABLED = "AP-DISABLED"
AP_NO_IR = "AP-NO_IR"
AP_CSA_FINISHED = "AP-CSA-FINISHED"
AP_MGMT_FRAME_RECEIVED = "AP-MGMT-FRAME-RECEIVED"

## station mode changes reported by an AP
STA_OPMODE_MAX_BW_CHANGED = "STA-OPMODE-MAX-BW-CHANGED"
STA_OPMODE_SMPS_MODE_CHANGED = "STA-OPMODE-SMPS-MODE-CHANGED"
STA_OPMODE_N_SS_CHANGED = "STA-OPMODE-N_SS-CHANGED"

## 4-address WDS links
WDS_STA_INTERFACE_ADDED = "WDS-STA-INTERFACE-ADDED"
WDS_STA_INTERFACE_REMOVED = "WDS-STA-INTERFACE-REMOVED"

## Wi-Fi Direct
P2P_DEVICE_FOUND = "P2P-DEVICE-FOUND"
P2P_DEVICE_LOST = "P2P-DEVICE-LOST"
P2P_GO_NEG_REQUEST = "P2P-GO-NEG-REQUEST"
P2P_GO_NEG_SUCCESS = "P2P-GO-NEG-SUCCESS"
P2P_GO_NEG_FAILURE = "P2P-GO-NEG-FAILURE"
P2P_GROUP_FORMATION_SUCCESS = "P2P-GROUP-FORMATION-SUCCESS"
P2P_GROUP_FORMATION_FAILURE = "P2P-GROUP-FORMATION-FAILURE"
P2P_GROUP_STARTED = "P2P-GROUP-STARTED"
P2P_GROUP_REMOVED = "P2P-GROUP-REMOVED"
P2P_CROSS_CONNECT_ENABLE = "P2P-CROSS-CONNECT-ENABLE"
P2P_CROSS_CONNECT_DISABLE = "P2P-CROSS-CONNECT-DISABLE"
P2P_PROV_DISC_SHOW_PIN = "P2P-PROV-DISC-SHOW-PIN"
P2P_PROV_DISC_ENTER_PIN = "P2P-PROV-DISC-ENTER-PIN"
P2P_PROV_DISC_PBC_REQ = "P2P-PROV-DISC-PBC-REQ"
P2P_PROV_DISC_PBC_RESP = "P2P-PROV-DISC-PBC-RESP"
P2P_PROV_DISC_FAILURE = "P2P-PROV-DISC-FAILURE"
P2P_SERV_DISC_REQ = "P2P-SERV-DISC-REQ"
P2P_SERV_DISC_RESP = "P2P-SERV-DISC-RESP"
P2P_SERV_ASP_RESP = "P2P-SERV-ASP-RESP"
P2P_INVITATION_RECEIVED = "P2P-INVITATION-RECEIVED"
P2P_INVITATION_RESULT = "P2P-INVITATION-RESULT"
P2P_INVITATION_ACCEPTED = "P2P-INVITATION-ACCEPTED"
P2P_FIND_STOPPED = "P2P-FIND-STOPPED"
P2P_PERSISTENT_PSK_FAIL = "P2P-PERSISTENT-PSK-FAIL"
P2P_PRESENCE_RESPONSE = "P2P-PRESENCE-RESPONSE"
P2P_NFC_BOTH_GO = "P2P-NFC-BOTH-GO"
P2P_NFC_PEER_CLIENT = "P2P-NFC-PEER-CLIENT"
P2P_NFC_WHILE_CLIENT = "P2P-NFC-WHILE-CLIENT"
P2P_FALLBACK_TO_GO_NEG = "P2P-FALLBACK-TO-GO-NEG"
P2P_FALLBACK_TO_GO_NEG_ENABLED = "P2P-FALLBACK-TO-GO-NEG-ENABLED"
P2P_REMOVE_AND_REFORM_GROUP = "P2P-REMOVE-AND-REFORM-GROUP"
P2P_BOOTSTRAP_REQUEST = "P2P-BOOTSTRAP-REQUEST"
P2P_BOOTSTRAP_SUCCESS = "P2P-BOOTSTRAP-SUCCESS"
P2P_BOOTSTRAP_FAILURE = "P2P-BOOTSTRAP-FAILURE"
P2P_LISTEN_OFFLOAD_STOPPED = "P2P-LISTEN-OFFLOAD-STOPPED"
P2P_LISTEN_OFFLOAD_STOP_REASON = "P2P-LISTEN-OFFLOAD-STOP-REASON"

## Wi-Fi Direct services
P2PS_PROV_START = "P2PS-PROV-START"
P2PS_PROV_DONE = "P2PS-PROV-DONE"

## proximity ranging
PR_PASN_NEGOTIATION_STARTED = "PR-PASN-NEGOTIATION-STARTED"
PR_PASN_RESULT = "PR-PASN-RESULT"
PR_RANGING_TERMINATED = "PR-RANGING-TERMINATED"
PR_RANGING_PARAMS = "PR-RANGING-PARAMS"
PR_PEER_MEASUREMENT = "PR-PEER-MEASUREMENT"
PR_RANGING_COMPLETE = "PR-RANGING-COMPLETE"
PR_PEER_FOUND = "PR-PEER-FOUND"

## Neighbor Awareness Networking
NAN_DISCOVERY_RESULT = "NAN-DISCOVERY-RESULT"
NAN_REPLIED = "NAN-REPLIED"
NAN_PUBLISH_TERMINATED = "NAN-PUBLISH-TERMINATED"
NAN_SUBSCRIBE_TERMINATED = "NAN-SUBSCRIBE-TERMINATED"
NAN_RECEIVE = "NAN-RECEIVE"
NAN_TRANSMIT_STATUS = "NAN-TRANSMIT-STATUS"
NAN_CLUSTER_JOIN = "NAN-CLUSTER-JOIN"
NAN_NDP_REQUEST = "NAN-NDP-REQUEST"
NAN_NDP_COUNTER_REQUEST = "NAN-NDP-COUNTER-REQUEST"
NAN_NDP_CONNECTED = "NAN-NDP-CONNECTED"
NAN_NDP_DISCONNECTED = "NAN-NDP-DISCONNECTED"
NAN_BOOTSTRAP_REQUEST = "NAN-BOOTSTRAP-REQUEST"
NAN_BOOTSTRAP_SUCCESS = "NAN-BOOTSTRAP-SUCCESS"
NAN_BOOTSTRAP_FAILURE = "NAN-BOOTSTRAP-FAILURE"
NAN_NIK_RECEIVED = "NAN-NIK-RECEIVED"
NAN_PAIRING_REQUEST = "NAN-PAIRING-REQUEST"
NAN_PEER_SCHEDULE_CHANGED = "NAN-PEER-SCHEDULE-CHANGED"
NAN_SCHEDULE_UPDATE_DONE = "NAN-SCHEDULE-UPDATE-DONE"
NAN_PAIRING_STATUS = "NAN-PAIRING-STATUS"
NAN_CHAN_EVACUATION = "NAN-CHAN-EVACUATION"
NAN_STOPPED = "NAN-STOPPED"

## 802.11s mesh
MESH_GROUP_STARTED = "MESH-GROUP-STARTED"
MESH_GROUP_REMOVED = "MESH-GROUP-REMOVED"
MESH_PEER_CONNECTED = "MESH-PEER-CONNECTED"
MESH_PEER_DISCONNECTED = "MESH-PEER-DISCONNECTED"
MESH_SAE_AUTH_FAILURE = "MESH-SAE-AUTH-FAILURE"
MESH_SAE_AUTH_BLOCKED = "MESH-SAE-AUTH-BLOCKED"

## Device Provisioning Protocol
DPP_AUTH_SUCCESS = "DPP-AUTH-SUCCESS"
DPP_AUTH_INIT_FAILED = "DPP-AUTH-INIT-FAILED"
DPP_NOT_COMPATIBLE = "DPP-NOT-COMPATIBLE"
DPP_RESPONSE_PENDING = "DPP-RESPONSE-PENDING"
DPP_SCAN_PEER_QR_CODE = "DPP-SCAN-PEER-QR-CODE"
DPP_AUTH_DIRECTION = "DPP-AUTH-DIRECTION"
DPP_CONF_RECEIVED = "DPP-CONF-RECEIVED"
DPP_CONF_SENT = "DPP-CONF-SENT"
DPP_CONF_FAILED = "DPP-CONF-FAILED"
DPP_CONN_STATUS_RESULT = "DPP-CONN-STATUS-RESULT"
DPP_CONFOBJ_AKM = "DPP-CONFOBJ-AKM"
DPP_CONFOBJ_SSID = "DPP-CONFOBJ-SSID"
DPP_CONFOBJ_SSID_CHARSET = "DPP-CONFOBJ-SSID-CHARSET"
DPP_CONFOBJ_PASS = "DPP-CONFOBJ-PASS"
DPP_CONFOBJ_IDPASS = "DPP-CONFOBJ-IDPASS"
DPP_CONFOBJ_PSK = "DPP-CONFOBJ-PSK"
DPP_CONNECTOR = "DPP-CONNECTOR"
DPP_C_SIGN_KEY = "DPP-C-SIGN-KEY"
DPP_PP_KEY = "DPP-PP-KEY"
DPP_NET_ACCESS_KEY = "DPP-NET-ACCESS-KEY"
DPP_SERVER_NAME = "DPP-SERVER-NAME"
DPP_CERTBAG = "DPP-CERTBAG"
DPP_CACERT = "DPP-CACERT"
DPP_MISSING_CONNECTOR = "DPP-MISSING-CONNECTOR"
DPP_NETWORK_ID = "DPP-NETWORK-ID"
DPP_CONFIGURATOR_ID = "DPP-CONFIGURATOR-ID"
DPP_RX = "DPP-RX"
DPP_TX = "DPP-TX"
DPP_TX_STATUS = "DPP-TX-STATUS"
DPP_FAIL = "DPP-FAIL"
DPP_PKEX_T_LIMIT = "DPP-PKEX-T-LIMIT"
DPP_INTRO = "DPP-INTRO"
DPP_CONF_REQ_RX = "DPP-CONF-REQ-RX"
DPP_CHIRP_STOPPED = "DPP-CHIRP-STOPPED"
DPP_MUD_URL = "DPP-MUD-URL"
DPP_BAND_SUPPORT = "DPP-BAND-SUPPORT"
DPP_ENROLLEE_CAPABILITY = "DPP-ENROLLEE-CAPABILITY"
DPP_CSR = "DPP-CSR"
DPP_CHIRP_RX = "DPP-CHIRP-RX"
DPP_CONF_NEEDED = "DPP-CONF-NEEDED"
DPP_PB_STATUS = "DPP-PB-STATUS"
DPP_PB_RESULT = "DPP-PB-RESULT"
DPP_RELAY_NEEDS_CONTROLLER = "DPP-RELAY-NEEDS-CONTROLLER"

## Hotspot 2.0
HS20_DEAUTH_IMMINENT_NOTICE = "HS20-DEAUTH-IMMINENT-NOTICE"
HS20_T_C_ACCEPTANCE = "HS20-T-C-ACCEPTANCE"
HS20_T_C_FILTERING_ADD = "HS20-T-C-FILTERING-ADD"
HS20_T_C_FILTERING_REMOVE = "HS20-T-C-FILTERING-REMOVE"

## 802.11u interworking
INTERWORKING_AP = "INTERWORKING-AP"
INTERWORKING_BLACKLISTED = "INTERWORKING-BLACKLISTED"
INTERWORKING_NO_MATCH = "INTERWORKING-NO-MATCH"
INTERWORKING_ALREADY_CONNECTED = "INTERWORKING-ALREADY-CONNECTED"
INTERWORKING_SELECTED = "INTERWORKING-SELECTED"

## Access Network Query Protocol
ANQP_QUERY_DONE = "ANQP-QUERY-DONE"

## Generic Advertisement Service
GAS_RESPONSE_INFO = "GAS-RESPONSE-INFO"
GAS_QUERY_START = "GAS-QUERY-START"
GAS_QUERY_DONE = "GAS-QUERY-DONE"

## received frames of interest
RX_ANQP = "RX-ANQP"
RX_HS20_ANQP = "RX-HS20-ANQP"
RX_HS20_ANQP_ICON = "RX-HS20-ANQP-ICON"
RX_HS20_ICON = "RX-HS20-ICON"
RX_MBO_ANQP = "RX-MBO-ANQP"
RX_VENUE_URL = "RX-VENUE-URL"
RX_PROBE_REQUEST = "RX-PROBE-REQUEST"

## radio resource measurement
RRM_NEIGHBOR_REP_RECEIVED = "RRM-NEIGHBOR-REP-RECEIVED"
RRM_NEIGHBOR_REP_REQUEST_FAILED = "RRM-NEIGHBOR-REP-REQUEST-FAILED"

## beacon reports
BEACON_REQ_TX_STATUS = "BEACON-REQ-TX-STATUS"
BEACON_RESP_RX = "BEACON-RESP-RX"

## link measurement
LINK_MSR_RESP_RX = "LINK-MSR-RESP-RX"

## Multi Band Operation
MBO_CELL_PREFERENCE = "MBO-CELL-PREFERENCE"
MBO_TRANSITION_REASON = "MBO-TRANSITION-REASON"

## BSS transition management
BSS_TM_QUERY = "BSS-TM-QUERY"
BSS_TM_RESP = "BSS-TM-RESP"

## co-located interference reporting
COLOC_INTF_REQ = "COLOC-INTF-REQ"
COLOC_INTF_REPORT = "COLOC-INTF-REPORT"

## dynamic frequency selection
DFS_RADAR_DETECTED = "DFS-RADAR-DETECTED"
DFS_NEW_CHANNEL = "DFS-NEW-CHANNEL"
DFS_CAC_START = "DFS-CAC-START"
DFS_CAC_COMPLETED = "DFS-CAC-COMPLETED"
DFS_NOP_FINISHED = "DFS-NOP-FINISHED"
DFS_PRE_CAC_EXPIRED = "DFS-PRE-CAC-EXPIRED"

## automatic channel selection
ACS_STARTED = "ACS-STARTED"
ACS_COMPLETED = "ACS-COMPLETED"
ACS_FAILED = "ACS-FAILED"

## automated frequency coordination
AFC_EVENT_RECEIVED = "AFC-EVENT-RECEIVED"
AFC_EVENT_COMPLETE = "AFC-EVENT-COMPLETE"

## credential changes
CRED_ADDED = "CRED-ADDED"
CRED_MODIFIED = "CRED-MODIFIED"
CRED_REMOVED = "CRED-REMOVED"

## traffic specification
TSPEC_ADDED = "TSPEC-ADDED"
TSPEC_REMOVED = "TSPEC-REMOVED"
TSPEC_REQ_FAILED = "TSPEC-REQ-FAILED"

## PMKSA cache
PMKSA_CACHE_ADDED = "PMKSA-CACHE-ADDED"
PMKSA_CACHE_REMOVED = "PMKSA-CACHE-REMOVED"

## interface state
INTERFACE_ENABLED = "INTERFACE-ENABLED"
INTERFACE_DISABLED = "INTERFACE-DISABLED"

## externally scheduled radio work
EXT_RADIO_WORK_START = "EXT-RADIO-WORK-START"
EXT_RADIO_WORK_TIMEOUT = "EXT-RADIO-WORK-TIMEOUT"

## EAP layer
EAP_ERROR_CODE = "EAP-ERROR-CODE"

## fast initial link setup
FILS_HLP_RX = "FILS-HLP-RX"

## IBSS RSN
IBSS_RSN_COMPLETED = "IBSS-RSN-COMPLETED"

## ESS disassociation
ESS_DISASSOC_IMMINENT = "ESS-DISASSOC-IMMINENT"

## operating channel validation
OCV_FAILURE = "OCV-FAILURE"

## pre-association security negotiation
PASN_AUTH_STATUS = "PASN-AUTH-STATUS"

## transition disable
TRANSITION_DISABLE = "TRANSITION-DISABLE"

## Wi-Fi Alliance capability signalling
WFA_GEN_CAPAB = "WFA-GEN-CAPAB"


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

    ## The key=value pairs in params, for the events that carry them -
    #  see parse_params() for what a payload without any yields
    @property
    def variables(self) -> Dict[str, str]:
        return parse_params(self.params)


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


## Split a payload on spaces, except inside a quoted span, where a space
#  is content and \" is an escaped quote rather than the closing one
def _split_params(text: str) -> List[str]:
    tokens = []
    current = []
    quoted = False
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif quoted and char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            quoted = not quoted
        elif char == " " and not quoted:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


## Parse the space-separated key=value pairs an event payload carries -
#  the reading inverse of format_params(), for payloads like
#
#      dst=02:00:00:00:03:00 freq=2412 type=11
#      id=0 ssid="two words" auth_failures=1 duration=10 reason=WRONG_KEY
#
#  A quoted value keeps its spaces and loses only the quotes; the content
#  is untouched, so a printf-escaped SSID stays escaped and
#  Ssid.from_printf() applies. A token without an "=" is skipped rather
#  than guessed at, exactly as parse_variables() treats such lines - a
#  prose payload (DPP-FAIL) or a bare value (DPP-NETWORK-ID) yields an
#  empty dict and no error, and Event.params still holds the text.
#
#  Substring checks against params cannot say this: "type=11" in params
#  also matches type=110 and subtype=11, where parse_params(params)
#  .get("type") == "11" matches exactly one thing
# @param params the payload, i.e. Event.params
# @return the pairs, in payload order, the last occurrence of a key
#         winning
def parse_params(params: str) -> Dict[str, str]:
    variables = {}
    for token in _split_params(params):
        key, sep, value = token.partition("=")
        if not sep or not key:
            continue
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        variables[key] = value
    return variables


## Shared base of the typed event views: the payload's key=value pairs
#  as a dict of exactly what arrived, a NAME saying which event the view
#  reads, and typed properties on each subclass for the fields worth
#  typing. Views exist only for events with a real consumer; everything
#  else stays raw in Event.params
class _EventView(_Variables):

    ## The event name this view reads
    NAME = ""

    ## The view over an event's payload
    # @param event a parsed event named NAME
    # @return the view
    # @raises ValueError for an event of a different name, which would
    #         otherwise read as a payload whose every field is absent -
    #         a silent kind of wrong
    @classmethod
    def from_event(cls, event: Event) -> '_EventView':
        if event.name != cls.NAME:
            raise ValueError(f"{event.name} is not {cls.NAME}")
        return cls(parse_params(event.params))


## CTRL-EVENT-DISCONNECTED: the association ended.
#
#  The wire carries bssid= and reason=, and locally_generated=1 only when
#  this side ended it - so locally_generated is a plain bool, absence
#  meaning the AP's doing
class Disconnected(_EventView):

    NAME = "CTRL-EVENT-DISCONNECTED"

    @property
    def bssid(self) -> Optional[str]:
        return self.get("bssid")

    ## The 802.11 reason code
    @property
    def reason(self) -> Optional[int]:
        return self._int("reason")

    ## True when this side ended the association rather than the AP
    @property
    def locally_generated(self) -> bool:
        return self.get("locally_generated") == "1"


## CTRL-EVENT-SSID-TEMP-DISABLED: the daemon has given up on a network
#  for a while.
#
#  The event that says why joining failed, emitted when the daemon stops
#  trying rather than once per attempt - reason=WRONG_KEY is the
#  wrong-passphrase signal a joining UI wants, and auth_failures tells
#  one fat-fingered attempt from a systematically refused association.
#  The ssid value arrives quoted and printf-escaped; ssid_bytes undoes
#  both
class SsidTempDisabled(_EventView):

    NAME = "CTRL-EVENT-SSID-TEMP-DISABLED"

    ## The network id, as LIST_NETWORKS spells it
    @property
    def id(self) -> Optional[int]:
        return self._int("id")

    ## The name as the octet string it is - see ScanResult.ssid_bytes
    @property
    def ssid_bytes(self) -> Optional[Ssid]:
        value = self.get("ssid")
        return None if value is None else Ssid.from_printf(value)

    ## The name as text when its bytes are UTF-8 - see Ssid.text
    @property
    def ssid_text(self) -> Optional[str]:
        value = self.ssid_bytes
        return None if value is None else value.text

    ## Failed attempts before the daemon gave up
    @property
    def auth_failures(self) -> Optional[int]:
        return self._int("auth_failures")

    ## Seconds the network stays disabled
    @property
    def duration(self) -> Optional[int]:
        return self._int("duration")

    ## Why, as the daemon spells it: WRONG_KEY, AUTH_FAILED, CONN_FAILED
    #  or NO_PSK_AVAILABLE
    @property
    def reason(self) -> Optional[str]:
        return self.get("reason")
