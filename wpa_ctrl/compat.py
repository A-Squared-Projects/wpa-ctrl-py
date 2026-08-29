## @package wpa_ctrl.compat
#
# A wpa_cli-shaped front end for code that currently shells out to it.
#
# execute_command() takes the same arguments and returns the same
# (success, output) pairs as the subprocess wrapper it replaces, so a caller
# can be repointed here without touching its parsing.
#
# @file compat.py

import logging
from typing import Optional, Tuple

from .client import REPLY_FAIL, REPLY_OK, REPLY_UNKNOWN, WpaCtrl
from .errors import WpaCtrlError

logger = logging.getLogger(__name__)

## Interface used when a caller does not name one, matching the -iwlan0 the
#  shell callers pass
DEFAULT_INTERFACE = "wlan0"

## One connection per interface, reused across calls. Opening a socket per
#  command would work, but every open binds and unlinks a file - the point
#  of this module is to stop paying that kind of cost per command
_clients = {}


## The shared connection for an interface, opened on first use
# @param ifname the interface to talk to
# @return the client
def get_client(ifname: str = DEFAULT_INTERFACE) -> WpaCtrl:
    client = _clients.get(ifname)
    if client is None:
        client = WpaCtrl(ifname)
        _clients[ifname] = client
    return client


## Close and forget any connections held by this module
def close_all():
    while _clients:
        _, client = _clients.popitem()
        try:
            client.close()
        except WpaCtrlError as ex:
            logger.warning(f"Closing {client.path} failed: {ex}")


## Run one control interface command, wpa_cli style.
#
#  Deliberately different from the wpa_cli wrapper in one way: that one
#  called os._exit(1) when the subprocess raised, to get the watchdog to
#  reboot the device. A library is the wrong place to decide that, so this
#  returns (False, None) and lets the caller choose. Anything relying on the
#  old behaviour needs to make that policy explicit at the call site.
#
# @param cmd_args the command and its arguments, e.g. ("set_network", "0",
#        "ssid", '"example"')
# @param no_logging suppress logging of the command, for anything carrying a
#        credential
# @param ifname the interface to talk to
# @return (True, None) for OK, (True, output) for a data reply, and
#         (False, None) for FAIL or any error reaching the daemon
def execute_command(*cmd_args, no_logging: bool = False,
                    ifname: str = DEFAULT_INTERFACE) -> Tuple[bool, Optional[str]]:
    # The control interface is case sensitive and answers UNKNOWN COMMAND to
    # anything else, but wpa_cli lets you type commands in lower case and
    # sends the canonical form. Callers moving off wpa_cli have lower case
    # spelled through their code, so do what wpa_cli did.
    #
    # The verb only. Everything after it is data - network ids, variable
    # names like ssid and key_mgmt, which wpa_supplicant wants in lower
    # case, and values like an SSID or a passphrase, where changing the case
    # would change the credential
    command = " ".join(str(arg) for arg in cmd_args)
    verb, separator, remainder = command.partition(" ")
    command = verb.upper() + separator + remainder
    if not no_logging:
        logger.debug(command)
    try:
        reply = get_client(ifname).request(command)
    except WpaCtrlError as ex:
        logger.error(f"Control interface command failed: {ex}")
        return False, None

    output = reply.rstrip("\n")
    # FAIL, FAIL-BUSY and friends, and UNKNOWN COMMAND. The last one is a
    # refusal too, and reporting it as a successful reply hands the caller a
    # string where it expected data
    if output.startswith(REPLY_FAIL) or output.startswith(REPLY_UNKNOWN):
        logger.warning(f"Control interface command result: {output}")
        return False, None
    if output == REPLY_OK:
        return True, None
    return True, output
