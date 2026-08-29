## @package wpa_ctrl.errors
#
# Exceptions raised by the wpa_supplicant control interface client.
#
# @file errors.py


## Base for every failure this package raises
class WpaCtrlError(Exception):
    pass


## The control socket could not be opened - wpa_supplicant is not running,
#  the interface does not exist, or this process cannot reach the socket
class WpaCtrlConnectionError(WpaCtrlError):
    pass


## No reply arrived within the timeout. The request may still have been
#  acted on: the control interface gives no way to know
class WpaCtrlTimeout(WpaCtrlError):
    pass


## wpa_supplicant answered, and the answer was a refusal
# @param command the command that was refused
# @param reply what came back (FAIL, UNKNOWN COMMAND, ...)
class WpaCtrlCommandFailed(WpaCtrlError):
    def __init__(self, command: str, reply: str):
        super().__init__(f"{command!r} failed: {reply.strip()!r}")
        self.command = command
        self.reply = reply
