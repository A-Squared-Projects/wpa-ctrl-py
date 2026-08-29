## @package wpa_ctrl.discovery
#
# Finding the interfaces to talk to, rather than hardcoding a name.
#
# "wlan0" is a default, not a promise: udev rules, systemd's predictable
# names and plain administrative renames all produce something else, and
# wpa_supplicant is equally happy managing several interfaces at once.
#
# The question this package can answer authoritatively is which interfaces
# have a control socket - control_sockets(), or a global socket's INTERFACES
# command. Nothing else knows that.
#
# Whether an interface is wireless is the kernel's question, not this
# package's, and is_wireless() here is a two-line sysfs check rather than a
# real answer: anything richer - interface type, phy, whether it is a P2P
# device - wants nl80211 through pyroute2 or iw. It is offered because it is
# cheap and sometimes all a caller needs, and it is opt-in.
#
# Notably it is NOT how find_interfaces() filters, because wpa_supplicant
# also handles wired 802.1X: a control socket can legitimately belong to an
# ethernet interface, and filtering those out by default would hide an
# interface this library can talk to perfectly well.
#
# @file discovery.py

import logging
import os
import stat
from typing import List, Optional

from .client import WpaCtrl
from .errors import WpaCtrlError
from .transport import DEFAULT_CTRL_DIR

logger = logging.getLogger(__name__)

## Where the kernel publishes its network interfaces
SYS_CLASS_NET = "/sys/class/net"
## The marker for a cfg80211 device. Preferred over the wireless/ directory,
#  which comes from wireless-extensions compatibility and is absent on a
#  kernel built without it
PHY80211 = "phy80211"


## Interfaces with a control socket in a directory, i.e. the ones this
#  library can actually connect to.
#
#  Entries are checked with stat rather than trusted by name: a crashed
#  daemon can leave something behind, and a plain file in this directory is
#  not something to hand to a caller as an interface
# @param ctrl_dir directory wpa_supplicant was told to use
# @return the interface names, sorted
def control_sockets(ctrl_dir: str = DEFAULT_CTRL_DIR) -> List[str]:
    try:
        entries = os.listdir(ctrl_dir)
    except OSError as ex:
        # No directory at all is the normal state when wpa_supplicant is not
        # running, or was pointed somewhere else - not an error here
        logger.debug(f"No control sockets in {ctrl_dir}: {ex}")
        return []

    names = []
    for entry in entries:
        path = os.path.join(ctrl_dir, entry)
        try:
            if stat.S_ISSOCK(os.stat(path).st_mode):
                names.append(entry)
        except OSError:
            # Vanished between listing and stat, or unreadable
            continue
    return sorted(names)


## True if an interface is a wireless device, according to the kernel.
#
#  Returns False when sysfs says the interface is not wireless AND when
#  there is no sysfs to ask - callers that need to tell those apart should
#  use have_sysfs()
# @param ifname the interface name
# @param sys_class_net override the sysfs location, for testing
def is_wireless(ifname: str, sys_class_net: str = SYS_CLASS_NET) -> bool:
    # lexists, not exists: phy80211 is a symlink into /sys/devices, and what
    # matters is that the kernel published it. exists() follows the link and
    # would answer "not wireless" for a device whose target is momentarily
    # unresolvable, e.g. one being torn down
    return os.path.lexists(os.path.join(sys_class_net, ifname, PHY80211))


## Wireless interfaces this kernel has, whether or not wpa_supplicant is
#  managing them
# @param sys_class_net override the sysfs location, for testing
# @return the interface names, sorted
def wireless_interfaces(sys_class_net: str = SYS_CLASS_NET) -> List[str]:
    try:
        entries = os.listdir(sys_class_net)
    except OSError as ex:
        logger.debug(f"No sysfs at {sys_class_net}: {ex}")
        return []
    return sorted(entry for entry in entries
                  if is_wireless(entry, sys_class_net))


## True if this system publishes interfaces in sysfs at all.
#
#  Worth asking before reading anything into an empty wireless_interfaces():
#  a container without /sys mounted, or a machine that is not Linux, answers
#  "no wireless interfaces" to a question it cannot actually hear
# @param sys_class_net override the sysfs location, for testing
def have_sysfs(sys_class_net: str = SYS_CLASS_NET) -> bool:
    return os.path.isdir(sys_class_net)


## The interfaces worth connecting to.
#
#  Prefers wpa_supplicant's own account of itself - the global control
#  socket, if this daemon was started with one (-g) - and otherwise reads
#  the control directory. Either way the answer is what has a control
#  socket, because that is what can be talked to.
#
#  Interfaces the kernel has never heard of are dropped: a socket outliving
#  its interface is a leftover, not something to hand back. That is an
#  existence check, deliberately not a wireless one - wpa_supplicant handles
#  wired 802.1X, so an ethernet interface with a control socket is a real
#  interface this library can talk to. Pass wireless_only to filter those
#  out anyway.
#
#  Both checks need sysfs, and where there is none - a container without
#  /sys, a host that is not Linux - they are skipped rather than applied
#  blind: "cannot tell" must not be reported as "none".
#
# @param ctrl_dir directory wpa_supplicant was told to use
# @param global_path the global control socket, if there is one
# @param wireless_only also drop interfaces the kernel says are not wireless
# @param sys_class_net override the sysfs location, for testing
# @return the interface names, sorted
def find_interfaces(ctrl_dir: str = DEFAULT_CTRL_DIR,
                    global_path: Optional[str] = None,
                    wireless_only: bool = False,
                    sys_class_net: str = SYS_CLASS_NET) -> List[str]:
    names = []
    if global_path:
        names = _interfaces_from_global(global_path)
    if not names:
        names = control_sockets(ctrl_dir)

    if have_sysfs(sys_class_net):
        names = [name for name in names
                 if _interface_exists(name, sys_class_net)
                 and (not wireless_only or is_wireless(name, sys_class_net))]
    return sorted(names)


## True if the kernel currently has an interface by this name
def _interface_exists(ifname: str, sys_class_net: str) -> bool:
    return os.path.isdir(os.path.join(sys_class_net, ifname))


## Ask a global control socket which interfaces it has. Failure to reach it
#  is not fatal: the caller falls back to reading the control directory
def _interfaces_from_global(global_path: str) -> List[str]:
    try:
        with WpaCtrl(path=global_path) as control:
            return control.interfaces()
    except WpaCtrlError as ex:
        logger.debug(f"Global socket {global_path} unusable: {ex}")
        return []
