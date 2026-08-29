## @package tests.test_discovery
#
# Unit tests for interface discovery.
#
# The point of this module is that "wlan0" is a default rather than a
# promise, so the tests use names that are not wlan0 wherever the name does
# not matter - a hardcoded assumption should fail here, not on a renamed
# device.
#
# @file test_discovery.py

import os
import shutil
import socket
import tempfile
import unittest
from unittest import TestCase

from fake_supplicant import FakeSupplicant

from wpa_ctrl import control_sockets, find_interfaces, have_sysfs, is_wireless, wireless_interfaces


def setUpModule():
    print(__name__ + " set up")

def tearDownModule():
    print(__name__ + " tear down")
    print()


class DiscoveryTestCase(TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.ctrl_dir = os.path.join(self.root, "ctrl")
        self.sys_class_net = os.path.join(self.root, "net")
        os.mkdir(self.ctrl_dir)
        os.mkdir(self.sys_class_net)
        self.sockets = []

    ## Put a real socket in the control directory, as wpa_supplicant would
    def add_socket(self, ifname: str):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(os.path.join(self.ctrl_dir, ifname))
        self.sockets.append(sock)
        self.addCleanup(sock.close)

    ## Add an interface to the fake sysfs, wireless or not
    def add_interface(self, ifname: str, wireless: bool):
        path = os.path.join(self.sys_class_net, ifname)
        os.mkdir(path)
        if wireless:
            os.symlink("../../ieee80211/phy0", os.path.join(path, "phy80211"))


class TestControlSockets(DiscoveryTestCase):

    def test_lists_sockets(self):
        self.add_socket("wlp2s0")
        self.add_socket("wlan1")
        self.assertEqual(control_sockets(self.ctrl_dir), ["wlan1", "wlp2s0"])

    ## A crashed daemon can leave things behind, and the directory is not
    #  necessarily ours alone - only sockets are interfaces
    def test_ignores_entries_that_are_not_sockets(self):
        self.add_socket("wlp2s0")
        open(os.path.join(self.ctrl_dir, "README"), "w").close()
        os.mkdir(os.path.join(self.ctrl_dir, "subdir"))
        self.assertEqual(control_sockets(self.ctrl_dir), ["wlp2s0"])

    ## wpa_supplicant not running is a normal state, not an error
    def test_missing_directory_is_empty_not_an_error(self):
        self.assertEqual(control_sockets(os.path.join(self.root, "absent")), [])


class TestSysfs(DiscoveryTestCase):

    def test_wireless_interfaces(self):
        self.add_interface("wlp2s0", wireless=True)
        self.add_interface("enp0s31f6", wireless=False)
        self.add_interface("lo", wireless=False)
        self.assertEqual(wireless_interfaces(self.sys_class_net), ["wlp2s0"])

    def test_is_wireless(self):
        self.add_interface("wlp2s0", wireless=True)
        self.add_interface("eth0", wireless=False)
        self.assertTrue(is_wireless("wlp2s0", self.sys_class_net))
        self.assertFalse(is_wireless("eth0", self.sys_class_net))
        self.assertFalse(is_wireless("nonexistent", self.sys_class_net))

    def test_have_sysfs(self):
        self.assertTrue(have_sysfs(self.sys_class_net))
        self.assertFalse(have_sysfs(os.path.join(self.root, "absent")))


class TestFindInterfaces(DiscoveryTestCase):

    ## wpa_supplicant handles wired 802.1X, so an ethernet interface with a
    #  control socket is a real interface this library can talk to. Filtering
    #  on wirelessness by default would hide it
    def test_a_wired_8021x_interface_is_not_dropped(self):
        self.add_socket("wlp2s0")
        self.add_socket("enp0s31f6")
        self.add_interface("wlp2s0", wireless=True)
        self.add_interface("enp0s31f6", wireless=False)
        self.assertEqual(
            find_interfaces(self.ctrl_dir, sys_class_net=self.sys_class_net),
            ["enp0s31f6", "wlp2s0"])

    def test_wireless_filter_is_available_opt_in(self):
        self.add_socket("wlp2s0")
        self.add_socket("enp0s31f6")
        self.add_interface("wlp2s0", wireless=True)
        self.add_interface("enp0s31f6", wireless=False)
        self.assertEqual(
            find_interfaces(self.ctrl_dir, wireless_only=True,
                            sys_class_net=self.sys_class_net),
            ["wlp2s0"])

    ## The decision worth locking in: with no sysfs to consult - a container
    #  with no /sys, or a host that is not Linux - the checks are skipped
    #  rather than applied blind. "Cannot tell" must not be reported as
    #  "none", which would silently strand a caller with no interfaces
    def test_without_sysfs_the_checks_are_skipped_not_applied(self):
        self.add_socket("wlp2s0")
        absent = os.path.join(self.root, "absent")
        self.assertEqual(find_interfaces(self.ctrl_dir, sys_class_net=absent),
                         ["wlp2s0"])
        self.assertEqual(
            find_interfaces(self.ctrl_dir, wireless_only=True,
                            sys_class_net=absent),
            ["wlp2s0"])

    ## A socket for an interface sysfs has never heard of is stale - the
    #  interface was renamed or removed and the daemon did not clean up.
    #  This is what the sysfs check is for, rather than wirelessness
    def test_stale_socket_for_an_absent_interface_is_dropped(self):
        self.add_socket("wlan0")
        self.add_interface("wlp2s0", wireless=True)
        self.add_socket("wlp2s0")
        self.assertEqual(
            find_interfaces(self.ctrl_dir, sys_class_net=self.sys_class_net),
            ["wlp2s0"])

    def test_prefers_the_global_socket_when_there_is_one(self):
        global_path = os.path.join(self.root, "global")
        server = FakeSupplicant(global_path, {"INTERFACES": "wlp2s0\nwlan1\n"})
        self.addCleanup(server.stop)
        self.add_interface("wlp2s0", wireless=True)
        self.add_interface("wlan1", wireless=True)
        # Nothing in the control directory at all: the answer comes from the
        # daemon, not the filesystem
        self.assertEqual(
            find_interfaces(self.ctrl_dir, global_path=global_path,
                            sys_class_net=self.sys_class_net),
            ["wlan1", "wlp2s0"])

    ## An unreachable global socket is not fatal - it is an optimisation
    #  over reading the directory, not a requirement
    def test_falls_back_to_the_directory_when_the_global_socket_is_dead(self):
        self.add_socket("wlp2s0")
        self.add_interface("wlp2s0", wireless=True)
        self.assertEqual(
            find_interfaces(self.ctrl_dir,
                            global_path=os.path.join(self.root, "no-global"),
                            sys_class_net=self.sys_class_net),
            ["wlp2s0"])


if __name__ == '__main__':
    unittest.main()
