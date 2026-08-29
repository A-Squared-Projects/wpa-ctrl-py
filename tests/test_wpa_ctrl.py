## @package tests.test_wpa_ctrl
#
# Unit tests for the pure-Python wpa_supplicant control interface client.
#
# These drive a fake supplicant over a real UNIX datagram socket rather than
# mocking the socket out: the framing is the part most likely to be wrong,
# and a mock would assert my own assumptions back at me.
#
# @file test_wpa_ctrl.py

import os
import shutil
import tempfile
import unittest
from unittest import TestCase

from fake_supplicant import FakeSupplicant

from wpa_ctrl import (
    HOSTAPD_CTRL_DIR,
    Event,
    WpaCtrl,
    WpaCtrlCommandFailed,
    WpaCtrlConnectionError,
    WpaCtrlTimeout,
    compat,
    interface_path,
    parse_event,
    quote,
)


def setUpModule():
    print(__name__ + " set up")

def tearDownModule():
    print(__name__ + " tear down")
    print()


class WpaCtrlTestCase(TestCase):

    ## Short paths on purpose: AF_UNIX addresses are limited to about 104
    #  bytes, and the default temp directory on some hosts eats most of that
    def setUp(self):
        self.directory = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.socket_path = os.path.join(self.directory, "wlan0")
        self.server = None

    def start_server(self, replies: dict) -> FakeSupplicant:
        self.server = FakeSupplicant(self.socket_path, replies)
        self.addCleanup(self.server.stop)
        return self.server

    def make_client(self, **kwargs) -> WpaCtrl:
        client = WpaCtrl(path=self.socket_path, client_dir=self.directory,
                         timeout=2.0, **kwargs)
        self.addCleanup(client.close)
        return client


class TestRequestReply(WpaCtrlTestCase):

    def test_ping(self):
        self.start_server({"PING": "PONG\n"})
        self.assertTrue(self.make_client().ping())

    def test_ok_command(self):
        server = self.start_server({"DISCONNECT": "OK\n"})
        self.make_client().disconnect()
        self.assertEqual(server.received, ["DISCONNECT"])

    ## A refusal is an exception, so a caller cannot skip past it by
    #  accident - that was easy to do with the (success, output) pairs
    def test_fail_raises(self):
        self.start_server({"SAVE_CONFIG": "FAIL\n"})
        with self.assertRaises(WpaCtrlCommandFailed):
            self.make_client().save_config()

    def test_try_command_returns_false_instead_of_raising(self):
        self.start_server({"SAVE_CONFIG": "FAIL\n"})
        self.assertFalse(self.make_client().try_command("SAVE_CONFIG"))

    def test_timeout_when_nothing_answers(self):
        self.start_server({})  # accepts, never replies
        client = self.make_client()
        with self.assertRaises(WpaCtrlTimeout):
            client.request("STATUS", timeout=0.2)

    def test_missing_socket_is_a_connection_error(self):
        client = WpaCtrl(path=os.path.join(self.directory, "absent"),
                         client_dir=self.directory)
        with self.assertRaises(WpaCtrlConnectionError):
            client.ping()

    ## The client's own socket is an artefact on disk; it must not be left
    #  behind, or /tmp fills up one connection at a time
    def test_client_socket_is_cleaned_up(self):
        self.start_server({"PING": "PONG\n"})
        client = self.make_client()
        client.ping()
        self.assertEqual(len(os.listdir(self.directory)), 2)
        client.close()
        self.assertEqual(os.listdir(self.directory), ["wlan0"])


class TestParsing(WpaCtrlTestCase):

    def test_status(self):
        self.start_server({"STATUS": "bssid=02:00:01:02:03:04\nssid=example\n"
                                     "wpa_state=COMPLETED\n"})
        status = self.make_client().status()
        self.assertEqual(status["wpa_state"], "COMPLETED")
        self.assertEqual(status["ssid"], "example")

    def test_status_verbose_uses_the_other_command(self):
        server = self.start_server({"STATUS-VERBOSE": "wpa_state=COMPLETED\n"})
        self.make_client().status(verbose=True)
        self.assertEqual(server.received, ["STATUS-VERBOSE"])

    def test_list_networks(self):
        self.start_server({"LIST_NETWORKS":
                           "network id / ssid / bssid / flags\n"
                           "0\texample network\tany\t[CURRENT]\n"
                           "1\tother\tany\t[DISABLED]\n"})
        networks = self.make_client().list_networks()
        self.assertEqual([n.id for n in networks], [0, 1])
        self.assertEqual(networks[0].ssid, "example network")
        self.assertTrue(networks[0].current)
        self.assertFalse(networks[0].disabled)
        self.assertTrue(networks[1].disabled)

    ## The SSID is the last column of a scan result, so a separator inside
    #  it has to be rejoined rather than truncating the name. wpa_supplicant
    #  escapes control characters on its way out, so this is belt and braces
    def test_ssid_containing_a_tab_survives(self):
        self.start_server({"SCAN_RESULTS":
                           "bssid / frequency / signal level / flags / ssid\n"
                           "00:11:22:33:44:55\t2412\t-45\t[]\ttabbed\tname\n"})
        results = self.make_client().scan_results()
        self.assertEqual(results[0].ssid, "tabbed\tname")

    def test_scan_results(self):
        self.start_server({"SCAN_RESULTS":
                           "bssid / frequency / signal level / flags / ssid\n"
                           "00:09:5b:95:e0:4e\t2412\t-45\t[WPA2-PSK-CCMP]\t"
                           "jkm private\n"})
        results = self.make_client().scan_results()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].bssid, "00:09:5b:95:e0:4e")
        self.assertEqual(results[0].frequency, 2412)
        self.assertEqual(results[0].signal_level, -45)
        self.assertEqual(results[0].ssid, "jkm private")

    def test_pmksa(self):
        self.start_server({"PMKSA":
                           "Index / AA / PMKID / expiration (in seconds) / opportunistic\n"
                           "1 / 02:00:01:02:03:04 / "
                           "000102030405060708090a0b0c0d0e0f / 41362 / 0\n"})
        entries = self.make_client().pmksa()
        self.assertEqual(entries[0].index, 1)
        self.assertEqual(entries[0].expiration, 41362)

    def test_add_network_returns_the_id(self):
        self.start_server({"ADD_NETWORK": "3\n"})
        self.assertEqual(self.make_client().add_network(), 3)

    def test_add_network_failure_raises(self):
        self.start_server({"ADD_NETWORK": "FAIL\n"})
        with self.assertRaises(WpaCtrlCommandFailed):
            self.make_client().add_network()

    def test_get_capability(self):
        self.start_server({"GET_CAPABILITY eap": "TLS PEAP TTLS\n"})
        self.assertEqual(self.make_client().get_capability("eap"),
                         ["TLS", "PEAP", "TTLS"])

    def test_interfaces(self):
        self.start_server({"INTERFACES": "wlan0\nwlan1\n"})
        self.assertEqual(self.make_client().interfaces(), ["wlan0", "wlan1"])

    ## Rows that make no sense are dropped, not raised: a caller asking for
    #  scan results wants the ones that parsed
    def test_unparsable_rows_are_skipped(self):
        self.start_server({"SCAN_RESULTS":
                           "bssid / frequency / signal level / flags / ssid\n"
                           "00:11:22:33:44:55\tnot-a-number\t-45\t[]\tone\n"
                           "00:11:22:33:44:66\t2412\t-45\t[]\ttwo\n"})
        results = self.make_client().scan_results()
        self.assertEqual([r.ssid for r in results], ["two"])


class TestNetworkCommands(WpaCtrlTestCase):

    def test_set_network_quotes_on_request(self):
        server = self.start_server({
            'SET_NETWORK 0 ssid "example"': "OK\n",
            "SET_NETWORK 0 key_mgmt NONE": "OK\n",
            })
        client = self.make_client()
        client.set_network(0, "ssid", "example", quoted=True)
        client.set_network(0, "key_mgmt", "NONE")
        self.assertEqual(server.received,
                         ['SET_NETWORK 0 ssid "example"',
                          "SET_NETWORK 0 key_mgmt NONE"])

    ## A quote or backslash in a passphrase must not end the quoted string
    def test_quote_escapes(self):
        self.assertEqual(quote('say "hi"'), '"say \\"hi\\""')
        self.assertEqual(quote("back\\slash"), '"back\\\\slash"')

    def test_select_enable_disable_remove(self):
        server = self.start_server({
            "SELECT_NETWORK 1": "OK\n",
            "ENABLE_NETWORK all": "OK\n",
            "DISABLE_NETWORK 1": "OK\n",
            "REMOVE_NETWORK all": "OK\n",
            })
        client = self.make_client()
        client.select_network(1)
        client.enable_network("all")
        client.disable_network(1)
        client.remove_network("all")
        self.assertEqual(len(server.received), 4)


class TestEvents(WpaCtrlTestCase):

    def test_parse_event_priority_and_name(self):
        event = parse_event("<3>CTRL-EVENT-CONNECTED - Connection to 00:11 completed\n")
        self.assertEqual(event.priority, 3)
        self.assertEqual(event.name, "CTRL-EVENT-CONNECTED")
        self.assertIn("Connection to", event.params)
        self.assertFalse(event.is_request)

    def test_parse_event_without_priority(self):
        event = parse_event("CTRL-EVENT-SCAN-RESULTS \n")
        self.assertEqual(event.name, "CTRL-EVENT-SCAN-RESULTS")

    def test_request_for_user_input_is_flagged(self):
        event = parse_event("<3>CTRL-REQ-PASSWORD-1:Password needed for SSID foo")
        self.assertTrue(event.is_request)

    def test_attach_then_receive(self):
        server = self.start_server({"ATTACH": "OK\n"})
        client = self.make_client()
        client.attach()
        self.assertTrue(client.attached)
        server.send_event("<3>CTRL-EVENT-CONNECTED - Connection completed")
        event = client.next_event(timeout=2)
        self.assertIsInstance(event, Event)
        self.assertEqual(event.name, "CTRL-EVENT-CONNECTED")

    def test_no_event_returns_none(self):
        self.start_server({"ATTACH": "OK\n"})
        client = self.make_client()
        client.attach()
        self.assertIsNone(client.next_event(timeout=0.1))

    ## The reason a single attached connection is usable for both: an event
    #  landing between a command and its reply must not be handed back as
    #  the reply
    def test_event_arriving_mid_command_is_not_mistaken_for_the_reply(self):
        def status_preceded_by_an_event(command):
            self.server.send_event("<3>CTRL-EVENT-SCAN-RESULTS ")
            return "wpa_state=COMPLETED\n"

        self.start_server({"STATUS": status_preceded_by_an_event})
        client = self.make_client()
        status = client.status()
        self.assertEqual(status["wpa_state"], "COMPLETED")
        # ...and the event is still there to be collected afterwards
        self.assertEqual(client.next_event().name, "CTRL-EVENT-SCAN-RESULTS")


class TestCompatLayer(WpaCtrlTestCase):

    def setUp(self):
        super().setUp()
        self.addCleanup(compat.close_all)

    def _client_for(self, replies):
        self.start_server(replies)
        client = self.make_client()
        compat._clients["wlan0"] = client
        return client

    def test_ok_returns_true_and_no_output(self):
        self._client_for({"disconnect": "OK\n"})
        self.assertEqual(compat.execute_command("disconnect"), (True, None))

    def test_data_reply_returns_the_text(self):
        self._client_for({"status": "wpa_state=COMPLETED\n"})
        success, output = compat.execute_command("status")
        self.assertTrue(success)
        self.assertEqual(output, "wpa_state=COMPLETED")

    def test_fail_returns_false(self):
        self._client_for({"save_config": "FAIL\n"})
        self.assertEqual(compat.execute_command("save_config"), (False, None))

    ## The wpa_cli wrapper called os._exit(1) here to trigger the watchdog.
    #  A library must not: the caller decides
    def test_unreachable_daemon_returns_false_rather_than_exiting(self):
        compat._clients["wlan0"] = WpaCtrl(
            path=os.path.join(self.directory, "absent"), client_dir=self.directory)
        self.assertEqual(compat.execute_command("status"), (False, None))

    def test_arguments_are_joined_like_wpa_cli(self):
        self._client_for({'set_network 0 ssid "example"': "OK\n"})
        self.assertEqual(
            compat.execute_command("set_network", 0, "ssid", '"example"'),
            (True, None))
        self.assertEqual(self.server.received, ['set_network 0 ssid "example"'])


class TestInterfacePath(TestCase):

    def test_default_directory(self):
        self.assertEqual(interface_path("wlan0"),
                         "/var/run/wpa_supplicant/wlan0")

    def test_explicit_directory(self):
        self.assertEqual(interface_path("wlan0", "/run/wpa_supplicant"),
                         "/run/wpa_supplicant/wlan0")

    ## hostapd speaks the same protocol from a different directory, per
    #  CONFIG_CTRL_IFACE_DIR in hostapd_cli.c
    def test_hostapd_directory(self):
        self.assertEqual(interface_path("wlan0", HOSTAPD_CTRL_DIR),
                         "/var/run/hostapd/wlan0")


if __name__ == '__main__':
    unittest.main()
