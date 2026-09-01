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
import sys
import tempfile
import unittest
from unittest import TestCase

from fake_supplicant import FakeSupplicant

from wpa_ctrl import (
    HOSTAPD_CTRL_DIR,
    BssMask,
    Event,
    Ssid,
    WpaCtrl,
    WpaCtrlCommandFailed,
    WpaCtrlConnectionError,
    WpaCtrlTimeout,
    compat,
    interface_path,
    parse_event,
    printf_decode,
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

    ## Where the abstract namespace exists the client leaves nothing on
    #  disk at all, so there is nothing to leak when a process is killed
    #  outright - and no writable directory is needed
    @unittest.skipUnless(sys.platform.startswith("linux"),
                         "abstract sockets are Linux only")
    def test_no_file_is_created_on_linux(self):
        self.start_server({"PING": "PONG\n"})
        client = self.make_client()
        client.ping()
        self.assertEqual(os.listdir(self.directory), ["wlan0"])

    ## The client's own socket is an artefact on disk; it must not be left
    #  behind, or /tmp fills up one connection at a time
    @unittest.skipIf(sys.platform.startswith("linux"),
                     "on Linux the address is abstract, not a file")
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

    ## The probe SAE support turns on: a build without CONFIG_SAE simply
    ## does not list it, and setting key_mgmt SAE on one fails
    def test_supports_key_mgmt(self):
        self.start_server({"GET_CAPABILITY key_mgmt":
                           "WPA-PSK WPA-EAP IEEE8021X NONE WPA-NONE FT-PSK "
                           "FT-EAP SAE FT-SAE OWE DPP\n"})
        client = self.make_client()
        self.assertTrue(client.supports_key_mgmt("SAE"))
        self.assertFalse(client.supports_key_mgmt("WPA-PSK-SHA256"))

    def test_supports_key_mgmt_on_a_build_without_sae(self):
        self.start_server({"GET_CAPABILITY key_mgmt":
                           "WPA-PSK WPA-EAP IEEE8021X NONE WPA-NONE\n"})
        self.assertFalse(self.make_client().supports_key_mgmt("SAE"))

    def test_interfaces(self):
        self.start_server({"INTERFACES": "wlan0\nwlan1\n"})
        self.assertEqual(self.make_client().interfaces(), ["wlan0", "wlan1"])

    def test_scan_result_ssid_decoding(self):
        self.start_server({"SCAN_RESULTS":
                           "bssid / frequency / signal level / flags / ssid\n"
                           "00:11:22:33:44:55\t2412\t-45\t[]\tCaf\\xc3\\xa9\n"})
        result = self.make_client().scan_results()[0]
        self.assertIsInstance(result.ssid_bytes, Ssid)
        self.assertEqual(result.ssid_bytes, "Café".encode())
        self.assertEqual(result.ssid_text, "Café")

    ## Rows that make no sense are dropped, not raised: a caller asking for
    #  scan results wants the ones that parsed
    def test_unparsable_rows_are_skipped(self):
        self.start_server({"SCAN_RESULTS":
                           "bssid / frequency / signal level / flags / ssid\n"
                           "00:11:22:33:44:55\tnot-a-number\t-45\t[]\tone\n"
                           "00:11:22:33:44:66\t2412\t-45\t[]\ttwo\n"})
        results = self.make_client().scan_results()
        self.assertEqual([r.ssid for r in results], ["two"])


## The BSS FIRST / BSS NEXT-<id> walk that wpa_cli's all_bss performs.
#  Ids are deliberately not contiguous in these fixtures - the daemon
#  assigns them for the life of a BSS entry, so a table that has seen any
#  expiry has holes, and a walk that counted instead of following ids
#  would fall into one
class TestIterBss(WpaCtrlTestCase):

    BSS_0 = ("id=0\nbssid=00:09:5b:95:e0:4e\nfreq=2412\nlevel=-45\n"
             "flags=[WPA2-PSK-CCMP][ESS]\nssid=jkm private\n")
    BSS_3 = ("id=3\nbssid=02:00:01:02:03:04\nfreq=5180\nlevel=-60\n"
             "flags=[SAE-CCMP][ESS]\nssid=other\n")

    def test_walks_by_id_until_the_reply_is_empty(self):
        server = self.start_server({"BSS FIRST": self.BSS_0,
                                    "BSS NEXT-0": self.BSS_3,
                                    "BSS NEXT-3": ""})
        table = list(self.make_client().iter_bss())
        self.assertEqual([info["ssid"] for info in table],
                         ["jkm private", "other"])
        self.assertEqual(server.received,
                         ["BSS FIRST", "BSS NEXT-0", "BSS NEXT-3"])

    def test_empty_table(self):
        self.start_server({"BSS FIRST": ""})
        self.assertEqual(list(self.make_client().iter_bss()), [])

    ## Each BSS is a round trip of its own, which is why this is a
    #  generator: a caller that stops stops the commands too
    def test_stopping_early_sends_no_further_commands(self):
        server = self.start_server({"BSS FIRST": self.BSS_0,
                                    "BSS NEXT-0": self.BSS_3,
                                    "BSS NEXT-3": ""})
        for info in self.make_client().iter_bss():
            self.assertEqual(info["ssid"], "jkm private")
            break
        self.assertEqual(server.received, ["BSS FIRST"])

    ## The walk is keyed on id, so a mask that leaves it out would end the
    #  walk after one BSS - ID is added rather than letting that happen
    def test_mask_is_sent_with_id_forced_in(self):
        server = self.start_server({"BSS FIRST MASK=0x7": self.BSS_0,
                                    "BSS NEXT-0 MASK=0x7": ""})
        table = list(self.make_client().iter_bss(mask=BssMask.BSSID | BssMask.FREQ))
        self.assertEqual(len(table), 1)
        self.assertEqual(server.received,
                         ["BSS FIRST MASK=0x7", "BSS NEXT-0 MASK=0x7"])

    ## A daemon answering NEXT with a BSS already seen is broken, but
    #  looping on it forever would be worse
    def test_a_repeated_id_ends_the_walk(self):
        self.start_server({"BSS FIRST": self.BSS_0,
                           "BSS NEXT-0": self.BSS_0})
        table = list(self.make_client().iter_bss())
        self.assertEqual(len(table), 1)

    def test_bss_takes_a_mask(self):
        server = self.start_server(
            {"BSS 00:09:5b:95:e0:4e MASK=0x1000": "ssid=jkm private\n"})
        info = self.make_client().bss("00:09:5b:95:e0:4e", mask=BssMask.SSID)
        self.assertEqual(info, {"ssid": "jkm private"})
        self.assertEqual(server.received, ["BSS 00:09:5b:95:e0:4e MASK=0x1000"])

    def test_bss_without_a_mask_sends_none(self):
        server = self.start_server({"BSS CURRENT": self.BSS_0})
        info = self.make_client().bss("CURRENT")
        self.assertEqual(info["bssid"], "00:09:5b:95:e0:4e")
        self.assertEqual(server.received, ["BSS CURRENT"])

    ## The reply is a Bss: still the dict of what the daemon sent, with
    #  typed properties over it - spelled as ScanResult spells them
    def test_bss_reply_is_typed(self):
        self.start_server({"BSS CURRENT": self.BSS_0})
        info = self.make_client().bss("CURRENT")
        self.assertIsInstance(info, dict)
        self.assertEqual(info.id, 0)
        self.assertEqual(info.bssid, "00:09:5b:95:e0:4e")
        self.assertEqual(info.frequency, 2412)
        self.assertEqual(info.signal_level, -45)
        self.assertEqual(info.ssid, "jkm private")
        self.assertTrue(info.security.psk)

    ## Fields carried as hex on the wire come back as their real types
    def test_hex_fields_are_decoded(self):
        self.start_server({"BSS CURRENT": "id=0\ncapabilities=0x0431\n"
                                          "ie=dd050050f20101\n"
                                          "wfd_subelems=000600411c440028\n"})
        info = self.make_client().bss("CURRENT")
        self.assertEqual(info.capabilities, 0x0431)
        self.assertEqual(info.ie, bytes.fromhex("dd050050f20101"))
        self.assertEqual(info.wfd_subelems, bytes.fromhex("000600411c440028"))

    def test_update_idx_and_mld_address(self):
        self.start_server({"BSS CURRENT": "id=0\nupdate_idx=42\n"
                                          "ap_mld_addr=02:00:01:02:03:04\n"})
        info = self.make_client().bss("CURRENT")
        self.assertEqual(info.update_idx, 42)
        self.assertEqual(info.ap_mld_addr, "02:00:01:02:03:04")

    ## Absent answers None, not a default: the mask decides what is
    #  reported, and "not asked for" must not read as a value - a missing
    #  flags field is not an open network
    def test_fields_the_mask_excluded_are_none(self):
        self.start_server({"BSS CURRENT MASK=0x2":
                           "bssid=02:00:01:02:03:04\n"})
        info = self.make_client().bss("CURRENT", mask=BssMask.BSSID)
        self.assertEqual(info.bssid, "02:00:01:02:03:04")
        self.assertIsNone(info.frequency)
        self.assertIsNone(info.security)

    ## An SSID is an octet string that the daemon escapes into ASCII on
    #  its way out. ssid_bytes undoes that; ssid_text reads the bytes as
    #  UTF-8, which a person's SSID almost always is
    def test_ssid_bytes_and_text(self):
        self.start_server({"BSS CURRENT": "id=0\nssid=Caf\\xc3\\xa9\n"})
        info = self.make_client().bss("CURRENT")
        self.assertEqual(info.ssid, "Caf\\xc3\\xa9")
        self.assertIsInstance(info.ssid_bytes, Ssid)
        self.assertEqual(info.ssid_bytes, "Café".encode())
        self.assertEqual(info.ssid_text, "Café")

    ## Arbitrary binary is a legal SSID. The bytes are always the truth;
    #  text answers None rather than a replacement-character rendering
    #  under which two different networks could look identical
    def test_binary_ssid_has_no_text(self):
        self.start_server({"BSS CURRENT": "id=0\nssid=\\x00\\xff\\xfe\n"})
        info = self.make_client().bss("CURRENT")
        self.assertEqual(info.ssid_bytes, b"\x00\xff\xfe")
        self.assertIsNone(info.ssid_text)


## The SSID type: octets first, text only when the octets are UTF-8
class TestSsid(TestCase):

    ## An Ssid is its octets - equal to, and hashing as, the plain bytes,
    #  so it drops into sets, dict keys and comparisons unannounced
    def test_is_its_bytes(self):
        self.assertEqual(Ssid(b"example"), b"example")
        self.assertIn(Ssid(b"example"), {b"example"})

    def test_from_printf(self):
        self.assertEqual(Ssid.from_printf("Caf\\xc3\\xa9"), "Café".encode())

    def test_text_reads_utf8(self):
        self.assertEqual(Ssid("Café".encode()).text, "Café")
        self.assertEqual(Ssid(b"plain").text, "plain")

    def test_text_refuses_what_is_not_utf8(self):
        self.assertIsNone(Ssid(b"\xff\xfe").text)

    ## The config side's three spellings: a quoted literal takes its bytes
    #  as they stand - no escape processing, content running to the last
    #  quote - P"..." adds the printf escapes, and anything else is hex
    def test_from_config(self):
        self.assertEqual(Ssid.from_config('"MyNet"'), b"MyNet")
        self.assertEqual(Ssid.from_config('"a\\x62c"'), b"a\\x62c")
        self.assertEqual(Ssid.from_config('"a"b"'), b'a"b')
        self.assertEqual(Ssid.from_config('P"a\\x00b"'), b"a\x00b")
        self.assertEqual(Ssid.from_config("4d794e6574"), b"MyNet")

    def test_from_config_refuses_what_the_daemon_would(self):
        for value in ('"unterminated', '"tail"x', "abc", "zz"):
            with self.assertRaises(ValueError):
                Ssid.from_config(value)

    ## The daemon's own rule when writing a config: quoted for printable
    #  ASCII, hex for everything else - UTF-8 included
    def test_config_value(self):
        self.assertEqual(Ssid(b"MyNet").config_value(), '"MyNet"')
        self.assertEqual(Ssid("Café".encode()).config_value(), "436166c3a9")
        self.assertEqual(Ssid(b"a\tb").config_value(), "610962")

    def test_config_value_round_trips(self):
        for octets in (b"MyNet", "Café".encode(), b"\x00\xff", b'a"b'):
            ssid = Ssid(octets)
            self.assertEqual(Ssid.from_config(ssid.config_value()), ssid)

    ## The use this exists for: the wire spelling (status, events, scan
    #  results) against the config spelling, compared as octets
    def test_wire_and_config_spellings_meet_as_octets(self):
        self.assertEqual(Ssid.from_printf("Caf\\xc3\\xa9"),
                         Ssid.from_config('"Café"'))
        self.assertEqual(Ssid.from_printf("Caf\\xc3\\xa9"),
                         Ssid.from_config("436166c3a9"))


## The inverse of the printf-style escaping the daemon applies to octet
#  strings on their way out. No server: this is a pure function
class TestPrintfDecode(TestCase):

    def test_printable_ascii_passes_through(self):
        self.assertEqual(printf_decode("plain name"), b"plain name")

    def test_named_escapes(self):
        self.assertEqual(printf_decode('a\\"b\\\\c\\e\\n\\r\\t'),
                         b'a"b\\c\x1b\n\r\t')

    def test_hex_escapes(self):
        self.assertEqual(printf_decode("Caf\\xc3\\xa9"), "Café".encode())
        self.assertEqual(printf_decode("\\x00\\xff"), b"\x00\xff")

    ## The daemon's decoder reads more than its encoder ever emits: a
    #  single-digit \xN, octal, an unknown escape standing for its
    #  character, a digitless \x or trailing backslash dropped. Both ends
    #  should read the wire the same way
    def test_dialect_edge_cases(self):
        self.assertEqual(printf_decode("\\x5z"), b"\x05z")
        self.assertEqual(printf_decode("\\xzz"), b"zz")
        self.assertEqual(printf_decode("\\q"), b"q")
        self.assertEqual(printf_decode("\\101\\60"), b"A0")
        self.assertEqual(printf_decode("\\0053"), b"\x053")
        self.assertEqual(printf_decode("end\\"), b"end")


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

    ## The reason the constants come from wpa_ctrl.h rather than the
    #  documentation: this one arrived on a live device during a scan and
    #  appears in neither doxygen file
    def test_undocumented_but_real_events_have_constants(self):
        from wpa_ctrl import events
        self.assertEqual(events.CTRL_EVENT_SCAN_STARTED,
                         "CTRL-EVENT-SCAN-STARTED")
        self.assertEqual(events.CTRL_EVENT_BSS_ADDED, "CTRL-EVENT-BSS-ADDED")
        self.assertEqual(events.AP_STA_CONNECTED, "AP-STA-CONNECTED")

    ## Every constant has to survive the round trip through the parser, or
    #  a caller comparing event.name against one of them silently never
    #  matches. Cheap to assert across the whole generated list
    def test_every_event_constant_parses_back_to_itself(self):
        from wpa_ctrl import events
        checked = 0
        for name in dir(events):
            value = getattr(events, name)
            if not name.isupper() or not isinstance(value, str):
                continue
            if value.endswith("-"):
                # A prefix rather than a whole name, e.g. CTRL-REQ-
                continue
            self.assertEqual(parse_event(f"<3>{value} params").name, value)
            checked += 1
        self.assertGreater(checked, 250, "the event list looks truncated")

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

    ## The control interface is case sensitive - lower case gets UNKNOWN
    #  COMMAND - and every caller migrating off wpa_cli has lower case
    #  spelled through its code, because wpa_cli accepted it
    def test_the_verb_is_sent_upper_case(self):
        self._client_for({"DISCONNECT": "OK\n"})
        self.assertEqual(compat.execute_command("disconnect"), (True, None))
        self.assertEqual(self.server.received, ["DISCONNECT"])

    ## Only the verb. A network id, a variable name like ssid or key_mgmt,
    #  and above all a value - an SSID or a passphrase - go through as they
    #  were given, because changing their case changes what they mean
    def test_arguments_keep_their_case(self):
        self._client_for({'SET_NETWORK 0 ssid "MyHome WiFi"': "OK\n"})
        self.assertEqual(
            compat.execute_command("set_network", 0, "ssid", '"MyHome WiFi"'),
            (True, None))
        self.assertEqual(self.server.received,
                         ['SET_NETWORK 0 ssid "MyHome WiFi"'])

    def test_ok_returns_true_and_no_output(self):
        self._client_for({"DISCONNECT": "OK\n"})
        self.assertEqual(compat.execute_command("disconnect"), (True, None))

    def test_data_reply_returns_the_text(self):
        self._client_for({"STATUS": "wpa_state=COMPLETED\n"})
        success, output = compat.execute_command("status")
        self.assertTrue(success)
        self.assertEqual(output, "wpa_state=COMPLETED")

    ## A refused command is not a successful reply carrying the word
    #  "UNKNOWN COMMAND" as its data
    def test_unknown_command_returns_false(self):
        self._client_for({"NO_SUCH_COMMAND": "UNKNOWN COMMAND\n"})
        self.assertEqual(compat.execute_command("no_such_command"),
                         (False, None))

    def test_fail_returns_false(self):
        self._client_for({"SAVE_CONFIG": "FAIL\n"})
        self.assertEqual(compat.execute_command("save_config"), (False, None))

    ## The wpa_cli wrapper called os._exit(1) here to trigger the watchdog.
    #  A library must not: the caller decides
    def test_unreachable_daemon_returns_false_rather_than_exiting(self):
        compat._clients["wlan0"] = WpaCtrl(
            path=os.path.join(self.directory, "absent"), client_dir=self.directory)
        self.assertEqual(compat.execute_command("status"), (False, None))

    def test_arguments_are_joined_like_wpa_cli(self):
        self._client_for({'SET_NETWORK 0 ssid "example"': "OK\n"})
        self.assertEqual(
            compat.execute_command("set_network", 0, "ssid", '"example"'),
            (True, None))
        self.assertEqual(self.server.received, ['SET_NETWORK 0 ssid "example"'])


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
