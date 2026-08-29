## @package tests.test_dpp
#
# Unit tests for the DPP (Wi-Fi Easy Connect) command surface.
#
# The onboarding flow these follow is the one in wpa_supplicant/README-DPP:
# create a Configurator, generate bootstrapping information, publish it as a
# QR code, listen, and authenticate.
#
# @file test_dpp.py

import os
import shutil
import tempfile
import unittest
from unittest import TestCase

from fake_supplicant import FakeSupplicant

from wpa_ctrl import WpaCtrl, WpaCtrlCommandFailed, format_params


def setUpModule():
    print(__name__ + " set up")

def tearDownModule():
    print(__name__ + " tear down")
    print()


class DppTestCase(TestCase):

    def setUp(self):
        self.directory = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.socket_path = os.path.join(self.directory, "wlan0")

    def client(self, replies: dict) -> WpaCtrl:
        self.server = FakeSupplicant(self.socket_path, replies)
        self.addCleanup(self.server.stop)
        client = WpaCtrl(path=self.socket_path, client_dir=self.directory,
                         timeout=2.0)
        self.addCleanup(client.close)
        return client


class TestFormatParams(TestCase):

    def test_pairs(self):
        self.assertEqual(format_params(type="qrcode", chan="81/1"),
                         "type=qrcode chan=81/1")

    ## pass is a Python keyword, and DPP has a pass= parameter
    def test_trailing_underscore_is_stripped(self):
        self.assertEqual(format_params(pass_="6162"), "pass=6162")

    ## A hexdump means exactly what its bytes say
    def test_values_are_untouched(self):
        self.assertEqual(format_params(ssid="6D79 4E6574".replace(" ", "")),
                         "ssid=6D794E6574")

    def test_none_is_omitted(self):
        self.assertEqual(format_params(chan=None, type="qrcode"),
                         "type=qrcode")


class TestConfigurator(DppTestCase):

    def test_add_returns_the_id(self):
        client = self.client({"DPP_CONFIGURATOR_ADD": "3\n"})
        self.assertEqual(client.dpp_configurator_add(), 3)

    def test_add_with_parameters(self):
        client = self.client({"DPP_CONFIGURATOR_ADD curve=P-256": "1\n"})
        self.assertEqual(client.dpp_configurator_add(curve="P-256"), 1)

    ## A refusal comes back as FAIL where an id was expected
    def test_add_failure_raises(self):
        client = self.client({"DPP_CONFIGURATOR_ADD": "FAIL\n"})
        with self.assertRaises(WpaCtrlCommandFailed):
            client.dpp_configurator_add()

    def test_get_key(self):
        client = self.client({"DPP_CONFIGURATOR_GET_KEY 1": "30770201...\n"})
        self.assertEqual(client.dpp_configurator_get_key(1), "30770201...")

    def test_sign(self):
        client = self.client({
            "DPP_CONFIGURATOR_SIGN conf=sta-dpp configurator=1 ssid=6D794E6574":
            "OK\n"})
        client.dpp_configurator_sign(conf="sta-dpp", configurator=1,
                                     ssid="6D794E6574")

    def test_remove_all(self):
        client = self.client({"DPP_CONFIGURATOR_REMOVE all": "OK\n"})
        client.dpp_configurator_remove("all")


class TestBootstrapping(DppTestCase):

    ## The Enrollee side of README-DPP: generate a key, publish its URI
    def test_generate_then_get_uri(self):
        client = self.client({
            "DPP_BOOTSTRAP_GEN type=qrcode mac=001122334455 chan=81/1": "5\n",
            "DPP_BOOTSTRAP_GET_URI 5": "DPP:C:81/1;M:001122334455;K:MDkw...;;\n",
            })
        bootstrap_id = client.dpp_bootstrap_gen(type="qrcode",
                                                mac="001122334455",
                                                chan="81/1")
        self.assertEqual(bootstrap_id, 5)
        self.assertTrue(client.dpp_bootstrap_get_uri(bootstrap_id)
                        .startswith("DPP:"))

    ## The Configurator side: take in the Enrollee's URI
    def test_qr_code_returns_the_peer_id(self):
        uri = "DPP:C:81/1;M:001122334455;K:MDkw...;;"
        client = self.client({f"DPP_QR_CODE {uri}": "2\n"})
        self.assertEqual(client.dpp_qr_code(uri), 2)

    def test_bootstrap_info(self):
        client = self.client({"DPP_BOOTSTRAP_INFO 5":
                              "type=QRCODE\nmac_addr=00:11:22:33:44:55\n"})
        info = client.dpp_bootstrap_info(5)
        self.assertEqual(info["type"], "QRCODE")

    def test_remove(self):
        client = self.client({"DPP_BOOTSTRAP_REMOVE 5": "OK\n"})
        client.dpp_bootstrap_remove(5)


class TestExchange(DppTestCase):

    ## Frequency in MHz, so 2412 is 2.4 GHz channel 1
    def test_listen_and_stop(self):
        client = self.client({"DPP_LISTEN 2412": "OK\n",
                              "DPP_STOP_LISTEN": "OK\n"})
        client.dpp_listen(2412)
        client.dpp_stop_listen()
        self.assertEqual(self.server.received, ["DPP_LISTEN 2412",
                                                "DPP_STOP_LISTEN"])

    def test_listen_with_role(self):
        client = self.client({"DPP_LISTEN 2412 role=enrollee": "OK\n"})
        client.dpp_listen(2412, role="enrollee")

    ## The provisioning request from README-DPP, legacy variant: the
    #  passphrase is a hexdump and pass is a Python keyword
    def test_auth_init_legacy_provisioning(self):
        client = self.client({
            "DPP_AUTH_INIT peer=2 conf=sta-psk ssid=6D794E6574 pass=736563726574":
            "OK\n"})
        client.dpp_auth_init(peer=2, conf="sta-psk", ssid="6D794E6574",
                             pass_="736563726574")
        self.assertIn("pass=736563726574", self.server.received[0])

    def test_push_button_without_parameters(self):
        client = self.client({"DPP_PUSH_BUTTON": "OK\n"})
        client.dpp_push_button()
        self.assertEqual(self.server.received, ["DPP_PUSH_BUTTON"])

    def test_pkex_add_returns_the_id(self):
        client = self.client({"DPP_PKEX_ADD own=1 code=secret": "7\n"})
        self.assertEqual(client.dpp_pkex_add(own=1, code="secret"), 7)


if __name__ == '__main__':
    unittest.main()
