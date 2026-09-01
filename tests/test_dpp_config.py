## Tests for the DPP configuration helpers.
#
# Every one of these guards a failure the control interface does not report.
# An empty field, a passphrase where a key belongs, or a channel that does
# not match the one a peer announces on all produce a command the daemon
# accepts and an exchange that then does nothing, with no event and no log
# line saying why.

import unittest

from wpa_ctrl import DppConf, Ssid, dpp_channel, dpp_configurator_params, dpp_hex


class TestHex(unittest.TestCase):

    def test_it_encodes(self):
        self.assertEqual(dpp_hex("abc"), "616263")

    ## Names are not ASCII in general, and the encoding has to survive that
    def test_it_encodes_beyond_ascii(self):
        self.assertEqual(dpp_hex("café"), "636166c3a9")

    ## The one that matters: an empty field is accepted by the daemon and
    ## then fails later with nothing to diagnose it by
    def test_an_empty_value_is_refused(self):
        with self.assertRaises(ValueError):
            dpp_hex("")
        with self.assertRaises(ValueError):
            dpp_hex(b"")

    ## An SSID need not be text at all, so the octets go in as they are -
    #  which is also how an Ssid flows straight into a DPP command
    def test_it_takes_octets(self):
        self.assertEqual(dpp_hex(b"\x00\xff"), "00ff")
        self.assertEqual(dpp_hex(Ssid("café".encode())), "636166c3a9")


class TestChannel(unittest.TestCase):

    def test_the_common_channels(self):
        self.assertEqual(dpp_channel(2412), "81/1")
        self.assertEqual(dpp_channel(2437), "81/6")
        self.assertEqual(dpp_channel(2472), "81/13")

    ## Channel 14 is its own operating class
    def test_channel_fourteen(self):
        self.assertEqual(dpp_channel(2484), "82/14")

    ## 5 GHz, by global operating class - a URI may be read in another
    ## regulatory domain, so a class meaning different things in different
    ## places would be worse than none
    def test_the_five_gigahertz_classes(self):
        self.assertEqual(dpp_channel(5180), "115/36")
        self.assertEqual(dpp_channel(5240), "115/48")
        self.assertEqual(dpp_channel(5260), "118/52")
        self.assertEqual(dpp_channel(5500), "121/100")
        self.assertEqual(dpp_channel(5745), "125/149")

    ## 6 GHz: class 131 holds the 20 MHz primaries; 5935 is class 136's
    ## lone channel 2
    def test_the_six_gigahertz_channels(self):
        self.assertEqual(dpp_channel(5955), "131/1")
        self.assertEqual(dpp_channel(5975), "131/5")
        self.assertEqual(dpp_channel(6255), "131/61")
        self.assertEqual(dpp_channel(7115), "131/233")
        self.assertEqual(dpp_channel(5935), "136/2")

    ## Anything else is not a channel this can name, and saying so beats
    ## inventing a spec a peer will never listen on
    def test_frequencies_it_cannot_name(self):
        self.assertIsNone(dpp_channel(2413))
        self.assertIsNone(dpp_channel(0))
        self.assertIsNone(dpp_channel(5900))
        # channel 65: in range, but between classes 118 and 121
        self.assertIsNone(dpp_channel(5325))
        # 5 MHz off the 6 GHz 20 MHz primary grid - a real frequency, but
        # not one a peer can announce on
        self.assertIsNone(dpp_channel(5960))
        self.assertIsNone(dpp_channel(7135))


class TestConfiguratorParams(unittest.TestCase):

    def test_a_passphrase_is_encoded(self):
        params = dpp_configurator_params(DppConf.STA_PSK_SAE, "example",
                                         passphrase="opensesame",
                                         configurator=1)
        self.assertEqual(params,
                         "conf=sta-psk-sae ssid=6578616d706c65 "
                         "pass=6f70656e736573616d65 configurator=1")

    ## A derived key is hex already and must not be encoded again
    def test_a_derived_key_is_passed_through(self):
        key = "ab" * 32
        params = dpp_configurator_params(DppConf.STA_PSK, "example", psk=key)
        self.assertIn(f"psk={key}", params)
        self.assertNotIn("pass=", params)

    ## SAE derives from the passphrase, so a key can only ever serve WPA2.
    ## Naming them differently is what keeps that decision visible
    def test_the_two_secrets_are_not_interchangeable(self):
        with self.assertRaises(ValueError):
            dpp_configurator_params(DppConf.STA_PSK, "example")
        with self.assertRaises(ValueError):
            dpp_configurator_params(DppConf.STA_PSK, "example",
                                    passphrase="x", psk="ab" * 32)

    ## A passphrase in the psk argument would be sent unencoded and the
    ## exchange would fail with nothing to say why
    def test_a_passphrase_in_the_key_argument_is_refused(self):
        with self.assertRaises(ValueError):
            dpp_configurator_params(DppConf.STA_PSK, "example",
                                    psk="opensesame")

    def test_an_empty_ssid_is_refused(self):
        with self.assertRaises(ValueError):
            dpp_configurator_params(DppConf.STA_PSK, "", passphrase="x")

    ## Anything the caller needs that this does not name
    def test_further_parameters_are_passed_through(self):
        params = dpp_configurator_params(DppConf.STA_SAE, "example",
                                         passphrase="x", expiry=1700000000)
        self.assertIn("expiry=1700000000", params)

    ## Absent optional parameters must not appear at all
    def test_an_absent_configurator_is_omitted(self):
        params = dpp_configurator_params(DppConf.STA_SAE, "example",
                                         passphrase="x")
        self.assertNotIn("configurator=", params)


if __name__ == "__main__":
    unittest.main()
