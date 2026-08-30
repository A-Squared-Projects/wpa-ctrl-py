## @package tests.test_security
#
# Unit tests for parsing the flags column of a scan result.
#
# The fixtures are flag strings as wpa_supplicant_ie_txt() prints them. Two
# shapes drive most of what is here: a key management name can contain a dash
# (PSK-SHA256) and so can a cipher (CCMP-256, EAP-SUITE-B-192), so the point
# where the key management list ends and the ciphers begin cannot be found by
# splitting on punctuation.
#
# @file test_security.py

import unittest
from unittest import TestCase

from wpa_ctrl import KeyMgmt, Pmf, ScanResult, parse_security


def setUpModule():
    print(__name__ + " set up")

def tearDownModule():
    print(__name__ + " tear down")
    print()


class TestOpenNetworks(TestCase):

    def test_open(self):
        security = parse_security("[ESS]")
        self.assertTrue(security.open)
        self.assertFalse(security.psk)
        self.assertFalse(security.sae)
        self.assertEqual(security.key_mgmt, frozenset())

    ## An empty group is what a BSS with no IEs at all produces
    def test_empty_groups(self):
        self.assertTrue(parse_security("[]").open)
        self.assertTrue(parse_security("").open)

    ## WEP has no key management suite, so it parses as no suites - but
    ## calling it open would tell a caller it needs no key
    def test_wep_is_not_open(self):
        security = parse_security("[WEP][ESS]")
        self.assertTrue(security.wep)
        self.assertFalse(security.open)


class TestPersonal(TestCase):

    def test_wpa2_psk(self):
        security = parse_security("[WPA2-PSK-CCMP][ESS]")
        self.assertTrue(security.psk)
        self.assertFalse(security.sae)
        self.assertFalse(security.transition_mode)
        self.assertEqual(security.key_mgmt, frozenset({"PSK"}))
        self.assertEqual(security.protocols, frozenset({"WPA2"}))

    def test_wpa_and_wpa2_psk(self):
        security = parse_security("[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][ESS]")
        self.assertTrue(security.psk)
        self.assertEqual(security.protocols, frozenset({"WPA", "WPA2"}))

    def test_sae_only(self):
        security = parse_security("[RSN-SAE-CCMP][MFPR][MFPC][ESS]")
        self.assertTrue(security.sae)
        self.assertTrue(security.sae_only)
        self.assertFalse(security.psk)
        self.assertFalse(security.transition_mode)

    ## Which protocol name an SAE BSS carries has varied between releases,
    ## and neither spelling changes what it is offering
    def test_sae_under_either_protocol_name(self):
        for flags in ("[RSN-SAE-CCMP][MFPR][ESS]", "[WPA2-SAE-CCMP][MFPR][ESS]"):
            self.assertTrue(parse_security(flags).sae_only, flags)

    ## The case this whole feature turns on: one BSS offering both, so a
    ## WPA2 client and a WPA3 client can each associate
    def test_transition_mode(self):
        security = parse_security("[WPA2-PSK+SAE-CCMP][MFPC][ESS]")
        self.assertTrue(security.psk)
        self.assertTrue(security.sae)
        self.assertTrue(security.transition_mode)
        self.assertFalse(security.sae_only)
        self.assertEqual(security.key_mgmt, frozenset({"PSK", "SAE"}))

    def test_fast_transition_counts_as_its_base_suite(self):
        security = parse_security("[WPA2-PSK+SAE+FT/SAE-CCMP][MFPC][ESS]")
        self.assertTrue(security.transition_mode)
        self.assertIn("FT/SAE", security.key_mgmt)

    ## FT/PSK on its own is still a passphrase network
    def test_ft_psk_alone(self):
        security = parse_security("[WPA2-FT/PSK-CCMP][ESS]")
        self.assertTrue(security.psk)
        self.assertFalse(security.sae)


class TestAmbiguousNames(TestCase):

    ## PSK-SHA256 must not read as PSK followed by a cipher called SHA256
    def test_psk_sha256(self):
        security = parse_security("[WPA2-PSK-SHA256-CCMP][ESS]")
        self.assertEqual(security.key_mgmt, frozenset({"PSK-SHA256"}))
        self.assertTrue(security.psk)

    ## The longest name in the vocabulary, followed by a dashed cipher
    def test_suite_b_192(self):
        security = parse_security("[WPA2-EAP-SUITE-B-192-GCMP-256][MFPR][ESS]")
        self.assertEqual(security.key_mgmt, frozenset({"EAP-SUITE-B-192"}))
        self.assertTrue(security.enterprise)
        self.assertFalse(security.psk)

    ## A suite added upstream after this code was written lands in the
    ## cipher position and is simply not claimed as one we know
    def test_unknown_suite_does_not_become_psk_or_sae(self):
        security = parse_security("[WPA2-NEWSUITE-CCMP][ESS]")
        self.assertFalse(security.psk)
        self.assertFalse(security.sae)
        self.assertFalse(security.open)


class TestOtherSuites(TestCase):

    def test_enterprise(self):
        security = parse_security("[WPA2-EAP-CCMP][ESS]")
        self.assertTrue(security.enterprise)
        self.assertFalse(security.psk)

    def test_owe(self):
        security = parse_security("[RSN-OWE-CCMP][MFPR][ESS]")
        self.assertTrue(security.owe)
        self.assertFalse(security.open)

    ## An AP configured by DPP advertises DPP alongside what it hands out
    def test_dpp_with_sae(self):
        security = parse_security("[WPA2-DPP+SAE-CCMP][MFPC][ESS]")
        self.assertTrue(security.sae)
        self.assertIn("DPP", security.key_mgmt)


class TestManagementFrameProtection(TestCase):

    def test_required(self):
        security = parse_security("[RSN-SAE-CCMP][MFPR][MFPC][ESS]")
        self.assertTrue(security.pmf_required)
        self.assertTrue(security.pmf_capable)

    def test_capable_only(self):
        security = parse_security("[WPA2-PSK+SAE-CCMP][MFPC][ESS]")
        self.assertFalse(security.pmf_required)
        self.assertTrue(security.pmf_capable)

    def test_absent(self):
        security = parse_security("[WPA2-PSK-CCMP][ESS]")
        self.assertFalse(security.pmf_required)
        self.assertFalse(security.pmf_capable)


class TestUnparsedFlagsSurvive(TestCase):

    ## Anything not recognised is kept rather than dropped, so a caller can
    ## still see a flag this code has never heard of
    def test_other_flags_are_kept(self):
        security = parse_security("[WPA2-PSK-CCMP][WPS][HS20][ESS]")
        self.assertEqual(security.flags, frozenset({"WPS", "HS20", "ESS"}))


class TestScanResultProperty(TestCase):

    def test_scan_result_parses_its_own_flags(self):
        result = ScanResult("00:11:22:33:44:55", 5180, -45,
                            "[WPA2-PSK+SAE-CCMP][MFPC][ESS]", "example")
        self.assertTrue(result.security.transition_mode)


class TestVocabulary(TestCase):

    ## The names a caller sets on a network are not the names a scan result
    ## reports, and mixing them up silently produces a network that never
    ## associates
    def test_configuration_names_differ_from_scan_names(self):
        self.assertEqual(KeyMgmt.WPA_PSK, "WPA-PSK")
        self.assertEqual(KeyMgmt.SAE, "SAE")
        self.assertNotIn(KeyMgmt.WPA_PSK, parse_security("[WPA2-PSK-CCMP]").key_mgmt)

    def test_pmf_values(self):
        self.assertEqual((Pmf.DISABLED, Pmf.OPTIONAL, Pmf.REQUIRED),
                         ("0", "1", "2"))


if __name__ == '__main__':
    unittest.main()
