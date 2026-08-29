## @package tests.test_events_loop
#
# Tests for driving a connection from an event loop rather than polling it.
#
# The point of fileno() is that a caller with its own loop - asyncio here,
# but a Qt notifier or a bare select would be the same - can wait on events
# without a thread and without a poll interval. These tests exercise that
# pattern end to end rather than just checking the descriptor is an integer,
# because the pattern is the thing that has to work.
#
# @file test_events_loop.py

import asyncio
import os
import shutil
import tempfile
import unittest
from unittest import TestCase

from fake_supplicant import FakeSupplicant

from wpa_ctrl import WpaCtrl, WpaCtrlConnectionError


def setUpModule():
    print(__name__ + " set up")

def tearDownModule():
    print(__name__ + " tear down")
    print()


class TestFileno(TestCase):

    def setUp(self):
        self.directory = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.socket_path = os.path.join(self.directory, "wlan0")

    def _monitor(self, replies=None):
        self.server = FakeSupplicant(self.socket_path,
                                     replies if replies is not None
                                     else {"ATTACH": "OK\n"})
        self.addCleanup(self.server.stop)
        client = WpaCtrl(path=self.socket_path, client_dir=self.directory,
                         timeout=2.0)
        self.addCleanup(client.close)
        return client

    def test_fileno_is_the_open_socket(self):
        client = self._monitor()
        client.open()
        self.assertGreaterEqual(client.fileno(), 0)

    ## Asking a closed connection for a descriptor is a mistake worth
    #  hearing about, rather than a -1 to register with a loop
    def test_fileno_before_open_raises(self):
        client = self._monitor()
        with self.assertRaises(WpaCtrlConnectionError):
            client.fileno()

    ## The documented pattern: attach, register the descriptor, and let the
    #  loop wake us when an event lands
    def test_events_arrive_through_an_asyncio_reader(self):
        async def scenario():
            monitor = self._monitor()
            monitor.open()
            monitor.attach()

            loop = asyncio.get_event_loop()
            received = []
            done = asyncio.Event()

            def on_readable():
                # Drain: one readable socket can hold several datagrams
                while monitor.pending():
                    event = monitor.next_event()
                    if event is None:
                        break
                    received.append(event.name)
                    if len(received) >= 2:
                        done.set()

            loop.add_reader(monitor.fileno(), on_readable)
            try:
                self.server.send_event("<3>DPP-AUTH-SUCCESS init=1")
                self.server.send_event("<3>DPP-CONF-RECEIVED ")
                await asyncio.wait_for(done.wait(), 5)
            finally:
                loop.remove_reader(monitor.fileno())
            return received

        loop = asyncio.new_event_loop()
        try:
            received = loop.run_until_complete(scenario())
        finally:
            loop.close()
        self.assertEqual(received, ["DPP-AUTH-SUCCESS", "DPP-CONF-RECEIVED"])


if __name__ == '__main__':
    unittest.main()
