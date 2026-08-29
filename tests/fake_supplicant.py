## @package tests.fake_supplicant
#
# A stand-in wpa_supplicant, shared by the test modules.
#
# It speaks over a real UNIX datagram socket rather than being a mock: the
# framing is the part most likely to be wrong, and a mock would only assert
# the implementation's own assumptions back at it.
#
# @file fake_supplicant.py

import socket
import threading


## A stand-in for wpa_supplicant: answers from a command->reply table and
#  can push unsolicited events at whoever last spoke to it
class FakeSupplicant:

    def __init__(self, path: str, replies: dict):
        self.path = path
        self.replies = replies
        self.received = []
        self._client = None
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._socket.bind(path)
        self._socket.settimeout(0.1)
        self._running = True
        self._thread = threading.Thread(target=self._serve)
        self._thread.daemon = True
        self._thread.start()

    def _serve(self):
        while self._running:
            try:
                data, client = self._socket.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            command = data.decode()
            self.received.append(command)
            self._client = client
            reply = self.replies.get(command)
            if callable(reply):
                reply = reply(command)
            if reply is not None:
                try:
                    self._socket.sendto(reply.encode(), client)
                except OSError:
                    return

    ## Push an unsolicited event to the last client seen
    def send_event(self, message: str):
        for _ in range(50):
            if self._client:
                break
            threading.Event().wait(0.01)
        self._socket.sendto(message.encode(), self._client)

    def stop(self):
        self._running = False
        self._thread.join(timeout=2)
        self._socket.close()
