"""
Unit tests for individual components of the Chat Application.
Tests include:
  - Password hashing function.
  - CustomProtocol encoding/decoding.
  - JSONProtocol encoding/decoding.
A FakeSocket class is used to simulate socket behavior.
"""

import unittest
import struct
import json
import hashlib

from server import hash_password, CustomProtocol, JSONProtocol

class FakeSocket:
    """
    A fake socket implementation using an internal bytearray buffer.
    This class supports sendall() and recv() so that our protocol classes
    can be tested without an actual network connection.
    """
    def __init__(self):
        self.buffer = bytearray()
        self.closed = False

    def sendall(self, data):
        if self.closed:
            raise RuntimeError("Socket is closed")
        self.buffer.extend(data)

    def recv(self, n):
        if self.closed:
            return b''
        if not self.buffer:
            return b''  # Simulate a blocking socket that returns empty if no data.
        data = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return bytes(data)

    def close(self):
        self.closed = True

class TestHashPassword(unittest.TestCase):
    def test_hash_consistency(self):
        password = "testpassword"
        salt, hashed = hash_password(password)
        # Recompute hash with the same salt.
        salt_bytes = bytes.fromhex(salt)
        _, hashed2 = hash_password(password, salt_bytes)
        self.assertEqual(hashed, hashed2, "Hashes should match when using the same salt and password.")

    def test_hash_uniqueness(self):
        password = "testpassword"
        salt1, hashed1 = hash_password(password)
        salt2, hashed2 = hash_password(password)
        # The salts (and thus the hashes) should be different for different invocations.
        self.assertNotEqual(salt1, salt2, "Salts should be different on different invocations.")
        self.assertNotEqual(hashed1, hashed2, "Hashes should be different due to different salts.")

class TestCustomProtocol(unittest.TestCase):
    def setUp(self):
        self.protocol = CustomProtocol()
        self.fake_socket = FakeSocket()

    def test_send_receive_message(self):
        command = 42
        fields = ["field1", "field2"]
        # Send a message using the custom binary protocol.
        self.protocol.send_message(self.fake_socket, command, fields)
        # Now receive the message from the same fake socket.
        received_command, received_fields = self.protocol.receive_message(self.fake_socket)
        self.assertEqual(received_command, command)
        self.assertEqual(received_fields, fields)

class TestJSONProtocol(unittest.TestCase):
    def setUp(self):
        self.protocol = JSONProtocol()
        self.fake_socket = FakeSocket()

    def test_send_receive_message(self):
        command = "TEST_COMMAND"
        fields = ["json_field1", "json_field2"]
        # Send a message using the JSON protocol.
        self.protocol.send_message(self.fake_socket, command, fields)
        # Now receive the message.
        received_command, received_fields = self.protocol.receive_message(self.fake_socket)
        self.assertEqual(received_command, command)
        self.assertEqual(received_fields, fields)

if __name__ == '__main__':
    unittest.main()