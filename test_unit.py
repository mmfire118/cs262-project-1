import unittest
import struct
import json
import os

from server import (
    hash_password,
    Account,
    CustomProtocol,
    JSONProtocol,
)

# =============================================================================
# FakeSocket: a simple in-memory socket replacement
# =============================================================================
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
            return b''  # Simulate a blocking socket that returns empty if no data
        data = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return bytes(data)

    def close(self):
        self.closed = True


# =============================================================================
# 1) Unit Tests for hash_password(...)
# =============================================================================
class TestHashPassword(unittest.TestCase):
    def test_hash_consistency(self):
        """Using the same salt and password must yield the same hash."""
        password = "testpassword"
        salt, hashed = hash_password(password)
        # Recompute hash with the same salt:
        salt_bytes = bytes.fromhex(salt)
        _, hashed2 = hash_password(password, salt_bytes)
        self.assertEqual(hashed, hashed2)

    def test_hash_uniqueness(self):
        """Different calls (with random salt) produce different salt/hash."""
        password = "testpassword"
        salt1, hashed1 = hash_password(password)
        salt2, hashed2 = hash_password(password)
        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(hashed1, hashed2)

    def test_empty_password(self):
        """Hashing an empty password still returns valid salt/hash."""
        password = ""
        salt, hashed = hash_password(password)
        self.assertTrue(salt, "Salt should not be empty for empty password")
        self.assertTrue(hashed, "Hash should not be empty for empty password")

    def test_long_password(self):
        """Hashing an extremely long password should still work."""
        password = "a" * 10000
        salt, hashed = hash_password(password)
        self.assertTrue(salt)
        self.assertTrue(hashed)


# =============================================================================
# 2) Unit Tests for the Account class
# =============================================================================
class TestAccount(unittest.TestCase):
    def setUp(self):
        # Create a sample Account instance for each test
        self.username = "testuser"
        self.salt = "abcdef123456"
        self.hashed_password = "deadbeefc0ffee"
        self.account = Account(self.username, self.salt, self.hashed_password)

    def test_init(self):
        """Test initial state of a new Account."""
        self.assertEqual(self.account.username, "testuser")
        self.assertEqual(self.account.salt, self.salt)
        self.assertEqual(self.account.hashed_password, self.hashed_password)
        self.assertEqual(self.account.messages, [])
        self.assertEqual(self.account.next_msg_id, 1)
        self.assertFalse(self.account.online)
        self.assertIsNone(self.account.conn)
        self.assertIsNone(self.account.protocol)

    def test_store_message(self):
        """Storing messages increments next_msg_id and saves them."""
        initial_id = self.account.next_msg_id
        # Manually append a message the same way ChatServer might do it
        msg_id = str(self.account.next_msg_id)
        self.account.next_msg_id += 1
        self.account.messages.append((msg_id, "sender", "Hello!"))

        self.assertEqual(self.account.next_msg_id, initial_id + 1)
        self.assertEqual(len(self.account.messages), 1)
        self.assertEqual(self.account.messages[0], (msg_id, "sender", "Hello!"))

    def test_delete_messages(self):
        """Simulate deleting multiple messages by ID."""
        # Add some messages
        for _ in range(3):
            msg_id = str(self.account.next_msg_id)
            self.account.next_msg_id += 1
            self.account.messages.append((msg_id, "someone", f"Message {msg_id}"))

        # Suppose we want to delete ID '1' and '2'
        ids_to_delete = {"1", "2"}
        before = len(self.account.messages)
        self.account.messages = [m for m in self.account.messages if m[0] not in ids_to_delete]
        after = len(self.account.messages)

        # Check that exactly 2 are removed
        self.assertEqual(before - after, 2)
        # Ensure only message 3 remains
        self.assertTrue(all(m[0] != "1" and m[0] != "2" for m in self.account.messages))

    def test_online_status(self):
        """Test toggling online/offline status and assigning a protocol/conn."""
        self.assertFalse(self.account.online)
        self.account.online = True
        self.account.conn = "fake_connection"
        self.account.protocol = "fake_protocol"
        self.assertTrue(self.account.online)
        self.assertEqual(self.account.conn, "fake_connection")
        self.assertEqual(self.account.protocol, "fake_protocol")
        # Mark offline
        self.account.online = False
        self.account.conn = None
        self.account.protocol = None
        self.assertFalse(self.account.online)
        self.assertIsNone(self.account.conn)
        self.assertIsNone(self.account.protocol)


# =============================================================================
# 3) Unit Tests for the Protocol Classes
# =============================================================================

class TestCustomProtocol(unittest.TestCase):
    def setUp(self):
        self.protocol = CustomProtocol()
        self.fake_socket = FakeSocket()

    def test_send_and_receive(self):
        """Test sending a command + fields and receiving them back."""
        command = 42
        fields = ["alpha", "beta", "gamma"]
        self.protocol.send_message(self.fake_socket, command, fields)

        # Now read from the same fake socket
        received_cmd, received_fields = self.protocol.receive_message(self.fake_socket)
        self.assertEqual(received_cmd, command)
        self.assertEqual(received_fields, fields)

    def test_send_no_fields(self):
        """Send a command with zero fields."""
        command = 99
        fields = []
        self.protocol.send_message(self.fake_socket, command, fields)
        received_cmd, received_fields = self.protocol.receive_message(self.fake_socket)
        self.assertEqual(received_cmd, 99)
        self.assertEqual(received_fields, [])

    def test_malformed_data(self):
        """
        Manually insert malformed data (e.g., partial header or partial payload)
        to ensure the protocol returns (None, None).
        """
        # Build a header that says (cmd=1, length=10),
        # but only provide fewer payload bytes, or partial field length
        header = struct.pack('!BI', 1, 10)  # Command=1, length=10
        partial_payload = struct.pack('!H', 20)  # field length=20, but we'll cut off
        self.fake_socket.sendall(header + partial_payload[:1])  # only 1 byte of the 2
        # Now try to receive
        cmd, fields = self.protocol.receive_message(self.fake_socket)
        self.assertIsNone(cmd)
        self.assertIsNone(fields)


class TestJSONProtocol(unittest.TestCase):
    def setUp(self):
        self.protocol = JSONProtocol()
        self.fake_socket = FakeSocket()

    def test_send_and_receive(self):
        """Test sending a JSON-based command + fields and receiving them back."""
        command = "TEST_CMD"
        fields = ["foo", "bar"]
        self.protocol.send_message(self.fake_socket, command, fields)

        rc_cmd, rc_fields = self.protocol.receive_message(self.fake_socket)
        self.assertEqual(rc_cmd, command)
        self.assertEqual(rc_fields, fields)

    def test_send_no_fields(self):
        """Send a JSON command with zero fields."""
        command = "EMPTY_CMD"
        fields = []
        self.protocol.send_message(self.fake_socket, command, fields)
        rc_cmd, rc_fields = self.protocol.receive_message(self.fake_socket)
        self.assertEqual(rc_cmd, "EMPTY_CMD")
        self.assertEqual(rc_fields, [])

    def test_malformed_data(self):
        """
        Manually inject malformed JSON data to ensure the protocol 
        returns (None, None).
        """
        # length=20, but we provide an invalid JSON string
        length_header = struct.pack('!I', 20)
        invalid_json = b'{' * 5  # obviously not valid JSON
        self.fake_socket.sendall(length_header + invalid_json)

        rc_cmd, rc_fields = self.protocol.receive_message(self.fake_socket)
        self.assertIsNone(rc_cmd)
        self.assertIsNone(rc_fields)


if __name__ == '__main__':
    unittest.main()
