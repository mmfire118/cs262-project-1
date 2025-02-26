"""
test_chat_grpc_unit.py

Unit tests for the chat server components in the gRPC version.
This suite tests:
  1) The hash_password() function.
  2) The Account class functionality.
  3) Protocol Buffer message serialization and deserialization
     for various message types defined in chat.proto.

These tests do not exercise the full gRPC server end-to-end; instead, they
verify that the utility functions and data models behave as expected.
"""

import unittest
import os
from grpc_server import hash_password, Account
import chat_pb2

# =============================================================================
# 1) Unit Tests for hash_password
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
        # Create a sample Account instance for each test.
        self.username = "testuser"
        self.salt = "abcdef123456"
        self.hashed_password = "deadbeefc0ffee"
        self.account = Account(self.username, self.salt, self.hashed_password)

    def test_init(self):
        """Test the initial state of a new Account."""
        self.assertEqual(self.account.username, "testuser")
        self.assertEqual(self.account.salt, self.salt)
        self.assertEqual(self.account.hashed_password, self.hashed_password)
        self.assertEqual(self.account.messages, [])
        self.assertEqual(self.account.next_msg_id, 1)
        self.assertFalse(self.account.online)

    def test_store_message(self):
        """Storing messages increments next_msg_id and saves them."""
        initial_id = self.account.next_msg_id
        msg_id = str(self.account.next_msg_id)
        self.account.next_msg_id += 1
        self.account.messages.append((msg_id, "sender", "Hello!"))
        self.assertEqual(self.account.next_msg_id, initial_id + 1)
        self.assertEqual(len(self.account.messages), 1)
        self.assertEqual(self.account.messages[0], (msg_id, "sender", "Hello!"))

    def test_delete_messages(self):
        """Simulate deleting multiple messages by ID."""
        # Add some messages.
        for _ in range(3):
            msg_id = str(self.account.next_msg_id)
            self.account.next_msg_id += 1
            self.account.messages.append((msg_id, "someone", f"Message {msg_id}"))
        # Delete messages with IDs "1" and "2".
        ids_to_delete = {"1", "2"}
        before = len(self.account.messages)
        self.account.messages = [m for m in self.account.messages if m[0] not in ids_to_delete]
        after = len(self.account.messages)
        self.assertEqual(before - after, 2)
        self.assertTrue(all(m[0] != "1" and m[0] != "2" for m in self.account.messages))

    def test_online_status(self):
        """Test toggling the online status of the account."""
        self.assertFalse(self.account.online)
        self.account.online = True
        self.assertTrue(self.account.online)
        self.account.online = False
        self.assertFalse(self.account.online)


# =============================================================================
# 3) Unit Tests for Protocol Buffer Message Serialization
# =============================================================================
class TestGRPCMessageSerialization(unittest.TestCase):
    def test_create_account_request_serialization(self):
        """Test serialization round-trip for CreateAccountRequest."""
        req = chat_pb2.CreateAccountRequest(username="alice", password="secret")
        data = req.SerializeToString()
        new_req = chat_pb2.CreateAccountRequest()
        new_req.ParseFromString(data)
        self.assertEqual(new_req.username, "alice")
        self.assertEqual(new_req.password, "secret")

    def test_login_request_serialization(self):
        """Test serialization round-trip for LoginRequest."""
        req = chat_pb2.LoginRequest(username="bob", password="password")
        data = req.SerializeToString()
        new_req = chat_pb2.LoginRequest()
        new_req.ParseFromString(data)
        self.assertEqual(new_req.username, "bob")
        self.assertEqual(new_req.password, "password")

    def test_malformed_data(self):
        """Ensure that attempting to parse malformed data raises an exception."""
        data = b"not a valid protobuf"
        req = chat_pb2.LoginRequest()
        with self.assertRaises(Exception):
            req.ParseFromString(data)

if __name__ == '__main__':
    unittest.main()
