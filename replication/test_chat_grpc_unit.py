"""
test_chat_grpc_unit.py

Unit tests for the chat server components in the gRPC version.
"""

import unittest

from grpc_server import hash_password, ChatDatabase
import chat_pb2

# =============================================================================
# 1) Unit Tests for hash_password
# =============================================================================

class TestHashPassword(unittest.TestCase):
    def test_hash_consistency(self):
        password = "testpassword"
        salt, hashed = hash_password(password)
        salt_bytes = bytes.fromhex(salt)
        _, hashed2 = hash_password(password, salt_bytes)
        self.assertEqual(hashed, hashed2)

    def test_hash_uniqueness(self):
        password = "testpassword"
        salt1, hashed1 = hash_password(password)
        salt2, hashed2 = hash_password(password)
        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(hashed1, hashed2)

    def test_empty_password(self):
        password = ""
        salt, hashed = hash_password(password)
        self.assertTrue(salt)
        self.assertTrue(hashed)

    def test_long_password(self):
        password = "a" * 10000
        salt, hashed = hash_password(password)
        self.assertTrue(salt)
        self.assertTrue(hashed)

# =============================================================================
# 2) Unit Tests for ChatDatabase (Accounts and Messages)
# =============================================================================

class TestChatDatabaseAccounts(unittest.TestCase):
    def setUp(self):
        self.db = ChatDatabase(":memory:")

    def test_create_and_get_account(self):
        success, msg = self.db.create_account("testuser", "salt123", "hash456")
        self.assertTrue(success)
        account = self.db.get_account("testuser")
        self.assertIsNotNone(account)
        self.assertEqual(account[0], "testuser")
        self.assertEqual(account[1], "salt123")
        self.assertEqual(account[2], "hash456")

    def test_account_duplicate(self):
        success, msg = self.db.create_account("testuser", "salt123", "hash456")
        self.assertTrue(success)
        success2, msg2 = self.db.create_account("testuser", "salt123", "hash456")
        self.assertFalse(success2)

class TestChatDatabaseMessages(unittest.TestCase):
    def setUp(self):
        self.db = ChatDatabase(":memory:")
        self.db.create_account("user", "s", "h")

    def test_message_id_assignment(self):
        id1 = self.db.add_message("user", "sender", "Hello")
        self.assertEqual(id1, "1")
        id2 = self.db.add_message("user", "sender", "Hello again")
        self.assertEqual(id2, "2")

    def test_get_unread_messages(self):
        self.db.add_message("user", "sender", "Msg1")
        self.db.add_message("user", "sender", "Msg2")
        msgs = self.db.get_messages("user", 10)
        self.assertEqual(len(msgs), 2)
        with self.db.lock:
            c = self.db.conn.cursor()
            c.execute("SELECT delivered FROM messages WHERE recipient=?", ("user",))
            for row in c.fetchall():
                self.assertEqual(row[0], 0)

    def test_mark_messages_delivered(self):
        id1 = self.db.add_message("user", "sender", "Msg1")
        id2 = self.db.add_message("user", "sender", "Msg2")
        msgs = self.db.get_messages("user", 10)
        self.assertEqual(len(msgs), 2)
        self.db.mark_messages_delivered("user", [id1, id2])
        msgs_after = self.db.get_messages("user", 10)
        self.assertEqual(len(msgs_after), 0)
        with self.db.lock:
            c = self.db.conn.cursor()
            c.execute("SELECT delivered FROM messages WHERE recipient=?", ("user",))
            for row in c.fetchall():
                self.assertEqual(row[0], 1)

    def test_delete_messages(self):
        id1 = self.db.add_message("user", "sender", "Msg1")
        id2 = self.db.add_message("user", "sender", "Msg2")
        msgs = self.db.get_messages("user", 10)
        self.assertEqual(len(msgs), 2)
        affected = self.db.delete_messages("user", [id1])
        self.assertEqual(affected, 1)
        msgs_after = self.db.get_messages("user", 10)
        self.assertEqual(len(msgs_after), 1)

# =============================================================================
# 3) Unit Tests for Protocol Buffer Message Serialization
# =============================================================================

class TestGRPCMessageSerialization(unittest.TestCase):
    def test_create_account_request_serialization(self):
        req = chat_pb2.CreateAccountRequest(username="alice", password="secret")
        data = req.SerializeToString()
        new_req = chat_pb2.CreateAccountRequest()
        new_req.ParseFromString(data)
        self.assertEqual(new_req.username, "alice")
        self.assertEqual(new_req.password, "secret")

    def test_login_request_serialization(self):
        req = chat_pb2.LoginRequest(username="bob", password="password")
        data = req.SerializeToString()
        new_req = chat_pb2.LoginRequest()
        new_req.ParseFromString(data)
        self.assertEqual(new_req.username, "bob")
        self.assertEqual(new_req.password, "password")

    def test_malformed_data(self):
        data = b"not a valid protobuf"
        req = chat_pb2.LoginRequest()
        with self.assertRaises(Exception):
            req.ParseFromString(data)

if __name__ == '__main__':
    unittest.main()
