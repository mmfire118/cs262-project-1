"""
test_chat_grpc.py

Integration tests for the gRPC chat server functionality. This suite tests:
  - Account creation
  - Login (both success and failure)
  - Listing accounts
  - Sending messages from one account to another
  - Reading messages
  - Deleting messages
  - Deleting an account

The tests launch a gRPC server in a background thread, then create client stubs 
to simulate multiple users.
"""

import unittest
import threading
import time
import grpc
from concurrent import futures
import argparse

import chat_pb2
import chat_pb2_grpc
from grpc_server import ChatServiceServicer

# -----------------------------------------------------------------------------
# Test class for the gRPC Chat Server
# -----------------------------------------------------------------------------

class TestChatServerGRPC(unittest.TestCase):
    """
    Unit tests for the gRPC-based chat server.
    """

    @classmethod
    def setUpClass(cls):
        """Start the gRPC chat server on localhost:50055."""
        cls.host = "localhost"
        cls.port = 50055
        cls.server_address = f"{cls.host}:{cls.port}"
        # Create a ChatServiceServicer instance
        cls.servicer = ChatServiceServicer()
        # Start the gRPC server with the servicer
        cls.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        chat_pb2_grpc.add_ChatServiceServicer_to_server(cls.servicer, cls.server)
        cls.server.add_insecure_port(cls.server_address)
        cls.server.start()
        # Give the server time to start
        time.sleep(0.2)
        # Create a channel and stub for tests
        cls.channel = grpc.insecure_channel(cls.server_address)
        cls.stub = chat_pb2_grpc.ChatServiceStub(cls.channel)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop(0)
        cls.channel.close()

    def setUp(self):
        """Clear the server's account state before each test."""
        with self.servicer.lock:
            self.servicer.accounts.clear()

    def test_create_account(self):
        """Test that an account can be created successfully."""
        request = chat_pb2.CreateAccountRequest(username="alice", password="secret")
        response = self.stub.CreateAccount(request)
        self.assertEqual(response.status, "OK")
        self.assertIn("Account created", response.message)

    def test_login_success(self):
        """Test a successful login after account creation."""
        # Create account first.
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="bob", password="password"))
        # Then login.
        login_response = self.stub.Login(chat_pb2.LoginRequest(username="bob", password="password"))
        self.assertEqual(login_response.status, "OK")
        self.assertIn("Login successful", login_response.message)
        self.assertGreaterEqual(login_response.unread_count, 0)

    def test_login_failure_wrong_password(self):
        """Test that login fails if the wrong password is provided."""
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="charlie", password="mypassword"))
        login_response = self.stub.Login(chat_pb2.LoginRequest(username="charlie", password="wrongpass"))
        self.assertEqual(login_response.status, "ERROR")
        self.assertIn("Incorrect password", login_response.message)

    def test_list_accounts(self):
        """Test that listing accounts returns the expected usernames."""
        # Create two accounts.
        for user, pwd in [("dave", "pass1"), ("eve", "pass2")]:
            self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username=user, password=pwd))
        list_response = self.stub.ListAccounts(chat_pb2.ListAccountsRequest(pattern="*"))
        self.assertEqual(list_response.status, "OK")
        # The returned list is in the 'accounts' field.
        accounts_list = list_response.accounts
        self.assertIn("dave", accounts_list)
        self.assertIn("eve", accounts_list)

    def test_send_and_read_message(self):
        """
        Test sending a message from one user to another and reading it.
        Simulate two clients by using separate stubs.
        """
        # Create and login as sender (alice) and receiver (frank)
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="alice", password="alicepw"))
        self.stub.Login(chat_pb2.LoginRequest(username="alice", password="alicepw"))
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="frank", password="frankpw"))
        self.stub.Login(chat_pb2.LoginRequest(username="frank", password="frankpw"))
        # alice sends a message to frank.
        send_response = self.stub.SendMessage(chat_pb2.SendMessageRequest(
            sender="alice", recipient="frank", message_text="Hello Frank!"))
        self.assertEqual(send_response.status, "OK")
        # frank reads messages.
        read_response = self.stub.ReadMessages(chat_pb2.ReadMessagesRequest(username="frank", num=10))
        self.assertEqual(read_response.status, "OK")
        messages = read_response.messages
        self.assertTrue(any("alice" in m and "Hello Frank!" in m for m in messages),
                        "Frank should have received a message from alice")

    def test_delete_message(self):
        """
        Test that a message can be deleted.
        Send a message, read it to obtain its ID, then delete it,
        and finally confirm that the message is no longer present.
        """
        # Create and login as sender (gina) and receiver (harry)
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="gina", password="ginapw"))
        self.stub.Login(chat_pb2.LoginRequest(username="gina", password="ginapw"))
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="harry", password="harrypw"))
        self.stub.Login(chat_pb2.LoginRequest(username="harry", password="harrypw"))
        # gina sends a message to harry.
        self.stub.SendMessage(chat_pb2.SendMessageRequest(
            sender="gina", recipient="harry", message_text="Test delete message"))
        time.sleep(0.2)  # Allow for asynchronous processing if needed.
        # harry reads messages to obtain the message ID.
        read_response = self.stub.ReadMessages(chat_pb2.ReadMessagesRequest(username="harry", num=10))
        messages = read_response.messages
        self.assertGreater(len(messages), 0, "Expected at least one message")
        # Assume message format: "<msg_id>: <sender>: <message text>"
        first_message = messages[0]
        msg_id = first_message.split(":")[0].strip()
        # Send a DELETE_MESSAGES request for that message.
        del_response = self.stub.DeleteMessages(chat_pb2.DeleteMessagesRequest(
            username="harry", message_ids=[msg_id]))
        self.assertEqual(del_response.status, "OK")
        self.assertIn("Deleted", del_response.message)
        # Read messages again; expect no messages.
        read_response_after = self.stub.ReadMessages(chat_pb2.ReadMessagesRequest(username="harry", num=10))
        self.assertEqual(len(read_response_after.messages), 0, "Expected no messages after deletion")

    def test_delete_account(self):
        """
        Test that an account can be deleted.
        After deletion, an attempt to login with the deleted account should fail.
        """
        # Create account 'ivy' and then delete it.
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="ivy", password="ivypw"))
        del_response = self.stub.DeleteAccount(chat_pb2.DeleteAccountRequest(username="ivy", password="ivypw"))
        self.assertEqual(del_response.status, "OK")
        self.assertIn("Account deleted", del_response.message)
        # Attempt to login with the deleted account.
        login_response = self.stub.Login(chat_pb2.LoginRequest(username="ivy", password="ivypw"))
        self.assertEqual(login_response.status, "ERROR", "Expected error when logging into a deleted account")

# -----------------------------------------------------------------------------
# Main entry point for the tests
# -----------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main()
