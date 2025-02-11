#!/usr/bin/env python3
"""
test_chat.py

Unit tests for the chat server functionality. This suite tests:
  - Account creation
  - Login (success and failure)
  - Listing accounts
  - Sending messages from one account to another
  - Reading messages
  - Deleting messages
  - Deleting an account

Tests are run for both the custom binary protocol and the JSON protocol.

Because the server pushes asynchronous messages (e.g. NEW_MESSAGE),
a helper function is provided that loops until it receives a response
message (CMD_RESPONSE for custom or "RESPONSE" for JSON) rather than an asynchronous push.
"""

import unittest
import socket
import threading
import time
import json
import struct
import hashlib

# Import the chat server code and protocol classes.
# It is assumed that these classes are defined in server.py.
from server import ChatServer, CustomProtocol, JSONProtocol, hash_password, \
    CMD_CREATE_ACCOUNT, CMD_LOGIN, CMD_LIST_ACCOUNTS, CMD_SEND_MESSAGE, \
    CMD_READ_MESSAGES, CMD_DELETE_MESSAGES, CMD_DELETE_ACCOUNT, CMD_RESPONSE, CMD_NEW_MESSAGE

# -----------------------------------------------------------------------------
# Helper functions for tests
# -----------------------------------------------------------------------------

def send_and_wait_response(sock, protocol, command, fields, expected_response=None, timeout=1.0):
    """
    Sends a command with the given fields over the socket using the specified protocol,
    then repeatedly calls receive_message() until a message with the expected response
    command is received or a timeout expires.

    Args:
        sock: A connected socket.
        protocol: An instance of CustomProtocol or JSONProtocol.
        command: The command code (integer) for custom protocol or command string for JSON.
        fields: A list of string fields.
        expected_response: The expected response command. If None,
            defaults to CMD_RESPONSE (for custom) or "RESPONSE" (for JSON).
        timeout: How long to wait (in seconds) for the expected response.

    Returns:
        A tuple (resp_command, resp_fields) as returned by protocol.receive_message,
        or (None, None) if no expected response is received before the timeout.
    """
    if expected_response is None:
        if isinstance(protocol, CustomProtocol):
            expected_response = CMD_RESPONSE
        else:
            expected_response = "RESPONSE"
    # Send the command.
    protocol.send_message(sock, command, fields)
    t0 = time.time()
    while time.time() - t0 < timeout:
        msg = protocol.receive_message(sock)
        if msg == (None, None):
            # Connection closed
            break
        resp_cmd, resp_fields = msg
        # For custom protocol, we expect CMD_RESPONSE.
        # For JSON protocol, we expect the command "RESPONSE".
        if resp_cmd == expected_response:
            return resp_cmd, resp_fields
        # Otherwise, ignore (likely asynchronous NEW_MESSAGE).
    return None, None

def drain_socket(sock, protocol, drain_time=0.2):
    """
    Drain all pending messages from the socket for a short period.

    Args:
        sock: A connected socket.
        protocol: The protocol instance.
        drain_time: Time (in seconds) to wait for additional messages.
    """
    t0 = time.time()
    while time.time() - t0 < drain_time:
        sock.settimeout(0.05)
        try:
            _ = protocol.receive_message(sock)
        except Exception:
            break
        except socket.timeout:
            break
    sock.settimeout(None)

def login_client(sock, protocol, username, password, use_create=False):
    """
    Helper function to log in (or create an account and then login) for a client.

    Args:
        sock: A connected socket.
        protocol: An instance of CustomProtocol or JSONProtocol.
        username: Username string.
        password: Plaintext password.
        use_create: If True, send a CREATE_ACCOUNT command instead of LOGIN.

    Returns:
        The response tuple (command, fields) from the server.
    """
    hashed_pw = hash_password(password)
    if use_create:
        cmd = CMD_CREATE_ACCOUNT if isinstance(protocol, CustomProtocol) else "CREATE_ACCOUNT"
    else:
        cmd = CMD_LOGIN if isinstance(protocol, CustomProtocol) else "LOGIN"
    return send_and_wait_response(sock, protocol, cmd, [username, hashed_pw])

# -----------------------------------------------------------------------------
# Test class for the Custom Binary Protocol
# -----------------------------------------------------------------------------

class TestChatServerCustom(unittest.TestCase):
    """
    Unit tests for the chat server using the custom binary protocol.
    """

    @classmethod
    def setUpClass(cls):
        """Start the chat server on localhost:12345 using the custom protocol."""
        cls.port = 12345
        cls.server = ChatServer("localhost", cls.port, protocol_type="custom")
        cls.server_thread = threading.Thread(target=cls.server.start)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.2)
        cls.protocol = CustomProtocol()

    def setUp(self):
        """Clear server state before each test."""
        with self.server.lock:
            self.server.accounts.clear()

    def connect_client(self):
        """
        Create a new client socket connected to the server.

        Returns:
            A tuple (sock, protocol) where protocol is a CustomProtocol instance.
        """
        sock = socket.create_connection(("localhost", self.port))
        return sock, self.protocol

    def test_create_account(self):
        """Test that an account can be created successfully."""
        sock, proto = self.connect_client()
        try:
            resp_cmd, resp_fields = send_and_wait_response(sock, proto, CMD_CREATE_ACCOUNT,
                                                            ["alice", hash_password("secret")])
            self.assertIsNotNone(resp_cmd, "Did not receive any response")
            self.assertEqual(resp_fields[0], "OK", "Expected OK response on account creation")
            self.assertIn("Account created", resp_fields[1])
        finally:
            sock.close()

    def test_login_success(self):
        """Test a successful login after account creation."""
        sock, proto = self.connect_client()
        try:
            send_and_wait_response(sock, proto, CMD_CREATE_ACCOUNT,
                                   ["bob", hash_password("password")])
            resp_cmd, resp_fields = send_and_wait_response(sock, proto, CMD_LOGIN,
                                                           ["bob", hash_password("password")])
            self.assertIsNotNone(resp_cmd, "No response received on login")
            self.assertEqual(resp_fields[0], "OK", "Expected OK response on successful login")
            self.assertIn("Login successful", resp_fields[1])
        finally:
            sock.close()

    def test_login_failure_wrong_password(self):
        """Test that login fails if the wrong password is provided."""
        sock, proto = self.connect_client()
        try:
            send_and_wait_response(sock, proto, CMD_CREATE_ACCOUNT,
                                   ["charlie", hash_password("mypassword")])
            resp_cmd, resp_fields = send_and_wait_response(sock, proto, CMD_LOGIN,
                                                           ["charlie", hash_password("wrongpass")])
            self.assertIsNotNone(resp_cmd, "No response received on login attempt")
            self.assertEqual(resp_fields[0], "ERROR", "Expected ERROR response on wrong password")
            self.assertIn("Incorrect password", resp_fields[1])
        finally:
            sock.close()

    def test_list_accounts(self):
        """Test that listing accounts returns the expected usernames."""
        for user, pwd in [("dave", "pass1"), ("eve", "pass2")]:
            sock, proto = self.connect_client()
            try:
                send_and_wait_response(sock, proto, CMD_CREATE_ACCOUNT, [user, hash_password(pwd)])
            finally:
                sock.close()
        sock, proto = self.connect_client()
        try:
            resp_cmd, resp_fields = send_and_wait_response(sock, proto, CMD_LIST_ACCOUNTS, ["*"])
            self.assertIsNotNone(resp_cmd, "No response received for list accounts")
            self.assertEqual(resp_fields[0], "OK")
            # Response format: ["OK", "Accounts list", <account1>, <account2>, ...]
            accounts_list = resp_fields[2:]
            self.assertIn("dave", accounts_list)
            self.assertIn("eve", accounts_list)
        finally:
            sock.close()

    def test_send_and_read_message(self):
        """
        Test sending a message from one user to another and reading it.
        This test simulates two clients: one for sending and one for reading.
        """
        # Create and login as sender (alice) and receiver (frank)
        sock_alice, proto = self.connect_client()
        sock_frank, _ = self.connect_client()
        try:
            send_and_wait_response(sock_alice, proto, CMD_CREATE_ACCOUNT, ["alice", hash_password("alicepw")])
            send_and_wait_response(sock_alice, proto, CMD_LOGIN, ["alice", hash_password("alicepw")])
            send_and_wait_response(sock_frank, proto, CMD_CREATE_ACCOUNT, ["frank", hash_password("frankpw")])
            send_and_wait_response(sock_frank, proto, CMD_LOGIN, ["frank", hash_password("frankpw")])
            # alice sends a message to frank.
            send_and_wait_response(sock_alice, proto, CMD_SEND_MESSAGE, ["frank", "Hello Frank!"])
            # Drain any asynchronous push messages on frank's socket.
            drain_socket(sock_frank, proto, drain_time=0.2)
            # Now frank issues a READ_MESSAGES command.
            resp_cmd, resp_fields = send_and_wait_response(sock_frank, proto, CMD_READ_MESSAGES, ["10"])
            self.assertIsNotNone(resp_cmd, "No response received for read messages")
            self.assertEqual(resp_fields[0], "OK")
            # The response should contain the message as one of the extra fields.
            messages = resp_fields[2:]
            self.assertTrue(any("alice" in m and "Hello Frank!" in m for m in messages),
                            "Frank should have received a message from alice")
        finally:
            sock_alice.close()
            sock_frank.close()

    def test_delete_message(self):
        """
        Test that a message can be deleted.
        The test sends a message, reads it to obtain its ID, then deletes it,
        and finally confirms that the message is no longer present.
        """
        sock_sender, proto = self.connect_client()
        sock_receiver, _ = self.connect_client()
        try:
            send_and_wait_response(sock_sender, proto, CMD_CREATE_ACCOUNT, ["gina", hash_password("ginapw")])
            send_and_wait_response(sock_sender, proto, CMD_LOGIN, ["gina", hash_password("ginapw")])
            send_and_wait_response(sock_receiver, proto, CMD_CREATE_ACCOUNT, ["harry", hash_password("harrypw")])
            send_and_wait_response(sock_receiver, proto, CMD_LOGIN, ["harry", hash_password("harrypw")])
            send_and_wait_response(sock_sender, proto, CMD_SEND_MESSAGE, ["harry", "Test delete message"])
            time.sleep(0.2)
            # Drain any asynchronous messages.
            drain_socket(sock_receiver, proto, drain_time=0.2)
            # Read messages to obtain the message ID.
            resp_cmd, resp_fields = send_and_wait_response(sock_receiver, proto, CMD_READ_MESSAGES, ["10"])
            messages = resp_fields[2:]
            self.assertGreater(len(messages), 0, "Expected at least one message")
            # Assume message format: "<msg_id>: <sender>: <message text>"
            first_message = messages[0]
            msg_id = first_message.split(":")[0].strip()
            # Send a DELETE_MESSAGES command for that message.
            del_resp_cmd, del_resp_fields = send_and_wait_response(sock_receiver, proto, CMD_DELETE_MESSAGES, [msg_id])
            self.assertIsNotNone(del_resp_cmd, "No response received for delete messages")
            self.assertEqual(del_resp_fields[0], "OK")
            self.assertIn("Deleted", del_resp_fields[1])
            # Read messages again; expect no messages.
            resp_cmd, resp_fields = send_and_wait_response(sock_receiver, proto, CMD_READ_MESSAGES, ["10"])
            new_messages = resp_fields[2:]
            self.assertEqual(len(new_messages), 0, "Expected no messages after deletion")
        finally:
            sock_sender.close()
            sock_receiver.close()

    def test_delete_account(self):
        """
        Test that an account can be deleted.
        After deletion, an attempt to login with the deleted account should fail.
        """
        sock, proto = self.connect_client()
        try:
            send_and_wait_response(sock, proto, CMD_CREATE_ACCOUNT, ["ivy", hash_password("ivypw")])
            del_resp_cmd, del_resp_fields = send_and_wait_response(sock, proto, CMD_DELETE_ACCOUNT,
                                                                   ["ivy", hash_password("ivypw")])
            self.assertIsNotNone(del_resp_cmd, "No response received for delete account")
            self.assertEqual(del_resp_fields[0], "OK")
            self.assertIn("Account deleted", del_resp_fields[1])
        finally:
            sock.close()
        # Now try to login with the deleted account.
        sock2, proto = self.connect_client()
        try:
            login_resp_cmd, login_resp_fields = send_and_wait_response(sock2, proto, CMD_LOGIN,
                                                                       ["ivy", hash_password("ivypw")])
            self.assertIsNotNone(login_resp_cmd, "No response received for login attempt on deleted account")
            self.assertEqual(login_resp_fields[0], "ERROR", "Expected error when logging into a deleted account")
        finally:
            sock2.close()

# -----------------------------------------------------------------------------
# Test class for the JSON Protocol
# -----------------------------------------------------------------------------

class TestChatServerJSON(unittest.TestCase):
    """
    Unit tests for the chat server using the JSON-based protocol.
    These tests mirror those for the custom protocol.
    """

    @classmethod
    def setUpClass(cls):
        """Start the chat server on localhost:12346 using the JSON protocol."""
        cls.port = 12346
        cls.server = ChatServer("localhost", cls.port, protocol_type="json")
        cls.server_thread = threading.Thread(target=cls.server.start)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.2)
        cls.protocol = JSONProtocol()

    def setUp(self):
        """Clear the server's account dictionary before each test."""
        with self.server.lock:
            self.server.accounts.clear()

    def connect_client(self):
        """
        Create a new client socket connected to the server.

        Returns:
            A tuple (sock, protocol) where protocol is a JSONProtocol instance.
        """
        sock = socket.create_connection(("localhost", self.port))
        return sock, self.protocol

    def test_create_account(self):
        """Test account creation using JSON protocol."""
        sock, proto = self.connect_client()
        try:
            resp_cmd, resp_fields = send_and_wait_response(sock, proto, "CREATE_ACCOUNT",
                                                            ["jack", hash_password("jackpw")])
            self.assertIsNotNone(resp_cmd, "No response received for create account")
            self.assertEqual(resp_fields[0], "OK")
            self.assertIn("Account created", resp_fields[1])
        finally:
            sock.close()

    def test_login_success(self):
        """Test successful login using JSON protocol."""
        sock, proto = self.connect_client()
        try:
            send_and_wait_response(sock, proto, "CREATE_ACCOUNT", ["kate", hash_password("katepw")])
            resp_cmd, resp_fields = send_and_wait_response(sock, proto, "LOGIN", ["kate", hash_password("katepw")])
            self.assertIsNotNone(resp_cmd, "No response received for login")
            self.assertEqual(resp_fields[0], "OK")
            self.assertIn("Login successful", resp_fields[1])
        finally:
            sock.close()

    def test_login_failure_wrong_password(self):
        """Test login failure (wrong password) using JSON protocol."""
        sock, proto = self.connect_client()
        try:
            send_and_wait_response(sock, proto, "CREATE_ACCOUNT", ["leo", hash_password("leopw")])
            resp_cmd, resp_fields = send_and_wait_response(sock, proto, "LOGIN", ["leo", hash_password("badpw")])
            self.assertIsNotNone(resp_cmd, "No response received for login attempt")
            self.assertEqual(resp_fields[0], "ERROR")
            self.assertIn("Incorrect password", resp_fields[1])
        finally:
            sock.close()

    def test_list_accounts(self):
        """Test listing accounts using JSON protocol."""
        for user, pwd in [("mia", "pw1"), ("nick", "pw2")]:
            sock, proto = self.connect_client()
            try:
                send_and_wait_response(sock, proto, "CREATE_ACCOUNT", [user, hash_password(pwd)])
            finally:
                sock.close()
        sock, proto = self.connect_client()
        try:
            resp_cmd, resp_fields = send_and_wait_response(sock, proto, "LIST_ACCOUNTS", ["*"])
            self.assertIsNotNone(resp_cmd, "No response received for list accounts")
            # Response: ["OK", "Accounts list", <account1>, <account2>, ...]
            accounts_list = resp_fields[2:]
            self.assertIn("mia", accounts_list)
            self.assertIn("nick", accounts_list)
        finally:
            sock.close()

    def test_send_and_read_message(self):
        """Test message sending and reading using JSON protocol."""
        sock_sender, proto = self.connect_client()
        sock_receiver, _ = self.connect_client()
        try:
            send_and_wait_response(sock_sender, proto, "CREATE_ACCOUNT", ["oliver", hash_password("oliverpw")])
            send_and_wait_response(sock_sender, proto, "LOGIN", ["oliver", hash_password("oliverpw")])
            send_and_wait_response(sock_receiver, proto, "CREATE_ACCOUNT", ["paula", hash_password("paulapw")])
            send_and_wait_response(sock_receiver, proto, "LOGIN", ["paula", hash_password("paulapw")])
            send_and_wait_response(sock_sender, proto, "SEND_MESSAGE", ["paula", "Hi Paula!"])
            time.sleep(0.2)
            drain_socket(sock_receiver, proto, drain_time=0.2)
            resp_cmd, resp_fields = send_and_wait_response(sock_receiver, proto, "READ_MESSAGES", ["10"])
            self.assertIsNotNone(resp_cmd, "No response received for read messages")
            self.assertEqual(resp_fields[0], "OK")
            messages = resp_fields[2:]
            self.assertTrue(any("oliver" in m and "Hi Paula!" in m for m in messages),
                            "Paula should have received a message from oliver")
        finally:
            sock_sender.close()
            sock_receiver.close()

    def test_delete_message(self):
        """Test deletion of a message using JSON protocol."""
        sock_sender, proto = self.connect_client()
        sock_receiver, _ = self.connect_client()
        try:
            send_and_wait_response(sock_sender, proto, "CREATE_ACCOUNT", ["quinn", hash_password("quinnpw")])
            send_and_wait_response(sock_sender, proto, "LOGIN", ["quinn", hash_password("quinnpw")])
            send_and_wait_response(sock_receiver, proto, "CREATE_ACCOUNT", ["rachel", hash_password("rachelpw")])
            send_and_wait_response(sock_receiver, proto, "LOGIN", ["rachel", hash_password("rachelpw")])
            send_and_wait_response(sock_sender, proto, "SEND_MESSAGE", ["rachel", "Test deletion in JSON"])
            time.sleep(0.2)
            drain_socket(sock_receiver, proto, drain_time=0.2)
            resp_cmd, resp_fields = send_and_wait_response(sock_receiver, proto, "READ_MESSAGES", ["10"])
            messages = resp_fields[2:]
            self.assertGreater(len(messages), 0)
            first_message = messages[0]
            msg_id = first_message.split(":")[0].strip()
            del_resp_cmd, del_resp_fields = send_and_wait_response(sock_receiver, proto, "DELETE_MESSAGES", [msg_id])
            self.assertIsNotNone(del_resp_cmd, "No response received for delete messages")
            self.assertEqual(del_resp_fields[0], "OK")
            self.assertIn("Deleted", del_resp_fields[1])
            resp_cmd, resp_fields = send_and_wait_response(sock_receiver, proto, "READ_MESSAGES", ["10"])
            new_messages = resp_fields[2:]
            self.assertEqual(len(new_messages), 0)
        finally:
            sock_sender.close()
            sock_receiver.close()

    def test_delete_account(self):
        """Test deleting an account using JSON protocol."""
        sock, proto = self.connect_client()
        try:
            send_and_wait_response(sock, proto, "CREATE_ACCOUNT", ["sam", hash_password("sampw")])
            del_resp_cmd, del_resp_fields = send_and_wait_response(sock, proto, "DELETE_ACCOUNT",
                                                                   ["sam", hash_password("sampw")])
            self.assertIsNotNone(del_resp_cmd, "No response received for delete account")
            self.assertEqual(del_resp_fields[0], "OK")
        finally:
            sock.close()
        sock2, proto = self.connect_client()
        try:
            login_resp_cmd, login_resp_fields = send_and_wait_response(sock2, proto, "LOGIN",
                                                                       ["sam", hash_password("sampw")])
            self.assertIsNotNone(login_resp_cmd, "No response received for login attempt on deleted account")
            self.assertEqual(login_resp_fields[0], "ERROR")
        finally:
            sock2.close()

# -----------------------------------------------------------------------------
# Main entry point for the tests
# -----------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main()
