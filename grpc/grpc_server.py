"""
grpc_server.py - A simple chat server for a client-server chat application using gRPC.

This server implements a chat service with the following features:
  - Creating an account
  - Logging in
  - Listing accounts (with optional wildcard matching)
  - Sending messages to recipients
  - Reading stored messages
  - Deleting messages
  - Deleting an account
  - Streaming new messages to online users

Communication is handled using gRPC and Protocol Buffers, which automatically
serialize and deserialize messages in a compact binary format.

Usage example:
    python grpc_server.py --host localhost --port 50051
"""

import grpc
from concurrent import futures
import time
import threading
import hashlib
import os
import queue
import fnmatch
import argparse

import chat_pb2
import chat_pb2_grpc

# =============================================================================
# Secure Password Hashing Helper Function
# =============================================================================
def hash_password(password, salt=None):
    """
    Securely hashes a password using PBKDF2-HMAC-SHA256 with a salt.

    Args:
        password (str): The plaintext password.
        salt (bytes, optional): A random salt. If None, a new 16-byte salt is generated.

    Returns:
        tuple: A pair (salt_hex, hashed_hex) where both values are hexadecimal strings.
    """
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 400000)
    return salt.hex(), hashed.hex()

# =============================================================================
# Data Model for User Accounts
# =============================================================================
class Account:
    """
    Represents a user account in the chat system.

    Attributes:
        username (str): The unique username.
        salt (str): Hexadecimal string representing the random salt.
        hashed_password (str): Hexadecimal string of the hashed password.
        messages (list): List of stored messages in the form (msg_id, sender, text).
        next_msg_id (int): Counter for assigning unique message IDs.
        online (bool): Flag indicating whether the user is currently logged in.
        message_queue (Queue): Queue for streaming new messages to the user.
    """
    def __init__(self, username, salt, hashed_password):
        self.username = username
        self.salt = salt              # Salt stored as a hex string.
        self.hashed_password = hashed_password  # Hashed password stored as a hex string.
        self.messages = []   # List to store messages: (msg_id, sender, text).
        self.next_msg_id = 1  # Counter for the next message ID.
        self.online = False   # User's online status.
        self.message_queue = queue.Queue()  # Queue for new message streaming.

# =============================================================================
# gRPC Chat Service Servicer Implementation
# =============================================================================
class ChatServiceServicer(chat_pb2_grpc.ChatServiceServicer):
    """
    Implements the gRPC chat service as defined in chat.proto.

    This class handles account creation, login, account listing, message sending,
    reading messages, deleting messages, deleting accounts, and streaming new messages.
    A global lock is used to ensure thread-safe access to the accounts data.
    """
    def __init__(self):
        self.accounts = {}  # Dictionary mapping usernames to Account instances.
        self.lock = threading.Lock()  # Lock for thread-safe operations.

    def CreateAccount(self, request, context):
        """
        Creates a new account if the username does not already exist.

        Args:
            request: A CreateAccountRequest containing the username and plaintext password.
            context: gRPC context (not used here).

        Returns:
            A Response indicating success or failure.
        """
        username = request.username
        password = request.password
        with self.lock:
            if username in self.accounts:
                return chat_pb2.Response(status="ERROR", message="Account exists; please login.")
            salt, hashed_pw = hash_password(password)
            self.accounts[username] = Account(username, salt, hashed_pw)
        return chat_pb2.Response(status="OK", message="Account created successfully.")

    def Login(self, request, context):
        """
        Authenticates a user and marks their account as online.

        Args:
            request: A LoginRequest with username and plaintext password.
            context: gRPC context.

        Returns:
            A LoginResponse indicating success or failure and the unread message count.
        """
        username = request.username
        password = request.password
        with self.lock:
            if username not in self.accounts:
                return chat_pb2.LoginResponse(status="ERROR", message="Account does not exist.", unread_count=0)
            account = self.accounts[username]
            salt_bytes = bytes.fromhex(account.salt)
            _, computed_hash = hash_password(password, salt_bytes)
            if account.hashed_password != computed_hash:
                return chat_pb2.LoginResponse(status="ERROR", message="Incorrect password.", unread_count=0)
            account.online = True
            unread_count = len(account.messages)
        return chat_pb2.LoginResponse(
            status="OK", 
            message=f"Login successful. Unread messages: {unread_count}",
            unread_count=unread_count
        )

    def ListAccounts(self, request, context):
        """
        Returns a list of accounts whose usernames match a given wildcard pattern.

        Args:
            request: A ListAccountsRequest containing the wildcard pattern.
            context: gRPC context.

        Returns:
            A ListAccountsResponse with the list of matching usernames.
        """
        pattern = request.pattern if request.pattern else "*"
        with self.lock:
            matching = [uname for uname in self.accounts if fnmatch.fnmatch(uname, pattern)]
        return chat_pb2.ListAccountsResponse(status="OK", message="Accounts list", accounts=matching)

    def SendMessage(self, request, context):
        """
        Sends a message from one user to another.

        Args:
            request: A SendMessageRequest containing sender, recipient, and message text.
            context: gRPC context.

        Returns:
            A Response indicating whether the message was successfully sent.
        """
        sender = request.sender
        recipient = request.recipient
        message_text = request.message_text
        with self.lock:
            if recipient not in self.accounts:
                return chat_pb2.Response(status="ERROR", message="Recipient does not exist.")
            recipient_account = self.accounts[recipient]
            msg_id = recipient_account.next_msg_id
            recipient_account.next_msg_id += 1
            message = (str(msg_id), sender, message_text)
            recipient_account.messages.append(message)
            # If the recipient is online, push the new message to their stream.
            if recipient_account.online:
                new_msg = chat_pb2.NewMessage(sender=sender, message_text=message_text, msg_id=str(msg_id))
                recipient_account.message_queue.put(new_msg)
        return chat_pb2.Response(status="OK", message="Message sent.")

    def ReadMessages(self, request, context):
        """
        Retrieves a specified number of messages for a user.

        Args:
            request: A ReadMessagesRequest with the username and the number of messages to read.
            context: gRPC context.

        Returns:
            A ReadMessagesResponse containing the retrieved messages.
        """
        username = request.username
        num = request.num if request.num > 0 else 10
        with self.lock:
            if username not in self.accounts:
                return chat_pb2.ReadMessagesResponse(status="ERROR", message="Account does not exist.", messages=[])
            account = self.accounts[username]
            msgs = account.messages[:num]
        # Format the messages for display.
        msgs_formatted = [f"{msg[0]}: {msg[1]}: {msg[2]}" for msg in msgs]
        return chat_pb2.ReadMessagesResponse(status="OK", message="Messages", messages=msgs_formatted)

    def DeleteMessages(self, request, context):
        """
        Deletes messages from a user's account based on provided message IDs.

        Args:
            request: A DeleteMessagesRequest with the username and a list of message IDs.
            context: gRPC context.

        Returns:
            A Response indicating the number of messages deleted.
        """
        username = request.username
        ids_to_delete = set(request.message_ids)
        with self.lock:
            if username not in self.accounts:
                return chat_pb2.Response(status="ERROR", message="Account does not exist.")
            account = self.accounts[username]
            before = len(account.messages)
            account.messages = [msg for msg in account.messages if msg[0] not in ids_to_delete]
            after = len(account.messages)
        return chat_pb2.Response(status="OK", message=f"Deleted {before - after} messages.")

    def DeleteAccount(self, request, context):
        """
        Deletes a user account after verifying the provided password.

        Args:
            request: A DeleteAccountRequest with the username and plaintext password.
            context: gRPC context.

        Returns:
            A Response indicating success or failure.
        """
        username = request.username
        password = request.password
        with self.lock:
            if username not in self.accounts:
                return chat_pb2.Response(status="ERROR", message="Account does not exist.")
            account = self.accounts[username]
            salt_bytes = bytes.fromhex(account.salt)
            _, computed_hash = hash_password(password, salt_bytes)
            if account.hashed_password != computed_hash:
                return chat_pb2.Response(status="ERROR", message="Incorrect password.")
            del self.accounts[username]
        return chat_pb2.Response(status="OK", message="Account deleted.")

    def MessageStream(self, request, context):
        """
        Streams new messages to a user.

        This is a server-side streaming RPC that continuously yields new messages
        from the user's message queue. It periodically checks if the account is still active.
        
        Args:
            request: A MessageStreamRequest containing the username.
            context: gRPC context.

        Yields:
            NewMessage messages as they arrive.
        """
        username = request.username
        with self.lock:
            if username not in self.accounts:
                context.set_details("Account does not exist.")
                context.set_code(grpc.StatusCode.NOT_FOUND)
                return
            account = self.accounts[username]
        # Continuously yield messages from the queue.
        while True:
            try:
                new_msg = account.message_queue.get(timeout=5)
                yield new_msg
            except queue.Empty:
                # If no message is received within timeout, check if account is still online.
                with self.lock:
                    if username not in self.accounts or not account.online:
                        break
                continue

# =============================================================================
# Server Startup
# =============================================================================
def serve(host, port):
    """
    Initializes and starts the gRPC chat server on the specified host and port.

    Args:
        host (str): The hostname or IP address to bind the server.
        port (int): The port number to bind the server.
    """
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatServiceServicer(), server)
    server_address = f"{host}:{port}"
    server.add_insecure_port(server_address)
    server.start()
    print(f"gRPC Chat Server started on {server_address}.")
    try:
        # Keep the server running indefinitely.
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        server.stop(0)

if __name__ == '__main__':
    # Parse command-line arguments for host and port configuration.
    parser = argparse.ArgumentParser(description="gRPC Chat Server")
    parser.add_argument("--host", default="[::]", help="Host to bind the server (default: all interfaces)")
    parser.add_argument("--port", type=int, default=50051, help="Port number to bind (default: 50051)")
    args = parser.parse_args()
    serve(args.host, args.port)
