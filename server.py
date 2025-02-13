"""
server.py - A simple chat server for a client-server chat application.

This server supports two wire protocols: a custom binary protocol and a JSON-based protocol.
It handles the following features:
  - Creating an account
  - Logging in
  - Listing accounts (with optional wildcard matching)
  - Sending messages to recipients
  - Reading stored messages
  - Deleting messages
  - Deleting an account

Usage examples:
    python3 server.py --host localhost --port 12345 --protocol custom
    python3 server.py --host localhost --port 12345 --protocol json
"""

import socket
import threading
import struct
import json
import hashlib
import fnmatch
import argparse
import os

# =============================================================================
# Secure Password Hashing Helper Function
# =============================================================================
def hash_password(password, salt=None):
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with a salt.

    Args:
        password: The plaintext password.
        salt: (Optional) A bytes object representing the salt. If None, a new 16-byte salt is generated.

    Returns:
        A tuple (salt_hex, hashed_hex) where both values are hexadecimal strings.
    """
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 400000)
    return salt.hex(), hashed.hex()

# =============================================================================
# Protocol Implementations
# =============================================================================

class CustomProtocol:
    """
    CustomProtocol implements a custom binary protocol for message exchange.

    Message format:
      - 1 byte: Command code.
      - 4 bytes: Payload length.
      - Payload: Sequence of fields, each field is:
            - 2 bytes: Field length.
            - Field data (UTF-8 encoded).
    """
    def send_message(self, sock, command, fields):
        """
        Encodes and sends a message over the socket.

        Args:
            sock: The socket object.
            command: The command code (an integer).
            fields: A list of string fields.
        """
        payload = b""
        for field in fields:
            field_bytes = field.encode('utf-8')
            payload += struct.pack('!H', len(field_bytes))
            payload += field_bytes
        header = struct.pack('!BI', command, len(payload))
        sock.sendall(header + payload)

    def recvall(self, sock, n):
        """
        Receives exactly n bytes from the socket.

        Args:
            sock: The socket object.
            n: Number of bytes to receive.

        Returns:
            Bytes object containing the data, or None if the connection is closed.
        """
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def receive_message(self, sock):
        """
        Receives and decodes a message from the socket using the custom protocol.

        Returns:
            A tuple (command, fields) where command is an integer and fields is a list of strings.
            Returns (None, None) if the connection is closed.
        """
        header = self.recvall(sock, 5)
        if not header:
            return None, None
        command, length = struct.unpack('!BI', header)
        payload = self.recvall(sock, length)
        fields = []
        offset = 0
        while offset < len(payload):
            if offset + 2 > len(payload):
                break
            field_len = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2
            field = payload[offset:offset+field_len].decode('utf-8')
            offset += field_len
            fields.append(field)
        return command, fields

class JSONProtocol:
    """
    JSONProtocol implements a JSON-based protocol for message exchange.

    Message format:
      - 4 bytes: Length of JSON payload.
      - JSON payload: UTF-8 encoded JSON string that represents a dictionary with keys:
            "command": <command string>
            "fields": A list of strings.
    """
    def send_message(self, sock, command, fields):
        """
        Encodes and sends a JSON message over the socket.

        Args:
            sock: The socket object.
            command: The command name (a string).
            fields: A list of string fields.
        """
        msg = {"command": command, "fields": fields}
        msg_str = json.dumps(msg)
        msg_bytes = msg_str.encode('utf-8')
        header = struct.pack('!I', len(msg_bytes))
        sock.sendall(header + msg_bytes)

    def recvall(self, sock, n):
        """
        Receives exactly n bytes from the socket.

        Args:
            sock: The socket object.
            n: Number of bytes to read.

        Returns:
            A bytes object containing the data, or None if the connection is closed.
        """
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def receive_message(self, sock):
        """
        Receives and decodes a JSON message from the socket.

        Returns:
            A tuple (command, fields) where command is a string and fields is a list of strings.
            Returns (None, None) if the connection is closed.
        """
        header = self.recvall(sock, 4)
        if not header:
            return None, None
        length = struct.unpack('!I', header)[0]
        msg_bytes = self.recvall(sock, length)
        if not msg_bytes:
            return None, None
        msg_str = msg_bytes.decode('utf-8')
        msg = json.loads(msg_str)
        command = msg.get("command")
        fields = msg.get("fields", [])
        return command, fields

# =============================================================================
# Command constants for the custom binary protocol.
# =============================================================================

CMD_CREATE_ACCOUNT  = 1
CMD_LOGIN           = 2
CMD_LIST_ACCOUNTS   = 3
CMD_SEND_MESSAGE    = 4
CMD_READ_MESSAGES   = 5
CMD_DELETE_MESSAGES = 6
CMD_DELETE_ACCOUNT  = 7
CMD_NEW_MESSAGE     = 8
CMD_RESPONSE        = 100

# =============================================================================
# Data Model for User Accounts
# =============================================================================

class Account:
    """
    Represents a user account in the chat application.

    Attributes:
        username: The unique username.
        salt: Hexadecimal string representation of the random salt.
        hashed_password: Hexadecimal string of the password hash.
        messages: List of messages in the form (msg_id, sender, text).
        next_msg_id: Counter for assigning message IDs.
        online: Boolean flag indicating if the user is currently logged in.
        conn: The socket connection associated with the user (if online).
        protocol: The protocol instance used for communication.
    """
    def __init__(self, username, salt, hashed_password):
        self.username = username
        self.salt = salt              # Salt stored as a hex string.
        self.hashed_password = hashed_password  # Hashed password as a hex string.
        self.messages = []   # List to store messages: (msg_id, sender, text).
        self.next_msg_id = 1
        self.online = False
        self.conn = None
        self.protocol = None

# =============================================================================
# Main Chat Server Class
# =============================================================================

class ChatServer:
    """
    Main server class for the chat application.

    This class accepts incoming client connections and handles commands for account
    creation, login, listing accounts, sending messages, reading messages, deleting messages,
    and deleting an account. It supports both a custom binary protocol and a JSON-based protocol.

    Passwords received from clients are in plaintext; the server salts and hashes them using
    PBKDF2-HMAC-SHA256.
    """
    def __init__(self, host, port, protocol_type="custom"):
        """
        Initializes the chat server.

        Args:
            host: The hostname or IP address to bind.
            port: The port number to bind.
            protocol_type: Either "custom" or "json" to select the protocol.
        """
        self.host = host
        self.port = port
        self.accounts = {}  # Dictionary mapping usernames to Account objects.
        self.lock = threading.Lock()  # Lock for thread-safe access to shared data.
        self.protocol_type = protocol_type
        if protocol_type == "custom":
            self.protocol = CustomProtocol()
        else:
            self.protocol = JSONProtocol()

    def start(self):
        """
        Starts the chat server, listens for incoming client connections, and dispatches them
        to separate threads.
        """
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Enable address reuse to prevent "Address already in use" errors.
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)
        print(f"Server listening on {self.host}:{self.port} using {self.protocol_type} protocol.")
        while True:
            conn, addr = server_sock.accept()
            print(f"Accepted connection from {addr}.")
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.daemon = True
            t.start()

    def handle_client(self, conn):
        """
        Handles communication with a connected client.

        The client must first log in or create an account. This method processes commands for:
          - Account creation (CREATE_ACCOUNT)
          - Login (LOGIN)
          - Listing accounts (LIST_ACCOUNTS)
          - Sending messages (SEND_MESSAGE)
          - Reading messages (READ_MESSAGES)
          - Deleting messages (DELETE_MESSAGES)
          - Deleting an account (DELETE_ACCOUNT)

        Args:
            conn: The socket connection to the client.
        """
        logged_in_user = None  # Track the username of the client once logged in.
        try:
            while True:
                command, fields = self.protocol.receive_message(conn)
                if command is None:
                    print("Connection closed by client.")
                    break

                if self.protocol_type == "custom":
                    if command == CMD_CREATE_ACCOUNT:
                        if len(fields) < 2:
                            self.send_error(conn, "Invalid fields for CREATE_ACCOUNT")
                            continue
                        username, password = fields[0], fields[1]
                        with self.lock:
                            if username in self.accounts:
                                self.send_error(conn, "Account exists; please login.")
                            else:
                                salt, hashed_pw = hash_password(password)
                                self.accounts[username] = Account(username, salt, hashed_pw)
                                self.send_response(conn, "Account created successfully.")
                    elif command == CMD_LOGIN:
                        if len(fields) < 2:
                            self.send_error(conn, "Invalid fields for LOGIN")
                            continue
                        username, password = fields[0], fields[1]
                        with self.lock:
                            if username not in self.accounts:
                                self.send_error(conn, "Account does not exist.")
                            else:
                                account = self.accounts[username]
                                salt_bytes = bytes.fromhex(account.salt)
                                _, computed_hash = hash_password(password, salt_bytes)
                                if account.hashed_password != computed_hash:
                                    self.send_error(conn, "Incorrect password.")
                                else:
                                    logged_in_user = username
                                    account.online = True
                                    account.conn = conn
                                    account.protocol = self.protocol
                                    unread_count = len(account.messages)
                                    self.send_response(conn, f"Login successful. Unread messages: {unread_count}")
                    elif command == CMD_LIST_ACCOUNTS:
                        pattern = fields[0] if fields and fields[0] != "" else "*"
                        with self.lock:
                            matching = [uname for uname in self.accounts if fnmatch.fnmatch(uname, pattern)]
                        self.send_response(conn, "Accounts list", *matching)
                    elif command == CMD_SEND_MESSAGE:
                        if logged_in_user is None:
                            self.send_error(conn, "Please login first.")
                            continue
                        if len(fields) < 2:
                            self.send_error(conn, "Invalid fields for SEND_MESSAGE")
                            continue
                        recipient, message_text = fields[0], fields[1]
                        with self.lock:
                            if recipient not in self.accounts:
                                self.send_error(conn, "Recipient does not exist.")
                            else:
                                recipient_account = self.accounts[recipient]
                                msg_id = recipient_account.next_msg_id
                                recipient_account.next_msg_id += 1
                                message = (str(msg_id), logged_in_user, message_text)
                                recipient_account.messages.append(message)
                                # If the recipient is online, immediately push the message.
                                if recipient_account.online and recipient_account.conn:
                                    try:
                                        self.protocol.send_message(recipient_account.conn, CMD_NEW_MESSAGE,
                                                                   [logged_in_user, message_text, str(msg_id)])
                                    except Exception as e:
                                        print(f"Error delivering immediate message: {e}")
                                self.send_response(conn, "Message sent.")
                    elif command == CMD_READ_MESSAGES:
                        if logged_in_user is None:
                            self.send_error(conn, "Please login first.")
                            continue
                        try:
                            num = int(fields[0]) if fields and fields[0].isdigit() else len(self.accounts[logged_in_user].messages)
                        except Exception:
                            num = len(self.accounts[logged_in_user].messages)
                        with self.lock:
                            account = self.accounts[logged_in_user]
                            msgs = account.messages[:num]
                        msgs_formatted = [f"{msg[0]}: {msg[1]}: {msg[2]}" for msg in msgs]
                        self.send_response(conn, "Messages", *msgs_formatted)
                    elif command == CMD_DELETE_MESSAGES:
                        if logged_in_user is None:
                            self.send_error(conn, "Please login first.")
                            continue
                        ids_to_delete = set(fields)
                        with self.lock:
                            account = self.accounts[logged_in_user]
                            before = len(account.messages)
                            account.messages = [msg for msg in account.messages if msg[0] not in ids_to_delete]
                            after = len(account.messages)
                        self.send_response(conn, f"Deleted {before - after} messages.")
                    elif command == CMD_DELETE_ACCOUNT:
                        if len(fields) < 2:
                            self.send_error(conn, "Invalid fields for DELETE_ACCOUNT")
                            continue
                        username, password = fields[0], fields[1]
                        with self.lock:
                            if username not in self.accounts:
                                self.send_error(conn, "Account does not exist.")
                            else:
                                account = self.accounts[username]
                                salt_bytes = bytes.fromhex(account.salt)
                                _, computed_hash = hash_password(password, salt_bytes)
                                if account.hashed_password != computed_hash:
                                    self.send_error(conn, "Incorrect password.")
                                else:
                                    del self.accounts[username]
                                    self.send_response(conn, "Account deleted.")
                                    conn.close()
                                    return
                    else:
                        self.send_error(conn, "Unknown command.")
                else:
                    # JSON protocol processing (similar to custom protocol, but commands are strings)
                    if command == "CREATE_ACCOUNT":
                        if len(fields) < 2:
                            self.send_error(conn, "Invalid fields for CREATE_ACCOUNT")
                            continue
                        username, password = fields[0], fields[1]
                        with self.lock:
                            if username in self.accounts:
                                self.send_error(conn, "Account exists; please login.")
                            else:
                                salt, hashed_pw = hash_password(password)
                                self.accounts[username] = Account(username, salt, hashed_pw)
                                self.send_response(conn, "Account created successfully.")
                    elif command == "LOGIN":
                        if len(fields) < 2:
                            self.send_error(conn, "Invalid fields for LOGIN")
                            continue
                        username, password = fields[0], fields[1]
                        with self.lock:
                            if username not in self.accounts:
                                self.send_error(conn, "Account does not exist.")
                            else:
                                account = self.accounts[username]
                                salt_bytes = bytes.fromhex(account.salt)
                                _, computed_hash = hash_password(password, salt_bytes)
                                if account.hashed_password != computed_hash:
                                    self.send_error(conn, "Incorrect password.")
                                else:
                                    logged_in_user = username
                                    account.online = True
                                    account.conn = conn
                                    account.protocol = self.protocol
                                    unread_count = len(account.messages)
                                    self.send_response(conn, f"Login successful. Unread messages: {unread_count}")
                    elif command == "LIST_ACCOUNTS":
                        pattern = fields[0] if fields and fields[0] != "" else "*"
                        with self.lock:
                            matching = [uname for uname in self.accounts if fnmatch.fnmatch(uname, pattern)]
                        self.send_response(conn, "Accounts list", *matching)
                    elif command == "SEND_MESSAGE":
                        if logged_in_user is None:
                            self.send_error(conn, "Please login first.")
                            continue
                        if len(fields) < 2:
                            self.send_error(conn, "Invalid fields for SEND_MESSAGE")
                            continue
                        recipient, message_text = fields[0], fields[1]
                        with self.lock:
                            if recipient not in self.accounts:
                                self.send_error(conn, "Recipient does not exist.")
                            else:
                                recipient_account = self.accounts[recipient]
                                msg_id = recipient_account.next_msg_id
                                recipient_account.next_msg_id += 1
                                message = (str(msg_id), logged_in_user, message_text)
                                recipient_account.messages.append(message)
                                if recipient_account.online and recipient_account.conn:
                                    try:
                                        self.protocol.send_message(recipient_account.conn, "NEW_MESSAGE",
                                                                   [logged_in_user, message_text, str(msg_id)])
                                    except Exception as e:
                                        print(f"Error delivering immediate message: {e}")
                                self.send_response(conn, "Message sent.")
                    elif command == "READ_MESSAGES":
                        if logged_in_user is None:
                            self.send_error(conn, "Please login first.")
                            continue
                        try:
                            num = int(fields[0]) if fields and fields[0].isdigit() else len(self.accounts[logged_in_user].messages)
                        except Exception:
                            num = len(self.accounts[logged_in_user].messages)
                        with self.lock:
                            account = self.accounts[logged_in_user]
                            msgs = account.messages[:num]
                        msgs_formatted = [f"{msg[0]}: {msg[1]}: {msg[2]}" for msg in msgs]
                        self.send_response(conn, "Messages", *msgs_formatted)
                    elif command == "DELETE_MESSAGES":
                        if logged_in_user is None:
                            self.send_error(conn, "Please login first.")
                            continue
                        ids_to_delete = set(fields)
                        with self.lock:
                            account = self.accounts[logged_in_user]
                            before = len(account.messages)
                            account.messages = [msg for msg in account.messages if msg[0] not in ids_to_delete]
                            after = len(account.messages)
                        self.send_response(conn, f"Deleted {before - after} messages.")
                    elif command == "DELETE_ACCOUNT":
                        if len(fields) < 2:
                            self.send_error(conn, "Invalid fields for DELETE_ACCOUNT")
                            continue
                        username, password = fields[0], fields[1]
                        with self.lock:
                            if username not in self.accounts:
                                self.send_error(conn, "Account does not exist.")
                            else:
                                account = self.accounts[username]
                                salt_bytes = bytes.fromhex(account.salt)
                                _, computed_hash = hash_password(password, salt_bytes)
                                if account.hashed_password != computed_hash:
                                    self.send_error(conn, "Incorrect password.")
                                else:
                                    del self.accounts[username]
                                    self.send_response(conn, "Account deleted.")
                                    conn.close()
                                    return
                    else:
                        self.send_error(conn, "Unknown command.")
        except Exception as e:
            print(f"Exception in client handler: {e}")
        finally:
            # Mark the account as offline when the connection is closed.
            if logged_in_user:
                with self.lock:
                    if logged_in_user in self.accounts:
                        self.accounts[logged_in_user].online = False
                        self.accounts[logged_in_user].conn = None
            conn.close()

    def send_response(self, conn, message, *extra_fields):
        """
        Sends a success response back to the client.

        Args:
            conn: The socket connection to the client.
            message: The primary response message.
            extra_fields: Additional fields to include in the response.
        """
        if self.protocol_type == "custom":
            self.protocol.send_message(conn, CMD_RESPONSE, ["OK", message] + list(extra_fields))
        else:
            self.protocol.send_message(conn, "RESPONSE", ["OK", message] + list(extra_fields))

    def send_error(self, conn, error_message):
        """
        Sends an error response back to the client.

        Args:
            conn: The socket connection to the client.
            error_message: A descriptive error message.
        """
        if self.protocol_type == "custom":
            self.protocol.send_message(conn, CMD_RESPONSE, ["ERROR", error_message])
        else:
            self.protocol.send_message(conn, "RESPONSE", ["ERROR", error_message])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chat Server")
    parser.add_argument("--host", default="localhost", help="Hostname or IP address to bind")
    parser.add_argument("--port", type=int, default=12345, help="Port number to bind")
    parser.add_argument("--protocol", choices=["custom", "json"], default="custom",
                        help="Wire protocol to use (custom or json)")
    args = parser.parse_args()
    
    server = ChatServer(args.host, args.port, protocol_type=args.protocol)
    server.start()
