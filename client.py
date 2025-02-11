"""
client.py - A simple chat client with a Tkinter graphical interface.

This client connects to the chat server using either a custom binary protocol
or a JSON-based protocol. It provides functionalities for:
  - Creating an account and logging in.
  - Sending messages (format: recipient: message text).
  - Listing accounts.
  - Reading messages.
  - Deleting messages.
  - Deleting the account.

Usage examples:
    python3 client.py --host localhost --port 12345 --protocol custom
    python3 client.py --host localhost --port 12345 --protocol json
"""

import socket
import threading
import struct
import json
import tkinter as tk
import tkinter.scrolledtext as st
import tkinter.messagebox as messagebox
import tkinter.simpledialog as simpledialog
import argparse

# =============================================================================
# Protocol Implementations
# =============================================================================

class CustomProtocol:
    """
    CustomProtocol implements the custom binary protocol for communication.

    Message format:
      - 1 byte: Command code.
      - 4 bytes: Payload length.
      - Payload: Multiple fields, each with:
            - 2 bytes: Field length.
            - Field data (UTF-8 encoded).
    """
    def send_message(self, sock, command, fields):
        """
        Encodes and sends a message over the given socket using the custom binary protocol.

        Args:
            sock: The socket to send data on.
            command: The command code (an integer).
            fields: A list of string fields to include in the message payload.
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
            sock: The socket from which to receive.
            n: The number of bytes to receive.

        Returns:
            A bytes object with the received data, or None if the connection is closed.
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
    JSONProtocol implements a JSON-based protocol for communication.

    Message format:
      - 4 bytes: Length of the JSON payload.
      - JSON payload: A UTF-8 encoded JSON string with keys "command" and "fields".
    """
    def send_message(self, sock, command, fields):
        """
        Encodes and sends a JSON message over the given socket.

        Args:
            sock: The socket to send the message on.
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
            sock: The socket to read from.
            n: The number of bytes to read.

        Returns:
            A bytes object containing the received data, or None if the connection is closed.
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
# Chat Client Class with Tkinter GUI
# =============================================================================

class ChatClient:
    """
    ChatClient implements a GUI-based client for the chat application.

    This class provides a Tkinter interface that allows the user to create an account,
    log in, send messages, list accounts, read stored messages, delete messages, and delete the account.
    It supports both a custom binary protocol and a JSON-based protocol.

    Note:
      The client sends the plaintext password. The server salts and hashes the password.
    """
    def __init__(self, host, port, protocol_type="custom"):
        """
        Initializes the ChatClient.

        Args:
            host: The server's hostname.
            port: The server's port number.
            protocol_type: Either "custom" or "json" to select the communication protocol.
        """
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.protocol_type = protocol_type
        if protocol_type == "custom":
            self.protocol = CustomProtocol()
        else:
            self.protocol = JSONProtocol()
        self.username = None  # The currently logged-in username
        self.running = True   # Flag to control the listener thread
        # Start a background thread to listen for messages from the server.
        self.listener_thread = threading.Thread(target=self.listen_to_server)
        self.listener_thread.daemon = True
        self.listener_thread.start()
        # Initialize the Tkinter GUI.
        self.root = tk.Tk()
        self.root.title("Chat Client")
        self.setup_gui()

    def setup_gui(self):
        """
        Sets up the graphical user interface with two frames:
          - A login frame for account creation and login.
          - A chat frame for sending messages and account management.
        """
        self.frame_login = tk.Frame(self.root)
        self.frame_chat = tk.Frame(self.root)
        
        # --- Login Frame ---
        tk.Label(self.frame_login, text="Username:").grid(row=0, column=0)
        self.entry_username = tk.Entry(self.frame_login)
        self.entry_username.grid(row=0, column=1)
        tk.Label(self.frame_login, text="Password:").grid(row=1, column=0)
        self.entry_password = tk.Entry(self.frame_login, show="*")
        self.entry_password.grid(row=1, column=1)
        self.btn_login = tk.Button(self.frame_login, text="Login", command=self.login)
        self.btn_login.grid(row=2, column=0)
        self.btn_create = tk.Button(self.frame_login, text="Create Account", command=self.create_account)
        self.btn_create.grid(row=2, column=1)
        self.frame_login.pack()

        # --- Chat Frame ---
        self.text_area = st.ScrolledText(self.frame_chat, state='disabled', width=50, height=20)
        self.text_area.pack()
        self.entry_message = tk.Entry(self.frame_chat, width=40)
        self.entry_message.pack(side='left')
        self.btn_send = tk.Button(self.frame_chat, text="Send", command=self.send_message)
        self.btn_send.pack(side='left')
        self.btn_list = tk.Button(self.frame_chat, text="List Accounts", command=self.list_accounts)
        self.btn_list.pack(side='left')
        self.btn_read = tk.Button(self.frame_chat, text="Read Messages", command=self.read_messages)
        self.btn_read.pack(side='left')
        self.btn_delete_msg = tk.Button(self.frame_chat, text="Delete Messages", command=self.delete_messages)
        self.btn_delete_msg.pack(side='left')
        self.btn_delete_acc = tk.Button(self.frame_chat, text="Delete Account", command=self.delete_account)
        self.btn_delete_acc.pack(side='left')

    def login(self):
        """
        Attempts to log in with the provided username and password.

        The plaintext password is sent to the server (which will apply salting and hashing).
        On a successful login, the login frame is hidden and the chat frame is shown.
        """
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return
        # Send the plaintext password.
        if self.protocol_type == "custom":
            self.protocol.send_message(self.sock, CMD_LOGIN, [username, password])
        else:
            self.protocol.send_message(self.sock, "LOGIN", [username, password])
        self.username = username
        self.frame_login.pack_forget()
        self.frame_chat.pack()

    def create_account(self):
        """
        Sends a request to create an account using the provided username and password.

        The plaintext password is sent to the server; the server will salt and hash it.
        """
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return
        if self.protocol_type == "custom":
            self.protocol.send_message(self.sock, CMD_CREATE_ACCOUNT, [username, password])
        else:
            self.protocol.send_message(self.sock, "CREATE_ACCOUNT", [username, password])
        messagebox.showinfo("Info", "Account creation requested. Please login.")

    def send_message(self):
        """
        Sends a message to another user.

        The message must be in the format "recipient: message text".
        """
        text = self.entry_message.get().strip()
        if not text:
            return
        if ':' not in text:
            messagebox.showerror("Error", "Message format must be: recipient: message")
            return
        recipient, message_text = text.split(':', 1)
        recipient = recipient.strip()
        message_text = message_text.strip()
        if self.protocol_type == "custom":
            self.protocol.send_message(self.sock, CMD_SEND_MESSAGE, [recipient, message_text])
        else:
            self.protocol.send_message(self.sock, "SEND_MESSAGE", [recipient, message_text])
        self.entry_message.delete(0, tk.END)

    def list_accounts(self):
        """
        Prompts the user for a wildcard pattern and sends a request to list matching accounts.
        """
        pattern = simpledialog.askstring("List Accounts", "Enter wildcard pattern (or leave blank for all):")
        if pattern is None:
            return
        if self.protocol_type == "custom":
            self.protocol.send_message(self.sock, CMD_LIST_ACCOUNTS, [pattern])
        else:
            self.protocol.send_message(self.sock, "LIST_ACCOUNTS", [pattern])

    def read_messages(self):
        """
        Prompts the user for the number of messages to read and sends a request to the server.
        """
        num = simpledialog.askstring("Read Messages", "How many messages to read?")
        if num is None or not num.isdigit():
            num = "10"
        if self.protocol_type == "custom":
            self.protocol.send_message(self.sock, CMD_READ_MESSAGES, [num])
        else:
            self.protocol.send_message(self.sock, "READ_MESSAGES", [num])

    def delete_messages(self):
        """
        Prompts the user for message IDs to delete and sends a deletion request to the server.
        """
        ids = simpledialog.askstring("Delete Messages", "Enter message IDs to delete (comma separated):")
        if ids is None:
            return
        id_list = [msg_id.strip() for msg_id in ids.split(",") if msg_id.strip()]
        if self.protocol_type == "custom":
            self.protocol.send_message(self.sock, CMD_DELETE_MESSAGES, id_list)
        else:
            self.protocol.send_message(self.sock, "DELETE_MESSAGES", id_list)

    def delete_account(self):
        """
        Prompts the user for confirmation and sends a request to delete the account.

        The plaintext password is sent to the server (which will verify it using the salted hash).
        """
        if messagebox.askyesno("Delete Account", "Are you sure you want to delete your account?"):
            password = self.entry_password.get().strip()
            if self.protocol_type == "custom":
                self.protocol.send_message(self.sock, CMD_DELETE_ACCOUNT, [self.username, password])
            else:
                self.protocol.send_message(self.sock, "DELETE_ACCOUNT", [self.username, password])
            self.sock.close()
            self.root.quit()

    def listen_to_server(self):
        """
        Runs in a background thread to listen for and process incoming messages from the server.

        Processes both response messages and asynchronous notifications (like new messages).
        """
        while self.running:
            try:
                command, fields = self.protocol.receive_message(self.sock)
                if command is None:
                    break
                if self.protocol_type == "custom":
                    if command == CMD_RESPONSE:
                        status = fields[0]
                        msg = fields[1] if len(fields) > 1 else ""
                        self.append_text(f"Server response: {status} – {msg}\n")
                        if len(fields) > 2:
                            self.append_text("\n".join(fields[2:]) + "\n")
                    elif command == CMD_NEW_MESSAGE:
                        sender = fields[0]
                        message_text = fields[1]
                        msg_id = fields[2]
                        self.append_text(f"New message from {sender}: {message_text} (ID: {msg_id})\n")
                else:
                    if command == "RESPONSE":
                        status = fields[0]
                        msg = fields[1] if len(fields) > 1 else ""
                        self.append_text(f"Server response: {status} – {msg}\n")
                        if len(fields) > 2:
                            self.append_text("\n".join(fields[2:]) + "\n")
                    elif command == "NEW_MESSAGE":
                        sender = fields[0]
                        message_text = fields[1]
                        msg_id = fields[2]
                        self.append_text(f"New message from {sender}: {message_text} (ID: {msg_id})\n")
            except Exception as e:
                self.append_text(f"Error receiving message: {e}\n")
                break
        self.sock.close()

    def append_text(self, text):
        """
        Appends text to the chat display area in a thread-safe manner.

        Args:
            text: The text string to append.
        """
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, text)
        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)

    def run(self):
        """
        Runs the Tkinter main loop.
        """
        self.root.mainloop()
        self.running = False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chat Client")
    parser.add_argument("--host", default="localhost", help="Server hostname")
    parser.add_argument("--port", type=int, default=12345, help="Server port")
    parser.add_argument("--protocol", choices=["custom", "json"], default="custom",
                        help="Wire protocol to use (custom or json)")
    args = parser.parse_args()

    client = ChatClient(args.host, args.port, protocol_type=args.protocol)
    client.run()
