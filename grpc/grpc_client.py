"""
grpc_client.py - A simple chat client with a Tkinter graphical interface using gRPC.

This client connects to the gRPC chat server using the generated stubs from chat.proto.
It provides functionalities for:
  - Creating an account and logging in.
  - Sending messages (format: recipient: message text).
  - Listing accounts.
  - Reading messages.
  - Deleting messages.
  - Deleting the account.

Usage examples:
    python grpc_client.py --host localhost --port 50051
"""

import grpc
import threading
import tkinter as tk
import tkinter.scrolledtext as st
import tkinter.messagebox as messagebox
import tkinter.simpledialog as simpledialog
import argparse

import chat_pb2
import chat_pb2_grpc

class ChatClient:
    """
    ChatClient encapsulates the client-side logic for a gRPC-based chat application.
    
    This client uses a Tkinter GUI to enable users to create accounts, log in,
    send messages, list accounts, read stored messages, delete messages, and delete their account.
    Communication with the chat server is handled via a gRPC channel and auto-generated stubs.
    """
    def __init__(self, host='localhost', port=50051):
        # Establish a gRPC insecure channel to the chat server at the specified host and port.
        self.channel = grpc.insecure_channel(f'{host}:{port}')
        # Create a stub for the ChatService using the generated classes from chat.proto.
        self.stub = chat_pb2_grpc.ChatServiceStub(self.channel)
        self.username = None  # This will be set upon successful login.
        self.running = True   # Flag used to control the background listener thread.

        # Initialize the Tkinter GUI.
        self.root = tk.Tk()
        self.root.title("Chat Client")
        self.setup_gui()

    def setup_gui(self):
        """
        Configures the graphical user interface.
        
        The interface is divided into two main frames:
          1. The login frame, used for account creation and login.
          2. The chat frame, used for sending and managing messages once logged in.
        """
        # Create the frame for login components.
        self.frame_login = tk.Frame(self.root)
        # Create the frame for chat operations.
        self.frame_chat = tk.Frame(self.root)
        
        # --- Login Frame Setup ---
        tk.Label(self.frame_login, text="Username:").grid(row=0, column=0)
        self.entry_username = tk.Entry(self.frame_login)
        self.entry_username.grid(row=0, column=1)
        tk.Label(self.frame_login, text="Password:").grid(row=1, column=0)
        self.entry_password = tk.Entry(self.frame_login, show="*")
        self.entry_password.grid(row=1, column=1)
        # Button to trigger the login process.
        self.btn_login = tk.Button(self.frame_login, text="Login", command=self.login)
        self.btn_login.grid(row=2, column=0)
        # Button to trigger account creation.
        self.btn_create = tk.Button(self.frame_login, text="Create Account", command=self.create_account)
        self.btn_create.grid(row=2, column=1)
        # Display the login frame.
        self.frame_login.pack()

        # --- Chat Frame Setup ---
        # A scrolled text widget displays chat messages.
        self.text_area = st.ScrolledText(self.frame_chat, state='disabled', width=50, height=20)
        self.text_area.pack()
        # Entry widget for composing messages.
        self.entry_message = tk.Entry(self.frame_chat, width=40)
        self.entry_message.pack(side='left')
        # Button to send the composed message.
        self.btn_send = tk.Button(self.frame_chat, text="Send", command=self.send_message)
        self.btn_send.pack(side='left')
        # Button to request listing of accounts.
        self.btn_list = tk.Button(self.frame_chat, text="List Accounts", command=self.list_accounts)
        self.btn_list.pack(side='left')
        # Button to request reading stored messages.
        self.btn_read = tk.Button(self.frame_chat, text="Read Messages", command=self.read_messages)
        self.btn_read.pack(side='left')
        # Button to delete specific messages.
        self.btn_delete_msg = tk.Button(self.frame_chat, text="Delete Messages", command=self.delete_messages)
        self.btn_delete_msg.pack(side='left')
        # Button to delete the user's account.
        self.btn_delete_acc = tk.Button(self.frame_chat, text="Delete Account", command=self.delete_account)
        self.btn_delete_acc.pack(side='left')

    def login(self):
        """
        Handles the login process.
        
        Retrieves the username and password from the GUI, performs input validation,
        and sends a LoginRequest via gRPC. Upon successful authentication, the login frame is hidden,
        and the chat frame is displayed. A background thread is then started to listen for incoming messages.
        """
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return
        try:
            response = self.stub.Login(chat_pb2.LoginRequest(username=username, password=password))
        except grpc.RpcError as e:
            messagebox.showerror("Error", f"RPC error: {e}")
            return

        if response.status != "OK":
            messagebox.showerror("Error", response.message)
            return

        # Store the username and update the UI.
        self.username = username
        self.append_text(f"Login successful. {response.message}\n")
        self.frame_login.pack_forget()  # Hide the login frame.
        self.frame_chat.pack()          # Show the chat frame.
        # Start a background thread to listen for server-pushed messages.
        threading.Thread(target=self.listen_to_messages, daemon=True).start()

    def create_account(self):
        """
        Initiates account creation.
        
        Sends a CreateAccountRequest via gRPC using the provided username and plaintext password.
        The server handles salting and hashing the password. A confirmation message is shown upon success.
        """
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return
        try:
            response = self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username=username, password=password))
        except grpc.RpcError as e:
            messagebox.showerror("Error", f"RPC error: {e}")
            return

        if response.status != "OK":
            messagebox.showerror("Error", response.message)
        else:
            messagebox.showinfo("Info", response.message)

    def send_message(self):
        """
        Sends a message to another user.
        
        The message must follow the format "recipient: message text". The method sends a SendMessageRequest via gRPC
        and clears the input field upon successful transmission.
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
        try:
            response = self.stub.SendMessage(chat_pb2.SendMessageRequest(
                sender=self.username, recipient=recipient, message_text=message_text))
        except grpc.RpcError as e:
            self.append_text(f"RPC error: {e}\n")
            return
        self.append_text(f"Server response: {response.status} - {response.message}\n")
        self.entry_message.delete(0, tk.END)  # Clear the input after sending.

    def list_accounts(self):
        """
        Requests a list of accounts matching a wildcard pattern.
        
        Prompts the user for a pattern and sends a ListAccountsRequest via gRPC.
        The resulting list of usernames is displayed in the text area.
        """
        pattern = simpledialog.askstring("List Accounts", "Enter wildcard pattern (or leave blank for all):")
        if pattern is None:
            return
        try:
            response = self.stub.ListAccounts(chat_pb2.ListAccountsRequest(pattern=pattern))
        except grpc.RpcError as e:
            self.append_text(f"RPC error: {e}\n")
            return
        if response.status != "OK":
            self.append_text(f"Error: {response.message}\n")
        else:
            self.append_text("Accounts:\n" + "\n".join(response.accounts) + "\n")

    def read_messages(self):
        """
        Requests a specified number of messages from the server.
        
        Prompts the user for the number of messages to read and sends a ReadMessagesRequest via gRPC.
        The retrieved messages are then displayed in the chat area.
        """
        num = simpledialog.askstring("Read Messages", "How many messages to read?")
        if num is None or not num.isdigit():
            num = 10
        else:
            num = int(num)
        try:
            response = self.stub.ReadMessages(chat_pb2.ReadMessagesRequest(username=self.username, num=num))
        except grpc.RpcError as e:
            self.append_text(f"RPC error: {e}\n")
            return
        if response.status != "OK":
            self.append_text(f"Error: {response.message}\n")
        else:
            self.append_text("Messages:\n" + "\n".join(response.messages) + "\n")

    def delete_messages(self):
        """
        Prompts the user for message IDs to delete and sends a DeleteMessagesRequest via gRPC.
        
        The server processes the request and responds with a status message, which is displayed to the user.
        """
        ids = simpledialog.askstring("Delete Messages", "Enter message IDs to delete (comma separated):")
        if ids is None:
            return
        id_list = [msg_id.strip() for msg_id in ids.split(",") if msg_id.strip()]
        try:
            response = self.stub.DeleteMessages(chat_pb2.DeleteMessagesRequest(username=self.username, message_ids=id_list))
        except grpc.RpcError as e:
            self.append_text(f"RPC error: {e}\n")
            return
        self.append_text(f"Server response: {response.status} - {response.message}\n")

    def delete_account(self):
        """
        Handles account deletion.
        
        Prompts the user for confirmation, then sends a DeleteAccountRequest (including the plaintext password)
        via gRPC. If deletion is successful, the client disconnects and exits.
        """
        if messagebox.askyesno("Delete Account", "Are you sure you want to delete your account?"):
            password = self.entry_password.get().strip()
            try:
                response = self.stub.DeleteAccount(chat_pb2.DeleteAccountRequest(username=self.username, password=password))
            except grpc.RpcError as e:
                messagebox.showerror("Error", f"RPC error: {e}")
                return
            if response.status != "OK":
                messagebox.showerror("Error", response.message)
            else:
                messagebox.showinfo("Info", response.message)
            self.channel.close()
            self.root.quit()

    def listen_to_messages(self):
        """
        Runs in a background thread to continuously listen for new messages from the server.
        
        The method uses a streaming gRPC call (MessageStreamRequest) to receive asynchronous notifications,
        appending each new message to the chat display.
        """
        try:
            for new_msg in self.stub.MessageStream(chat_pb2.MessageStreamRequest(username=self.username)):
                self.append_text(f"New message from {new_msg.sender}: {new_msg.message_text} (ID: {new_msg.msg_id})\n")
        except grpc.RpcError as e:
            self.append_text(f"Message stream error: {e}\n")
        self.channel.close()

    def append_text(self, text):
        """
        Appends text to the chat display area in a thread-safe manner.
        
        Args:
            text (str): The text to be appended to the chat display.
        """
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, text)
        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)

    def run(self):
        """
        Starts the Tkinter main loop, allowing the client to run indefinitely until closed.
        """
        self.root.mainloop()
        self.running = False

if __name__ == "__main__":
    # Parse command-line arguments for server host and port.
    parser = argparse.ArgumentParser(description="gRPC Chat Client")
    parser.add_argument("--host", default="localhost", help="Server hostname (default: localhost)")
    parser.add_argument("--port", type=int, default=50051, help="Server port (default: 50051)")
    args = parser.parse_args()

    # Instantiate and run the ChatClient with the specified host and port.
    client = ChatClient(args.host, args.port)
    client.run()
