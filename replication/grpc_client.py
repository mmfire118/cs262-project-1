"""
grpc_client.py - A simple chat client with a Tkinter GUI using gRPC. This client connects to one or more gRPC chat servers.

Usage:
    python grpc_client.py --servers localhost:50051,localhost:50052,localhost:50053
"""

import grpc
import threading
import tkinter as tk
import tkinter.scrolledtext as st
import tkinter.messagebox as messagebox
import tkinter.simpledialog as simpledialog
import argparse
import queue
import time

import chat_pb2
import chat_pb2_grpc

class ChatClient:
    """
    ChatClient implements a Tkinter-based GUI client that communicates with a gRPC chat server.
    
    It provides functionalities for:
      - Account creation and login.
      - Sending, reading, and deleting messages.
      - Listing accounts.
      - Dynamically adding new server endpoints.
    """
    def __init__(self, server_addresses):
        """
        Initializes the ChatClient instance.

        Args:
            server_addresses (list): List of server addresses (host:port) to connect to.
        """
        self.server_addresses = server_addresses
        self.channels = [grpc.insecure_channel(addr) for addr in server_addresses]
        self.stubs = [chat_pb2_grpc.ChatServiceStub(ch) for ch in self.channels]
        self.current_index = 0
        self.dead_stubs = {}
        self.username = None
        self.running = True
        self.message_queue = queue.Queue()
        self.root = tk.Tk()
        self.root.title("Chat Client")
        self.login_marker = 0  
        self.last_poll_marker = 0
        self.setup_gui()

    def setup_gui(self):
        """
        Sets up the Tkinter GUI components including the login and chat frames.
        """
        self.frame_login = tk.Frame(self.root)
        self.frame_chat = tk.Frame(self.root)
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
        self.frame_chat.pack_forget()
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
        self.btn_add_server = tk.Button(self.frame_chat, text="Add Server", command=self.add_server)
        self.btn_add_server.pack(side='left')

    def add_server(self):
        """
        Prompts the user to enter a new server address and attempts to add it as a replica.
        
        It creates a new channel and stub for the specified server and uses the ReplicationService
        to add it to the set of replica addresses.
        """
        new_addr = simpledialog.askstring("Add Server", "Enter new server address (host:port):")
        if new_addr:
            channel = grpc.insecure_channel(new_addr)
            stub = chat_pb2_grpc.ChatServiceStub(channel)
            self.channels.append(channel)
            self.stubs.append(stub)
            self.server_addresses.append(new_addr)
            added = False
            for idx, ch in enumerate(self.channels):
                try:
                    rep_stub = chat_pb2_grpc.ReplicationServiceStub(ch)
                    resp = rep_stub.AddReplica(chat_pb2.AddReplicaRequest(replica_address=new_addr), timeout=5)
                    messagebox.showinfo("Info", f"Added server {new_addr}: {resp.message}")
                    added = True
                    break
                except grpc.RpcError as e:
                    print(f"AddReplica RPC failed on {self.server_addresses[idx]}: {e}")
                    continue
            if not added:
                messagebox.showerror("Error", f"Failed to add server {new_addr} via AddReplica RPC.")

    def retry_rpc(self, rpc_call):
        """
        Tries the given RPC call on available stubs, rotating through them until one succeeds.

        Args:
            rpc_call (function): A lambda function that accepts a stub and performs an RPC call.

        Returns:
            The result of the successful RPC call.

        Raises:
            grpc.RpcError: If all RPC calls fail.
        """
        errors = []
        now = time.time()
        num = len(self.stubs)
        for i in range(num):
            idx = (self.current_index + i) % num
            if idx in self.dead_stubs and now < self.dead_stubs[idx]:
                errors.append(f"{self.server_addresses[idx]} skipped (dead)")
                continue
            try:
                result = rpc_call(self.stubs[idx])
                self.current_index = idx
                if idx in self.dead_stubs:
                    del self.dead_stubs[idx]
                return result
            except grpc.RpcError as e:
                errors.append(f"{self.server_addresses[idx]}: {e}")
                self.dead_stubs[idx] = now + 30
        raise grpc.RpcError("All RPC calls failed: " + "; ".join(errors))

    def heartbeat_loop(self):
        """
        Continuously sends Heartbeat RPC calls in a background thread to keep the client marked as online.
        """
        while self.running:
            try:
                self.retry_rpc(lambda stub: stub.Heartbeat(chat_pb2.HeartbeatRequest(username=self.username), timeout=5))
            except grpc.RpcError:
                pass
            time.sleep(1)

    def poll_new_messages(self):
        """
        Polls the server periodically for new messages since the last seen message ID.

        New messages are put into a queue to be displayed in the chat window.
        """
        while self.running:
            try:
                response = self.retry_rpc(lambda stub: stub.ReadMessages(
                    chat_pb2.ReadMessagesRequest(username=self.username, num=10, last_seen_id=self.last_poll_marker)))
                if response.status == "OK" and response.messages:
                    new_ids = []
                    for m in response.messages:
                        parts = m.split(":", 1)
                        if parts:
                            try:
                                msg_id = int(parts[0].strip())
                                new_ids.append(msg_id)
                            except ValueError:
                                continue
                        self.message_queue.put(m + "\n")
                    if new_ids:
                        self.last_poll_marker = max(new_ids)
            except grpc.RpcError as e:
                self.message_queue.put(f"Polling RPC error: {e}\n")
            time.sleep(1)

    def poll_messages(self):
        """
        Continuously checks the internal message queue and appends new messages to the chat display.
        """
        try:
            while True:
                message = self.message_queue.get_nowait()
                self.append_text(message)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_messages)

    def replicate_login(self):
        """
        Replicates the login operation to all replica servers using the ReplicationService.
        """
        for ch in self.channels:
            try:
                rep_stub = chat_pb2_grpc.ReplicationServiceStub(ch)
                rep_stub.ReplicateOperation(chat_pb2.ReplicationRequest(op="LOGIN", username=self.username, forwarded=False), timeout=5)
            except grpc.RpcError as e:
                print(f"Replicate login error: {e}")

    def login(self):
        """
        Handles the login process.

        Retrieves the username and password from the GUI, performs the login RPC,
        updates internal state, and starts background threads for heartbeat and message polling.
        """
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return
        try:
            response = self.retry_rpc(lambda stub: stub.Login(chat_pb2.LoginRequest(username=username, password=password)))
        except grpc.RpcError as e:
            messagebox.showerror("Error", f"RPC error: {e}")
            return
        if response.status != "OK":
            messagebox.showerror("Error", response.message)
            return
        self.username = username
        self.login_marker = response.last_seen_id
        self.last_poll_marker = response.last_seen_id
        if response.unread_count > 0:
            self.append_text(f"Login successful. You have {response.unread_count} unread message(s).\n")
        else:
            self.append_text("Login successful.\n")
        self.append_text(f"Username: {username}\n")
        self.frame_login.pack_forget()
        self.frame_chat.pack()
        self.replicate_login()
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=self.poll_new_messages, daemon=True).start()
        self.root.after(100, self.poll_messages)

    def create_account(self):
        """
        Handles the account creation process.

        Retrieves the username and password from the GUI and sends a CreateAccount RPC.
        Displays the server response as an info or error message.
        """
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return
        try:
            response = self.retry_rpc(lambda stub: stub.CreateAccount(chat_pb2.CreateAccountRequest(username=username, password=password)))
        except grpc.RpcError as e:
            messagebox.showerror("Error", f"RPC error: {e}")
            return
        if response.status != "OK":
            messagebox.showerror("Error", response.message)
        else:
            messagebox.showinfo("Info", response.message)

    def read_messages(self):
        """
        Retrieves messages from the server.

        Prompts the user for the number of messages to read and sends a ReadMessages RPC.
        Updates internal markers and appends the messages to the chat display.
        """
        num_str = simpledialog.askstring("Read Messages", "How many messages to read?")
        num = 10
        if num_str and num_str.isdigit():
            num = int(num_str)
        marker = 0 if self.login_marker > 0 else self.last_poll_marker
        try:
            response = self.retry_rpc(lambda stub: stub.ReadMessages(chat_pb2.ReadMessagesRequest(username=self.username, num=num, last_seen_id=marker)))
        except grpc.RpcError as e:
            self.append_text(f"RPC error: {e}\n")
            return
        if response.status != "OK":
            self.append_text(f"Error: {response.message}\n")
        else:
            new_ids = []
            for m in response.messages:
                parts = m.split(":", 1)
                if parts:
                    try:
                        new_ids.append(int(parts[0].strip()))
                    except ValueError:
                        continue
            if new_ids:
                max_id = max(new_ids)
                self.last_poll_marker = max_id
            if marker == 0:
                self.login_marker = 0
            self.append_text("Messages:\n" + "\n".join(response.messages) + "\n")

    def send_message(self):
        """
        Sends a message to another user.

        Expects the message in the format "recipient: message text". Sends a SendMessage RPC
        and appends the server response to the chat display.
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
            response = self.retry_rpc(lambda stub: stub.SendMessage(chat_pb2.SendMessageRequest(sender=self.username, recipient=recipient, message_text=message_text)))
        except grpc.RpcError as e:
            self.append_text(f"RPC error: {e}\n")
            return
        self.append_text(f"Server response: {response.status} - {response.message}\n")
        self.entry_message.delete(0, tk.END)

    def list_accounts(self):
        """
        Requests and displays a list of accounts from the server.

        Prompts the user for a wildcard pattern and sends a ListAccounts RPC.
        """
        pattern = simpledialog.askstring("List Accounts", "Enter wildcard pattern (or leave blank for all):")
        if pattern is None:
            return
        try:
            response = self.retry_rpc(lambda stub: stub.ListAccounts(chat_pb2.ListAccountsRequest(pattern=pattern)))
        except grpc.RpcError as e:
            self.append_text(f"RPC error: {e}\n")
            return
        if response.status != "OK":
            self.append_text(f"Error: {response.message}\n")
        else:
            self.append_text("Accounts:\n" + "\n".join(response.accounts) + "\n")

    def delete_messages(self):
        """
        Prompts the user for message IDs to delete and sends a DeleteMessages RPC.

        Displays the server response indicating the number of messages deleted.
        """
        ids = simpledialog.askstring("Delete Messages", "Enter message IDs to delete (comma separated):")
        if ids is None:
            return
        id_list = [msg_id.strip() for msg_id in ids.split(",") if msg_id.strip()]
        try:
            response = self.retry_rpc(lambda stub: stub.DeleteMessages(chat_pb2.DeleteMessagesRequest(username=self.username, message_ids=id_list)))
        except grpc.RpcError as e:
            self.append_text(f"RPC error: {e}\n")
            return
        self.append_text(f"Server response: {response.status} - {response.message}\n")

    def delete_account(self):
        """
        Deletes the user's account.

        After confirming with the user and sending a DeleteAccount RPC, closes all channels and exits the client.
        """
        if messagebox.askyesno("Delete Account", "Are you sure you want to delete your account?"):
            password = self.entry_password.get().strip()
            try:
                response = self.retry_rpc(lambda stub: stub.DeleteAccount(chat_pb2.DeleteAccountRequest(username=self.username, password=password)))
            except grpc.RpcError as e:
                messagebox.showerror("Error", f"RPC error: {e}")
                return
            if response.status != "OK":
                messagebox.showerror("Error", response.message)
            else:
                messagebox.showinfo("Info", response.message)
            for ch in self.channels:
                ch.close()
            self.root.quit()

    def poll_messages(self):
        """
        Continuously polls the internal message queue and appends any new messages to the chat display.
        """
        try:
            while True:
                message = self.message_queue.get_nowait()
                self.append_text(message)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_messages)

    def append_text(self, text):
        """
        Appends text to the chat display in a thread-safe manner.

        Args:
            text (str): The text to append.
        """
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, text)
        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)

    def run(self):
        """
        Starts the Tkinter main loop and runs the chat client.
        """
        self.root.mainloop()
        self.running = False

if __name__ == "__main__":
    """
    Parses command-line arguments for server addresses and starts the chat client.
    """
    parser = argparse.ArgumentParser(description="gRPC Chat Client")
    parser.add_argument("--servers", default="localhost:50051", help="Comma-separated list of server addresses (default: localhost:50051)")
    args = parser.parse_args()
    server_list = [addr.strip() for addr in args.servers.split(",") if addr.strip()]
    client = ChatClient(server_list)
    client.run()
