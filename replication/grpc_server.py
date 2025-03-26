"""
grpc_server.py - Upgraded chat server with persistence, replication, dynamic state transfer,
heartbeat, and replicated login.

Usage examples:
  Main server:
    python grpc_server.py --host localhost --port 50051 --db_file chat_server1.db --replicas localhost:50052,localhost:50053
  Dynamic replica:
    python grpc_server.py --host localhost --port 50054 --db_file chat_server4.db --replicas localhost:50051,localhost:50052,localhost:50053 --join localhost:50051
"""

import grpc
from concurrent import futures
import time, threading, hashlib, os, sqlite3, argparse

import chat_pb2, chat_pb2_grpc

def hash_password(password, salt=None):
    """
    Hashes the given password using PBKDF2-HMAC-SHA256.

    Args:
        password (str): The plaintext password.
        salt (bytes, optional): A salt to use. If None, a random 16-byte salt is generated.

    Returns:
        tuple: A tuple (salt_hex, hashed_hex) where both the salt and hash are hexadecimal strings.
    """
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 400000)
    return salt.hex(), hashed.hex()

class ChatDatabase:
    """
    Provides persistent storage for the chat application using SQLite.

    Manages accounts, messages, and metadata in a thread-safe manner.
    """
    def __init__(self, db_file):
        """
        Initializes the ChatDatabase with the specified SQLite database file.

        Args:
            db_file (str): Path to the SQLite database file.
        """
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.lock = threading.Lock()
        self.create_tables()

    def create_tables(self):
        """
        Creates the required tables (accounts, messages, metadata) in the database if they do not exist.
        """
        with self.lock:
            c = self.conn.cursor()
            # Accounts table
            c.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    username TEXT PRIMARY KEY,
                    salt TEXT,
                    hashed_password TEXT
                )
            """)
            # Messages table
            c.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY,
                    recipient TEXT,
                    sender TEXT,
                    message_text TEXT,
                    delivered INTEGER DEFAULT 0
                )
            """)
            # Metadata table
            c.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value INTEGER
                )
            """)
            c.execute("INSERT OR IGNORE INTO metadata (key, value) VALUES ('max_message_id', 0)")
            self.conn.commit()

    def create_account(self, username, salt, hashed_password):
        """
        Creates a new account in the database.

        Args:
            username (str): The account username.
            salt (str): The salt used for password hashing.
            hashed_password (str): The hashed password.

        Returns:
            tuple: (True, message) if account creation is successful; (False, error message) otherwise.
        """
        with self.lock:
            c = self.conn.cursor()
            try:
                c.execute("INSERT INTO accounts (username, salt, hashed_password) VALUES (?, ?, ?)",
                          (username, salt, hashed_password))
                self.conn.commit()
                return True, "Account created successfully."
            except sqlite3.IntegrityError:
                return False, "Account exists; please login."

    def get_account(self, username):
        """
        Retrieves account details for the given username.

        Args:
            username (str): The username to query.

        Returns:
            tuple or None: A tuple (username, salt, hashed_password) if found; None otherwise.
        """
        with self.lock:
            c = self.conn.cursor()
            c.execute("SELECT username, salt, hashed_password FROM accounts WHERE username=?", (username,))
            return c.fetchone()

    def delete_account(self, username):
        """
        Deletes the account with the specified username.

        Args:
            username (str): The username to delete.

        Returns:
            bool: True if an account was deleted; False otherwise.
        """
        with self.lock:
            c = self.conn.cursor()
            c.execute("DELETE FROM accounts WHERE username=?", (username,))
            self.conn.commit()
            return c.rowcount > 0

    def add_message(self, recipient, sender, message_text, msg_id=None):
        """
        Adds a new message to the database for the specified recipient.

        Args:
            recipient (str): The recipient username.
            sender (str): The sender username.
            message_text (str): The message content.
            msg_id (int, optional): If provided, use this ID; otherwise, generate a new one based on metadata.

        Returns:
            str: The message ID as a string.
        """
        with self.lock:
            c = self.conn.cursor()
            if msg_id is None:
                c.execute("SELECT value FROM metadata WHERE key='max_message_id'")
                row = c.fetchone()
                current_max = row[0] if row and row[0] is not None else 0
                new_id = current_max + 1
                c.execute("INSERT INTO messages (id, recipient, sender, message_text, delivered) VALUES (?, ?, ?, ?, 0)",
                          (new_id, recipient, sender, message_text))
                c.execute("UPDATE metadata SET value = ? WHERE key='max_message_id'", (new_id,))
                self.conn.commit()
                msg_id = new_id
            else:
                c.execute("INSERT OR IGNORE INTO messages (id, recipient, sender, message_text, delivered) VALUES (?, ?, ?, ?, 0)",
                          (msg_id, recipient, sender, message_text))
                self.conn.commit()
            return str(msg_id)

    def get_messages(self, username, num, min_id=0):
        """
        Retrieves a list of unread messages for a given user.

        Args:
            username (str): The recipient username.
            num (int): The maximum number of messages to retrieve.
            min_id (int, optional): Only return messages with ID greater than this value.

        Returns:
            list: A list of tuples (id, sender, message_text) for unread messages.
        """
        with self.lock:
            c = self.conn.cursor()
            if min_id > 0:
                c.execute("SELECT id, sender, message_text FROM messages WHERE recipient=? AND delivered=0 AND id > ? ORDER BY id ASC LIMIT ?",
                          (username, min_id, num))
            else:
                c.execute("SELECT id, sender, message_text FROM messages WHERE recipient=? AND delivered=0 ORDER BY id ASC LIMIT ?",
                          (username, num))
            return c.fetchall()

    def mark_messages_delivered(self, username, message_ids):
        """
        Marks the specified messages as delivered (read) for the given user.

        Args:
            username (str): The recipient username.
            message_ids (list): A list of message IDs to mark as delivered.
        """
        with self.lock:
            c = self.conn.cursor()
            placeholders = ",".join("?" for _ in message_ids)
            query = f"UPDATE messages SET delivered=1 WHERE recipient=? AND id IN ({placeholders})"
            params = [username] + [int(mid) for mid in message_ids]
            c.execute(query, params)
            self.conn.commit()

    def delete_messages(self, username, message_ids):
        """
        Deletes the specified messages for the given user.

        Args:
            username (str): The recipient username.
            message_ids (list): A list of message IDs to delete.

        Returns:
            int: The number of messages deleted.
        """
        with self.lock:
            c = self.conn.cursor()
            placeholders = ",".join("?" for _ in message_ids)
            query = f"DELETE FROM messages WHERE recipient=? AND id IN ({placeholders})"
            params = [username] + [int(mid) for mid in message_ids]
            c.execute(query, params)
            affected = c.rowcount
            self.conn.commit()
            return affected

class PersistentChatServiceServicer(chat_pb2_grpc.ChatServiceServicer):
    """
    gRPC Chat Service Servicer that provides persistent, replicated chat functionality.

    Uses a SQLite database for storage and supports replication via separate replica addresses.
    """
    def __init__(self, db_file, replica_addresses):
        """
        Initializes the servicer with a database file and a list of replica addresses.

        Args:
            db_file (str): Path to the SQLite database file.
            replica_addresses (list): List of addresses for replica servers.
        """
        self.db = ChatDatabase(db_file)
        self.online_users = {}
        self.lock = threading.Lock()
        self.replica_addresses = replica_addresses

    def get_state_snapshot(self):
        """
        Creates a state snapshot of the server's current persistent state.

        The snapshot includes all accounts, messages (with delivered status), and the maximum message ID.
        
        Returns:
            StateSnapshot: A Protocol Buffer message containing the state snapshot.
        """
        snapshot = chat_pb2.StateSnapshot()
        max_id = 0
        with self.db.lock:
            c = self.db.conn.cursor()
            c.execute("SELECT username, salt, hashed_password FROM accounts")
            for row in c.fetchall():
                acc = snapshot.accounts.add()
                acc.username = row[0]
                acc.salt = row[1]
                acc.hashed_password = row[2]
            c.execute("SELECT id, recipient, sender, message_text, delivered FROM messages")
            for row in c.fetchall():
                msg = snapshot.messages.add()
                msg.id = row[0]
                msg.recipient = row[1]
                msg.sender = row[2]
                msg.message_text = row[3]
                msg.delivered = row[4]
                if row[0] > max_id:
                    max_id = row[0]
            c.execute("SELECT value FROM metadata WHERE key='max_message_id'")
            row = c.fetchone()
            meta_max = row[0] if row and row[0] is not None else 0
            snapshot.max_message_id = meta_max if meta_max > max_id else max_id
        print(f"State snapshot has max_message_id: {snapshot.max_message_id}")
        return snapshot

    def load_state(self, snapshot):
        """
        Loads a state snapshot into the current server's database.

        The method inserts accounts and messages from the snapshot and updates the metadata table.
        
        Args:
            snapshot (StateSnapshot): The state snapshot to load.
        """
        with self.db.lock:
            c = self.db.conn.cursor()
            for acc in snapshot.accounts:
                try:
                    c.execute("INSERT INTO accounts (username, salt, hashed_password) VALUES (?, ?, ?)",
                              (acc.username, acc.salt, acc.hashed_password))
                    with self.lock:
                        self.online_users.setdefault(acc.username, True)
                except sqlite3.IntegrityError:
                    pass
            for msg in snapshot.messages:
                c.execute("INSERT OR IGNORE INTO messages (id, recipient, sender, message_text, delivered) VALUES (?, ?, ?, ?, ?)",
                          (msg.id, msg.recipient, msg.sender, msg.message_text, msg.delivered))
            c.execute("UPDATE metadata SET value = ? WHERE key='max_message_id'", (snapshot.max_message_id,))
            self.db.conn.commit()
            print(f"Transferred max_message_id set in metadata: {snapshot.max_message_id}")

    def apply_create_account(self, username, salt, hashed_password, forwarded=False):
        """
        Creates a new account and optionally replicates the operation to replicas.

        Args:
            username (str): The account username.
            salt (str): The salt used for password hashing.
            hashed_password (str): The hashed password.
            forwarded (bool): Indicates if the operation was forwarded from a replica.

        Returns:
            tuple: (success (bool), message (str))
        """
        success, msg = self.db.create_account(username, salt, hashed_password)
        if success:
            with self.lock:
                self.online_users[username] = True
            if not forwarded:
                self.replicate_update("CREATE_ACCOUNT", {"username": username, "salt": salt, "hashed_password": hashed_password})
        return success, msg

    def apply_login(self, username, forwarded=False):
        """
        Marks an account as online and optionally replicates the login event.

        Args:
            username (str): The account username.
            forwarded (bool): Indicates if the operation was forwarded from a replica.
        """
        with self.lock:
            if username not in self.online_users:
                print(f"Replicated login: marking {username} as online")
                self.online_users[username] = True

    def apply_send_message(self, recipient, sender, message_text, forwarded=False):
        """
        Sends a message to a recipient and optionally replicates the operation.

        Args:
            recipient (str): The recipient username.
            sender (str): The sender username.
            message_text (str): The message text.
            forwarded (bool): Indicates if the operation was forwarded from a replica.

        Returns:
            str: The message ID as a string.
        """
        msg_id = self.db.add_message(recipient, sender, message_text)
        if not forwarded:
            self.replicate_update("SEND_MESSAGE", {"recipient": recipient, "sender": sender, "message_text": message_text})
        return msg_id

    def apply_delete_messages(self, username, message_ids, forwarded=False):
        """
        Deletes messages for a user and optionally replicates the operation.

        Args:
            username (str): The recipient username.
            message_ids (list): A list of message IDs to delete.
            forwarded (bool): Indicates if the operation was forwarded from a replica.

        Returns:
            int: Number of messages deleted.
        """
        affected = self.db.delete_messages(username, message_ids)
        if not forwarded:
            self.replicate_update("DELETE_MESSAGES", {"username": username, "message_ids": message_ids})
        return affected

    def apply_delete_account(self, username, forwarded=False):
        """
        Deletes an account and optionally replicates the operation.

        Args:
            username (str): The account username.
            forwarded (bool): Indicates if the operation was forwarded from a replica.

        Returns:
            tuple: (True, message) if successful; (False, error message) otherwise.
        """
        success = self.db.delete_account(username)
        if success:
            with self.lock:
                if username in self.online_users:
                    del self.online_users[username]
            if not forwarded:
                self.replicate_update("DELETE_ACCOUNT", {"username": username})
            return True, "Account deleted."
        else:
            return False, "Account does not exist."

    def CreateAccount(self, request, context):
        """
        Handles the CreateAccount RPC.

        Args:
            request (CreateAccountRequest): The account creation request.
            context (grpc.ServicerContext): The RPC context.

        Returns:
            Response: A response indicating success or failure.
        """
        salt, hashed_pw = hash_password(request.password)
        success, msg = self.apply_create_account(request.username, salt, hashed_pw, forwarded=False)
        status = "OK" if success else "ERROR"
        return chat_pb2.Response(status=status, message=msg)

    def Login(self, request, context):
        """
        Handles the Login RPC.

        Args:
            request (LoginRequest): The login request.
            context (grpc.ServicerContext): The RPC context.

        Returns:
            LoginResponse: A response indicating success or failure along with unread count and last_seen_id.
        """
        acct = self.db.get_account(request.username)
        if not acct:
            return chat_pb2.LoginResponse(status="ERROR", message="Account does not exist.", unread_count=0, last_seen_id=0)
        username, salt, stored_hash = acct
        salt_bytes = bytes.fromhex(salt)
        _, computed_hash = hash_password(request.password, salt_bytes)
        if stored_hash != computed_hash:
            return chat_pb2.LoginResponse(status="ERROR", message="Incorrect password.", unread_count=0, last_seen_id=0)
        self.replicate_update("LOGIN", {"username": username})
        with self.lock:
            self.online_users[username] = True
        unread_msgs = self.db.get_messages(username, 1000)
        unread_count = len(unread_msgs)
        last_seen_id = max((row[0] for row in unread_msgs), default=0)
        return chat_pb2.LoginResponse(
            status="OK",
            message=f"Login successful. Unread messages: {unread_count}",
            unread_count=unread_count,
            last_seen_id=last_seen_id
        )

    def ListAccounts(self, request, context):
        """
        Handles the ListAccounts RPC.

        Args:
            request (ListAccountsRequest): The request containing a wildcard pattern.
            context (grpc.ServicerContext): The RPC context.

        Returns:
            ListAccountsResponse: A response containing the list of matching account usernames.
        """
        pattern = request.pattern if request.pattern else "%"
        with self.db.lock:
            c = self.db.conn.cursor()
            c.execute("SELECT username FROM accounts WHERE username LIKE ?", (pattern.replace("*", "%"),))
            accounts = [row[0] for row in c.fetchall()]
        return chat_pb2.ListAccountsResponse(status="OK", message="Accounts list", accounts=accounts)

    def SendMessage(self, request, context):
        """
        Handles the SendMessage RPC.

        Args:
            request (SendMessageRequest): The message sending request.
            context (grpc.ServicerContext): The RPC context.

        Returns:
            Response: A response indicating success or failure, with the message ID.
        """
        if not self.db.get_account(request.recipient):
            return chat_pb2.Response(status="ERROR", message="Recipient does not exist.")
        msg_id = self.apply_send_message(request.recipient, request.sender, request.message_text, forwarded=False)
        return chat_pb2.Response(status="OK", message=f"Message sent with id {msg_id}")

    def ReadMessages(self, request, context):
        """
        Handles the ReadMessages RPC.

        Depending on the request.num value:
          - If num == 0: returns a count of unread messages.
          - If num > 0: returns up to that many unread messages and marks them as delivered.
        
        Args:
            request (ReadMessagesRequest): The request with username, num, and last_seen_id.
            context (grpc.ServicerContext): The RPC context.

        Returns:
            ReadMessagesResponse: A response containing the messages or unread count.
        """
        min_id = request.last_seen_id if request.last_seen_id > 0 else 0
        if request.num == 0:
            msgs = self.db.get_messages(request.username, 1000, min_id=min_id)
            count = len(msgs)
            return chat_pb2.ReadMessagesResponse(status="OK", message=f"Unread: {count}", messages=[])
        else:
            msgs = self.db.get_messages(request.username, request.num, min_id=min_id)
            msg_ids = [row[0] for row in msgs]
            self.db.mark_messages_delivered(request.username, msg_ids)
            msgs_formatted = [f"{row[0]}: {row[1]}: {row[2]}" for row in msgs]
            self.replicate_update("DELETE_MESSAGES", {"username": request.username, "message_ids": [str(mid) for mid in msg_ids]})
            return chat_pb2.ReadMessagesResponse(status="OK", message="Messages", messages=msgs_formatted)

    def DeleteMessages(self, request, context):
        """
        Handles the DeleteMessages RPC, permanently removing messages.

        Args:
            request (DeleteMessagesRequest): The request with the username and message IDs.
            context (grpc.ServicerContext): The RPC context.

        Returns:
            Response: A response indicating the number of messages deleted.
        """
        affected = self.apply_delete_messages(request.username, request.message_ids, forwarded=False)
        return chat_pb2.Response(status="OK", message=f"Deleted {affected} messages.")

    def DeleteAccount(self, request, context):
        """
        Handles the DeleteAccount RPC, removing a user account after password verification.

        Args:
            request (DeleteAccountRequest): The request with the username and plaintext password.
            context (grpc.ServicerContext): The RPC context.

        Returns:
            Response: A response indicating success or failure.
        """
        acct = self.db.get_account(request.username)
        if not acct:
            return chat_pb2.Response(status="ERROR", message="Account does not exist.")
        _, salt, stored_hash = acct
        salt_bytes = bytes.fromhex(salt)
        _, computed_hash = hash_password(request.password, salt_bytes)
        if stored_hash != computed_hash:
            return chat_pb2.Response(status="ERROR", message="Incorrect password.")
        success, msg = self.apply_delete_account(request.username, forwarded=False)
        return chat_pb2.Response(status="OK" if success else "ERROR", message=msg)

    def Heartbeat(self, request, context):
        """
        Handles the Heartbeat RPC to mark a user as online.

        Args:
            request (HeartbeatRequest): The heartbeat request containing the username.
            context (grpc.ServicerContext): The RPC context.

        Returns:
            Response: A response acknowledging the heartbeat.
        """
        username = request.username
        with self.lock:
            if username not in self.online_users:
                print(f"Heartbeat: marking {username} as online")
                self.online_users[username] = True
        return chat_pb2.Response(status="OK", message="Heartbeat acknowledged.")

    def replicate_update(self, op, data):
        """
        Replicates an operation to all replica servers.

        Args:
            op (str): The operation code (e.g., "CREATE_ACCOUNT", "LOGIN", etc.).
            data (dict): The data associated with the operation.
        """
        req = chat_pb2.ReplicationRequest(op=op, forwarded=True)
        if op == "CREATE_ACCOUNT":
            req.username = data["username"]
            req.salt = data["salt"]
            req.hashed_password = data["hashed_password"]
        elif op == "LOGIN":
            req.username = data["username"]
        elif op == "SEND_MESSAGE":
            req.recipient = data["recipient"]
            req.sender = data["sender"]
            req.message_text = data["message_text"]
        elif op == "DELETE_MESSAGES":
            req.username = data["username"]
            req.message_ids.extend(data["message_ids"])
        elif op == "DELETE_ACCOUNT":
            req.username = data["username"]
        for addr in self.replica_addresses:
            try:
                channel = grpc.insecure_channel(addr)
                stub = chat_pb2_grpc.ReplicationServiceStub(channel)
                response = stub.ReplicateOperation(req, timeout=5)
                print(f"[Replication] To {addr}: {response.message}")
            except Exception as e:
                print(f"[Replication] To {addr} failed: {e}")

class ReplicationServiceServicer(chat_pb2_grpc.ReplicationServiceServicer):
    """
    Implements the ReplicationService for replicating operations and transferring state.
    """
    def __init__(self, persistent_servicer):
        """
        Initializes the replication service with a reference to the persistent servicer.

        Args:
            persistent_servicer (PersistentChatServiceServicer): The primary chat service servicer.
        """
        self.persistent_servicer = persistent_servicer

    def ReplicateOperation(self, request, context):
        """
        Handles a replication operation from another server.

        Args:
            request (ReplicationRequest): The replication request.
            context (grpc.ServicerContext): The RPC context.

        Returns:
            Response: A response indicating success or failure.
        """
        op = request.op
        if op == "CREATE_ACCOUNT":
            success, msg = self.persistent_servicer.apply_create_account(
                request.username, request.salt, request.hashed_password, forwarded=True)
            return chat_pb2.Response(status="OK" if success else "ERROR", message=msg)
        elif op == "LOGIN":
            self.persistent_servicer.apply_login(request.username, forwarded=True)
            return chat_pb2.Response(status="OK", message="Login replicated.")
        elif op == "SEND_MESSAGE":
            msg_id = self.persistent_servicer.apply_send_message(
                request.recipient, request.sender, request.message_text, forwarded=True)
            return chat_pb2.Response(status="OK", message=f"Message added with id {msg_id}")
        elif op == "DELETE_MESSAGES":
            affected = self.persistent_servicer.apply_delete_messages(
                request.username, request.message_ids, forwarded=True)
            return chat_pb2.Response(status="OK", message=f"Deleted {affected} messages.")
        elif op == "DELETE_ACCOUNT":
            success, msg = self.persistent_servicer.apply_delete_account(
                request.username, forwarded=True)
            return chat_pb2.Response(status="OK" if success else "ERROR", message=msg)
        else:
            return chat_pb2.Response(status="ERROR", message="Unknown replication operation.")

    def AddReplica(self, request, context):
        """
        Adds a new replica to the system.

        Args:
            request (AddReplicaRequest): The request containing the new replica address.
            context (grpc.ServicerContext): The RPC context.

        Returns:
            Response: A response confirming the addition of the replica.
        """
        new_addr = request.replica_address
        if new_addr not in self.persistent_servicer.replica_addresses:
            self.persistent_servicer.replica_addresses.append(new_addr)
            print(f"[Replication] Added new replica: {new_addr}")
        return chat_pb2.Response(status="OK", message="Replica added.")

    def TransferState(self, request, context):
        """
        Transfers the current state snapshot to a joining replica.

        Args:
            request (Empty): An empty request.
            context (grpc.ServicerContext): The RPC context.

        Returns:
            StateSnapshot: A snapshot of the current state including accounts, messages, and max_message_id.
        """
        snapshot = self.persistent_servicer.get_state_snapshot()
        return snapshot

def serve(host, port, db_file, replica_list, join_addr):
    """
    Starts the gRPC chat server with replication and dynamic state transfer.

    Args:
        host (str): The hostname to bind.
        port (int): The port number.
        db_file (str): The SQLite database file to use.
        replica_list (list): A list of replica server addresses.
        join_addr (str): Address of an existing replica to join state from (if any).
    """
    persistent_servicer = PersistentChatServiceServicer(db_file, replica_list)
    if join_addr:
        joined = False
        candidates = [join_addr] + replica_list
        attempts = 0
        while not joined and attempts < 5:
            for addr in candidates:
                try:
                    print(f"Attempting state transfer from {addr}")
                    join_channel = grpc.insecure_channel(addr)
                    join_stub = chat_pb2_grpc.ReplicationServiceStub(join_channel)
                    snapshot = join_stub.TransferState(chat_pb2.Empty(), timeout=10)
                    persistent_servicer.load_state(snapshot)
                    print(f"State transfer complete from {addr}.")
                    joined = True
                    break
                except Exception as e:
                    print(f"State transfer failed from {addr}: {e}")
            if not joined:
                attempts += 1
                time.sleep(5)
        if not joined:
            try:
                if os.path.getsize(db_file) > 100:
                    print("Warning: State transfer failed but local DB is non-empty; continuing with local state.")
                    joined = True
                else:
                    print("Error: State transfer failed and local state is empty.")
            except Exception:
                print("Error: Unable to check local DB size; continuing with empty state.")
    rep_servicer = ReplicationServiceServicer(persistent_servicer)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_pb2_grpc.add_ChatServiceServicer_to_server(persistent_servicer, server)
    chat_pb2_grpc.add_ReplicationServiceServicer_to_server(rep_servicer, server)
    server_address = f"{host}:{port}"
    server.add_insecure_port(server_address)
    server.start()
    print(f"gRPC Persistent Chat Server started on {server_address}.")
    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        server.stop(0)

if __name__ == '__main__':
    """
    Parses command-line arguments and starts the chat server.
    """
    parser = argparse.ArgumentParser(description="Persistent gRPC Chat Server with Replication and Dynamic State Transfer")
    parser.add_argument("--host", default="[::]", help="Host to bind (default: [::])")
    parser.add_argument("--port", type=int, default=50051, help="Port number (default: 50051)")
    parser.add_argument("--db_file", default="chat_server.db", help="SQLite database file (default: chat_server.db)")
    parser.add_argument("--replicas", default="", help="Comma-separated list of replica addresses (e.g., localhost:50052,localhost:50053)")
    parser.add_argument("--join", default="", help="Address of an existing replica to join state from (e.g., localhost:50051)")
    args = parser.parse_args()
    replica_list = [addr.strip() for addr in args.replicas.split(",") if addr.strip()]
    join_addr = args.join.strip() if args.join else None
    serve(args.host, args.port, args.db_file, replica_list, join_addr)
