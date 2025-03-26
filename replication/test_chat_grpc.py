"""
test_chat_grpc.py

Integration tests for the gRPC chat server functionality with new behavior added for replication.
"""

import os
import shutil
import tempfile
import unittest
import time
import grpc
from concurrent import futures

import chat_pb2
import chat_pb2_grpc
from grpc_server import PersistentChatServiceServicer, ReplicationServiceServicer

def get_temp_db():
    temp_dir = tempfile.mkdtemp()
    return os.path.join(temp_dir, "test_chat_server.db"), temp_dir

class TestChatServerGRPC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db_file, cls.temp_dir = get_temp_db()
        cls.host = "localhost"
        cls.port = 50055
        cls.server_address = f"{cls.host}:{cls.port}"
        cls.chat_servicer = PersistentChatServiceServicer(cls.db_file, replica_addresses=[])
        cls.rep_servicer = ReplicationServiceServicer(cls.chat_servicer)
        cls.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        chat_pb2_grpc.add_ChatServiceServicer_to_server(cls.chat_servicer, cls.server)
        chat_pb2_grpc.add_ReplicationServiceServicer_to_server(cls.rep_servicer, cls.server)
        cls.server.add_insecure_port(cls.server_address)
        cls.server.start()
        time.sleep(0.2)
        cls.channel = grpc.insecure_channel(cls.server_address)
        cls.stub = chat_pb2_grpc.ChatServiceStub(cls.channel)
        cls.rep_stub = chat_pb2_grpc.ReplicationServiceStub(cls.channel)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop(0)
        cls.channel.close()
        shutil.rmtree(cls.temp_dir)

    def setUp(self):
        with self.chat_servicer.db.lock:
            c = self.chat_servicer.db.conn.cursor()
            c.execute("DELETE FROM accounts")
            c.execute("DELETE FROM messages")
            c.execute("UPDATE metadata SET value = 0 WHERE key='max_message_id'")
            self.chat_servicer.db.conn.commit()
        with self.chat_servicer.lock:
            self.chat_servicer.online_users.clear()

    def test_create_account(self):
        req = chat_pb2.CreateAccountRequest(username="alice", password="secret")
        resp = self.stub.CreateAccount(req)
        self.assertEqual(resp.status, "OK")
        self.assertIn("Account created", resp.message)

    def test_login_success(self):
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="bob", password="password"))
        resp = self.stub.Login(chat_pb2.LoginRequest(username="bob", password="password"))
        self.assertEqual(resp.status, "OK")
        self.assertIn("Login successful", resp.message)
        self.assertGreaterEqual(resp.unread_count, 0)

    def test_login_failure_wrong_password(self):
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="charlie", password="mypassword"))
        resp = self.stub.Login(chat_pb2.LoginRequest(username="charlie", password="wrongpass"))
        self.assertEqual(resp.status, "ERROR")
        self.assertIn("Incorrect password", resp.message)

    def test_list_accounts(self):
        for user, pwd in [("dave", "pass1"), ("eve", "pass2")]:
            self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username=user, password=pwd))
        resp = self.stub.ListAccounts(chat_pb2.ListAccountsRequest(pattern="*"))
        self.assertEqual(resp.status, "OK")
        self.assertIn("dave", resp.accounts)
        self.assertIn("eve", resp.accounts)

    def test_send_and_read_message(self):
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="alice", password="alicepw"))
        self.stub.Login(chat_pb2.LoginRequest(username="alice", password="alicepw"))
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="frank", password="frankpw"))
        self.stub.Login(chat_pb2.LoginRequest(username="frank", password="frankpw"))
        send_resp = self.stub.SendMessage(chat_pb2.SendMessageRequest(
            sender="alice", recipient="frank", message_text="Hello Frank!"))
        self.assertEqual(send_resp.status, "OK")
        read_resp = self.stub.ReadMessages(chat_pb2.ReadMessagesRequest(username="frank", num=10))
        self.assertEqual(read_resp.status, "OK")
        messages = read_resp.messages
        self.assertTrue(any("alice" in m and "Hello Frank!" in m for m in messages))
        read_resp2 = self.stub.ReadMessages(chat_pb2.ReadMessagesRequest(username="frank", num=0))
        self.assertIn("Unread: 0", read_resp2.message)

    def test_delete_message(self):
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="gina", password="ginapw"))
        self.stub.Login(chat_pb2.LoginRequest(username="gina", password="ginapw"))
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="harry", password="harrypw"))
        self.stub.Login(chat_pb2.LoginRequest(username="harry", password="harrypw"))
        self.stub.SendMessage(chat_pb2.SendMessageRequest(
            sender="gina", recipient="harry", message_text="Test delete message"))
        time.sleep(0.2)
        read_resp = self.stub.ReadMessages(chat_pb2.ReadMessagesRequest(username="harry", num=10))
        messages = read_resp.messages
        self.assertGreater(len(messages), 0)
        first_msg = messages[0]
        msg_id = first_msg.split(":")[0].strip()
        del_resp = self.stub.DeleteMessages(chat_pb2.DeleteMessagesRequest(username="harry", message_ids=[msg_id]))
        self.assertEqual(del_resp.status, "OK")
        read_resp_after = self.stub.ReadMessages(chat_pb2.ReadMessagesRequest(username="harry", num=10))
        self.assertEqual(len(read_resp_after.messages), 0)

    def test_delete_account(self):
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="ivy", password="ivypw"))
        del_resp = self.stub.DeleteAccount(chat_pb2.DeleteAccountRequest(username="ivy", password="ivypw"))
        self.assertEqual(del_resp.status, "OK")
        login_resp = self.stub.Login(chat_pb2.LoginRequest(username="ivy", password="ivypw"))
        self.assertEqual(login_resp.status, "ERROR")

    def test_read_does_not_delete_messages(self):
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="jack", password="jackpw"))
        self.stub.Login(chat_pb2.LoginRequest(username="jack", password="jackpw"))
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="kate", password="katepw"))
        self.stub.Login(chat_pb2.LoginRequest(username="kate", password="katepw"))
        self.stub.SendMessage(chat_pb2.SendMessageRequest(sender="jack", recipient="kate", message_text="Msg1"))
        self.stub.SendMessage(chat_pb2.SendMessageRequest(sender="jack", recipient="kate", message_text="Msg2"))
        read_resp = self.stub.ReadMessages(chat_pb2.ReadMessagesRequest(username="kate", num=10))
        self.assertEqual(len(read_resp.messages), 2)
        read_resp2 = self.stub.ReadMessages(chat_pb2.ReadMessagesRequest(username="kate", num=0))
        self.assertIn("Unread: 0", read_resp2.message)
        msg_ids = [m.split(":")[0].strip() for m in read_resp.messages]
        del_resp = self.stub.DeleteMessages(chat_pb2.DeleteMessagesRequest(username="kate", message_ids=msg_ids))
        self.assertEqual(del_resp.status, "OK")
        read_resp3 = self.stub.ReadMessages(chat_pb2.ReadMessagesRequest(username="kate", num=10))
        self.assertEqual(len(read_resp3.messages), 0)

    def test_dynamic_state_transfer(self):
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="leo", password="leopw"))
        self.stub.Login(chat_pb2.LoginRequest(username="leo", password="leopw"))
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="mia", password="miapw"))
        self.stub.Login(chat_pb2.LoginRequest(username="mia", password="miapw"))
        self.stub.SendMessage(chat_pb2.SendMessageRequest(sender="leo", recipient="mia", message_text="Hello Mia!"))
        self.stub.SendMessage(chat_pb2.SendMessageRequest(sender="leo", recipient="mia", message_text="How are you?"))
        time.sleep(0.2)
        snapshot = self.rep_stub.TransferState(chat_pb2.Empty(), timeout=10)
        dynamic_db_file, dynamic_temp_dir = get_temp_db()
        dynamic_servicer = PersistentChatServiceServicer(dynamic_db_file, replica_addresses=[])
        dynamic_rep_servicer = ReplicationServiceServicer(dynamic_servicer)
        dynamic_servicer.load_state(snapshot)
        dynamic_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        chat_pb2_grpc.add_ChatServiceServicer_to_server(dynamic_servicer, dynamic_server)
        chat_pb2_grpc.add_ReplicationServiceServicer_to_server(dynamic_rep_servicer, dynamic_server)
        dynamic_address = "localhost:50056"
        dynamic_server.add_insecure_port(dynamic_address)
        dynamic_server.start()
        time.sleep(0.2)
        dynamic_channel = grpc.insecure_channel(dynamic_address)
        dynamic_stub = chat_pb2_grpc.ChatServiceStub(dynamic_channel)
        login_resp = dynamic_stub.Login(chat_pb2.LoginRequest(username="mia", password="miapw"))
        self.assertEqual(login_resp.status, "OK")
        self.assertEqual(login_resp.unread_count, 2)
        send_resp = dynamic_stub.SendMessage(chat_pb2.SendMessageRequest(sender="leo", recipient="mia", message_text="Dynamic hello"))
        self.assertEqual(send_resp.status, "OK")
        new_msg_id = int(send_resp.message.split()[-1])
        self.assertGreater(new_msg_id, snapshot.max_message_id, "New message id should be greater than transferred max.")
        dynamic_server.stop(0)
        dynamic_channel.close()
        shutil.rmtree(dynamic_temp_dir)

    def test_resilience_heartbeat(self):
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(username="nick", password="nickpw"))
        login_resp = self.stub.Login(chat_pb2.LoginRequest(username="nick", password="nickpw"))
        self.assertEqual(login_resp.status, "OK")
        for _ in range(5):
            hb_resp = self.stub.Heartbeat(chat_pb2.HeartbeatRequest(username="nick"))
            self.assertEqual(hb_resp.status, "OK")
            time.sleep(0.1)

if __name__ == '__main__':
    unittest.main()
