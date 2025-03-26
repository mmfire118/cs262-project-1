# Persistent gRPC Chat System with Replication and Dynamic Replica Addition

This project implements a fault‑tolerant, persistent chat system using gRPC, SQLite, and Tkinter. It supports:

- **Persistence:**  
  Each server stores its state (accounts, messages, and a metadata value tracking the maximum message ID) in its own SQLite database.
  
- **Replication:**  
  Write operations (e.g. account creation and message sending) are applied locally and then forwarded via a ReplicationService RPC to the other replicas.
  
- **Dynamic Replica Addition:**  
  New replicas can join on the fly by transferring state from an existing live server.
  
- **Client:**  
  A gRPC client with a Tkinter interface that supports multiple servers and uses simple retry logic to automatically handle server failures.

---

## Prerequisites

- **Python 3.12** (or later)
- Required Python packages:
  - `grpcio`
  - `grpcio-tools`
  - `tkinter` (usually bundled with Python)
  - Standard libraries (`sqlite3`, `argparse`, `queue`, etc.)

Install the gRPC packages (if not already installed):

```bash
pip install grpcio grpcio-tools
```

---

## Files Provided

- **`chat.proto`** – The Protocol Buffers definition for the Chat and Replication services.  
- **`grpc_server.py`** – The upgraded server supporting persistence, replication, and dynamic state transfer.
- **`grpc_client.py`** – The chat client with a Tkinter interface that accepts a comma‑separated list of server addresses.

---

## Generating gRPC Python Files

From the project directory, run:

```bash
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. chat.proto
```

This creates the files `chat_pb2.py` and `chat_pb2_grpc.py`.

---

## How It Works

### Server Details

- **Persistence and Metadata:**  
  Each server uses SQLite to persist accounts, messages, and a metadata table. The metadata table stores the current maximum message ID so that when state is transferred, dynamic servers continue numbering new messages without “resetting” the ID counter.

- **Replication:**  
  Write operations (e.g. CreateAccount, SendMessage) are applied locally and then replicated via the ReplicationService RPC to all other servers. The client uses multiple servers for fault tolerance.

- **Dynamic State Transfer:**  
  A new (dynamic) replica uses the `--join` flag to contact an existing server, receive a state snapshot (including accounts, messages, and the donor’s max_message_id), and load that state into its own database. The metadata is updated so that new messages will be assigned IDs greater than the donor’s maximum.

### Client Details

- **Multi-Server Connection:**  
  The client accepts a comma‑separated list of server addresses (using the `--servers` flag) and maintains a separate gRPC channel/stub for each.

- **Simple Retry Logic:**  
  If an RPC fails on one server, the client automatically cycles to another available server.

- **User Interface:**  
  The Tkinter interface allows you to create an account, log in, send messages (using the format `recipient: message text`), list accounts, read messages (which now marks them as delivered instead of deleting), and delete messages or your account.

---

## Run Commands

### Main Servers

Open three separate terminal windows and run:

- **Server 1:**
  ```bash
  python grpc_server.py --host localhost --port 50051 --db_file chat_server1.db --replicas localhost:50052,localhost:50053
  ```
- **Server 2:**
  ```bash
  python grpc_server.py --host localhost --port 50052 --db_file chat_server2.db --replicas localhost:50051,localhost:50053
  ```
- **Server 3:**
  ```bash
  python grpc_server.py --host localhost --port 50053 --db_file chat_server3.db --replicas localhost:50051,localhost:50052
  ```

### Client

In a new terminal window, run the client (using the updated server list):

```bash
python grpc_client.py --servers localhost:50051,localhost:50052,localhost:50053
```

### Dynamic Replica

To add a dynamic replica (which will copy state from a live server), run in another terminal:

```bash
python grpc_server.py --host localhost --port 50054 --db_file chat_server4.db --replicas localhost:50051,localhost:50052,localhost:50053 --join localhost:50051
```

Then, to include it in client connections, click the 'Add Server' button in any open clients and input:

```bash
localhost:50054
```

or for new clients, run:

```bash
python grpc_client.py --servers localhost:50051,localhost:50052,localhost:50053,localhost:50054
```

### Running on Multiple Machines with ngrok

If you need to run instances of the chat server on different machines that are behind NATs or firewalls, you can use [ngrok](https://ngrok.com) to forward the gRPC ports to a public endpoint. Here’s how to set it up as an example with Machines A, B, and C:

1. **Install ngrok**  
   Download and install ngrok from [ngrok.com/download](https://ngrok.com/download).

2. **Expose the server port with ngrok**
   In a separate terminal on all machines, forward the gRPC port:
   ```bash
   ngrok tcp 50051
   ```
   This command will output a public forwarding address (e.g., `0.tcp.ngrok.io:12345`, do not include the `tcp://` header). Use this address in the `--replicas` list on the other machines and when starting the client.
  
3. **Start the gRPC server**  
   For example, on Machine A run:
   ```bash
   python grpc_server.py --host localhost --port 50051 --db_file chat_serverA.db --replicas <MachineB_Public_Address>,<MachineC_Public_Address>
   ```
   Do this respectively for all machines.

5. **Configure the client**
   When starting the client, use the ngrok forwarding addresses for all servers:
   ```bash
   python grpc_client.py --servers <MachineA_Public_Address>,<MachineB_Public_Address>,<MachineC_Public_Address>
   ```

Keep the ngrok sessions active while your servers are running. This setup ensures that the gRPC communication (including replication and dynamic state transfer) works across different networks.


## Project Structure

- **grpc_server.py:** Implements the gRPC chat server.
- **grpc_client.py:** Implements the gRPC chat client with a Tkinter GUI.
- **chat.proto:** Protocol Buffers definition file for the chat service.
- **chat_pb2.py / chat_pb2_grpc.py:** Auto-generated gRPC code.
- **test_chat_grpc.py:** Integration tests for the chat server.
- **test_unit_grpc.py:** Unit tests for utility functions, data models, and Protocol Buffer message serialization.
- **test_efficiency_grpc.py:** Efficiency tests showing the compactness of Protocol Buffers compared to custom binary and JSON.
- **README.md:** This documentation file.
- **notebook_grpc.md:** The engineering notebook documenting the gRPC re-implementation process.