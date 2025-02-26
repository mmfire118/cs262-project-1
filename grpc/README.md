# Chat App (gRPC Re-Implementation)

This project is a chat application that demonstrates a client-server architecture using gRPC and Protocol Buffers. The application supports account creation, login, listing accounts (with wildcard matching), sending messages, reading stored messages, deleting messages, and deleting accounts—with real‑time streaming of new messages to online users.

Communication is handled via gRPC, which automatically serializes and deserializes messages into a compact binary format using Protocol Buffers. This eliminates the need for custom serialization code, improves maintainability, and enhances scalability.

## Features

- **Account Management:** Create accounts, log in, and delete accounts.
- **Messaging:** Send messages between users, read stored messages, and delete messages.
- **Real-Time Streaming:** If a recipient is online, messages are streamed immediately.
- **Secure Password Handling:** Passwords are salted and hashed using PBKDF2-HMAC-SHA256.
- **gRPC Communication:** Efficient, cross-language, and standardized remote procedure calls.

## Prerequisites

- **Python 3.x** (recommended: Python 3.12)
- **pip**
- **gRPC and Protocol Buffers Packages:**  
  Install required packages with:
  ```bash
  pip install --upgrade pip grpcio grpcio-tools protobuf
  ```

## Generating gRPC Code

Before running the server or client, generate the gRPC classes from the `chat.proto` file:

```bash
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. chat.proto
```

This command creates the files `chat_pb2.py` and `chat_pb2_grpc.py`.

## Running the Server

Start the gRPC chat server by specifying the host and port. For example:

```bash
python grpc_server.py --host localhost --port 50051
```

This will bind the server to all interfaces on port 50051.

## Running the Client

Launch the chat client with:

```bash
python grpc_client.py --host localhost --port 50051
```

A Tkinter graphical interface will open, allowing you to:
- Create an account and log in.
- Send messages (formatted as `recipient: message text`).
- List accounts.
- Read and delete messages.
- Delete your account.

## Running Tests

The project includes both unit tests and integration tests.

- **Unit Tests:** Verify utility functions, data models, and Protocol Buffer message serialization.
  ```bash
  python test_chat_grpc_unit.py
  ```
- **Integration Tests:** Test the end-to-end functionality of the server using simulated clients.
  ```bash
  python test_chat_grpc.py
  ```
- **Efficiency Tests:**  
  Measure and compare the message sizes of different serialization methods. In our tests:
  - Custom Binary Protocol produced **81 bytes**
  - JSON Protocol produced **125 bytes**
  - gRPC (Protocol Buffers) produced **18 bytes**
  Run:
  ```bash
  python test_efficiency_grpc.py
  ```

---

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