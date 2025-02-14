# Simple Client-Server Chat Application

## Overview
This project implements a client‑server chat application with the following features:
- **Account Management:** Create accounts, log in, and delete accounts.
- **Messaging:** Send, receive, list, read, and delete messages.
- **Protocols:** Supports both a custom binary protocol and a JSON‑based protocol.
- **GUI:** The client application uses a Tkinter‑based graphical interface.

## Wire Protocols
### Custom Binary Protocol
- **Message Format:**
  - 1 byte: Command code.
  - 4 bytes: Payload length.
  - Payload: One or more fields, each with:
    - 2 bytes: Field length.
    - Field data (UTF‑8 encoded).

### JSON‑Based Protocol
- **Message Format:**
  - 4 bytes: Length of the JSON payload.
  - JSON payload: A UTF‑8 encoded JSON string with keys `"command"` and `"fields"`.

## File Structure
Below is an example of the project tree:
```
├── client.py
├── design.md
├── notebook.md
├── README.md
├── server.py
├── test_chat.py
├── test_unit.py
└── test_efficiency.py
```
- `client.py`: Implements the chat client with a Tkinter‑based GUI. It handles login, account creation, sending messages, and more.
- `server.py`: Implements the chat server that accepts multiple client connections, manages user accounts, and routes messages. It supports both protocols.
- `test_chat.py`: Contains integration tests that simulate end‑to‑end interactions between clients and the server.
- `test_unit.py`: Contains unit tests for lower‑level functions such as the password hashing function and the protocol (encoding/decoding) classes.
- `test_efficiency.py`: Compares the size of messages sent using the custom binary protocol and the JSON protocol.


## Running the Application
### Client
```bash
python3 client.py --host localhost --port 12345 --protocol custom
python3 client.py --host localhost --port 12345 --protocol json
```
### Server
```bash
python3 server.py --host localhost --port 12345 --protocol custom
python3 server.py --host localhost --port 12345 --protocol json
```

## Running Tests
### Integration Tests
```bash
python3 -m unittest test_chat.py
```
### Unit Tests
```bash
python3 -m unittest test_unit.py
```
