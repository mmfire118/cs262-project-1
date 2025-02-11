# Chat Application

A simple Python chat application using a client-server model with two wire protocols (custom binary and JSON). The client features a basic Tkinter GUI.

## Installation

```
python3 -m venv venv
source venv/bin/activate
```

## Usage

Server (custom binary protocol)
```
python3 server.py --host localhost --port 12345 --protocol custom
```

Server (JSON protocol)
```
python3 server.py --host localhost --port 12345 --protocol json
```

Client (custom binary protocol)
```
python3 client.py --host localhost --port 12345 --protocol custom
```

Client (JSON protocol)
```
python3 client.py --host localhost --port 12345 --protocol json
```

## Tests

```
python3 test_chat.py
```
