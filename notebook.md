# Engineering Notebook

**Project Title:** Chat App
**By:** Miles Pines and William Zhang

---

## 1. What We're Building

We're working on a simple chat app that uses a client-server model. Our app includes these features:

- **Account Creation:** We can create an account with a unique username and a password (which we hash before sending).
- **Login:** We log in using our username and hashed password. If we get something wrong, the app shows an error.
- **Listing Accounts:** We can see all accounts or filter them using wildcards.
- **Sending Messages:** We send messages to other users. If the recipient is online, they get the message immediately; otherwise, the server stores it until timport struct
import json
import hashlib

# Command code for our custom protocol (e.g., account creation)
CMD_CREATE_ACCOUNT = 1

def measure_custom_message_size(command, fields):
    """
    Encodes a message using our custom binary protocol and returns its size in bytes.
    """
    payload = b""
    for field in fields:
        field_bytes = field.encode('utf-8')
        # Each field gets a 2-byte length prefix
        payload += struct.pack('!H', len(field_bytes)) + field_bytes
    # Header: 1 byte command + 4 bytes for payload length
    header = struct.pack('!BI', command, len(payload))
    message = header + payload
    return len(message)

def measure_json_message_size(command, fields):
    """
    Encodes a message using our JSON protocol and returns its size in bytes.
    """
    msg = {"command": command, "fields": fields}
    msg_str = json.dumps(msg)
    msg_bytes = msg_str.encode('utf-8')
    # 4-byte header indicating message length
    header = struct.pack('!I', len(msg_bytes))
    message = header + msg_bytes
    return len(message)

if __name__ == '__main__':
    # Example: account creation message
    username = "testuser"
    password = "secret"
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
    fields = [username, hashed_pw]
    
    custom_size = measure_custom_message_size(CMD_CREATE_ACCOUNT, fields)
    json_size = measure_json_message_size("CREATE_ACCOUNT", fields)
    
    print("Message sizes for account creation:")
    print("Custom Binary Protocol size: {} bytes".format(custom_size))
    print("JSON Protocol size: {} bytes".format(json_size))
hey log in.
- **Reading Messages:** We can request a specific number of unread messages.
- **Deleting Messages:** We have the option to delete one or more messages permanently.
- **Deleting an Account:** We can delete an account, and the server handles any stored messages accordingly.

We implemented two different ways for the client and server to talk:

1. **Custom Binary Protocol:** This one is built for efficiency, keeping the message size small.
2. **JSON Protocol:** This method uses JSON for a more human-readable format (though it has extra overhead).

Our client has a basic GUI built with Tkinter, and our server supports multiple clients at once using threads.

---

## 2. Our Design Thoughts

### Wire Protocols
- **Custom Binary Protocol:**  
  - **Pros:** Super low overhead and small messages.
  - **Cons:** Not human-readable, so debugging can sometimes be a pain.
- **JSON Protocol:**  
  - **Pros:** Easy to read and debug.
  - **Cons:** More overhead because it’s text-based.

### Security
- **Password Handling:**  
  - We hash the password using SHA-256 before sending it.
  - *Note for later:* We might add salting or a more secure key exchange later.

### Concurrency & Scaling
- **Multiple Clients:**  
  - Our server spawns a new thread for each client.
  - *To think about:* How many simultaneous connections can we handle? We should run some load tests soon.

### Testing & Validation
- **Unit Tests:**  
  - We wrote comprehensive tests to cover account creation, login, messaging, and deletion using both protocols.
- **Message Size Comparison:**  
  - We created a small piece of code (see below) to measure the sizes of messages produced by each protocol.

---

## 3. Testing Message Sizes

To see how efficient each protocol is, we wrote this simple code snippet. It calculates the size (in bytes) of a message for a given command and set of fields.

```python
import struct
import json
import hashlib

# Command code for our custom protocol (e.g., account creation)
CMD_CREATE_ACCOUNT = 1

def measure_custom_message_size(command, fields):
    """
    Encodes a message using our custom binary protocol and returns its size in bytes.
    """
    payload = b""
    for field in fields:
        field_bytes = field.encode('utf-8')
        # Each field gets a 2-byte length prefix
        payload += struct.pack('!H', len(field_bytes)) + field_bytes
    # Header: 1 byte command + 4 bytes for payload length
    header = struct.pack('!BI', command, len(payload))
    message = header + payload
    return len(message)

def measure_json_message_size(command, fields):
    """
    Encodes a message using our JSON protocol and returns its size in bytes.
    """
    msg = {"command": command, "fields": fields}
    msg_str = json.dumps(msg)
    msg_bytes = msg_str.encode('utf-8')
    # 4-byte header indicating message length
    header = struct.pack('!I', len(msg_bytes))
    message = header + msg_bytes
    return len(message)

if __name__ == '__main__':
    # Example: account creation message
    username = "testuser"
    password = "secret"
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
    fields = [username, hashed_pw]
    
    custom_size = measure_custom_message_size(CMD_CREATE_ACCOUNT, fields)
    json_size = measure_json_message_size("CREATE_ACCOUNT", fields)
    
    print("Message sizes for account creation:")
    print("Custom Binary Protocol size: {} bytes".format(custom_size))
    print("JSON Protocol size: {} bytes".format(json_size))

We see that the output:
```
Message sizes for account creation:
Custom Binary Protocol size: 81 bytes
JSON Protocol size: 125 bytes
```
shows our custom binary protocol is a slightly better size than the JSON protocol. This makes sense because the JSON protocol has additional overhead to make the key value pairs human-readable. In contrast, our custom binary protocol is shorter with less readability.