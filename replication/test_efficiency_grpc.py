import struct
import json
import hashlib
import chat_pb2

CMD_CREATE_ACCOUNT = 1

def measure_custom_message_size(command, fields):
    """
    Encodes a message using our custom binary protocol and returns its size in bytes.

    Message format:
      - 1 byte: Command code.
      - 4 bytes: Payload length.
      - Payload: For each field, 2 bytes for length followed by UTF-8 encoded data.
      
    Args:
        command (int): The command code.
        fields (list): List of string fields.

    Returns:
        int: Total message size in bytes.
    """
    payload = b""
    for field in fields:
        field_bytes = field.encode('utf-8')
        payload += struct.pack('!H', len(field_bytes)) + field_bytes
    header = struct.pack('!BI', command, len(payload))
    message = header + payload
    return len(message)

def measure_json_message_size(command, fields):
    """
    Encodes a message using our JSON protocol and returns its size in bytes.

    Message format:
      - 4 bytes: Length of JSON payload.
      - JSON payload: UTF-8 encoded JSON string representing {"command": <command>, "fields": <fields>}.
      
    Args:
        command (str): The command name.
        fields (list): List of string fields.

    Returns:
        int: Total message size in bytes.
    """
    msg = {"command": command, "fields": fields}
    msg_str = json.dumps(msg)
    msg_bytes = msg_str.encode('utf-8')
    header = struct.pack('!I', len(msg_bytes))
    message = header + msg_bytes
    return len(message)

def measure_grpc_message_size():
    """
    Creates a gRPC CreateAccountRequest message and returns the size of its serialized form in bytes.
    """
    username = "testuser"
    password = "secret"
    request = chat_pb2.CreateAccountRequest(username=username, password=password)
    data = request.SerializeToString()
    return len(data)

def measure_message_data_size():
    """
    Creates a MessageData message (with the new delivered field) and returns the size of its serialized form.
    """
    msg = chat_pb2.MessageData(id=123, recipient="user", sender="sender", message_text="Hello, world!", delivered=0)
    data = msg.SerializeToString()
    return len(data)

def measure_state_snapshot_size():
    """
    Creates a StateSnapshot message (including max_message_id) and returns the size of its serialized form.
    """
    snapshot = chat_pb2.StateSnapshot()
    acc = snapshot.accounts.add()
    acc.username = "alice"
    acc.salt = "somesalt"
    acc.hashed_password = "somehash"
    msg = snapshot.messages.add()
    msg.id = 1
    msg.recipient = "bob"
    msg.sender = "alice"
    msg.message_text = "Hello, Bob!"
    msg.delivered = 0
    snapshot.max_message_id = 1
    data = snapshot.SerializeToString()
    return len(data)

if __name__ == '__main__':
    username = "testuser"
    password = "secret"
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
    fields = [username, hashed_pw]
    
    custom_size = measure_custom_message_size(CMD_CREATE_ACCOUNT, fields)
    json_size = measure_json_message_size("CREATE_ACCOUNT", fields)
    grpc_size = measure_grpc_message_size()
    message_data_size = measure_message_data_size()
    state_snapshot_size = measure_state_snapshot_size()
    
    print("Message sizes for account creation:")
    print("Custom Binary Protocol size: {} bytes".format(custom_size))
    print("JSON Protocol size: {} bytes".format(json_size))
    print("gRPC (Protocol Buffers) size (CreateAccountRequest): {} bytes".format(grpc_size))
    print("gRPC MessageData size: {} bytes".format(message_data_size))
    print("gRPC StateSnapshot size: {} bytes".format(state_snapshot_size))
