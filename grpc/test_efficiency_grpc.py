import struct
import json
import hashlib
import chat_pb2

# Command code for our custom protocol (e.g., account creation)
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
        # Prefix each field with its 2-byte length
        payload += struct.pack('!H', len(field_bytes)) + field_bytes
    # Header consists of 1 byte for the command and 4 bytes for payload length
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
    # 4-byte header indicating message length
    header = struct.pack('!I', len(msg_bytes))
    message = header + msg_bytes
    return len(message)

def measure_grpc_message_size():
    """
    Creates a gRPC CreateAccountRequest message and returns the size of its serialized form in bytes.

    This uses Protocol Buffers to automatically serialize the message into a compact binary format.

    Returns:
        int: Size of the serialized gRPC message in bytes.
    """
    # For comparison, we use the same fields as above: username and plaintext password.
    username = "testuser"
    password = "secret"
    request = chat_pb2.CreateAccountRequest(username=username, password=password)
    data = request.SerializeToString()
    return len(data)

if __name__ == '__main__':
    # Example: account creation message fields
    username = "testuser"
    password = "secret"
    # For custom and JSON protocols, we hash the password for demonstration purposes.
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
    fields = [username, hashed_pw]
    
    custom_size = measure_custom_message_size(CMD_CREATE_ACCOUNT, fields)
    json_size = measure_json_message_size("CREATE_ACCOUNT", fields)
    grpc_size = measure_grpc_message_size()
    
    print("Message sizes for account creation:")
    print("Custom Binary Protocol size: {} bytes".format(custom_size))
    print("JSON Protocol size: {} bytes".format(json_size))
    print("gRPC (Protocol Buffers) size: {} bytes".format(grpc_size))
