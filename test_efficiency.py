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
