import struct
import time
from constants import ALEXMESH_VERSION

# AlexMesh frame header format
# version, type, origin_id, dest_id, ttl, msg_id
HEADER_FORMAT = '!BB6s6sBQ'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def generate_msg_id():
    """Generates a unique message ID based on current time in milliseconds."""
    return int(time.time() * 1000)

def build_frame(msg_type, origin_id, dest_id=b'\x00'*6, ttl=5, payload=b'', msg_id=None):
    """Constructs an AlexMesh frame."""
    if msg_id is None:
        msg_id = generate_msg_id()
    header = struct.pack(HEADER_FORMAT, ALEXMESH_VERSION, msg_type, origin_id, dest_id, ttl, msg_id)
    return header + payload

def parse_frame(data):
    """Parses a raw frame and returns the header fields + payload."""
    if len(data) < HEADER_SIZE:
        return None
    version, msg_type, origin_id, dest_id, ttl, msg_id = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    payload = data[HEADER_SIZE:]
    return version, msg_type, origin_id, dest_id, ttl, msg_id, payload