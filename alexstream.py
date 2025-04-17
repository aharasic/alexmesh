# alexstream.py

from enum import IntEnum
import struct

# Flags for the transport protocol
class StreamFlag(IntEnum):
    SYN = 0x01
    ACK = 0x02
    FIN = 0x04
    DATA = 0x08

# AlexStream header: stream_id (2B) | flags (1B) | seq (4B) | ack (4B)
HEADER_FORMAT = '!H B I I'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

class AlexStreamSession:
    def __init__(self, stream_id, peer_id):
        self.stream_id = stream_id         # Unique ID for the session
        self.peer_id = peer_id             # Node ID of the other party
        self.next_seq = 0                  # Next sequence number to send
        self.expected_seq = 0              # Sequence number expected from peer
        self.open = True                   # Session status
        self.buffer = {}                   # Received out-of-order packets

    def __repr__(self):
        return f"AlexStreamSession(id={self.stream_id}, peer={self.peer_id.hex()}, open={self.open})"


def build_stream_segment(stream_id, flags, seq, ack, payload=b''):
    """Creates a transport segment to be encapsulated in the AlexMesh payload."""
    header = struct.pack(HEADER_FORMAT, stream_id, flags, seq, ack)
    return header + payload


def parse_stream_segment(data):
    """Parses a transport segment from payload."""
    if len(data) < HEADER_SIZE:
        return None
    stream_id, flags, seq, ack = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    payload = data[HEADER_SIZE:]
    return stream_id, flags, seq, ack, payload


class AlexStreamManager:
    """Manages multiple sessions for a single node."""
    def __init__(self):
        self.sessions = {}  # stream_id -> AlexStreamSession

    def create_session(self, stream_id, peer_id):
        session = AlexStreamSession(stream_id, peer_id)
        self.sessions[stream_id] = session
        return session

    def get_session(self, stream_id):
        return self.sessions.get(stream_id)

    def close_session(self, stream_id):
        if stream_id in self.sessions:
            self.sessions[stream_id].open = False
