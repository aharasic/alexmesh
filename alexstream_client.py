# alexstream_client.py

from scapy.all import Ether, sendp
from constants import *
from utils import get_mac, mac_str
from protocol import build_frame
from alexstream import *
import sys
import time
import random

# Converts MAC string to bytes
def str_to_mac(mac_str):
    return bytes(int(b, 16) for b in mac_str.split(':'))

def send_segment(interface, segment_payload, dest_mac, origin_id, dest_id):
    frame = build_frame(MSG_TYPE_MESSAGE, origin_id, dest_id, ttl=5, payload=segment_payload)
    pkt = Ether(dst=dest_mac, src=mac_str(origin_id), type=ALEXMESH_ETHERTYPE) / frame
    sendp(pkt, iface=interface, verbose=False)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: sudo python3 alexstream_client.py <interface> <dest_mac> <message>")
        sys.exit(1)

    iface = sys.argv[1]
    dest_mac = str_to_mac(sys.argv[2])
    message = sys.argv[3].encode()

    origin_id = get_mac()
    dest_id = dest_mac

    stream_id = random.randint(1, 65535)  # Random stream/session ID
    manager = AlexStreamManager()
    session = manager.create_session(stream_id, dest_id)

    # 1. Send SYN
    syn = build_stream_segment(stream_id, StreamFlag.SYN, seq=0, ack=0)
    send_segment(iface, syn, sys.argv[2], origin_id, dest_id)
    print(f"[CLIENT] SYN sent with stream_id={stream_id}")
    time.sleep(0.5)

    # 2. Send DATA
    session.next_seq = 1
    data = build_stream_segment(stream_id, StreamFlag.DATA, seq=1, ack=0, payload=message)
    send_segment(iface, data, sys.argv[2], origin_id, dest_id)
    print(f"[CLIENT] DATA sent: {message.decode()}")
    time.sleep(0.5)

    # 3. Send FIN
    fin = build_stream_segment(stream_id, StreamFlag.FIN, seq=2, ack=0)
    send_segment(iface, fin, sys.argv[2], origin_id, dest_id)
    print(f"[CLIENT] FIN sent. Session closed.")
