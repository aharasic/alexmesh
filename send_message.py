from scapy.all import Ether, sendp
from constants import *
from utils import get_mac, mac_str
from protocol import build_frame
import sys

def str_to_mac(mac_str):
    """Converts a MAC address string to bytes."""
    return bytes(int(b, 16) for b in mac_str.split(':'))

def send_message(interface, dest_mac_str, msg):
    """Sends a message to a specific destination node."""
    origin_id = get_mac()
    dest_id = str_to_mac(dest_mac_str)
    payload = msg.encode()

    frame = build_frame(MSG_TYPE_MESSAGE, origin_id, dest_id, ttl=5, payload=payload)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_str(origin_id), type=ALEXMESH_ETHERTYPE) / frame
    sendp(pkt, iface=interface, verbose=False)
    print(f"[SEND] Message sent to {dest_mac_str}: {msg}")

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: sudo python3 send_message.py <interface> <dest_mac> <message>")
        sys.exit(1)

    send_message(sys.argv[1], sys.argv[2], sys.argv[3])