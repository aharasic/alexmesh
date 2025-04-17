from scapy.all import Ether, sendp
from constants import *
from utils import get_mac, mac_str
from protocol import build_frame
import sys

def send_handshake(interface):
    """Sends a broadcast handshake to announce the node to the network."""
    node_id = get_mac()
    print(f"[SEND] Sending handshake from {mac_str(node_id)}")

    payload = build_frame(MSG_TYPE_HANDSHAKE, node_id)

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_str(node_id), type=ALEXMESH_ETHERTYPE) / payload
    sendp(pkt, iface=interface, verbose=False)
    print("[SEND] Broadcast handshake sent")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: sudo python3 send_handshake.py <interface>")
        sys.exit(1)

    send_handshake(sys.argv[1])