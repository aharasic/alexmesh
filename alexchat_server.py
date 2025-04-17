# alexchat_server.py

from scapy.all import Ether, sniff, sendp
from constants import *
from utils import get_mac, mac_str
from protocol import parse_frame, build_frame
from alexstream import *
import sys
import threading

received_ids = set()
manager = AlexStreamManager()
node_id = get_mac()
active_sessions = {}

# Send a segment

def send_segment(iface, dest_mac, origin_id, dest_id, payload):
    frame = build_frame(MSG_TYPE_MESSAGE, origin_id, dest_id, ttl=5, payload=payload)
    pkt = Ether(dst=dest_mac, src=mac_str(origin_id), type=ALEXMESH_ETHERTYPE) / frame
    sendp(pkt, iface=iface, verbose=False)

# Handle packet from the network

def handle_packet(pkt, iface):
    global active_sessions

    if Ether not in pkt or pkt[Ether].type != ALEXMESH_ETHERTYPE:
        return

    eth = pkt[Ether]
    parsed = parse_frame(bytes(eth.payload))
    if not parsed:
        return

    version, msg_type, origin_id, dest_id, ttl, msg_id, payload = parsed

    if origin_id == node_id or msg_id in received_ids:
        return

    received_ids.add(msg_id)

    result = parse_stream_segment(payload)
    if not result:
        return

    stream_id, flags, seq, ack, data = result
    session = manager.get_session(stream_id)
    if not session:
        session = manager.create_session(stream_id, origin_id)
        active_sessions[stream_id] = origin_id

    print(f"[RECV] Stream {stream_id} | Flags: {flags} | Seq: {seq}")

    if flags & StreamFlag.SYN:
        syn_ack = build_stream_segment(stream_id, StreamFlag.SYN | StreamFlag.ACK, seq=0, ack=seq + 1)
        send_segment(iface, eth.src, node_id, origin_id, syn_ack)
        print("[SERVER] SYN-ACK sent.")

    elif flags & StreamFlag.DATA:
        print(f"Client: {data.decode(errors='ignore')}")
        ack = build_stream_segment(stream_id, StreamFlag.ACK, seq=0, ack=seq + len(data))
        send_segment(iface, eth.src, node_id, origin_id, ack)

    elif flags & StreamFlag.FIN:
        ack = build_stream_segment(stream_id, StreamFlag.ACK, seq=0, ack=seq + 1)
        send_segment(iface, eth.src, node_id, origin_id, ack)
        print("[SERVER] Session closed.")
        session.open = False
        del active_sessions[stream_id]

# Background thread to receive traffic

def start_listener(interface):
    sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, interface), store=0)

# Input loop to chat back

def chat_loop(interface):
    while True:
        msg = input("You: ")
        for stream_id, dest_id in active_sessions.items():
            segment = build_stream_segment(stream_id, StreamFlag.DATA, seq=1, ack=0, payload=msg.encode())
            send_segment(interface, mac_str(dest_id), node_id, dest_id, segment)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: sudo python3 alexchat_server.py <interface>")
        sys.exit(1)

    iface = sys.argv[1]
    print(f"[AlexChat Server] Running on {mac_str(node_id)}")

    threading.Thread(target=start_listener, args=(iface,), daemon=True).start()
    chat_loop(iface)
