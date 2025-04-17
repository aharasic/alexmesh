from scapy.all import Ether, sendp, sniff, get_if_hwaddr
from constants import *
from utils import get_mac, mac_str
from protocol import build_frame, parse_frame
import sys
import time
import threading

# Keeps track of known neighbors with their MAC and last seen timestamp
neighbors = {}  # node_id (MAC in bytes) -> {'last_seen': timestamp, 'mac': str}

# Message deduplication store to avoid processing duplicates
received_msg_ids = set()

def update_neighbors(node_id, mac_str):
    """Updates the neighbors list when a node is seen."""
    neighbors[node_id] = {
        'last_seen': time.time(),
        'mac': mac_str
    }
    print("\n📡 Known neighbors:")
    for nid, info in neighbors.items():
        ago = time.time() - info['last_seen']
        print(f" - {mac_str(nid)} ({info['mac']}), seen {int(ago)}s ago")

def handle_packet(pkt, node_id, iface):
    """Handles incoming packets: processes, replies, or forwards them."""
    try:
        if Ether not in pkt:
            return

        eth = pkt[Ether]
        if eth.type != ALEXMESH_ETHERTYPE:
            return

        parsed = parse_frame(bytes(eth.payload))
        if not parsed:
            return

        version, msg_type, origin_id, dest_id, ttl, msg_id, payload = parsed

        # Ignore own packets
        if origin_id == node_id:
            return

        if msg_id in received_msg_ids:
            return

        received_msg_ids.add(msg_id)

        print(f"[RECV] From {mac_str(origin_id)} -> To {mac_str(dest_id)} | Type: {msg_type} | TTL: {ttl} | ID: {msg_id}")
        update_neighbors(origin_id, eth.src)

        # Message is for this node
        if dest_id == node_id:
            if msg_type == MSG_TYPE_HANDSHAKE:
                reply_payload = build_frame(MSG_TYPE_HANDSHAKE, node_id, origin_id, ttl=5)
                response = Ether(dst=eth.src, src=eth.dst, type=ALEXMESH_ETHERTYPE) / reply_payload
                sendp(response, iface=iface, verbose=False)
                print(f"[SEND] Handshake reply sent to {eth.src}")
            elif msg_type == MSG_TYPE_MESSAGE:
                print(f"[INFO] Message received: {payload.decode(errors='ignore')}")
                # Send ACK
                ack_payload = build_frame(MSG_TYPE_STATUS, node_id, origin_id, ttl=5, payload=f"ACK:{msg_id}".encode())
                ack_frame = Ether(dst=eth.src, src=eth.dst, type=ALEXMESH_ETHERTYPE) / ack_payload
                sendp(ack_frame, iface=iface, verbose=False)
                print(f"[SEND] ACK sent to {mac_str(origin_id)} for ID {msg_id}")
            elif msg_type == MSG_TYPE_STATUS:
                print(f"[ACK] Confirmation received from {mac_str(origin_id)}: {payload.decode(errors='ignore')}")

        # Forward if not the destination
        elif ttl > 0:
            ttl -= 1
            fwd_payload = build_frame(msg_type, origin_id, dest_id, ttl, payload, msg_id)
            fwd_frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_str(node_id), type=ALEXMESH_ETHERTYPE) / fwd_payload
            sendp(fwd_frame, iface=iface, verbose=False)
            print(f"[FWD] Forwarded packet to {mac_str(dest_id)} with TTL={ttl} | ID: {msg_id}")

    except Exception as e:
        print(f"[ERROR] {e}")

def send_heartbeat(node_id, iface):
    """Periodically sends a broadcast handshake to stay visible in the mesh."""
    while True:
        payload = build_frame(MSG_TYPE_HANDSHAKE, node_id, b'\x00'*6, ttl=5)
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_str(node_id), type=ALEXMESH_ETHERTYPE) / payload
        sendp(pkt, iface=iface, verbose=False)
        print("[SEND] Heartbeat handshake broadcast")
        time.sleep(5)

def run(interface):
    """Starts the AlexMesh node, heartbeat, and listener."""
    node_id = get_mac()
    print(f"AlexMesh Node ID: {mac_str(node_id)}")

    # Start the heartbeat thread
    threading.Thread(target=send_heartbeat, args=(node_id, interface), daemon=True).start()

    # Start listening for packets
    sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, node_id, interface), store=0)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: sudo python3 node.py <interface>")
        sys.exit(1)

    run(sys.argv[1])
