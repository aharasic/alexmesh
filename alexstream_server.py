# alexstream_server.py

from scapy.all import Ether, sniff, sendp
from constants import *
from utils import get_mac, mac_str
from protocol import parse_frame, build_frame
from alexstream import *
import sys

received_ids = set()
manager = AlexStreamManager()

# Handle incoming AlexMesh packets

def handle_packet(pkt, node_id, iface):
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

    # Process stream layer
    result = parse_stream_segment(payload)
    if not result:
        return

    stream_id, flags, seq, ack, data = result
    session = manager.get_session(stream_id)
    if not session:
        session = manager.create_session(stream_id, origin_id)

    print(f"[SERVER] Stream {stream_id} | Flags: {flags} | Seq: {seq} | Ack: {ack}")

    if flags & StreamFlag.SYN:
        print("[SERVER] SYN received. Sending SYN-ACK.")
        syn_ack = build_stream_segment(stream_id, StreamFlag.SYN | StreamFlag.ACK, seq=0, ack=seq+1)
        response = build_frame(MSG_TYPE_MESSAGE, node_id, origin_id, ttl=5, payload=syn_ack)
        reply = Ether(dst=eth.src, src=eth.dst, type=ALEXMESH_ETHERTYPE) / response
        sendp(reply, iface=iface, verbose=False)

    elif flags & StreamFlag.DATA:
        print(f"[SERVER] DATA received: {data.decode(errors='ignore')}")
        # Respond with ACK
        ack_seg = build_stream_segment(stream_id, StreamFlag.ACK, seq=0, ack=seq+len(data))
        response = build_frame(MSG_TYPE_MESSAGE, node_id, origin_id, ttl=5, payload=ack_seg)
        reply = Ether(dst=eth.src, src=eth.dst, type=ALEXMESH_ETHERTYPE) / response
        sendp(reply, iface=iface, verbose=False)
        print("[SERVER] ACK sent.")

    elif flags & StreamFlag.FIN:
        print("[SERVER] FIN received. Session closing.")
        session.open = False
        fin_ack = build_stream_segment(stream_id, StreamFlag.ACK, seq=0, ack=seq+1)
        response = build_frame(MSG_TYPE_MESSAGE, node_id, origin_id, ttl=5, payload=fin_ack)
        reply = Ether(dst=eth.src, src=eth.dst, type=ALEXMESH_ETHERTYPE) / response
        sendp(reply, iface=iface, verbose=False)
        print("[SERVER] Final ACK sent.")


def run(interface):
    node_id = get_mac()
    print(f"AlexStream Server running as {mac_str(node_id)} on interface {interface}")
    sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, node_id, interface), store=0)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: sudo python3 alexstream_server.py <interface>")
        sys.exit(1)

    run(sys.argv[1])
