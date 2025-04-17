# AlexChat: A Decentralized Peer-to-Peer Chat Over AlexMesh

**AlexChat** is a chat application that runs on top of **AlexMesh**, a custom Layer 3 + Layer 4 network protocol that operates directly over Ethernet frames without using IP. This project demonstrates real-time communication between nodes in a fully decentralized, peer-to-peer network stack built from scratch.

---

## 📡 How It Works

AlexChat builds on the AlexMesh protocol stack:

- **AlexMesh (L3)** handles node discovery, addressing, and mesh-based routing over raw Ethernet (using a custom EtherType).
- **AlexStream (L4)** implements reliable communication, session control, sequencing, and acknowledgments, similar to TCP.
- **AlexChat** is the application layer that enables interactive messaging between nodes.

No IP, no TCP, no NAT. Just pure Layer 2+3+4, designed and implemented from scratch.

---

## 🧱 Components

| File                  | Description                                |
|-----------------------|--------------------------------------------|
| `constants.py`        | Protocol constants                         |
| `utils.py`            | Helper functions (MAC handling)            |
| `protocol.py`         | AlexMesh frame encoding/decoding           |
| `alexstream.py`       | AlexStream Layer 4 transport logic         |
| `node.py`             | AlexMesh base node listener                |
| `send_handshake.py`   | Broadcasts handshake messages              |
| `send_message.py`     | Sends raw directed messages over mesh      |
| `alexstream_client.py`| Sends a full Layer 4 stream (one-off)      |
| `alexstream_server.py`| Server listener for AlexStream sessions    |
| `alexchat_client.py`  | Interactive CLI chat sender (Layer 4)      |
| `alexchat_server.py`  | Interactive CLI chat receiver              |

---

## 💻 Getting Started

### 🛠 Requirements
- Python 3.6+
- `scapy`
- Root privileges (for raw socket access)

Install dependencies:
```bash
pip install scapy
```

### 🔧 Run Server
```bash
sudo python3 alexchat_server.py <interface>
```

### 💬 Run Client
```bash
sudo python3 alexchat_client.py <interface> <server_mac>
```

### Example
```
sudo python3 alexchat_server.py en0
sudo python3 alexchat_client.py en0 6a:xx:xx:xx:xx:xx
```

---

## 🧠 Why?

This project is a proof-of-concept for:
- Local-only communication without any IP stack
- Peer-to-peer sessions with custom protocol logic
- Full control of Layer 2-4
- Educational exploration of OSI stack internals

---

## ⚠️ Disclaimer
This software is experimental and runs with raw socket access. It is not encrypted and is intended for local LAN testing and learning purposes.

---

## 🧑‍💻 Author
**Alex Harasic** – April 2025
