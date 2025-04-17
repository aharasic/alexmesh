import uuid

def get_mac():
    """Returns the MAC address of the current machine as bytes."""
    mac = uuid.getnode()
    return mac.to_bytes(6, byteorder='big')

def mac_str(mac):
    """Converts a MAC address in bytes to a human-readable string."""
    return ':'.join(f'{b:02x}' for b in mac)