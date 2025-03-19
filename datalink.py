import struct

def handle_ethernet_frame(frame, curr_MAC):
    """
    Handles a received Ethernet frame.

    :param frame: The received Ethernet frame as bytes.
    :param curr_MAC: The current MAC address.

    It extracts the source and destination MAC addresses, data length, packet type and data from the frame.
    Data here can consist of Ethernet frame and IP packet / ARP packet inside.
    Returns IP packet / ARP packet depending on packet type.
    Drops frame if destination MAC has no match and is not a broadcast MAC or its a unkown packet type.
    """
    src_mac = frame[:2].decode()
    dst_mac = frame[2:4].decode()
    data_length = frame[4]
    packet_type_byte = frame[5]  # ADDED new field to differentiate the packet type
    data = frame[6:]
    print("--DataLink layer--")
    print(f"Received frame: {frame.hex()}, from {src_mac}, meant for {dst_mac}")

    if dst_mac == curr_MAC or dst_mac == "FF":
        if packet_type_byte == 0:
            return data, "IP"
        elif packet_type_byte == 1:
            return data, "ARP"
        else:
            print(f"Unknown packet type: {packet_type_byte}")
            return None, None
    else:
        print(f"MAC addresses not matched. Dropped frame: {frame.hex()}")
        return None, None

def handle_sniffed_ethernet_frame(frame):
    """
    Handles a received sniffed Ethernet frame.

    :param frame: The received Ethernet frame as bytes.

    It extracts the source and destination MAC addresses, data length, and data from the frame.
    Data here can consist of Ethernet frame and IP packet inside.
    Returns IP packet.
    """
    src_mac = frame[:2].decode()
    dst_mac = frame[2:4].decode()
    data_length = frame[4]
    # Ethernet Frame Data, the IP Packet is inside the Ethernet Frame
    # Consist of the entire IP Packet
    data = frame[5:]
    
    return data
    
def form_ethernet_frame(src_mac, dst_mac, data, packet_type):
    """
    Forms an Ethernet frame with the source and destination MAC addresses and data.

    :param
        src_mac: The source MAC address as a string.
        dst_mac: The destination MAC address as a string.
        data: The data to be sent as bytes.
        packet_type: The packet type as a string. (0 for "IP" packets, 1 for "ARP" packets)
    """
    print("--DataLink layer--")
    print(f"Ethernet frame: src_mac: {src_mac}, dst_mac: {dst_mac}, data length: {len(data)}, data: {data}")
    type_byte = bytes([0]) if packet_type == "IP" else bytes([1])
    return src_mac.encode() + dst_mac.encode() + bytes([len(data)]) + type_byte + data

def form_arp_frame(operation, sender_mac, sender_ip, target_mac, target_ip):
    """
    1. Form an ARP packet with the operation, sender MAC and IP, target MAC and IP.
    
    :param
        operation: 1 for request, 2 for reply
        sender_mac: The sender MAC address as a string.
        sender_ip: The sender IP address as a string.
        target_mac: The target MAC address as a string.
        target_ip: The target IP address as a string.
    """
    print("--FORM ARP packet--")
    print(f"operation: {operation}, sender_mac: {sender_mac}, sender_ip: {sender_ip}, target_mac: {target_mac}, target_ip: {target_ip}")
    arp_packet = bytes([operation]) + sender_mac.encode() + bytes([int(sender_ip, 16)]) + target_mac.encode() + bytes([int(target_ip, 16)])

    """
    2. Form an Ethernet frame with the source and destination MAC addresses and data.
    
    :param
        src_mac: The sender MAC address as a string.
        dst_mac: The broadcast MAC or target MAC address as a string.
        data: The arp packet.
        packet_type: The packet type as a string. ("IP" / "ARP")
    """
    return form_ethernet_frame(sender_mac, target_mac, arp_packet, "ARP")
    
def handle_arp_packet(arp_packet):
    """
    Parse ARP packet by extracting the concatenated fields in order:
    operation + sender_mac + sender_ip + target_mac + target_ip
    """
    operation = arp_packet[0]
    sender_mac = arp_packet[1:3].decode()
    sender_ip = '0x' + hex(struct.unpack('B', arp_packet[3:4])[0]).upper()[-2:]
    target_mac = arp_packet[4:6].decode()
    target_ip = '0x' + hex(struct.unpack('B', arp_packet[6:7])[0]).upper()[-2:]
    print("--HANDLE ARP packet--")
    print(f"ARP packet: operation: %d, sender_mac: %s, sender_ip: %s, target_mac: %s, target_ip: %s", operation, sender_mac, sender_ip, target_mac, target_ip)
    return [operation, sender_mac, sender_ip, target_mac, target_ip]
