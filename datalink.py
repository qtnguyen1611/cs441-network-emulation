def handle_ethernet_frame(frame, curr_MAC):
    """
    Handles a received Ethernet frame.

    :param frame: The received Ethernet frame as bytes.
    :param curr_MAC: The current MAC address.

    It extracts the source and destination MAC addresses, data length, and data from the frame.
    Data here can consist of Ethernet frame and IP packet inside.
    Returns IP packet if the destination MAC address matches the current MAC address.
    Otherwise, it drops the frame.
    """
    src_mac = frame[:2].decode()
    dst_mac = frame[2:4].decode()
    data_length = frame[4]
    # Ethernet Frame Data, the IP Packet is inside the Ethernet Frame
    # Consist of the entire IP Packet
    data = frame[5:]
    print("--DataLink layer--")
    print(f"Received frame: {frame.hex()}, from {src_mac}, meant for {dst_mac}")
    
    # Check if destination MAC is is current MAC
    if dst_mac == curr_MAC:
        print(f"MAC Address matches, processing IP Packet")
        return data
    else:
        print(f"MAC addresses not matched. Dropped frame: {frame.hex()}")
        return None
    
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
    
def form_ethernet_frame(src_mac, dst_mac, data):
    """
    Forms an Ethernet frame with the source and destination MAC addresses and data.

    :param
        src_mac: The source MAC address as a string.
        dst_mac: The destination MAC address as a string.
        data: The data to be sent as bytes.
    """
    print("--DataLink layer--")
    print(f"Ethernet frame: src_mac: {src_mac}, dst_mac: {dst_mac}, data length: {len(data)}, data: {data}")
    return src_mac.encode() + dst_mac.encode() + bytes([len(data)]) + data
