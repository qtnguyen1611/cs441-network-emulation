def handle_ethernet_frame(frame, curr_MAC):
    """
    Handles a received Ethernet frame.

    :param frame: The received Ethernet frame as bytes.

    It extracts the source and destination MAC addresses, data length, and data from the frame.
    Data here can consist of the entire IP Packet or just message sent using Ethernet.
    If the Data is an IP Packet, it calls `handle_ip_packet` with the data.
    If not, it checks if the destination MAC address matches N2's MAC address and it will process to print out the message.
    Otherwise, it prints out the dropped frame's hex representation.
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
    Handles a received Ethernet frame.

    :param frame: The received Ethernet frame as bytes.

    It extracts the source and destination MAC addresses, data length, and data from the frame.
    Data here can consist of the entire IP Packet or just message sent using Ethernet.
    If the Data is an IP Packet, it calls `handle_ip_packet` with the data.
    If not, it checks if the destination MAC address matches N2's MAC address and it will process to print out the message.
    Otherwise, it prints out the dropped frame's hex representation.
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
    print(f"src_mac: {src_mac}, dst_mac: {dst_mac}, data: {data}")
    return src_mac.encode() + dst_mac.encode() + bytes([len(data)]) + data
