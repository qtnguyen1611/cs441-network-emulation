import struct

def handle_ip_packet(packet, curr_IP):
    """
    Processes an incoming IP packet.

    This function extracts the source and destination IP addresses, protocol,
    and data from the incoming packet. It checks if the destination IP matches
    the current IP. It drops the packet if the destination IP does not match
    the current IP. It returns the source IP, protocol, and data if the destination
    IP matches the current IP. 

    Args:
        packet (bytes): The incoming IP packet as a byte sequence.
        curr_IP: The current IP address.
    """
    print("--Network layer--")    
    src_ip = '0x' + hex(struct.unpack('B', packet[0:1])[0]).upper()[-2:]
    dst_ip = '0x' + hex(struct.unpack('B', packet[1:2])[0]).upper()[-2:]
    # Only can return Protocol 0 - Ping
    protocol = packet[2]
    data_length = packet[3]
    data = packet[4:5+data_length]
    data = data.decode('utf-8')

    print(f"src_ip: {src_ip}, dst_ip: {dst_ip}, protocol: {protocol}, data_length: {data_length}, data: {data} \n")
    
    if dst_ip == curr_IP:
        print(f"IP Address matches, processing IP Packet")
        return [src_ip, protocol, data]
    else:
        print(f"IP addresses not matched. Dropped packet.")
        return None

def handle_sniffed_ip_packet(packet):
    """
    Processes an incoming IP packet and manages ping replies.

    This function extracts the source and destination IP addresses, protocol,
    and data from the incoming packet. 

    Returns the source IP, destination IP, protocol, and data.

    Args:
        packet (bytes): The incoming IP packet as a byte sequence.
    """
    src_ip = '0x' + hex(struct.unpack('B', packet[0:1])[0]).upper()[-2:]
    dst_ip = '0x' + hex(struct.unpack('B', packet[1:2])[0]).upper()[-2:]
    # Only can return Protocol 0 - Ping
    protocol = packet[2]
    data_length = packet[3]
    data = packet[4:5+data_length]
    data = data.decode('utf-8')

    return [src_ip, dst_ip, protocol, data]


def router_handle_ip_packet(packet):
    """
    Processes an incoming IP packet for router.

    This function extracts and returns the source and destination IP 
    addresses, protocol, and data from the incoming packet.

    Args:
        packet (bytes): The incoming IP packet as a byte sequence.
    """
    print("--Network layer--")    
    src_ip = '0x' + hex(struct.unpack('B', packet[0:1])[0]).upper()[-2:]
    dst_ip = '0x' + hex(struct.unpack('B', packet[1:2])[0]).upper()[-2:]
    # Only can return Protocol 0 - Ping
    protocol = packet[2]
    data_length = packet[3]
    data = packet[4:5+data_length]
    data = data.decode('utf-8')

    print(f"src_ip: {src_ip}, dst_ip: {dst_ip}, protocol: {protocol}, data_length: {data_length}, data: {data} \n")
    
    return [src_ip, dst_ip, protocol, data]

    
def form_ip_packet(src_ip, dst_ip, protocol, message):
    """
    Forms an IP packet with the source and destination IP addresses, protocol,
    and message.

    This function takes in the source IP address, destination IP address, protocol,
    and message as arguments. It forms an IP packet by concatenating the source IP
    address, destination IP address, protocol, and message. The IP packet is then
    returned as a byte sequence.

    Args:
        src_ip (str): The source IP address as a string.
        dst_ip (str): The destination IP address as a string.
        protocol (int): The protocol number as an integer.
        message (str): The message to be sent as a string.

    Returns:
        bytes: The formed IP packet as a byte sequence.
    """
    return bytes([int(src_ip, 16), int(dst_ip, 16), protocol, len(message)]) + message.encode()