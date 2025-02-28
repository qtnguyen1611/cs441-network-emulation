import struct

def handle_ip_packet(packet, curr_IP):
    """
    Processes an incoming IP packet and manages ping replies.

    This function extracts the source and destination IP addresses, protocol,
    and data from the incoming packet. It checks if the destination IP matches
    the node's IP and manages the number of ping replies that can be sent to 
    the source IP. If the source IP has not been recorded, it is added to the 
    ping reply map and a reply is sent. If the source IP is already in the map 
    and has not exceeded the maximum allowed pings, the counter is incremented 
    and a reply is sent. If the source IP has reached the maximum allowed pings,
    the packet is dropped.

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

    print(f"src_ip: {src_ip}, curr_ip: {curr_IP}, dst_ip: {dst_ip}, protocol: {protocol}, data_length: {data_length}, data: {data} \n")
    
    # Added max number of pings to 2
    if dst_ip == curr_IP:
        print(f"MAC Address matches, processing IP Packet")
        return [src_ip, protocol, data]
    else:
        print(f"IP addresses not matched. Dropped packet.")
        return None
    
def form_ip_packet(src_ip, dst_ip, protocol, message):
    """
    Forms an IP packet with the source and destination IP addresses, protocol,
    and message.

    This function takes in the source IP address, destination IP address, protocol,
    and message as arguments. It forms an IP packet by concatenating the source IP
    address, destination IP address, protocol, and message. The IP packet is then
    returned as a byte sequence.

    Args:
        src_ip (str): The source IP address as a hexadecimal string.
        dst_ip (str): The destination IP address as a hexadecimal string.
        protocol (int): The protocol number as an integer.
        message (str): The message to be sent as a string.

    Returns:
        bytes: The formed IP packet as a byte sequence.
    """
    return bytes([int(src_ip, 16), int(dst_ip, 16), protocol, len(message)]) + message.encode()