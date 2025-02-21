import socket
import struct
import threading

# Node3's MAC and IP addresses
N3_MAC = "N3"
N3_IP = 0x2B

# ARP Table
arp_table = {
    # IP: MAC
    
    # Node2
    "0x2A": "N2",
    # Router
    "0x21": "R2"
}

# Port Table / the Peers we are sending to
# Have to ensure the MAC -> Port mapping is correct
port_table = {
    # MAC : Socket
    
    # Router
    "R2": 1530,
    # Node 2
    "N2": 1510
}

shutdown_event = threading.Event()
peers = [("127.0.0.1", 1510), ('127.0.0.1', 1530)]  # IP and port of node1 and node2

def handle_peer(sock):
    while not shutdown_event.is_set():
        try:
            frame, addr = sock.recvfrom(260)
            if frame:
                handle_frame(frame)
        except Exception as e:
            print(f"Error: {e}")
            break

def handle_frame(frame):
    """
    Handles a received Ethernet frame.

    :param frame: The received Ethernet frame as bytes.

    It extracts the source and destination MAC addresses, data length, and data from the frame.
    Data here can consist of the entire IP Packet or just message sent using Ethernet.
    If the Data is an IP Packet, it calls `handle_ip_packet` with the data.
    If not, it checks if the destination MAC address matches N3's MAC address and it will process to print out the message.
    Otherwise, it prints out the dropped frame's hex representation.
    """
    src_mac = frame[:2].decode()
    dst_mac = frame[2:4].decode()
    data_length = frame[4]
    # Ethernet Frame Data, the IP Packet is inside the Ethernet Frame
    # Consist of the entire IP Packet
    data = frame[5:]
    
    print(f"Received frame: {frame.hex()}, from {src_mac}, meant for {dst_mac}")
    
    # Check the first byte if it has '0x' in it
    checkIfIPPacket = hex(struct.unpack('B', data[0:1])[0]).upper()
    print(f"First Byte: {checkIfIPPacket}, Check if IP Packet: {checkIfIPPacket}")
    if checkIfIPPacket[:2] == '0X':
        # It is a IP Packet and let the IP Layer handle it
        print(f"IP Packet Detected")
        handle_ip_packet(data)
    else:
        # No IP Packet, continue with Ethernet Frame
        if dst_mac == N3_MAC:
            print(f"Received frame for me: {frame.hex()}, from {src_mac}, data lenght: {data_length}, message: {data[4:].decode()}")
        else:
            print(f"Dropped frame: {frame.hex()}")

def handle_ip_packet(packet):
    src_ip = hex(struct.unpack('B', packet[0:1])[0]).upper()
    print(f"src_ip: {src_ip}")
    dst_ip = hex(struct.unpack('B', packet[1:2])[0]).upper()
    print(f"dst_ip: {dst_ip}")
    # Only can return Protocol 0 - Ping
    protocol = packet[2]
    data_length = packet[3]
    data = packet[4:5+data_length]
    data = data.decode('utf-8')

    print(f"src_ip: {src_ip}, dst_ip: {dst_ip}, protocol: {protocol}, data_length: {data_length}, data: {data}")

    # Not working yet
    if dst_ip == N3_IP:
        if protocol == 0:  # Ping protocol
            reply_packet = bytes([dst_ip, src_ip, protocol, data_length]) + data
            send_ip_packet(reply_packet)

def send_ip_packet(dst_ip, message):
    """
    Sends an IP packet to a destination IP address.

    This function takes in a destination IP address and a message as arguments.
    It checks if the destination IP address is in the ARP table. If it is, it
    retrieves the destination MAC address from the ARP table and sends the IP
    packet to ethernet frame for processing. 
    If the destination IP address is not
    in the ARP table, it sets the destination MAC address to the router and
    sends the IP packet to ethernet frame for processing.

    Args:
        dst_ip (str): The destination IP address as a hexadecimal string.
        message (str): The message to be sent as a string.
    """
    # Check IP Addr against ARP Table
    if dst_ip in arp_table.keys():
        print(f"Destination IP found in ARP Table")
        dst_mac = arp_table[dst_ip]
        print(f"dst_mac: {dst_mac}")
        ipPacket = bytes([N3_IP, int(dst_ip, 16), 0, len(message)]) + message.encode() 
        send_ethernet_frame(dst_mac, ipPacket, True)
    else:
        # Set Destination MAC to Router
        print(f"Destination IP not found in ARP Table, sending to Router")
        dst_mac = "R2"
        ipPacket = bytes([N3_IP, int(dst_ip, 16), 0, len(message)]) + message.encode() 
        send_ethernet_frame(dst_mac, ipPacket, True)
    
    # frame = N2_MAC.encode() + dst_mac.encode() + bytes([len(packet)]) + packet
    # print(f"Sending frame: {frame.hex()}")
    # for peer in peers:
    #     sock.sendto(frame, peer)

def send_ethernet_frame(passedInMac, broadcast_message, fromSendIP):
    """
    Sends an Ethernet frame containing a broadcast message to a node with the
    specified MAC address.

    This function takes in a MAC address, a broadcast message, and a boolean as
    arguments. It checks if the boolean is True, if so it takes in the IP Packet, 
    gets the length of the entire message, and adds in the
    Source, Dest MAC and Data Length. If the boolean is False, it takes in the
    broadcast message, gets the MAC address from the ARP table, and adds in the
    Source, Dest MAC and Data Length.

    Args:
        passedInMac (str): The MAC address of the node to send the message to.
        broadcast_message (bytes): The message to be broadcasted to the node.
        fromSendIP (bool): A boolean indicating whether this function was called
            from the IP layer (True) or the Ethernet layer (False).
    """
     # Check if we are sending from IP or Ethernet
    if fromSendIP:
        # Count the DataLength
        dataLength = struct.unpack('!B', broadcast_message[3:4])[0]
        print(f"Data Length: {dataLength}")
        # Get the length of the entire message
        dataLength = int(dataLength)
        # Add in the Source, Dest MAC and Data Length
        etherFrame = N3_MAC.encode() + passedInMac.encode() + bytes([dataLength]) + broadcast_message
    else:
        for macAddr in arp_table.values(): 
            print(f"ARP Table MAC Address: {macAddr}")
            if passedInMac == macAddr:
                etherFrame = N3_MAC.encode() + macAddr.encode() + bytes([len(broadcast_message)]) + broadcast_message.encode()
        
    # Broadcast to all nodes
    for macAddr in port_table.keys():
        print(f"Sending Ethernet Frame to {macAddr} , Destination Port: {port_table[macAddr]} , Frame: {etherFrame}")
        sock.sendto(etherFrame, ("127.0.0.1", port_table[macAddr]))

def start_node():
    host = '127.0.0.1'
    port = 1511

    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    threading.Thread(target=handle_peer, args=(sock,)).start()

    print("Hello! Welcome to the chatroom.\n")
    print("Instructions:\n")
    print("  1. Type 'send <destination IP> <message>' to send a message to a specific node\n")
    print("  2. Type 'ethernet <destination MAC> <message>' to send a message to specified node\n")

    while not shutdown_event.is_set():
        userinput = input('> \n')
        if userinput.strip():
            if userinput.startswith("send"):
                _, dst_ip_str, message = userinput.split(" ", 2)
                send_ip_packet(dst_ip_str, message)
                # dst_ip = int(dst_ip_str, 16)
                # packet = bytes([N2_IP, dst_ip, 0, len(message)]) + message.encode()
                # print(packet)
                # send_ip_packet(packet)
            elif userinput.startswith("ethernet"):
                _, macAddr, broadcast_message = userinput.split(" ", 2)
                send_ethernet_frame(macAddr, broadcast_message, False)

    sock.close()

if __name__ == "__main__":
    try:
        start_node()
    except KeyboardInterrupt:
        print("Shutting down...")
        shutdown_event.set()