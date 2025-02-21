import socket
import threading

# Node2's MAC and IP addresses
N2_MAC = "N2"
N2_IP = 0x2A

# ARP Table
arp_table = {
    # IP: MAC
    
    # Node3
    "0x2B": "N3",
    # Router
    "0x21": "R2"
}

# Port Table / the Peers we are sending to
# Have to ensure the MAC -> Port mapping is correct
port_table = {
    # MAC : Socket
    
    # Router
    "R2": 1530,
    # Node 3
    "N3": 1511
}

shutdown_event = threading.Event()

# Technically can be removed
peers = [("127.0.0.1", 1511), ('127.0.0.1', 1530)]  # IP and port of node1 and node3

def handle_peer(sock):
    """
    Handles a peer connection. This function is run in a separate thread and
    responsible for receiving Ethernet frames from the socket and passing them to
    handle_frame.

    Args:
        sock (socket.socket): The socket object to receive frames from
    """
    while not shutdown_event.is_set():
        try:
            frame, addr = sock.recvfrom(260)
            if frame:
                handle_frame(frame)
        except Exception as e:
            print(f"Error: {e}")
            break

def handle_frame(frame):
    src_mac = frame[:2].decode()
    dst_mac = frame[2:4].decode()
    data_length = frame[4]
    data = frame[5:5+data_length]

    print(f"Received frame: {frame.hex()}, from {src_mac}, meant for {dst_mac}")
    print(f"Message: {data.decode()}")

    if dst_mac == N2_MAC:
        print(f"Received frame for me: {frame.hex()}, from {src_mac}, data lenght: {data_length}, message: {data.decode()}")
        # handle_ip_packet(data)
    else:
        print(f"Dropped frame: {frame.hex()}")

def handle_ip_packet(packet):
    src_ip = packet[0]
    dst_ip = packet[1]
    protocol = packet[2]
    data_length = packet[3]
    data = packet[4:4+data_length]

    print(f"Received IP packet: {packet.hex()}")

    if dst_ip == N2_IP:
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
        ipPacket = bytes([N2_IP, int(dst_ip, 16), 0, len(message)]) + message.encode() 
        send_ethernet_frame(dst_mac, ipPacket, True)
    else:
        # Set Destination MAC to Router
        print(f"Destination IP not found in ARP Table, sending to Router")
        dst_mac = "R2"
        ipPacket = bytes([N2_IP, int(dst_ip, 16), 0, len(message)]) + message.encode() 
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
        # Decode and count the DataLength
        data_length = broadcast_message.decode()
        # Get the length of the entire message
        data_length = len(data_length)
        # Add in the Source, Dest MAC and Data Length
        etherFrame = N2_MAC.encode() + passedInMac.encode() + bytes([data_length]) + broadcast_message
    else:
        for macAddr in arp_table.values(): 
            print(f"ARP Table MAC Address: {macAddr}")
            if passedInMac == macAddr:
                etherFrame = N2_MAC.encode() + macAddr.encode() + bytes([len(broadcast_message)]) + broadcast_message.encode()
        
    # Broadcast to all nodes
    for macAddr in port_table.keys():
        print(f"Sending Ethernet Frame to {macAddr} , Destination Port: {port_table[macAddr]} , Frame: {etherFrame}")
        sock.sendto(etherFrame, ("127.0.0.1", port_table[macAddr]))

def start_node():
    host = '127.0.0.1'
    port = 1510

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