import socket
import threading

# Node3's MAC and IP addresses
N3_MAC = "N3"
N3_IP = 0x2B

# ARP Table
arp_table = {
    # IP: MAC
    
    # Node2
    0x2A: "N2",
    # Router
    0x21: "R2"
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
    It prints out the frame's hex representation, destination MAC address, and message.
    If the destination MAC address matches N3's MAC address, it calls `handle_ip_packet` with the data.
    Otherwise, it prints out the dropped frame's hex representation.
    """
    src_mac = frame[:2].decode()
    dst_mac = frame[2:4].decode()
    data_length = frame[4]
    data = frame[5:5+data_length]

    print(f"Received frame: {frame.hex()}, from {src_mac}, meant for {dst_mac}")
    print(f"Message: {data.decode()}")

    if dst_mac == N3_MAC:
        print(f"Received frame for me: {frame.hex()}, from {src_mac}, message: {data.decode()}")
        # handle_ip_packet(data)
    else:
        print(f"Dropped frame: {frame.hex()}")

# To Fix
def handle_ip_packet(packet):
    src_ip = packet[0]
    dst_ip = packet[1]
    protocol = packet[2]
    data_length = packet[3]
    data = packet[4:4+data_length]

    print(f"Received IP packet: {packet.hex()}")

    if dst_ip == N3_IP:
        if protocol == 0:  # Ping protocol
            reply_packet = bytes([dst_ip, src_ip, protocol, data_length]) + data
            send_ip_packet(reply_packet)

def send_ip_packet(packet):
    frame = N3_MAC.encode() + "R2".encode() + bytes([len(packet)]) + packet
    print(f"Sending frame: {frame.hex()}")
    for peer in peers:
        sock.sendto(frame, peer)

def send_ethernet_frame(userEnteredMacAddr, broadcast_message):
    """
    Sends an Ethernet frame containing a broadcast message to a node with the
    specified MAC address.

    This function takes in a MAC address and a broadcast message as arguments. It
    checks if the MAC address is in the ARP table and encodes the message along
    with the necessary headers and sends it to the destination MAC address that
    is present in the port table.

    Args:
        userEnteredMacAddr (str): The MAC address of the node to send the message to.
        broadcast_message (str): The message to be broadcasted to the node.
    """
    for macAddr in arp_table.values(): 
        print(f"ARP Table MAC Address: {macAddr}")
        if userEnteredMacAddr == macAddr:
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
                dst_ip = int(dst_ip_str, 16)
                packet = bytes([N3_IP, dst_ip, 0, len(message)]) + message.encode()
                send_ip_packet(packet)
            elif userinput.startswith("ethernet"):
                _, macAddr, broadcast_message = userinput.split(" ", 2)
                send_ethernet_frame(macAddr, broadcast_message)

    sock.close()

if __name__ == "__main__":
    try:
        start_node()
    except KeyboardInterrupt:
        print("Shutting down...")
        shutdown_event.set()