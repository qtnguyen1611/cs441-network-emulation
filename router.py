import socket
import struct
import threading

# Router's MAC addresses
R1_MAC = "R1"
R2_MAC = "R2"

# Router's IP addresses
R1_IP = 0x11
R2_IP = 0x21

# ARP Table
arp_table = {
    # IP: MAC
    
    # Node 1
    "0x1A": "N1",
    
    # Node2
    "0x2A": "N2",
    # Node3
    "0x2B": "N3",
}

# Port Table / the Peers we are sending to
# Have to ensure the MAC -> Port mapping is correct
port_table = {
    # MAC : Socket
    
    # Node 1
    "N1": 1500,
    
    # Node 2
    "N2": 1510,
    
    # Node 3
    "N3": 1511
}

# Router to Nodes Mapping
# List which nodes are connected to which router port
nodes_to_router_mapping = {
    # Nodes MAC : Router MAC
    "N1": "R1",
    "N2": "R2",
    "N3": "R2"
}

# Handles the number of ping reply to a specific IP
pingReplyMap = {}

shutdown_event = threading.Event()
peers = [("127.0.0.1", 1500), ("127.0.0.1", 1510), ("127.0.0.1", 1511)]  # IP and port of node1, node2, and node3

# ARP table mapping IP addresses to MAC addresses
interface_mapping = {
    # MAC : IP
    R1_MAC: R1_IP,
    R2_MAC: R2_IP
}

def handle_peer(sock, interface):
    while not shutdown_event.is_set():
        try:
            frame, addr = sock.recvfrom(260)
            if frame:
                handle_frame(frame, interface)
        except Exception as e:
            print(f"Error: {e}")
            break

# Handles a received Ethernet frame.
def handle_frame(frame, interface):
    src_mac = frame[:2].decode()
    dst_mac = frame[2:4].decode()
    data_length = frame[4]
    # Ethernet Frame Data, the IP Packet is inside the Ethernet Frame
    # Consist of the entire IP Packet
    data = frame[5:]
    
    print("In handle_frame \n")
    print(f"Received frame: {frame.hex()}, from {src_mac}, meant for {dst_mac} on {interface}")
    
    '''
    Currently pinging router won't work will implement when have time
    '''
    
    # Check the first byte & second byte has '0x' in it 
    checkDestIP = '0x' + hex(struct.unpack('B', data[1:2])[0]).upper()[-2:]
    print(f"checkDestIP: {checkDestIP}")
    
    # Check if the packet is an IP Packet and the destination MAC is the Router's MAC
    if checkDestIP in arp_table.keys() and (dst_mac == R1_MAC or dst_mac == R2_MAC):
        print(f"IP Packet Detected \n")
        handle_ip_packet(data, interface)
    else:
        # No IP Packet, continue with Ethernet Frame
        if dst_mac == R1_MAC or dst_mac == R2_MAC:
            print(f"Received frame for me: {frame.hex()}, from {src_mac}, on {interface}, data lenght: {data_length}, message: {data[4:].decode()}")
        else:
            print(f"Dropped frame: {frame.hex()}")

# Handles a received IP packet.
def handle_ip_packet(packet, interface):
    src_ip = '0x' + hex(struct.unpack('B', packet[0:1])[0]).upper()[-2:]
    dst_ip = '0x' + hex(struct.unpack('B', packet[1:2])[0]).upper()[-2:]
    # Only can return Protocol 0 - Ping
    protocol = packet[2]
    data_length = packet[3]
    data = packet[4:5+data_length]
    data = data.decode('utf-8')

    print("In handle_ip_packet")
    print("Interface: ", interface)
    print(f"src_ip: {src_ip}, dst_ip: {dst_ip}, protocol: {protocol}, data_length: {data_length}, data: {data} \n")
    
    formattedR1IP = hex(R1_IP)
    formattedR2IP = hex(R2_IP)
    
    # Ping is meant for Router
    if dst_ip == formattedR1IP or dst_ip == formattedR2IP:
        # Perform Ping Reply
        pass
    # Ping is not meant for Router but the Dest IP is in the ARP Table
    elif dst_ip in arp_table:
        print(f"Destination IP in ARP Table {dst_ip}")
        # Check which exit to use
        if interface == "R1":
            newInterface = "R2"
        else:
            newInterface = "R1"
        # Exit interface to use
        print(f"Interface to use: {newInterface} \n")
            
        # Forward the packet to the correct destination IP with the data
        send_ip_packet(src_ip, dst_ip, data, newInterface)
    # No destination IP in ARP Table
    else:
        print(f"Packet dropped, destination IP not in ARP Table {dst_ip}")
        
    # src_ip = packet[0]
    # dst_ip = packet[1]
    # protocol = packet[2]
    # data_length = packet[3]
    # data = packet[4:4+data_length]

    # print(f"Received IP packet on {interface}: {packet.hex()}")

    # if dst_ip in arp_table:
    #     dst_mac = arp_table[dst_ip]
    #     if dst_mac == R1_MAC or dst_mac == R2_MAC:
    #         if protocol == 0:  # Ping protocol
    #             reply_packet = bytes([dst_ip, src_ip, protocol, data_length]) + data
    #             send_ip_packet(reply_packet, interface)
    #     else:
    #         send_ip_packet(packet, interface)
    # else:
    #     print(f"Unknown destination IP: {dst_ip}")

def send_ip_packet(src_ip, dst_ip, message, interface):
    print("In send_ip_packet")
    if dst_ip in arp_table:
        print(f"Destination IP found in ARP Table {dst_ip} \n")
        # MAC address of the destination IP
        dst_mac = arp_table[dst_ip]
        
        ipPacket = bytes([int(src_ip, 16), int(dst_ip, 16), 0, len(message)]) + message.encode()
        send_ethernet_frame(dst_mac, ipPacket, True, interface)
    else:
        print(f"Destination IP not found in ARP Table {dst_ip}, packet dropped \n")
     
    # dst_ip = packet[1]
    # dst_mac = arp_table[dst_ip]

    # frame = dst_mac.encode() + interface.encode() + bytes([len(packet)]) + packet

    # print(f"Sending frame on {interface}: {frame.hex()}")

    # for peer in peers:
    #     sock.sendto(frame, peer)

def send_ethernet_frame(passedInMac, broadcast_message, fromSendIP, interface):
     # Check if we are sending from IP or Ethernet
    """
    Constructs and sends an Ethernet frame to a specified MAC address.

    This function prepares an Ethernet frame using the provided MAC address, 
    broadcast message, and interface. 
    It determines whether the call originates 
    from the IP layer or the Ethernet layer, and constructs the frame 
    accordingly. 
    If the destination MAC address is in the ARP table, it sends 
    the frame to nodes on the appropriate interface.

    Args:
        passedInMac (str): The MAC address of the destination node.
        broadcast_message (bytes or str): The message to be included in the frame.
        fromSendIP (bool): Indicates if the function was called from the IP layer.
        interface (str): The interface through which the frame is to be sent.
    """
    print(f"Exit interface to use: {interface} \n")
    # Check if sending from IP or Ethernet
    if fromSendIP:
        # Count the DataLength
        dataLength = struct.unpack('!B', broadcast_message[3:4])[0]
        # Get the length of the entire message
        dataLength = int(dataLength)
        # Add in the Source, Dest MAC and Data Length
        if isinstance(broadcast_message, bytes):
            etherFrame = interface.encode() + passedInMac.encode() + bytes([len(broadcast_message)]) + broadcast_message
        else:
            etherFrame = interface.encode() + passedInMac.encode() + bytes([len(broadcast_message.encode())]) + broadcast_message.encode()
    else:
        # Sending of Ethernet Frame only from Ethernet Layer within any IP Packet
        for macAddr in arp_table.values(): 
            print(f"ARP Table MAC Address: {macAddr}")
            # Check if Dest MAC is in the ARP Table
            if passedInMac == macAddr:
                # Check dest Mac against nodes to router mapping key (e.g. N1, N2)
                if passedInMac in nodes_to_router_mapping.keys():
                    sourceMac = nodes_to_router_mapping[passedInMac]
                etherFrame = sourceMac.encode() + macAddr.encode() + bytes([len(broadcast_message.encode())]) + broadcast_message.encode()
    # Broadcast to nodes on the correct interface only
    for nodesMac in nodes_to_router_mapping.keys():
        # Check the table for the correct exit port
        if nodes_to_router_mapping[nodesMac] == interface:
            print(f"Sending Ethernet Frame to {nodesMac} , Destination Port: {port_table[nodesMac]} , Frame: {etherFrame}")
            sock.sendto(etherFrame, ("127.0.0.1", port_table[nodesMac]))

# Not used atm
def broadcast_frame(frame, interface):
    print(f"Broadcasting frame on {interface}: {frame.hex()}")
    for peer in peers:
        sock.sendto(frame, peer)

def start_router():
    host = '127.0.0.1'
    port1 = 1520
    port2 = 1530

    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port1))

    threading.Thread(target=handle_peer, args=(sock, R1_MAC)).start()

    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock2.bind((host, port2))

    threading.Thread(target=handle_peer, args=(sock2, R2_MAC)).start()

    print("Router started on ports 1520 and 1530")

if __name__ == "__main__":
    try:
        start_router()
        shutdown_event.wait()  # Wait for the shutdown event to be set
    except KeyboardInterrupt:
        print("Shutting down...")
        shutdown_event.set()