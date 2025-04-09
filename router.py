import socket
import struct
import threading
from datalink import handle_ethernet_frame, form_ethernet_frame, handle_arp_packet, form_arp_frame
from network import router_handle_ip_packet, form_ip_packet

# Router's MAC addresses
R1_MAC = "R1"
R2_MAC = "R2"

# Router's IP addresses
R1_IP = "0x11"
R2_IP = "0x21"

# ARP Table empty by default
arp_table = {
    # IP: MAC
    
    # Node 1
    # "0x1A": "N1",
    
    # Node2
    # "0x2A": "N2",
    # Node3
    # "0x2B": "N3",
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

nodesIP_to_router_mapping = {
    # Nodes IP : Router MAC
    "0x1A": "R1",
    "0x2A": "R2",
    "0x2B": "R2"
}

shutdown_event = threading.Event()
peers_r1 = [("127.0.0.1", 1500)]  # IP and port of node1
peers_r2 = [("127.0.0.1", 1510), ("127.0.0.1", 1511)]  # IP and port of node2, and node3
# ARP table mapping IP addresses to MAC addresses
interface_mapping = {
    # MAC : IP
    R1_MAC: R1_IP,
    R2_MAC: R2_IP
}

# Store the messages while arp is resolving
pending_messages = {} 

# IPs that are directly reachable
SAME_SUBNET_IPS = ["0x1A", "0x11", "0x21", "0x2A", "0x2B"]  

def handle_peer(sock, interface):
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
                process_frame(frame, interface)
        except Exception as e:
            if not shutdown_event.is_set():
                print(f"Error: {e}")
            break
        
# Function to add a message to the pending_messages dictionary
def add_pending_message(dst_ip, src_ip, message, protocol):
    if dst_ip not in pending_messages:
        pending_messages[dst_ip] = []
    pending_messages[dst_ip].append((src_ip, message, protocol))

def update_arp_table(ip, mac):
    """Update ARP table with new IP-MAC mapping"""
    arp_table[ip] = mac
    print("--ARP Table contents--")
    for ip, mac in arp_table.items():
        print(f"IP: {ip}, MAC: {mac}")

def process_frame(frame, interface):
    """
        Processes an Ethernet frame received from the socket.
        Ethernet frame may contain an IP packet or an ARP packet.
    """
    decapsulation_result = handle_ethernet_frame(frame, interface)
    if not decapsulation_result:
        return
        
    packet, packet_type = decapsulation_result
    if not packet:
        return
        
    if packet_type == "IP":
        process_ip_packet(packet, interface)
    elif packet_type == "ARP":
        process_arp_packet(packet, interface)

def process_ip_packet(packet, interface):
    """
    Decapsulates the IP packet, and try to sends the message.
    """
    data = router_handle_ip_packet(packet)
    if not data:
        return
    src_ip, dst_ip, protocol, msg_type, message = data
    send_message(src_ip, dst_ip, protocol, message, msg_type)

def process_arp_packet(packet, interface):
    """
    Decapsulates the ARP packet.
    Check ARP request or reply. (operation == 1 for request, 2 for reply)
    If ARP request, send ARP reply.
    If ARP reply, check and try to send packet that previously couldn't be sent out due to missing ARP.
    """
    data = handle_arp_packet(packet)
    if not data:
        return
        
    operation, sender_mac, sender_ip, target_mac, target_ip = data
    update_arp_table(sender_ip, sender_mac)
    
    if operation == 1:
        handle_arp_request(target_ip, sender_mac, sender_ip, interface)
    elif operation == 2:
        send_pending_messages()

def handle_arp_request(target_ip, sender_mac, sender_ip, interface):
    """Handle ARP request by sending appropriate ARP reply"""
    if target_ip == R1_IP:
        ethernet_frame = form_arp_frame(2, R1_MAC, R1_IP, sender_mac, sender_ip)
        send_packet(ethernet_frame, interface)
    elif target_ip == R2_IP:
        ethernet_frame = form_arp_frame(2, R2_MAC, R2_IP, sender_mac, sender_ip)
        send_packet(ethernet_frame, interface)
    else:
        print("Invalid interface for ARP request")

def send_pending_messages():
    """
    Send any pending messages stored in the pending_messages dictionary.
    This function iterates over all destination IPs and their corresponding messages,
    Sends each message, and then clears the messages for that destination IP.
    """
    for dst_ip, messages in pending_messages.items():
        # Router MAC
        for src_ip, message, protocol in messages:
            print("--SEND PENDING MESSAGES--")
            print(f"Destination IP: {dst_ip}, Source IP: {src_ip}, Message: {message}")
            send_message(src_ip, dst_ip, protocol, message)
        # Clear all messages for destination IP after sending
        pending_messages[dst_ip] = []

def send_message(src_ip, dst_ip, protocol, message, msg_type=0):
    """
    Forward a message to a destination IP address.
    
    This function use destination IP address to determine the Router MAC address and IP address
    Next it check if we have the MAC address for destination IP address in the ARP table.
    If it does, it forms the ethernet frame with the IP packet. 
    If it doesn't, it sends an ARP request for the destination MAC address only if the destination IP address is in the same subnet.
    
    Args:
        src_ip (str): The source IP address as a string.
        dst_ip (str): The destination IP address as a string.
        protocol (int): The protocol number as an integer. (0 for ICMP)
        message (str): The message to be sent as a string.
    """
    routerMac = nodesIP_to_router_mapping[dst_ip]
    routerIP = interface_mapping[routerMac]

    if dst_ip in arp_table:
        if protocol == 0:
            print(f"--Destination IP in ARP Table {dst_ip}--")
            # Check which exit to use based on node to router mapping
            # Compare against arp_table and get the value
            dst_mac = arp_table[dst_ip]
            # Use this value to compare against key for nodes_to_router_mapping and get the value
            # This value is the exit interface to use
            print(f"Interface to use: {routerMac} \n")
            ip_packet = form_ip_packet(src_ip, dst_ip, 0, msg_type, message)
            ethernet_frame = form_ethernet_frame(routerMac, dst_mac, ip_packet, "IP")
            send_packet(ethernet_frame, routerMac)
    elif dst_ip in SAME_SUBNET_IPS:
        """Handle IP packets for destinations in the same subnet but not in ARP table"""
        add_pending_message(dst_ip, src_ip, message, protocol)
        ethernet_frame = form_arp_frame(1, routerMac, routerIP, "FF", dst_ip)
        send_packet(ethernet_frame, routerMac)    
    else:
        print(f"Packet dropped, destination IP not in ARP Table {dst_ip}")

def send_packet(ethernet_frame, interface):
    # Broadcast to all nodes
    for nodesMac in nodes_to_router_mapping.keys():
        # Check the table for the correct exit port
        if nodes_to_router_mapping[nodesMac] == interface:
            print("--Sending Ethernet Frame--")
            print(f"Destination Mac: {nodesMac} , Destination Port: {port_table[nodesMac]} , Frame: {ethernet_frame}")
            sock.sendto(ethernet_frame, ("127.0.0.1", port_table[nodesMac]))

# Not used atm
def broadcast_frame(frame, interface):
    print(f"Broadcasting frame on {interface}: {frame.hex()}")
    for peer in peers_r2 + peers_r1:
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
