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

# ARP Table
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

shutdown_event = threading.Event()
peers_r1 = [("127.0.0.1", 1500)]  # IP and port of node1
peers_r2 = [("127.0.0.1", 1510), ("127.0.0.1", 1511)]  # IP and port of node2, and node3
# ARP table mapping IP addresses to MAC addresses
interface_mapping = {
    # MAC : IP
    R1_MAC: R1_IP,
    R2_MAC: R2_IP
}

pending_messages = {} # Store the messages while arp is resolving
SAME_SUBNET_IPS = ["0x1A", "0x11", "0x21", "0x2A", "0x2B"]  # IPs that are directly reachable

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
def add_pending_message(dst_ip, src_ip, message):
    if dst_ip not in pending_messages:
        pending_messages[dst_ip] = []
    pending_messages[dst_ip].append((src_ip, message))
    
def process_frame(frame, interface):
    decapsulation_result = handle_ethernet_frame(frame, interface)
    if decapsulation_result:
        packet, type = decapsulation_result
        if packet:
            if type == "IP":
                data = router_handle_ip_packet(packet)
                if data:
                    src_ip, dst_ip, protocol, message = data
                    if dst_ip in arp_table.keys():
                        handle_known_destination(src_ip, dst_ip, protocol, message)
                    
                    # By default there is no destination IP in ARP Table
                    else:
                        # Check if ip address is valid ?
                        if dst_ip in SAME_SUBNET_IPS:
                            # Make the arp  request for the mac address of destination IP and store messsage in pending_messages
                            # Need ARP for destination
                            add_pending_message(dst_ip, src_ip, message)
                            if dst_ip == "0x1A":
                                ethernet_frame = form_arp_frame(1, R1_MAC, R1_IP, "FF", dst_ip)
                                broadcast_frame(ethernet_frame, R1_MAC)
                            else:
                                ethernet_frame = form_arp_frame(1, R2_MAC, R2_IP, "FF", dst_ip)
                                broadcast_frame(ethernet_frame, R2_MAC)
                        else:
                            print(f"Packet dropped, destination IP not in ARP Table {dst_ip}")
            elif type == "ARP":
                print("ARP packet is detected")
                data = handle_arp_packet(packet)
                if data:
                    operation, sender_mac, sender_ip, target_mac, target_ip = data
                    arp_table[sender_ip] = sender_mac # Update ARP table regardless if its a request or reply
                    # Print the arp_table for debugging
                    print("ARP Table contents:")
                    for ip, mac in arp_table.items():
                        print(f"IP: {ip}, MAC: {mac}")
                        
                    if operation == 1:
                        if target_ip == R1_IP:
                            # Send ARP reply in respond to sender ARP request
                            ethernet_frame = form_arp_frame(2, R1_MAC, R1_IP, sender_mac, sender_ip)
                            send_packet(ethernet_frame, interface)
                        elif target_ip == R2_IP:
                            # Send ARP reply in respond to sender ARP request
                            ethernet_frame = form_arp_frame(2, R2_MAC, R2_IP, sender_mac, sender_ip)
                            send_packet(ethernet_frame, interface)
                    elif operation == 2:  # ARP Reply
                        send_pending_messages()

def send_pending_messages():
    """
    Send any pending messages stored in the pending_messages dictionary.
    This function iterates over all destination IPs and their corresponding messages,
    sends each message, and then clears the messages for that destination IP.
    """
    print("send pending messages....")
    for dst_ip, messages in pending_messages.items():
        for src_ip, message in messages:
            print(f"Destination IP: {dst_ip}, Source IP: {src_ip}, Message: {message}")
            send_message(dst_ip, src_ip, message)
        # Clear all messages for destination IP after sending
        pending_messages[dst_ip] = []

def handle_known_destination(src_ip, dst_ip, protocol, message):
    print(f"Destination IP in ARP Table {dst_ip}")
    
    # Check which exit to use based on node to router mapping
    # Compare against arp_table and get the value
    dst_mac = arp_table[dst_ip]

    # Use this value to compare against key for nodes_to_router_mapping and get the value
    # This value is the exit interface to use
    new_interface = nodes_to_router_mapping[dst_mac]
    print(f"Interface to use: {new_interface} \n")

    # Forward the packet to the correct destination IP with the data
    if protocol == 0:
        send_message(src_ip, dst_ip, message)

def send_message(src_ip, dst_ip, message):
    """
    Forward a message to a destination IP address.
    
    This function takes in a destination IP address and a message as arguments.
    It check if the destination IP address is in the same subnet. If it is, it
    retrieves the destination MAC address from the ARP table and forms the ethernet
    frame with the IP packet. If the destination IP address is not in the ARP table,
    it send arp request for destination mac address.
    
    If the destination IP address is in different subnet, it check if router ip address 
    is in the ARP table. If the router IP address is not in the ARP table,
    it send arp request for router mac address.
    
    Message not send will be buffered into pending_messages

    It then passes the ethernet frame to send_packet to send the message.
    Args:
        dst_ip (str): The destination IP address as a string.
        message (str): The message to be sent as a string.
    """
    ip = R2_IP
    mac = R2_MAC
    if dst_ip == "0x1A":
        ip = R1_IP
        mac = R1_MAC
    print("the info: ", ip, mac)
    
    # Direct routing
    if dst_ip in arp_table.keys():
        dst_mac = arp_table[dst_ip]
        ip_packet = form_ip_packet(src_ip, dst_ip, 0, message)
        ethernet_frame = form_ethernet_frame(mac, dst_mac, ip_packet)
        send_packet(ethernet_frame, mac)
    else:
        # Need ARP for destination
        add_pending_message(dst_ip, src_ip, message)
        ethernet_frame = form_arp_frame(1, mac, ip, "FF", dst_ip)
        broadcast_frame(ethernet_frame, mac)

def send_packet(ethernet_frame, interface):
    # Broadcast to all nodes
    for nodesMac in nodes_to_router_mapping.keys():
        # Check the table for the correct exit port
        if nodes_to_router_mapping[nodesMac] == interface:
            print(f"Sending Ethernet Frame to {nodesMac} , Destination Port: {port_table[nodesMac]} , Frame: {ethernet_frame}")
            sock.sendto(ethernet_frame, ("127.0.0.1", port_table[nodesMac]))

# Not used atm
def broadcast_frame(frame, interface):
    print(f"Broadcasting frame on {interface}: {frame.hex()}")
    if interface == R1_MAC:
        for peer in peers_r1:
            sock.sendto(frame, peer)
    elif interface == R2_MAC:
        for peer in peers_r2:
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