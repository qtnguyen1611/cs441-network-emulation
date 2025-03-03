import socket
import threading
from datalink import handle_ethernet_frame, form_ethernet_frame
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

shutdown_event = threading.Event()
peers = [("127.0.0.1", 1500), ("127.0.0.1", 1510), ("127.0.0.1", 1511)]  # IP and port of node1, node2, and node3

# ARP table mapping IP addresses to MAC addresses
interface_mapping = {
    # MAC : IP
    R1_MAC: R1_IP,
    R2_MAC: R2_IP
}

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

def process_frame(frame, interface):
    ip_packet = handle_ethernet_frame(frame, interface)
    if ip_packet:
        data = router_handle_ip_packet(ip_packet)
        if data:
            src_ip, dst_ip, protocol, message = data
            if dst_ip in arp_table:
                handle_known_destination(src_ip, dst_ip, protocol, message)
            
            # No destination IP in ARP Table
            else:
                print(f"Packet dropped, destination IP not in ARP Table {dst_ip}")

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
        send_message(src_ip, dst_ip, message, new_interface)

def send_message(src_ip, dst_ip, message, newInterface):
    """
    Forwards a message to a destination IP address.

    This function takes in source and destination IP address, message and router's 
    interface as arguments. It checks if the destination IP address is in the ARP 
    table. If it is, it retrieves the destination MAC address from the ARP table and 
    forms the ethernet frame with the IP packet. If the destination IP address is not
    in the ARP table, it will drop the packet.

    It then passes the ethernet frame to send_packet to send the message.
    Args:
        dst_ip (str): The destination IP address as a string.
        message (str): The message to be sent as a string.
    """
    # Check IP Addr against ARP Table
    ip_packet = form_ip_packet(src_ip, dst_ip, 0, message)
    if dst_ip in arp_table.keys():
        dst_mac = arp_table[dst_ip]
        print(f"Destination IP found in ARP Table, dst_mac: {dst_mac} \n")
        ethernet_frame = form_ethernet_frame(newInterface, dst_mac, ip_packet)
        send_packet(ethernet_frame, newInterface)
        

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