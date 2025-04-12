import socket
import sys
import threading
from datalink import handle_ethernet_frame, form_ethernet_frame, handle_sniffed_ethernet_frame, handle_arp_packet, form_arp_frame
from network import handle_ip_packet, handle_sniffed_ip_packet, form_ip_packet
from firewall_node3 import check_firewall_rules, push_firewall_rule

firewall_status = False
sniffing_status = False

# Node3's MAC and IP addresses
N3_MAC = "N3"
N3_IP = "0x2B"

# ARP Table empty at the start
arp_table = {
    # IP: MAC
    
    # Node2
    # "0x2A": "N2",
    # Router
    # "0x21": "R2"
}

# Port Table / the Peers we are sending to
# Have to ensure the MAC -> Port mapping is correct
port_table = {
    # MAC : Socket
    
    # Router 2
    "R2": 1530,
    # Node 2
    "N2": 1510,
    # Attacker Node
    "N4" : 1512
    
}

# Handles the number of ping reply to a specific IP
pingReplyMap = {}

shutdown_event = threading.Event()
peers = [("127.0.0.1", 1510), ('127.0.0.1', 1530)]  # IP and port of node1 and node2

ROUTER_IP = "0x21" # Store gateway IP
pending_messages = {} # Store messages while arp is resolving
SAME_SUBNET_IPS =  ["0x21", "0x2A", "0x1C"] # Help decide if packet need to send to router 

def handle_peer(sock):
    """
    Handles a peer connection. This function is run in a separate thread and
    responsible for receiving Ethernet frames from the socket and passing them to
    functions to handle it.

    Args:
        sock (socket.socket): The socket object to receive frames from
    """
    while not shutdown_event.is_set():
        try:
            frame, addr = sock.recvfrom(260)
            if frame:
                process_frame(frame)
        except Exception as e:
            if not shutdown_event.is_set():
                print(f"Error: {e}")
            break

# Function to add a message to the pending_messages dictionary
def add_pending_message(dst_ip, src_ip, message):
    """
    Function to store messages that cannnot be sent out due to missing ARP records.
    Stored messages are sent out once ARP are resolve.
    """
    if dst_ip not in pending_messages:
        pending_messages[dst_ip] = []
    pending_messages[dst_ip].append((src_ip, message))

def process_frame(frame):
    """
    Processes an Ethernet frame received from the socket.
    Handles both sniffing mode and normal operation mode.
    
    Args:
        frame (bytes): The raw Ethernet frame data
    """
    if sniffing_status:
        process_sniffed_frame(frame)
    else:
        process_normal_frame(frame)

def process_sniffed_frame(frame):
    """
    Processes a frame in sniffing mode, extracting and displaying packet information
    without filtering by destination MAC.
    
    Args:
        frame (bytes): The raw Ethernet frame data
    """
    ip_packet = handle_sniffed_ethernet_frame(frame)
    data = handle_sniffed_ip_packet(ip_packet)
    src_ip, dst_ip, protocol, msg_type, message = data
    print(f"Packet Sniffed from: {src_ip} -> {dst_ip}, protocol: {protocol}, msg_type: {msg_type}, message: {message}")

def process_normal_frame(frame):
    """
    Processes a frame in normal operation mode, filtering by destination MAC.
    
    Args:
        frame (bytes): The raw Ethernet frame data
    """
    decapsulation_result = handle_ethernet_frame(frame, N3_MAC)
    if not decapsulation_result:
        return
        
    packet, packet_type = decapsulation_result
    if not packet:
        return
        
    if packet_type == "IP":
        process_ip_packet(packet)
    elif packet_type == "ARP":
        process_arp_packet(packet)

def process_ip_packet(packet):
    """
    Processes an IP packet extracted from an Ethernet frame.
    Applies firewall rules if firewall is enabled.
    
    Args:
        packet (bytes): The IP packet data
    """
    data = handle_ip_packet(packet, N3_IP)
    if not data:
        return
        
    src_ip, protocol, msg_type, message = data
    
    if firewall_status:
        process_with_firewall(src_ip, protocol, msg_type, message)
    else:
        process_without_firewall(src_ip, protocol, msg_type, message)

def process_arp_packet(packet):
    """
    Processes an ARP packet extracted from an Ethernet frame.
    Handles both ARP requests (operation=1) and replies (operation=2).
    
    Args:
        packet (bytes): The ARP packet data
    """
    data = handle_arp_packet(packet)
    if not data:
        return
        
    operation, sender_mac, sender_ip, target_mac, target_ip = data
    
    # Update ARP table regardless if request or reply
    update_arp_table(sender_ip, sender_mac)
    
    # Handle ARP request
    if operation == 1 and target_ip == N3_IP:
        send_arp_reply(sender_mac, sender_ip)
    # Handle ARP reply
    elif operation == 2:
        send_pending_messages()

def update_arp_table(ip, mac):
    """
    Updates the ARP table with a new IP-MAC mapping and prints the current table.
    
    Args:
        ip (str): The IP address
        mac (str): The MAC address
    """
    arp_table[ip] = mac
    print("--ARP Table contents--")
    for ip, mac in arp_table.items():
        print(f"IP: {ip}, MAC: {mac}")

def send_arp_reply(requester_mac, requester_ip):
    """
    Sends an ARP reply to a node that requested our MAC address.
    
    Args:
        requester_mac (str): The MAC address of the requesting node
        requester_ip (str): The IP address of the requesting node
    """
    ethernet_frame = form_arp_frame(2, N3_MAC, N3_IP, requester_mac, requester_ip)
    send_packet(ethernet_frame)

def send_pending_messages():
    """
    Send any pending messages stored in the pending_messages dictionary.
    This function iterates over all destination IPs and their corresponding messages,
    sends each message, and then clears the messages for that destination IP.
    """
    for dst_ip, messages in pending_messages.items():
        for src_ip, message in messages:
            print("--SEND PENDING MESSAGES--")
            print(f"Destination IP: {dst_ip}, Source IP: {src_ip}, Message: {message}")
            send_message(dst_ip, message)
        # Clear all messages for destination IP after sending
        pending_messages[dst_ip] = []

def process_with_firewall(src_ip, protocol, msg_type, message):
    action = check_firewall_rules(src_ip, N3_IP, protocol)
    if action == "allow":
        process_protocol(src_ip, protocol, msg_type, message)
    else:
        print(f"Dropped packet from {src_ip} : Firewall rule denied.")

def process_without_firewall(src_ip, protocol, msg_type, message):
    process_protocol(src_ip, protocol, msg_type, message)

def process_protocol(src_ip, protocol, msg_type, message):
    if protocol == 0:
        if msg_type == 0:
            send_message(src_ip, message, 8)
        else:
            print("Dropped packet: Maximum number of pings reached.")
        
def send_message(dst_ip, message, msg_type=0):
    """
    Sends an message to a destination IP address.
    
    This function takes in a destination IP address and a message as arguments.
    It check if the destination IP address is in the same subnet and decide if 
    the packet need to send to router.
    
    It then check if destination IP address is in the ARP table. If the router 
    IP address is not in the ARP table, it send arp request for router mac address.
    
    Message not send will be buffered into pending_messages

    It then passes the ethernet frame to send_packet to send the message.
    Args:
        dst_ip (str): The destination IP address as a string.
        message (str): The message to be sent as a string.
    """
    if dst_ip in SAME_SUBNET_IPS:
        # Direct routing - same subnet
        target_ip = dst_ip
    else:
        # Route through router
        target_ip = ROUTER_IP

    if target_ip in arp_table.keys():
        target_mac = arp_table[target_ip]
        ip_packet = form_ip_packet(N3_IP, dst_ip, 0, msg_type, message)
        ethernet_frame = form_ethernet_frame(N3_MAC, target_mac, ip_packet, "IP")
        send_packet(ethernet_frame)
    else:
        # Need ARP for target
        add_pending_message(dst_ip, N3_IP, message)
        ethernet_frame = form_arp_frame(1, N3_MAC, N3_IP, "FF", target_ip)
        send_packet(ethernet_frame)
        

def send_packet(ethernet_frame):
    # Broadcast to all nodes
    for macAddr in port_table.keys():
        print("--Sending Ethernet Frame--")
        print(f"Destination Mac: {macAddr}, Destination Port: {port_table[macAddr]} , Frame: {ethernet_frame.hex()}")
        sock.sendto(ethernet_frame, ("127.0.0.1", port_table[macAddr]))

def start_node():
    host = '127.0.0.1'
    port = 1511

    global sock
    global firewall_status
    global sniffing_status
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    threading.Thread(target=handle_peer, args=(sock,)).start()

    print("Hello! Welcome to Node 3.\n")
    print("Instructions:\n")
    print("  1. Type 'send <destination IP> <message>' to send a message to a specific node\n")
    print("  2. Type 'on firewall' to turn on firewall\n")
    print("  3. Type 'off firewall' to turn off firewall\n")
    print("  4. Type 'add firewall rule <source IP> <destination IP> <protocol> <action>' to add firewall rule (first rule is always default)\n")
    print("  5. Type 'start sniffing' to turn on sniffing\n")
    print("  6. Type 'stop sniffing' to turn off sniffing\n")

    while not shutdown_event.is_set():
        try:
            # Use sys.stdin.readline() instead of input()
            userinput = sys.stdin.readline().strip()
            if userinput:
                if userinput.startswith("send"):
                    _, dst_ip_str, message = userinput.split(" ", 2)
                    send_message(dst_ip_str, message, 0)
                elif userinput.startswith("on firewall"):
                    firewall_status = True
                    print("Firewall is now on.")
                elif userinput.startswith("off firewall"):
                    firewall_status = False
                    print("Firewall is now off.")
                elif userinput.startswith("add firewall rule"):
                    _, _, _, src_ip, dst_ip, protocol, action = userinput.split(" ", 6)
                    new_rule = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": int(protocol),
                        "action": action
                    }
                    push_firewall_rule(new_rule)
                    print(f"Firewall rule added: {new_rule}")
                elif userinput.startswith("start sniffing"):
                    sniffing_status = True
                    print("Sniffing started...")
                elif userinput.startswith("stop sniffing"):
                    sniffing_status = False
                    print("Sniffing stopped...")
                else:
                    print("Invalid command. Please try again.")
        except EOFError:
            break

    sock.close()

if __name__ == "__main__":
    try:
        start_node()
    except KeyboardInterrupt:
        print("Shutting down...")
        shutdown_event.set()
