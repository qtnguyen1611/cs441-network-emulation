import socket
import threading
from datalink import handle_ethernet_frame, form_ethernet_frame, handle_arp_packet, form_arp_frame
from network import handle_sniffed_ip_packet, form_ip_packet

# Declare global variables at the top of the script
requester_ip = None
requester_mac = None

# Attacker's MAC and IP addresses
attacker_MAC = "N4"
attacker_IP = "0x1C"

# ARP Table
arp_table = {
    # IP: MAC
    # Node2
    # "0x2A": "N2",
    # Node3
    # "0x2B": "N3",
    # Router
    # "0x21": "R2"
}

# Port Table / the Peers we are sending to
# Have to ensure the MAC -> Port mapping is correct
port_table = {
    # MAC : Socket
    # Node 2
    "N2":1510,
    # Router 2
    "R2": 1530,
    # Node 3
    "N3": 1511
}

# Handles the number of ping reply to a specific IP
pingReplyMap = {}

shutdown_event = threading.Event()

# Technically can be removed
peers = [("127.0.0.1", 1511), ('127.0.0.1', 1530)]  # IP and port of node1 and node3

ROUTER_IP = "0x21" # Store gateway IP
pending_messages = {} # Store the messages while arp is resolving
SAME_SUBNET_IPS = ["0x21", "0x2A", "0x2B"]  # Help decide if packet need to send to router 

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
            print(f"Error: {e}")
            break

# Function to add a message to the pending_messages dictionary
def add_pending_message(dst_ip, src_ip, msg_type, message):
    """
    Function to store messages that cannnot be sent out due to missing ARP records.
    Stored messages are sent out once ARP are resolve.
    """
    if dst_ip not in pending_messages:
        pending_messages[dst_ip] = []
    pending_messages[dst_ip].append((src_ip, msg_type, message))

def process_frame(frame):
    """
    Processes an Ethernet frame received from the socket.
    Ethernet frame may contain an IP packet or an ARP packet.
    
    Args:
        frame (bytes): The raw Ethernet frame data
    """
    decapsulation_result = handle_ethernet_frame(frame, attacker_MAC)
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
    
    Args:
        packet (bytes): The IP packet data
    """
    data = handle_sniffed_ip_packet(packet)
    if data:
        src_ip, dst_ip, protocol, msg_type, message = data
        process_protocol(dst_ip, src_ip, protocol, msg_type, message)

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
    if operation == 1 and target_ip == attacker_IP:
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
    ethernet_frame = form_arp_frame(2, attacker_MAC, attacker_IP, requester_mac, requester_ip)
    send_packet(ethernet_frame)

def send_gratitous_arp(requester_ip, requester_mac):
    """
    Sends an ARP reply to a node that requested our MAC address.
    
    Args:
        requester_mac (str): The MAC address of the requesting node
        requester_ip (str): The IP address of the requesting node
    """
    ethernet_frame = form_arp_frame(2, attacker_MAC, requester_ip, requester_mac, requester_ip)
    send_packet(ethernet_frame)

def send_pending_messages():
    """
    Send any pending messages stored in the pending_messages dictionary.
    This function iterates over all destination IPs and their corresponding messages,
    sends each message, and then clears the messages for that destination IP.
    """
    for dst_ip, messages in pending_messages.items():
        for src_ip, message_type, message in messages:
            print("--SEND PENDING MESSAGES--")
            print(f"Destination IP: {dst_ip}, Source IP: {src_ip}, Message: {message}")
            send_message(src_ip, dst_ip, message, message_type) # relaying message type
        # Clear all messages for destination IP after sending
        pending_messages[dst_ip] = []

def process_protocol(dst_ip, src_ip, protocol, msg_type, message):
    if protocol == 0:
        # no drop for ping as i am just forwarding
        send_message(src_ip, dst_ip, message, msg_type)
        
        
def send_message(src_ip, dst_ip, message, msg_type=0):
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
        # Modify the message to show modification done by the attacker
        ip_packet = form_ip_packet(src_ip, dst_ip, 0, msg_type, message + "HACK")
        ethernet_frame = form_ethernet_frame(attacker_MAC, target_mac, ip_packet, "IP")
        send_packet(ethernet_frame)
    else:
        # Need ARP for target
        add_pending_message(dst_ip, src_ip, msg_type, message)
        ethernet_frame = form_arp_frame(1, attacker_MAC, attacker_IP, "FF", target_ip) # attacker uses his own ip and mac for arp lookup request; which might result in duplicate
        send_packet(ethernet_frame)
        

def send_packet(ethernet_frame):
    # Broadcast to all nodes
    for macAddr in port_table.keys():
        print("--Sending Ethernet Frame--")
        print(f"Destination Mac: {macAddr} , Destination Port: {port_table[macAddr]} , Frame: {ethernet_frame.hex()}")
        sock.sendto(ethernet_frame, ("127.0.0.1", port_table[macAddr]))

def start_node():
    global requester_ip, requester_mac  # Declare them as global inside the function
    
    host = '127.0.0.1'
    port = 1512

    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    threading.Thread(target=handle_peer, args=(sock,)).start()

    print("Hello! Welcome to Attacker Node.\n")
    print("Instructions:\n")
    print("  1. Type 'send <destination IP> <message>' to send a message to a specific node\n")
    print("  2. Type 'ARP <target_ip> <FF/specific_mac>' to ARP poison. \n")
    print("     Example: ARP 0x2B FF will broadcast to everyone that attacker MAC address N4 will be associated to 0x2B.\n")
    print("     Example: ARP 0x2B N2 will ARP update N2 that attacker MAC address N4 will be associated to 0x2B.\n")

    while not shutdown_event.is_set():
        userinput = input('> \n')
        if userinput.strip():
            if userinput.startswith("send"):
                _, dst_ip_str, message = userinput.split(" ", 2)
                send_message(dst_ip_str, message)
            elif userinput.startswith("ARP"):
                print("ARP Poisoning...")
                # FORM GRATITOUS ARP PACKET AND SEND IT OUT
                _, requester_ip, requester_mac = userinput.split(" ", 2)
                send_gratitous_arp(requester_ip, requester_mac)
            else:
                print("Invalid command. Please try again.")

    sock.close()

if __name__ == "__main__":
    try:
        start_node()
    except KeyboardInterrupt:
        print("Shutting down...")
        shutdown_event.set()