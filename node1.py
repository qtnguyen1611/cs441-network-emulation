import socket
import struct
import threading
from datalink import handle_ethernet_frame, form_ethernet_frame, handle_arp_packet, form_arp_frame
from network import handle_ip_packet, form_ip_packet

# Node1's MAC and IP addresses
N1_MAC = "N1"
N1_IP = "0x1A"

# ARP Table empty at the start
arp_table = {
    # IP: MAC
    
    # Router
    # "0x11": "R1"
}

# Port Table / the Peers we are sending to
# Have to ensure the MAC -> Port mapping is correct
port_table = {
    # MAC : Socket
    
    # Router 1
    "R1": 1520
}

# Handles the number of ping reply to a specific IP
pingReplyMap = {}

shutdown_event = threading.Event()

peers = [('127.0.0.1', 1520)]  # IP and port of router

ROUTER_IP = "0x11" # Store gateway IP
pending_messages = {} # Store messages while arp is resolving
SAME_SUBNET_IPS = ["0x11"]  # Help decide if packet need to send to router 

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
        Ethernet frame may contain an IP packet or an ARP packet.
        ARP packet can be a request (operation = 1) or reply (operation = 2)
    """
    decapsulation_result = handle_ethernet_frame(frame, N1_MAC)
    if decapsulation_result:
        packet, type = decapsulation_result
        if packet:
            if type == "IP":
                data = handle_ip_packet(packet, N1_IP)
                if data:
                    src_ip, protocol, message = data
                    process_protocol(src_ip, protocol, message)
            elif type == "ARP":
                data = handle_arp_packet(packet)
                if data:
                    operation, sender_mac, sender_ip, target_mac, target_ip = data
                    # Update ARP table regardless if request or reply
                    arp_table[sender_ip] = sender_mac
                    print("ARP Table contents:")
                    for ip, mac in arp_table.items():
                        print(f"IP: {ip}, MAC: {mac}")
                    
                    # Send ARP reply in respond to ARP request or send pending messages upon receiving ARP reply
                    if operation == 1:
                        if target_ip == N1_IP:
                            ethernet_frame = form_arp_frame(2, N1_MAC, N1_IP, sender_mac, sender_ip)
                            send_packet(ethernet_frame)
                    elif operation == 2:
                        send_pending_messages()

def send_pending_messages():
    """
    Send any pending messages stored in the pending_messages dictionary.
    This function iterates over all destination IPs and their corresponding messages,
    sends each message, and then clears the messages for that destination IP.
    """
    for dst_ip, messages in pending_messages.items():
        for src_ip, message in messages:
            print(f"Destination IP: {dst_ip}, Source IP: {src_ip}, Message: {message}")
            send_message(dst_ip, message)
        # Clear all messages for destination IP after sending
        pending_messages[dst_ip] = []

def process_protocol(src_ip, protocol, message):
    if protocol == 0:
        if src_ip not in pingReplyMap:
            pingReplyMap[src_ip] = 1
            send_message(src_ip, message)
        else:
            del pingReplyMap[src_ip]
            print("Dropped packet: Maximum number of pings reached.")

def send_message(dst_ip, message):
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
        ip_packet = form_ip_packet(N1_IP, dst_ip, 0, message)
        ethernet_frame = form_ethernet_frame(N1_MAC, target_mac, ip_packet)
        send_packet(ethernet_frame)
    else:
        # Need ARP for target
        add_pending_message(dst_ip, N1_IP, message)
        ethernet_frame = form_arp_frame(1, N1_MAC, N1_IP, "FF", target_ip)
        send_packet(ethernet_frame)

def send_packet(ethernet_frame):
    # Broadcast to all nodes
    for macAddr in port_table.keys():
        print(f"Sending Ethernet Frame to {macAddr} , Destination Port: {port_table[macAddr]} , Frame: {ethernet_frame.hex()}")
        sock.sendto(ethernet_frame, ("127.0.0.1", port_table[macAddr]))

def send_spoofed_packet(src_ip, dst_ip, message):
    """
    Sends an message to a destination IP address with the spoofed source IP.

    This function takes in source and destination IP address and a message as arguments.
    It checks if the destination IP address is in the ARP table. If it is, it
    retrieves the destination MAC address from the ARP table and forms the ethernet
    frame with the IP packet.
    If the destination IP address is not in the ARP table, it sets the destination 
    MAC address to the router and forms the ethernet frame with the IP packet.

    It then passes the ethernet frame to send_packet to send the message.
    Args:
        dst_ip (str): The destination IP address as a hexadecimal string.
        message (str): The message to be sent as a string.
    """
    # Check IP Addr against ARP Table
    ip_packet = form_ip_packet(src_ip, dst_ip, 0, message)
    if dst_ip in arp_table.keys():
        dst_mac = arp_table[dst_ip]
        print(f"Destination IP found in ARP Table, dst_mac: {dst_mac} \n")
        ethernet_frame = form_ethernet_frame(N1_MAC, dst_mac, ip_packet)
    else:
        # Set Destination MAC to Router
        print(f"Destination IP not found in ARP Table, sending to Router \n")
        dst_mac = "R1"
        ethernet_frame = form_ethernet_frame(N1_MAC, dst_mac, ip_packet)
    send_packet(ethernet_frame)

def start_node():
    host = '127.0.0.1'
    port = 1500

    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    threading.Thread(target=handle_peer, args=(sock,)).start()

    print("Hello! Welcome to Node 1.\n")
    print("Instructions:\n")
    print("  1. Type 'send <destination IP> <message>' to send a message to a specific node\n")
    print("  2. Type 'spoof <source IP> <destination IP> <message>' to send a message to specified node\n")

    while not shutdown_event.is_set():
        userinput = input('> \n')
        if userinput.strip():
            if userinput.startswith("send"):
                _, dst_ip_str, message = userinput.split(" ", 2)
                send_message(dst_ip_str, message)
            elif userinput.startswith("spoof"):
                _, src_ip_str, dst_ip_str, message = userinput.split(" ", 3)
                send_spoofed_packet(src_ip_str, dst_ip_str, message)
            else:
                print("Invalid command. Please try again.")


    sock.close()

if __name__ == "__main__":
    try:
        start_node()
    except KeyboardInterrupt:
        print("Shutting down...")
        shutdown_event.set()