import socket
import threading
from datalink import handle_ethernet_frame, form_ethernet_frame
from network import handle_ip_packet, form_ip_packet

# Node1's MAC and IP addresses
N1_MAC = "N1"
N1_IP = "0x1A"

# ARP Table
arp_table = {
    # IP: MAC
    
    # Router
    "0x11": "R1"
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

peers = [('127.0.0.1', 1520)]  # IP and port of node2 and node3

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
                ip_packet = handle_ethernet_frame(frame, N1_MAC)
                if ip_packet:
                    data = handle_ip_packet(ip_packet, N1_IP)
                    if data:
                        src_ip, protocol, message = data
                        if protocol == 0:
                            if src_ip not in pingReplyMap:
                                pingReplyMap[src_ip] = 1
                                send_message(src_ip, message)
                            else:
                                del pingReplyMap[src_ip]
                                print("Dropped packet: Maximum number of pings reached.")


        except Exception as e:
            print(f"Error: {e}")
            break

def send_message(dst_ip, message):
    """
    Sends an message to a destination IP address.

    This function takes in a destination IP address and a message as arguments.
    It checks if the destination IP address is in the ARP table. If it is, it
    retrieves the destination MAC address from the ARP table and forms the ethernet
    frame with the IP packet.
    If the destination IP address is not in the ARP table, it sets the destination 
    MAC address to the router and forms the ethernet frame with the IP packet.

    It then passes the ethernet frame to send_packet to send the message.
    Args:
        dst_ip (str): The destination IP address as a string.
        message (str): The message to be sent as a string.
    """
    # Check IP Addr against ARP Table
    ip_packet = form_ip_packet(N1_IP, dst_ip, 0, message)
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