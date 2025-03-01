import socket
import threading
from datalink import handle_ethernet_frame, form_ethernet_frame
from network import handle_ip_packet, form_ip_packet
from firewall_node3 import check_firewall_rules

firewall_status = False

# Node3's MAC and IP addresses
N3_MAC = "N3"
N3_IP = "0x2B"

# ARP Table
arp_table = {
    # IP: MAC
    
    # Node2
    "0x2A": "N2",
    # Router
    "0x21": "R2"
}

# Port Table / the Peers we are sending to
# Have to ensure the MAC -> Port mapping is correct
port_table = {
    # MAC : Socket
    
    # Router 2
    "R2": 1530,
    # Node 2
    "N2": 1510
}

# Handles the number of ping reply to a specific IP
pingReplyMap = {}

shutdown_event = threading.Event()
peers = [("127.0.0.1", 1510), ('127.0.0.1', 1530)]  # IP and port of node1 and node2

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
                ip_packet = handle_ethernet_frame(frame, N3_MAC)
                if ip_packet:
                    data = handle_ip_packet(ip_packet, N3_IP)
                    if data:
                        src_ip, protocol, message = data
                        if firewall_status:
                            action = check_firewall_rules(src_ip, N3_IP, protocol)
                            if action == "allow":
                                if protocol == 0:
                                    if src_ip not in pingReplyMap:
                                        pingReplyMap[src_ip] = 1
                                        send_message(src_ip, message)
                                    else:
                                        del pingReplyMap[src_ip]
                                        print("Dropped packet: Maximum number of pings reached.")
                            else:
                                print(f"Dropped packet from {src_ip} : Firewall rule denied.")
                        else:
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
    ip_packet = form_ip_packet(N3_IP, dst_ip, 0, message)
    if dst_ip in arp_table.keys():
        dst_mac = arp_table[dst_ip]
        print(f"Destination IP found in ARP Table, dst_mac: {dst_mac} \n")
        ethernet_frame = form_ethernet_frame(N3_MAC, dst_mac, ip_packet)
    else:
        # Set Destination MAC to Router
        print(f"Destination IP not found in ARP Table, sending to Router \n")
        dst_mac = "R2"
        ethernet_frame = form_ethernet_frame(N3_MAC, dst_mac, ip_packet)
    send_packet(ethernet_frame)
        

def send_packet(ethernet_frame):
    # Broadcast to all nodes
    for macAddr in port_table.keys():
        print(f"Sending Ethernet Frame to {macAddr} , Destination Port: {port_table[macAddr]} , Frame: {ethernet_frame.hex()}")
        sock.sendto(ethernet_frame, ("127.0.0.1", port_table[macAddr]))

def start_node():
    host = '127.0.0.1'
    port = 1511

    global sock
    global firewall_status
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    threading.Thread(target=handle_peer, args=(sock,)).start()

    print("Hello! Welcome to the chatroom.\n")
    print("Instructions:\n")
    print("  1. Type 'send <destination IP> <message>' to send a message to a specific node\n")
    print("  2. Type 'ethernet <destination MAC> <message>' to send a message to specified node\n")
    print("  3. Type 'on firewall' to turn on firewall\n")
    print("  4. Type 'off firewall' to turn off firewall\n")

    while not shutdown_event.is_set():
        userinput = input('> \n')
        if userinput.strip():
            if userinput.startswith("send"):
                _, dst_ip_str, message = userinput.split(" ", 2)
                send_message(dst_ip_str, message)
                # dst_ip = int(dst_ip_str, 16)
                # packet = bytes([N3_IP, dst_ip, 0, len(message)]) + message.encode()
                # print(packet)
                # send_ip_packet(packet)
            # elif userinput.startswith("ethernet"):
            #     _, macAddr, broadcast_message = userinput.split(" ", 2)
            #     send_ethernet_frame(macAddr, broadcast_message, False)
            elif userinput.startswith("on firewall"):
                firewall_status = True
                print("Firewall is now on.")
            elif userinput.startswith("off firewall"):
                firewall_status = False
                print("Firewall is now off.")

    sock.close()

if __name__ == "__main__":
    try:
        start_node()
    except KeyboardInterrupt:
        print("Shutting down...")
        shutdown_event.set()