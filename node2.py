import socket
import threading

# Node2's MAC and IP addresses
N2_MAC = "N2"
N2_IP = 0x2A

# ARP Table
arp_table = {
    # IP: MAC
    
    # Node3
    0x2B: "N3",
    # Router
    0x21: "R2"
}

shutdown_event = threading.Event()
peers = [("127.0.0.1", 1511), ('127.0.0.1', 1530)]  # IP and port of node1 and node3

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
    src_mac = frame[:2].decode()
    dst_mac = frame[2:4].decode()
    data_length = frame[4]
    data = frame[5:5+data_length]

    print(f"Received frame: {frame.hex()}")

    if dst_mac == N2_MAC:
        handle_ip_packet(data)
    else:
        print(f"Dropped frame: {frame.hex()}")

def handle_ip_packet(packet):
    src_ip = packet[0]
    dst_ip = packet[1]
    protocol = packet[2]
    data_length = packet[3]
    data = packet[4:4+data_length]

    print(f"Received IP packet: {packet.hex()}")

    if dst_ip == N2_IP:
        if protocol == 0:  # Ping protocol
            reply_packet = bytes([dst_ip, src_ip, protocol, data_length]) + data
            send_ip_packet(reply_packet)

def send_ip_packet(packet):
    # Check IP Addr against ARP Table
    dst_ip = packet[1]
    if dst_ip in arp_table:
        dst_mac = arp_table[dst_ip]
    else:
        dst_mac = "R2"
        return
    
    frame = N2_MAC.encode() + dst_mac.encode() + bytes([len(packet)]) + packet
    print(f"Sending frame: {frame.hex()}")
    for peer in peers:
        sock.sendto(frame, peer)

def start_node():
    host = '127.0.0.1'
    port = 1510

    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    threading.Thread(target=handle_peer, args=(sock,)).start()

    print("Hello! Welcome to the chatroom.\n")
    print("Instructions:\n")
    print("  1. Type 'send <destination IP> <message>' to send a message to a specific node\n")

    while not shutdown_event.is_set():
        userinput = input('> \n')
        if userinput.strip():
            if userinput.startswith("send"):
                _, dst_ip_str, message = userinput.split(" ", 2)
                dst_ip = int(dst_ip_str, 16)
                packet = bytes([N2_IP, dst_ip, 0, len(message)]) + message.encode()
                print(packet)
                send_ip_packet(packet)

    sock.close()

if __name__ == "__main__":
    try:
        start_node()
    except KeyboardInterrupt:
        print("Shutting down...")
        shutdown_event.set()