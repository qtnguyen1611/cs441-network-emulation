import socket
import threading

# Router's MAC addresses
R1_MAC = "R1"
R2_MAC = "R2"

# Router's IP addresses
R1_IP = 0x11
R2_IP = 0x21

shutdown_event = threading.Event()
peers = [("127.0.0.1", 1500), ("127.0.0.1", 1510), ("127.0.0.1", 1511)]  # IP and port of node1, node2, and node3

# ARP table mapping IP addresses to MAC addresses
arp_table = {
    R1_IP: R1_MAC,
    R2_IP: R2_MAC
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

def handle_frame(frame, interface):
    src_mac = frame[:2].decode()
    dst_mac = frame[2:4].decode()
    data_length = frame[4]
    data = frame[5:5+data_length]

    print(f"Received frame on {interface}: {frame.hex()}")

    if dst_mac == R1_MAC or dst_mac == R2_MAC:
        handle_ip_packet(data, interface)
    else:
        broadcast_frame(frame, interface)

def handle_ip_packet(packet, interface):
    src_ip = packet[0]
    dst_ip = packet[1]
    protocol = packet[2]
    data_length = packet[3]
    data = packet[4:4+data_length]

    print(f"Received IP packet on {interface}: {packet.hex()}")

    if dst_ip in arp_table:
        dst_mac = arp_table[dst_ip]
        if dst_mac == R1_MAC or dst_mac == R2_MAC:
            if protocol == 0:  # Ping protocol
                reply_packet = bytes([dst_ip, src_ip, protocol, data_length]) + data
                send_ip_packet(reply_packet, interface)
        else:
            send_ip_packet(packet, interface)
    else:
        print(f"Unknown destination IP: {dst_ip}")

def send_ip_packet(packet, interface):
    dst_ip = packet[1]
    dst_mac = arp_table[dst_ip]

    frame = dst_mac.encode() + interface.encode() + bytes([len(packet)]) + packet

    print(f"Sending frame on {interface}: {frame.hex()}")

    for peer in peers:
        sock.sendto(frame, peer)

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