import socket
import threading

# Router's MAC addresses
R1_MAC = "R1"
R2_MAC = "R2"

# Router's IP addresses
R1_IP = 0x11
R2_IP = 0x21

clients = []
clients_lock = threading.Lock()
arp_table = {
    0x1A: "N1",
    0x2A: "N2",
    0x2B: "N3",
    0x11: R1_MAC,
    0x21: R2_MAC
}

shutdown_event = threading.Event()

def handle_client(client_socket, client_address, interface):
    print(f"New connection from {client_address} on {interface}")
    with clients_lock:
        clients.append((client_socket, interface))

    while not shutdown_event.is_set():
        try:
            frame = client_socket.recv(260)
            if frame:
                handle_frame(frame, interface)
            else:
                break
        except Exception as e:
            print(f"Error: {e}")
            break

    print(f"Connection from {client_address} has been closed.")
    with clients_lock:
        clients.remove((client_socket, interface))
    client_socket.close()

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

    with clients_lock:
        for client_socket, client_interface in clients:
            if client_interface == interface:
                try:
                    client_socket.sendall(frame)
                except Exception as e:
                    print(f"Error: {e}")
                    client_socket.close()
                    clients.remove((client_socket, client_interface))

def broadcast_frame(frame, interface):
    print(f"Broadcasting frame on {interface}: {frame.hex()}")
    with clients_lock:
        for client_socket, client_interface in clients:
            if client_interface == interface:
                try:
                    client_socket.sendall(frame)
                except Exception as e:
                    print(f"Error: {e}")
                    client_socket.close()
                    clients.remove((client_socket, client_interface))

def start_router():
    R1_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    R2_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    R1_socket.bind(('127.0.0.1', 1500))
    R2_socket.bind(('127.0.0.1', 1510))
    R1_socket.listen(5)
    R2_socket.listen(5)
    print("Router 1 started on port 1500")
    print("Router 2 started on port 1510")

    def accept_connections(router_socket, interface):
        while not shutdown_event.is_set():
            try:
                client_socket, client_address = router_socket.accept()
                threading.Thread(target=handle_client, args=(client_socket, client_address, interface)).start()
            except Exception as e:
                print(f"Error accepting connections: {e}")
                break

    threading.Thread(target=accept_connections, args=(R1_socket, R1_MAC)).start()
    threading.Thread(target=accept_connections, args=(R2_socket, R2_MAC)).start()

if __name__ == "__main__":
    try:
        start_router()
        shutdown_event.wait()  # Wait for the shutdown event to be set
    except KeyboardInterrupt:
        print("Shutting down...")
        shutdown_event.set()