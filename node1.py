import socket
import threading

# Node1's MAC and IP addresses
N1_MAC = "N1"
N1_IP = 0x1A

shutdown_event = threading.Event()

def handle_client(client_socket):
    while not shutdown_event.is_set():
        try:
            frame = client_socket.recv(260)
            if frame:
                handle_frame(frame)
            else:
                break
        except Exception as e:
            print(f"Error: {e}")
            break

def handle_frame(frame):
    src_mac = frame[:2].decode()
    dst_mac = frame[2:4].decode()
    data_length = frame[4]
    data = frame[5:5+data_length]

    print(f"Received frame: {frame.hex()}")

    if dst_mac == N1_MAC:
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

    if dst_ip == N1_IP:
        if protocol == 0:  # Ping protocol
            reply_packet = bytes([dst_ip, src_ip, protocol, data_length]) + data
            send_ip_packet(reply_packet)

def send_ip_packet(packet):
    frame = N1_MAC.encode() + "R1".encode() + bytes([len(packet)]) + packet
    print(f"Sending frame: {frame.hex()}")
    s.sendall(frame)

def start_node():
    host = '127.0.0.1'
    port = 1500

    global s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    threading.Thread(target=handle_client, args=(s,)).start()

    print("Hello! Welcome to the chatroom.\n")
    print("Instructions:\n")
    print("  1. Type 'send <destination IP> <message>' to send a message to a specific node\n")

    while not shutdown_event.is_set():
        userinput = input('> \n')
        if userinput.strip():
            if userinput.startswith("send"):
                _, dst_ip_str, message = userinput.split(" ", 2)
                dst_ip = int(dst_ip_str, 16)
                packet = bytes([N1_IP, dst_ip, 0, len(message)]) + message.encode()
                send_ip_packet(packet)

    s.close()

if __name__ == "__main__":
    try:
        start_node()
    except KeyboardInterrupt:
        print("Shutting down...")
        shutdown_event.set()