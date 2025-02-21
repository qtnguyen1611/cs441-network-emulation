import socket
import struct
import threading

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
    R1_IP: R1_MAC,
    R2_IP: R2_MAC
}

port_table = {
    # MAC : Socket
    
    # Router
    "R1": 1520,
    "R2": 1530,
    # Node 2
    "N1": 1500,
    "N2": 1510,
    "N3": 1511
}

shutdown_event = threading.Event()
peers = [("127.0.0.1", 1500), ("127.0.0.1", 1510), ("127.0.0.1", 1511)]  # IP and port of node1, node2, and node3

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
    data = frame[5:]

    print(f"Received frame on {interface}: {frame.hex()}")

    if dst_mac == R1_MAC or dst_mac == R2_MAC:
        print(f"Received frame for me on {interface}: {frame.hex()}")
        handle_ip_packet(data, interface)
    else:
        # do nothing
        print(f"Dropped frame on {interface}: {frame.hex()}")
        pass
        # broadcast_frame(frame, interface)

def handle_ip_packet(packet, interface):
    src_ip = '0x' + hex(struct.unpack('B', packet[0:1])[0]).upper()[-2:]
    dst_ip = '0x' + hex(struct.unpack('B', packet[1:2])[0]).upper()[-2:]
    protocol = packet[2]
    data_length = packet[3]
    type = -1
    if(protocol == 0):
        print("Protocol is 0")
        type = packet[4]
        print("type is ", type)
        data = packet[5:6+data_length]
        data = data.decode('utf-8')
    else:
        data = packet[4:5+data_length]
        data = data.decode('utf-8')

    print(f"Received IP packet on {interface}: {packet.hex()}")

    if dst_ip in arp_table:
        dst_mac = arp_table[dst_ip]
        if dst_mac == R1_MAC or dst_mac == R2_MAC:
            if protocol == 0:  # Ping protocol
                reply_packet = bytes([dst_ip, src_ip, protocol, data_length]) + data
                send_ip_packet(reply_packet, interface, True)
        else:
            send_ip_packet(packet, interface, True)
    else:
        print(f"Unknown destination IP: {dst_ip}")

def send_ip_packet(packet, interface, fromSendIP):
    dst_ip = '0x' + hex(struct.unpack('B', packet[1:2])[0]).upper()[-2:]
    print(dst_ip)
    dst_mac = arp_table[dst_ip]
     # Check if we are sending from IP or Ethernet
    if fromSendIP:
        # Count the DataLength
        dataLength = struct.unpack('!B', packet[4:5])[0]
        print(f"Data Length: {dataLength}")
        # Get the length of the entire message
        dataLength = int(dataLength)
        # Add in the Source, Dest MAC and Data Length
        etherFrame = interface.encode() + dst_mac.encode() + bytes([dataLength]) + packet
    else:
        for macAddr in arp_table.values(): 
            print(f"ARP Table MAC Address: {macAddr}")
            if dst_mac == macAddr:
                etherFrame = interface.encode() + macAddr.encode() + bytes([len(packet)]) + packet.encode()
        

    # for peer in peers:
    #     sock.sendto(frame, peer)
    if dst_mac in port_table:
        port = port_table[dst_mac]
        print(f"Port for {dst_mac}: {port}")
        sock.sendto(etherFrame, ("127.0.0.1", port))
    else:
        print(f"Key {dst_mac} not found in port_table")

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