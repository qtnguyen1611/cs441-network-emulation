import sys
import unittest
import subprocess
import time

class TestNetworkIntegration(unittest.TestCase):
    def setUp(self):
        """Set up the router and nodes as subprocesses for each test."""
        self.processes = {}
        self.log_files = {}  # Track log files separately

        scripts = ["router.py", "node1.py", "node2.py", "node3.py", "attackerNode1.py"]

        for script in scripts:
            # Open log file in write mode (truncates existing file)
            log_file = open(f"{script}.log", "w")
            if sys.platform == "win32":
                process = subprocess.Popen(
                    ["python", "-u", script],
                    stdin=subprocess.PIPE,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            else:
                process = subprocess.Popen(
                    ["python3", "-u", script],
                    stdin=subprocess.PIPE,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            self.processes[script] = process
            self.log_files[script] = log_file  # Store reference to log file

        time.sleep(1)  # Allow processes to initialize

    def tearDown(self):
        """Terminate all subprocesses and close log files after each test."""
        # First terminate processes
        for script, process in self.processes.items():
            if process.poll() is None:
                # Close stdin if it's not closed already
                if process.stdin and not process.stdin.closed:
                    process.stdin.close()
                    
                # Terminate the process
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
        
        # Then close all log files
        for script, log_file in self.log_files.items():
            if not log_file.closed:
                log_file.close()
        
        # Clear references
        self.processes.clear()
        self.log_files.clear()

    def test_message_node1_to_node2(self):
        """Test sending a message from Node1 to Node2."""
        # Send a message from Node1 to Node2
        node1_process = self.processes["node1.py"]

        # Check if the process is still running
        if node1_process.poll() is not None:
            self.fail("Node1 process has terminated unexpectedly.")

        # Send the message from Node1
        node1_process.stdin.write("send 0x2A Hello, Node2!\n")
        node1_process.stdin.flush()

        # Allow time for the message to propagate
        time.sleep(1)

        # Verify the output in Node2's log
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2A, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node2!", node2_output, "Node2 did not receive the ping from Node1.")
            
        # Verify the output in Node1's log
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("src_ip: 0x2A, dst_ip: 0x1A, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node2!", node1_output, "Node1 did not get the ping reply from Node2.")
           

    def test_arp_poison_node2(self):
        """Test sending a ARP poison message from Attacker to Node2."""
        # Send a message from attacker to node 2
        attacker_process = self.processes["attackerNode1.py"]

        # Check if the process is still running
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")

        # Send ARP Poison message to Node2
        attacker_process.stdin.write("ARP 0x21 N2\n")
        attacker_process.stdin.flush()

        # Allow time for the message to propagate
        time.sleep(1)

        # Verify the output in Node2's log
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("IP: 0x21, MAC: N4", node2_output, "Node2 arp did not get poison.")
            
    def test_arp_poison_router(self):
        """Test sending a ARP poison message from Attacker to Router2."""
        # Send a message from attacker to node 2
        attacker_process = self.processes["attackerNode1.py"]

        # Check if the process is still running
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")

        # Send ARP Poison message to Node2
        attacker_process.stdin.write("ARP 0x2A R2\n")
        attacker_process.stdin.flush()

        # Allow time for the message to propagate
        time.sleep(1)

        # Verify the output in router2's log
        with open("router.py.log", "r") as router2_log:
            router2_output = router2_log.read()
            self.assertIn("IP: 0x2A, MAC: N4", router2_output, "Router2 arp did not get poison.")

    def test_mitm_attack_node1_to_node2(self):
        """Test the complete MITM attack sequence."""
        # Step 1: Test normal communication
        node1_process = self.processes["node1.py"]
        if node1_process.poll() is not None:
            self.fail("Node1 process has terminated unexpectedly.")
        node1_process.stdin.write("send 0x2A Hello, Node2!\n")
        node1_process.stdin.flush()
        time.sleep(1)

        # Verify normal communication
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2A, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node2!", node2_output, "Node2 did not receive the ping from Node1.")
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("src_ip: 0x2A, dst_ip: 0x1A, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node2!", node1_output, "Node1 did not get the ping reply from Node2.")

        # Step 2: ARP poison Node2
        attacker_process = self.processes["attackerNode1.py"]
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")
        attacker_process.stdin.write("ARP 0x21 N2\n")
        attacker_process.stdin.flush()
        time.sleep(1)
        
        # Verify Node2's poisoning
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("IP: 0x21, MAC: N4", node2_output, "Node2 arp did not get poison.")
        
        # Step 3: ARP poison Router
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")
        attacker_process.stdin.write("ARP 0x2A R2\n")
        attacker_process.stdin.flush()
        time.sleep(1)
        
        # Verify the output in Node2's log
        with open("router.py.log", "r") as router2_log:
            router2_output = router2_log.read()
            self.assertIn("IP: 0x2A, MAC: N4", router2_output, "Router2 arp did not get poison.")
            
        # Step 4: Test communication after ARP poisoning
        node1_process = self.processes["node1.py"]
        if node1_process.poll() is not None:
            self.fail("Node1 process has terminated unexpectedly.")
        node1_process.stdin.write("send 0x2A Hello, Node2!\n")
        node1_process.stdin.flush()
        time.sleep(1)

        # Step 5: Check attacker intercepted original message
        with open("attackerNode1.py.log", "r") as attacker_log:
            attacker_output = attacker_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2A, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node2!", attacker_output, "Attacker did not intercept or alter the message from Node1.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: N2, data length: 22, data: b'\\x1a*\\x00\\x00\\x11Hello, Node2!HACK'", attacker_output, "Attacker did not forward modified message to Node2.")
            self.assertIn("src_ip: 0x2A, dst_ip: 0x1A, protocol: 0, msg_type: 8, data_length: 17, data: Hello, Node2!HACK", attacker_output, "Attacker did not intercept the reply from Node2.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: R2, data length: 26, data: b'*\\x1a\\x00\\x08\\x15Hello, Node2!HACKHACK'", attacker_output, "Attacker did not forward modified reply to Node1.")

        # Node2 received modified data
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2A, protocol: 0, msg_type: 0, data_length: 17, data: Hello, Node2!HACK", node2_output, "Node2 did not receive the modified message from attacker.")

        # Node1 received modified reply
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("src_ip: 0x2A, dst_ip: 0x1A, protocol: 0, msg_type: 8, data_length: 21, data: Hello, Node2!HACKHACK", node1_output, "Node1 did not receive the modified reply from attacker.")

    def test_mitm_attack_node2_to_node1(self):
        """Test MITM attack when Node2 sends message to Node1."""
        # Step 1: Test normal communication
        node2_process = self.processes["node2.py"]
        if node2_process.poll() is not None:
            self.fail("Node2 process has terminated unexpectedly.")
        node2_process.stdin.write("send 0x1A Hello, Node1!\n")
        node2_process.stdin.flush()
        time.sleep(1)

        # Verify normal communication
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("src_ip: 0x2A, dst_ip: 0x1A, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node1!", node1_output, "Node1 did not receive the ping from Node2.")
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2A, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node1!", node2_output, "Node2 did not get the ping reply from Node1.")

        # Step 2: ARP poison Node2
        attacker_process = self.processes["attackerNode1.py"]
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")
        attacker_process.stdin.write("ARP 0x21 N2\n")
        attacker_process.stdin.flush()
        time.sleep(1)
        
        # Verify Node2's poisoning
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("IP: 0x21, MAC: N4", node2_output, "Node2 arp did not get poison.")
        
        # Step 3: ARP poison Router
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")
        attacker_process.stdin.write("ARP 0x2A R2\n")
        attacker_process.stdin.flush()
        time.sleep(1)
        
        # Verify the router received poison
        with open("router.py.log", "r") as router2_log:
            router2_output = router2_log.read()
            self.assertIn("IP: 0x2A, MAC: N4", router2_output, "Router2 arp did not get poison.")
            
        # Step 4: Test communication after ARP poisoning
        node2_process.stdin.write("send 0x1A Hello, Node1!\n")
        node2_process.stdin.flush()
        time.sleep(1)

        # Step 5: Check attacker intercepted original message
        with open("attackerNode1.py.log", "r") as attacker_log:
            attacker_output = attacker_log.read()
            self.assertIn("src_ip: 0x2A, dst_ip: 0x1A, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node1!", attacker_output, "Attacker did not intercept or alter the message from Node2.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: R2, data length: 22, data: b'*\\x1a\\x00\\x00\\x11Hello, Node1!HACK'", attacker_output, "Attacker did not forward modified message to Node1.")
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2A, protocol: 0, msg_type: 8, data_length: 17, data: Hello, Node1!HACK", attacker_output, "Attacker did not intercept the reply from Node1.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: N2, data length: 26, data: b'\\x1a*\\x00\\x08\\x15Hello, Node1!HACKHACK'", attacker_output, "Attacker did not forward modified reply to Node2.")

        # Node1 received modified data
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("src_ip: 0x2A, dst_ip: 0x1A, protocol: 0, msg_type: 0, data_length: 17, data: Hello, Node1!HACK", node1_output, "Node1 did not receive the modified message from attacker.")

        # Node2 received modified reply
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2A, protocol: 0, msg_type: 8, data_length: 21, data: Hello, Node1!HACKHACK", node2_output, "Node2 did not receive the modified reply from attacker.")

    def test_mitm_attack_node3_to_node1(self):
        """Test MITM attack when Node3 sends message to Node1."""
        # Step 1: Test normal communication
        node3_process = self.processes["node3.py"]
        if node3_process.poll() is not None:
            self.fail("Node3 process has terminated unexpectedly.")
        node3_process.stdin.write("send 0x1A Hello, Node1!\n")
        node3_process.stdin.flush()
        time.sleep(1)

        # Verify normal communication
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("src_ip: 0x2B, dst_ip: 0x1A, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node1!", node1_output, "Node1 did not receive the ping from Node3.")
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2B, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node1!", node3_output, "Node3 did not get the ping reply from Node1.")

        # Step 2: ARP poison Node3
        attacker_process = self.processes["attackerNode1.py"]
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")
        attacker_process.stdin.write("ARP 0x21 N3\n")
        attacker_process.stdin.flush()
        time.sleep(1)

        # Verify Node3's poisoning
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("IP: 0x21, MAC: N4", node3_output, "Node3 arp did not get poison.")

        # Step 3: ARP poison Router
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")
        attacker_process.stdin.write("ARP 0x2B R2\n")
        attacker_process.stdin.flush()
        time.sleep(1)

        # Verify the router received poison
        with open("router.py.log", "r") as router2_log:
            router2_output = router2_log.read()
            self.assertIn("IP: 0x2B, MAC: N4", router2_output, "Router2 arp did not get poison.")

        # Step 4: Test communication after ARP poisoning
        node3_process.stdin.write("send 0x1A Hello, Node1!\n")
        node3_process.stdin.flush()
        time.sleep(1)

        # Step 5: Check attacker intercepted original message
        with open("attackerNode1.py.log", "r") as attacker_log:
            attacker_output = attacker_log.read()
            self.assertIn("src_ip: 0x2B, dst_ip: 0x1A, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node1!", attacker_output, "Attacker did not intercept or alter the message from Node3.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: R2, data length: 22, data: b'+\\x1a\\x00\\x00\\x11Hello, Node1!HACK'", attacker_output, "Attacker did not forward modified message to Node1.")
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2B, protocol: 0, msg_type: 8, data_length: 17, data: Hello, Node1!HACK", attacker_output, "Attacker did not intercept the reply from Node1.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: N3, data length: 26, data: b'\\x1a+\\x00\\x08\\x15Hello, Node1!HACKHACK'", attacker_output, "Attacker did not forward modified reply to Node3.")

        # Node1 received modified data
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("src_ip: 0x2B, dst_ip: 0x1A, protocol: 0, msg_type: 0, data_length: 17, data: Hello, Node1!HACK", node1_output, "Node1 did not receive the modified message from attacker.")

        # Node3 received modified reply
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2B, protocol: 0, msg_type: 8, data_length: 21, data: Hello, Node1!HACKHACK", node3_output, "Node3 did not receive the modified reply from attacker.")

    def test_mitm_attack_node1_to_node3(self):
        """Test MITM attack when Node1 sends message to Node3."""
        # Step 1: Test normal communication
        node1_process = self.processes["node1.py"]
        if node1_process.poll() is not None:
            self.fail("Node1 process has terminated unexpectedly.")
        node1_process.stdin.write("send 0x2B Hello, Node3!\n")
        node1_process.stdin.flush()
        time.sleep(1)

        # Verify normal communication
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2B, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node3!", node3_output, "Node3 did not receive the ping from Node1.")
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("src_ip: 0x2B, dst_ip: 0x1A, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node3!", node1_output, "Node1 did not get the ping reply from Node3.")

        # Step 2: ARP poison Node3
        attacker_process = self.processes["attackerNode1.py"]
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")
        attacker_process.stdin.write("ARP 0x21 N3\n")
        attacker_process.stdin.flush()
        time.sleep(1)

        # Verify Node3's poisoning
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("IP: 0x21, MAC: N4", node3_output, "Node3 arp did not get poison.")

        # Step 3: ARP poison Router
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")
        attacker_process.stdin.write("ARP 0x2B R2\n")
        attacker_process.stdin.flush()
        time.sleep(1)

        # Verify the router received poison
        with open("router.py.log", "r") as router2_log:
            router2_output = router2_log.read()
            self.assertIn("IP: 0x2B, MAC: N4", router2_output, "Router2 arp did not get poison.")

        # Step 4: Test communication after ARP poisoning
        node1_process.stdin.write("send 0x2B Hello, Node3!\n")
        node1_process.stdin.flush()
        time.sleep(1)

        # Step 5: Check attacker intercepted original message
        with open("attackerNode1.py.log", "r") as attacker_log:
            attacker_output = attacker_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2B, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node3!", attacker_output, "Attacker did not intercept or alter the message from Node1.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: N3, data length: 22, data: b'\\x1a+\\x00\\x00\\x11Hello, Node3!HACK'", attacker_output, "Attacker did not forward modified message to Node3.")
            self.assertIn("src_ip: 0x2B, dst_ip: 0x1A, protocol: 0, msg_type: 8, data_length: 17, data: Hello, Node3!HACK", attacker_output, "Attacker did not intercept the reply from Node3.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: R2, data length: 26, data: b'+\\x1a\\x00\\x08\\x15Hello, Node3!HACKHACK'", attacker_output, "Attacker did not forward modified reply to Node1.")

        # Node3 received modified data
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2B, protocol: 0, msg_type: 0, data_length: 17, data: Hello, Node3!HACK", node3_output, "Node3 did not receive the modified message from attacker.")

        # Node1 received modified reply
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("src_ip: 0x2B, dst_ip: 0x1A, protocol: 0, msg_type: 8, data_length: 21, data: Hello, Node3!HACKHACK", node1_output, "Node1 did not receive the modified reply from attacker.")

    def test_mitm_attack_node2_to_node3(self):
        # Step 1: Test normal communication
        node2_process = self.processes["node2.py"]
        if node2_process.poll() is not None:
            self.fail("Node2 process has terminated unexpectedly.")
        node2_process.stdin.write("send 0x2B Hello, Node3!\n")
        node2_process.stdin.flush()
        time.sleep(1)
        # Verify normal communication
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("src_ip: 0x2A, dst_ip: 0x2B, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node3!", node3_output, "Node3 did not receive the ping from Node2.")
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("src_ip: 0x2B, dst_ip: 0x2A, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node3!", node2_output, "Node2 did not get the ping reply from Node3.")
        # Step 2: ARP poison Node2
        attacker_process = self.processes["attackerNode1.py"]
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")
        attacker_process.stdin.write("ARP 0x2B N2\n")
        attacker_process.stdin.flush()
        time.sleep(1)
        # Verify Node2's poisoning
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("IP: 0x2B, MAC: N4", node2_output, "Node2 arp did not get poison.")
        
        # Step 3: ARP poison Node3
        attacker_process = self.processes["attackerNode1.py"]
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")
        attacker_process.stdin.write("ARP 0x2A N3\n")
        attacker_process.stdin.flush()
        time.sleep(1)
        # Verify Node3's poisoning
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("IP: 0x2A, MAC: N4", node3_output, "Node3 arp did not get poison.")
            
        # Step 4: Test communication after ARP poisoning
        node2_process.stdin.write("send 0x2B Hello, Node3!\n")
        node2_process.stdin.flush()
        time.sleep(1)
        
        # Step 5: Check attacker intercepted original message
        with open("attackerNode1.py.log", "r") as attacker_log:
            attacker_output = attacker_log.read()
            self.assertIn("src_ip: 0x2A, dst_ip: 0x2B, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node3!", attacker_output, "Attacker did not intercept or alter the message from Node2.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: N3, data length: 22, data: b'*+\\x00\\x00\\x11Hello, Node3!HACK'", attacker_output, "Attacker did not forward modified message to Node3.")
            self.assertIn("src_ip: 0x2B, dst_ip: 0x2A, protocol: 0, msg_type: 8, data_length: 17, data: Hello, Node3!HACK", attacker_output, "Attacker did not intercept the reply from Node3.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: N2, data length: 26, data: b'+*\\x00\\x08\\x15Hello, Node3!HACKHACK'", attacker_output, "Attacker did not forward modified reply to Node2.")
        # Node2 received modified data
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("src_ip: 0x2B, dst_ip: 0x2A, protocol: 0, msg_type: 8, data_length: 21, data: Hello, Node3!HACKHACK", node2_output, "Node2 did not receive the modified message from attacker.")
        # Node3 received modified reply
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("src_ip: 0x2A, dst_ip: 0x2B, protocol: 0, msg_type: 0, data_length: 17, data: Hello, Node3!HACK", node3_output, "Node3 did not receive the modified reply from attacker.")

    def test_mitm_attack_node3_to_node2(self):
        # Step 1: Test normal communication
        node3_process = self.processes["node3.py"]
        if node3_process.poll() is not None:
            self.fail("Node3 process has terminated unexpectedly.")
        node3_process.stdin.write("send 0x2A Hello, Node2!\n")
        node3_process.stdin.flush()
        time.sleep(1)

        # Verify normal communication
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("src_ip: 0x2B, dst_ip: 0x2A, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node2!", node2_output, "Node2 did not receive the ping from Node3.")
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("src_ip: 0x2A, dst_ip: 0x2B, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node2!", node3_output, "Node3 did not get the ping reply from Node2.")

        # Step 2: ARP poison Node3
        attacker_process = self.processes["attackerNode1.py"]
        if attacker_process.poll() is not None:
            self.fail("Attacker process has terminated unexpectedly.")
        attacker_process.stdin.write("ARP 0x2A N3\n")
        attacker_process.stdin.flush()
        time.sleep(1)

        # Verify Node3's poisoning
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("IP: 0x2A, MAC: N4", node3_output, "Node3 arp did not get poison.")

        # Step 3: ARP poison Node2
        attacker_process.stdin.write("ARP 0x2B N2\n")
        attacker_process.stdin.flush()
        time.sleep(1)

        # Verify Node2's poisoning
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("IP: 0x2B, MAC: N4", node2_output, "Node2 arp did not get poison.")

        # Step 4: Test communication after ARP poisoning
        node3_process.stdin.write("send 0x2A Hello, Node2!\n")
        node3_process.stdin.flush()
        time.sleep(1)

        # Step 5: Check attacker intercepted original message
        with open("attackerNode1.py.log", "r") as attacker_log:
            attacker_output = attacker_log.read()
            self.assertIn("src_ip: 0x2B, dst_ip: 0x2A, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node2!", attacker_output, "Attacker did not intercept or alter the message from Node3.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: N2, data length: 22, data: b'+*\\x00\\x00\\x11Hello, Node2!HACK'", attacker_output, "Attacker did not forward modified message to Node2.")
            self.assertIn("src_ip: 0x2A, dst_ip: 0x2B, protocol: 0, msg_type: 8, data_length: 17, data: Hello, Node2!HACK", attacker_output, "Attacker did not intercept the reply from Node2.")
            self.assertIn("Forming Ethernet frame: src_mac: N4, dst_mac: N3, data length: 26, data: b'*+\\x00\\x08\\x15Hello, Node2!HACKHACK'", attacker_output, "Attacker did not forward modified reply to Node3.")

        # Node3 received modified data
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("src_ip: 0x2A, dst_ip: 0x2B, protocol: 0, msg_type: 8, data_length: 21, data: Hello, Node2!HACKHACK", node3_output, "Node3 did not receive the modified message from attacker.")
        
        # Node2 received modified reply
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("src_ip: 0x2B, dst_ip: 0x2A, protocol: 0, msg_type: 0, data_length: 17, data: Hello, Node2!HACK", node2_output, "Node2 did not receive the modified reply from attacker.")

if __name__ == "__main__":
    unittest.main()