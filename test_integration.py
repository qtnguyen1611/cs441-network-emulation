import os
import sys
import unittest
import subprocess
import time

class TestNetworkIntegration(unittest.TestCase):
    def setUp(self):
        """Set up the router and nodes as subprocesses for each test."""
        self.processes = {}
        self.log_files = {}  # Track log files separately

        scripts = ["router.py", "node1.py", "node2.py", "node3.py"]

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
            self.assertIn("Hello, Node2!", node2_output, "Node2 did not receive the expected message.")
            self.assertIn("IP Address matches, processing IP Packet", node2_output, "Node2 did not process the IP packet.")
            self.assertIn("Destination Mac: R2 , Destination Port: 1530 , Frame: 4e32523212002a1a00080d48656c6c6f2c204e6f64653221", node2_output, "Node2 did not send the ethernet frame to router.")
            self.assertIn("Destination Mac: N3 , Destination Port: 1511 , Frame: 4e32523212002a1a00080d48656c6c6f2c204e6f64653221", node2_output, "Node2 did not send the ethernet frame node 3.")
        
        # Verify the output in Node1's log
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("Destination IP: 0x2A, Source IP: 0x1A, Message: Hello, Node2!", node1_output, "Node1 did not send the message.")
            self.assertIn("src_ip: 0x2A, dst_ip: 0x1A, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node2! ", node1_output, "Node1 did not receive ping back from node2.")
            self.assertIn("Dropped packet: Maximum number of pings reached.", node1_output, "Node1 did not drop endless ping.")
        
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("MAC addresses not matched. Dropped frame: 4e32523212002a1a00080d48656c6c6f2c204e6f64653221", node3_output, "Node3 did not drop packet.")

        with open("router.py.log", "r") as router_log:
            router_output = router_log.read()
            self.assertIn("Received frame: 4e31523112001a2a00000d48656c6c6f2c204e6f64653221, from N1", router_output, "Router did not receive packet from node1.")

    def test_message_node2_to_node3(self):
        """Test sending a message from Node2 to Node3."""
        node2_process = self.processes["node2.py"]

        # Check if the process is still running
        if node2_process.poll() is not None:
            self.fail("Node2 process has terminated unexpectedly.")

        # Send the message from Node2 to Node3
        node2_process.stdin.write("send 0x2B Hello, Node3!\n")
        node2_process.stdin.flush()

        # Allow time for the message to propagate
        time.sleep(1)

        # Verify the output in Node3's log
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("Hello, Node3!", node3_output, "Node3 did not receive the expected message.")
            self.assertIn("IP Address matches, processing IP Packet", node3_output, "Node3 did not process the IP packet.")
            self.assertIn("Destination Mac: R2, Destination Port: 1530 , Frame: 4e334e3212002b2a00080d48656c6c6f2c204e6f64653321", node3_output, "Node3 did not send the ethernet frame to router.")
            self.assertIn("Destination Mac: N2, Destination Port: 1510 , Frame: 4e334e3212002b2a00080d48656c6c6f2c204e6f64653321", node3_output, "Node3 did not send the ethernet frame node 2.")
        
        # Verify the output in Node2's log
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("Destination IP: 0x2B, Source IP: 0x2A, Message: Hello, Node3!", node2_output, "Node2 did not send the message.")
            self.assertIn("src_ip: 0x2B, dst_ip: 0x2A, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node3! ", node2_output, "Node2 did not receive ping back from node3.")
            self.assertIn("Dropped packet: Maximum number of pings reached.", node2_output, "Node2 did not drop endless ping.")

    def test_sniff_message_node1_to_node2(self):
        """Test sending a message from Node1 to Node2."""
        node1_process = self.processes["node1.py"]
        node3_process = self.processes["node3.py"]

        # Check if the process is still running
        if node1_process.poll() is not None:
            self.fail("Node1 process has terminated unexpectedly.")

        # Setup sniffing in Node3
        node3_process.stdin.write("start sniffing\n")
        node3_process.stdin.flush()

        # Send the message from Node1
        node1_process.stdin.write("send 0x2A Hello, Node2!\n")
        node1_process.stdin.flush()

        # Allow time for the message to propagate
        time.sleep(1)

        # Verify the output in Node2's log
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("Hello, Node2!", node2_output, "Node2 did not receive the expected message.")
            self.assertIn("IP Address matches, processing IP Packet", node2_output, "Node2 did not process the IP packet.")
            self.assertIn("Destination Mac: R2 , Destination Port: 1530 , Frame: 4e32523212002a1a00080d48656c6c6f2c204e6f64653221", node2_output, "Node2 did not send the ethernet frame to router.")
            self.assertIn("Destination Mac: N3 , Destination Port: 1511 , Frame: 4e32523212002a1a00080d48656c6c6f2c204e6f64653221", node2_output, "Node2 did not send the ethernet frame node 3.")
        
        # Verify the output in Node1's log
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("Destination IP: 0x2A, Source IP: 0x1A, Message: Hello, Node2!", node1_output, "Node1 did not send the message.")
            self.assertIn("src_ip: 0x2A, dst_ip: 0x1A, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node2! ", node1_output, "Node1 did not receive ping back from node2.")
            self.assertIn("Dropped packet: Maximum number of pings reached.", node1_output, "Node1 did not drop endless ping.")
        
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("src_ip: 0x1A, dst_ip: 0x2A, protocol: 0, msg_type: 0, data_length: 13, data: Hello, Node2! ", node3_output, "Node3 did not sniff packet from Node1 to Node2.")
            self.assertIn("src_ip: 0x2A, dst_ip: 0x1A, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node2! ", node3_output, "Node3 did not sniff packet ping reply from Node2 to Node1.")

        with open("router.py.log", "r") as router_log:
            router_output = router_log.read()
            self.assertIn("Received frame: 4e31523112001a2a00000d48656c6c6f2c204e6f64653221, from N1", router_output, "Router did not receive packet from node1.")

    def test_spoof_message_node1_to_node3(self):
        """Test sending a spoofed message from Node1 to Node3 impersonating Node2."""
        node1_process = self.processes["node1.py"]

        # Check if the process is still running
        if node1_process.poll() is not None:
            self.fail("Node1 process has terminated unexpectedly.")

        # Send the spoofed message from Node1 to Node3
        node1_process.stdin.write("spoof 0x2A 0x2B spoofed message\n")
        node1_process.stdin.flush()

        # Allow time for the message to propagate
        time.sleep(1)

        # Verify the output in Node2's log
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("spoofed message", node3_output, "Node3 did not receive the expected message.")
            self.assertIn("IP Address matches, processing IP Packet", node3_output, "Node3 did not process the IP packet.")
            self.assertIn("Destination Mac: R2, Destination Port: 1530 , Frame: 4e3346460701014e332b46462a", node3_output, "Node3 did not send the ethernet frame to router.")
            self.assertIn("Destination Mac: N2, Destination Port: 1510 , Frame: 4e3346460701014e332b46462a", node3_output, "Node3 did not send the ethernet frame node 2.")
        
        # Verify the output in Node1's log
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("Destination IP: 0x2B, Source IP: 0x2A, Message: spoofed message", node1_output, "Node1 did not send the spoofed message.")
            self.assertNotIn("src_ip: 0x2B, dst_ip: 0x1A, protocol: 0, msg_type: 0, data_length: 15, data: spoofed message ", node1_output, "Node1 should not receive ping back from node3.")
        
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("src_ip: 0x2B, dst_ip: 0x2A, protocol: 0, msg_type: 0, data_length: 15, data: spoofed message ", node2_output, "Node2 did not receive the spoofed ping reply from node3.")
            self.assertIn("Forming Ethernet frame: src_mac: N2, dst_mac: N3", node2_output, "Node2 form reply to node3.")
            self.assertIn("Destination Mac: N3 , Destination Port: 1511 , Frame: 4e324e3314002a2b00080f73706f6f666564206d657373616765", node2_output, "Node2 did not send the spoofed reply to node 3.")
            self.assertIn("Destination Mac: R2 , Destination Port: 1530 , Frame: 4e324e3314002a2b00080f73706f6f666564206d657373616765", node2_output, "Node2 did not send the spoofed reply to router.")


    def test_firewall_message_node2_to_node3(self):
        """Test sending a message from Node2 to Node3 which enabled firewall, Node3 should drop packet."""
        node2_process = self.processes["node2.py"]
        node3_process = self.processes["node3.py"]

        # Check if the process is still running
        if node2_process.poll() is not None:
            self.fail("Node2 process has terminated unexpectedly.")

        # Setup firewall and enable it in Node3
        node3_process.stdin.write("add firewall rule * * 0 allow\n")
        node3_process.stdin.write("add firewall rule 0x2A 0x2B 0 deny\n")
        node3_process.stdin.write("on firewall\n")
        node3_process.stdin.flush()

        # Send the message from Node2 to Node3
        node2_process.stdin.write("send 0x2B Hello, Node3!\n")
        node2_process.stdin.flush()

        # Allow time for the message to propagate
        time.sleep(1)

        # Verify the output in Node3's log
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("Firewall rule added: {'src_ip': '*', 'dst_ip': '*', 'protocol': 0, 'action': 'allow'}", node3_output, "Node3 did not set default rule.")
            self.assertIn("Firewall rule added: {'src_ip': '0x2A', 'dst_ip': '0x2B', 'protocol': 0, 'action': 'deny'}", node3_output, "Node3 did not set deny rule.")
            self.assertIn("Firewall is now on.", node3_output, "Node3 did not enable firewall.")
            self.assertIn("Dropped packet from 0x2A : Firewall rule denied.", node3_output, "Node3 did not drop the packet due to firewall rule.")
        
        # Verify the output in Node2's log
        with open("node2.py.log", "r") as node2_log:
            node2_output = node2_log.read()
            self.assertIn("Destination IP: 0x2B, Source IP: 0x2A, Message: Hello, Node3!", node2_output, "Node2 did not send the message.")
            self.assertNotIn("src_ip: 0x2B, dst_ip: 0x2A, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node3! ", node2_output, "Node2 should not receive ping back from node3.")

    def test_firewall_message_node1_to_node3(self):
        """Test sending a message from Node1 to Node3 which enabled firewall, Node3 should receive packet as firewall did not block Node1, only Node2."""
        node1_process = self.processes["node1.py"]
        node3_process = self.processes["node3.py"]

        # Check if the process is still running
        if node1_process.poll() is not None:
            self.fail("Node1 process has terminated unexpectedly.")

        # Setup firewall and enable it in Node3
        node3_process.stdin.write("add firewall rule * * 0 allow\n")
        node3_process.stdin.write("add firewall rule 0x2A 0x2B 0 deny\n")
        node3_process.stdin.write("on firewall\n")
        node3_process.stdin.flush()

        # Send the message from Node1
        node1_process.stdin.write("send 0x2B Hello, Node3!\n")
        node1_process.stdin.flush()

        # Allow time for the message to propagate
        time.sleep(1)

        # Verify the output in Node3's log
        with open("node3.py.log", "r") as node3_log:
            node3_output = node3_log.read()
            self.assertIn("Hello, Node3!", node3_output, "Node3 did not receive the expected message.")
            self.assertIn("IP Address matches, processing IP Packet", node3_output, "Node3 did not process the IP packet.")
            self.assertIn("Destination Mac: R2, Destination Port: 1530 , Frame: 4e33523212002b1a00080d48656c6c6f2c204e6f64653321", node3_output, "Node3 did not send the ethernet frame to router.")
            self.assertIn("Destination Mac: N2, Destination Port: 1510 , Frame: 4e33523212002b1a00080d48656c6c6f2c204e6f64653321", node3_output, "Node3 did not send the ethernet frame node 3.")
        
        # Verify the output in Node1's log
        with open("node1.py.log", "r") as node1_log:
            node1_output = node1_log.read()
            self.assertIn("Destination IP: 0x2B, Source IP: 0x1A, Message: Hello, Node3!", node1_output, "Node1 did not send the message.")
            self.assertIn("src_ip: 0x2B, dst_ip: 0x1A, protocol: 0, msg_type: 8, data_length: 13, data: Hello, Node3! ", node1_output, "Node1 did not receive ping back from node2.")
            self.assertIn("Dropped packet: Maximum number of pings reached.", node1_output, "Node1 did not drop endless ping.")
        

if __name__ == "__main__":
    unittest.main()