import sys
import unittest
import subprocess
import time

class TestNetworkIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up the router and nodes as subprocesses."""
        cls.processes = {}
        cls.logs = {}

        # Start the router and nodes as background processes
        scripts = ["router.py", "node1.py", "node2.py", "node3.py"]

        for script in scripts:
            log_file = open(f"{script}.log", "w")  # Log file for each process
            if sys.platform == "win32":
                process = subprocess.Popen(
                    ["python", "-u", script],  # Add the -u flag for unbuffered output
                    stdin=subprocess.PIPE,  # Enable stdin for sending input
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                cls.processes[script] = process
                cls.logs[script] = log_file
            else:
                process = subprocess.Popen(
                    ["python3", "-u", script],  # Add the -u flag for unbuffered output
                    stdin=subprocess.PIPE,  # Enable stdin for sending input
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                cls.processes[script] = process
                cls.logs[script] = log_file

        # Allow time for all processes to initialize
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        """Terminate all subprocesses and close log files."""
        for process in cls.processes.values():
            if process.poll() is None:  # Check if the process is still running
                process.terminate()
                process.wait()
        for log_file in cls.logs.values():
            if not log_file.closed:
                log_file.close()

    # def setUp(self):
    #     """Clear log files before each test case."""
    #     scripts = ["router.py", "node1.py", "node2.py", "node3.py"]
    #     for script in scripts:
    #         log_file_path = f"{script}.log"
    #         with open(log_file_path, "w") as log_file:
    #             log_file.truncate()  # Clear the contents of the log file

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


if __name__ == "__main__":
    unittest.main()