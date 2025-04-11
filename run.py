import subprocess
import sys

def run_in_terminal(script_name):
    """Runs a Python script in a new terminal window."""
    if sys.platform == "win32":
        # Windows (uses 'start' to open a new command prompt)
        subprocess.Popen(["start", "cmd", "/k", f"python {script_name}"], shell=True)
    elif sys.platform == "darwin":
        # macOS (uses 'osascript' to open a new Terminal tab)
        subprocess.Popen(["osascript", "-e", f'tell application "Terminal" to do script "python3 {script_name}"'])
    else:
        # Linux (uses 'gnome-terminal' or 'x-terminal-emulator')
        subprocess.Popen(["gnome-terminal", "--", "bash", "-c", f"python3 {script_name}; exec bash"])

if __name__ == "__main__":
    scripts = ["node1.py", "router.py", "node2.py", "node3.py", "attackerNode1.py"]  # Replace with actual script names
    
    for script in scripts:
        run_in_terminal(script)