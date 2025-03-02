# Define the firewall rule table as a hashmap
# Last rule is always allow all or deny all
firewall_rules = [
    # {
    #     "src_ip": "0x2A",
    #     "dst_ip": "0x2B",
    #     "protocol": 0,
    #     "action": "deny"
    # },
    # {
    #     "src_ip": "*",
    #     "dst_ip": "*",
    #     "protocol": 0,
    #     "action": "allow"
    # }
]

def check_firewall_rules(src_ip, dst_ip, protocol):
    """
    Checks the firewall rules to determine if a packet should be allowed or denied.

    Args:
        src_ip (str): The source IP address of the packet.
        dst_ip (str): The destination IP address of the packet.
        protocol (str): The protocol of the packet (e.g., 0, 1).

    Returns:
        str: "allow" if the packet is allowed, "deny" if the packet is denied.
    """
    for rule in reversed(firewall_rules):  # Iterate from top to bottom of the stack
        if (rule["src_ip"] == src_ip or rule["src_ip"] == "*") and \
           (rule["dst_ip"] == dst_ip or rule["dst_ip"] == "*") and \
           rule["protocol"] == protocol:
            return rule["action"]
    # return firewall_rules[len(firewall_rules)-1]["action"]

def push_firewall_rule(rule):
    """
    Pushes a new rule onto the firewall rule stack.

    Args:
        rule (dict): The firewall rule to be added.
    """
    firewall_rules.append(rule)

def pop_firewall_rule():
    """
    Pops the top rule from the firewall rule stack.

    Returns:
        dict: The firewall rule that was removed.
    """
    if firewall_rules:
        return firewall_rules.pop()
    return None