# Define the firewall rule table as a hashmap
# Last rule is always allow all or deny all
firewall_rules = {
    1: {
        "src_ip": "0x2A",
        "dst_ip": "0x2B",
        "protocol": 0,
        "action": "deny"
    },
    2: {
        "src_ip": "*",
        "dst_ip": "*",
        "protocol": 0,
        "action": "allow"
    }
}

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
    for rule_id, rule in firewall_rules.items():
        if rule["src_ip"] == src_ip and rule["dst_ip"] == dst_ip and rule["protocol"] == protocol:
            return rule["action"]
    return firewall_rules[len(firewall_rules)-1]["action"]