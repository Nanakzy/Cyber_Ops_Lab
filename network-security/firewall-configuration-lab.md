# Firewall Configuration Lab

## Objective

Configure and test firewall rules using Cisco Packet Tracer and Linux `iptables` / `ufw` to control inbound and outbound network traffic, enforce a least-privilege access policy, and verify rule effectiveness.

---

## Tools Used

- **Cisco Packet Tracer** – Network topology simulation and ACL/firewall configuration
- **Linux CLI** – `iptables` and `ufw` firewall management
- **Python** – Automated rule verification scripting (optional)

---

## Lab Setup

### Cisco Packet Tracer Topology
1. Open Cisco Packet Tracer and build the following topology:
   - 1× Router (e.g., Cisco 2911)
   - 2× Switches (one for internal LAN, one for DMZ)
   - Internal hosts: 192.168.1.0/24
   - DMZ (web server): 10.0.0.0/24
   - External/Internet: 203.0.113.0/24

2. Assign IP addresses to all interfaces as per the topology.

### Linux Firewall Environment
1. Use a Linux VM (Ubuntu 22.04 or similar).
2. Ensure `iptables` or `ufw` is installed (`sudo apt install ufw`).
3. Note all active network interfaces (`ip a`).

**Environment:**
- Simulation Tool: [e.g., Cisco Packet Tracer 8.x]
- Linux OS: [e.g., Ubuntu 22.04]
- Network Topology: Internal LAN → Router/Firewall → DMZ → Internet

---

## Methodology

### Part 1 – Cisco Packet Tracer ACL Configuration

1. Access the router CLI in Packet Tracer.
2. Create a named extended ACL to control traffic:

```
Router(config)# ip access-list extended INTERNAL_POLICY
Router(config-ext-nacl)# permit tcp 192.168.1.0 0.0.0.255 any eq 80
Router(config-ext-nacl)# permit tcp 192.168.1.0 0.0.0.255 any eq 443
Router(config-ext-nacl)# permit icmp 192.168.1.0 0.0.0.255 any
Router(config-ext-nacl)# deny   ip any any log
Router(config-ext-nacl)# exit
Router(config)# interface GigabitEthernet0/0
Router(config-if)# ip access-group INTERNAL_POLICY in
```

3. Apply ACL to the appropriate interface (inbound/outbound).
4. Verify with `show ip access-lists` and test connectivity using Packet Tracer's simulation mode.

### Part 2 – Linux `ufw` Firewall Configuration

1. Reset and enable the firewall:

```bash
sudo ufw reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

2. Allow only required services:

```bash
sudo ufw allow ssh           # Port 22
sudo ufw allow http          # Port 80
sudo ufw allow https         # Port 443
```

3. Enable the firewall and verify:

```bash
sudo ufw enable
sudo ufw status verbose
```

4. Test rules using `nmap` from an external host:

```bash
nmap -sV <target_ip>
```

---

## Findings

> *(Replace this section with actual test results.)*

| # | Rule Tested | Expected Result | Actual Result | Pass/Fail |
|---|-------------|-----------------|---------------|-----------|
| 1 | HTTP (port 80) inbound | Allowed | Allowed | ✅ Pass |
| 2 | HTTPS (port 443) inbound | Allowed | Allowed | ✅ Pass |
| 3 | SSH (port 22) inbound | Allowed | Allowed | ✅ Pass |
| 4 | Telnet (port 23) inbound | Denied | Denied | ✅ Pass |
| 5 | FTP (port 21) inbound | Denied | [Result] | [Pass/Fail] |
| 6 | ICMP from internal to external | Allowed | [Result] | [Pass/Fail] |

**Screenshot(s):** *(Add Packet Tracer topology and `ufw status` screenshots to `images/` folder.)*

---

## Security Recommendations

1. **Default Deny Policy** – Always start with a deny-all policy and explicitly allow only required traffic.
2. **Disable Unnecessary Services** – Close unused ports (Telnet, FTP, etc.) and replace with encrypted alternatives (SSH, SFTP).
3. **Log Denied Traffic** – Enable firewall logging to detect unauthorized access attempts.
4. **Regular Rule Audits** – Periodically review and remove stale or overly permissive rules.
5. **Use Stateful Inspection** – Prefer stateful firewalls over stateless ACLs for more intelligent traffic management.
6. **Segment with DMZ** – Place public-facing services in a DMZ, separate from the internal network.

---

## Lessons Learned

- ACL rule order is critical; the first matching rule is applied and subsequent rules are skipped.
- A default deny policy significantly reduces the attack surface with minimal operational overhead.
- Testing firewall rules with `nmap` provides confidence that rules behave as expected.
- Logging denied connections is essential for detecting reconnaissance and unauthorized access attempts.
- Combining network-level firewalls (router ACLs) with host-level firewalls (`ufw`/`iptables`) provides defense-in-depth.
