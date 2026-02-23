# Wireshark Traffic Analysis Lab

## Objective

Capture and analyze network traffic using Wireshark to identify normal versus anomalous behavior, detect potential threats, and document findings in a structured security report.

---

## Tools Used

- **Wireshark** – Network packet capture and protocol analysis
- **Linux CLI** – Interface management and traffic generation
- **Wireshark Display Filters** – Isolating specific traffic types (HTTP, DNS, TCP, etc.)

---

## Lab Setup

1. Install Wireshark on your analysis machine (`sudo apt install wireshark` on Debian/Ubuntu).
2. Identify the target network interface (e.g., `eth0`, `wlan0`) using `ip a` or `ifconfig`.
3. Configure Wireshark to capture on the desired interface.
4. Optionally, generate test traffic using `ping`, `curl`, or `nmap` from a separate host.
5. Save captures as `.pcap` files for offline analysis.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Wireshark Version: [e.g., 4.x]
- Network Interface: [e.g., eth0]
- Capture Duration: [e.g., 5 minutes]

---

## Methodology

1. **Start Capture** – Begin packet capture on the identified network interface.
2. **Generate/Observe Traffic** – Browse websites, ping hosts, or run services to produce traffic.
3. **Apply Display Filters** – Use filters to isolate traffic of interest:
   - `http` – Filter HTTP traffic
   - `dns` – Filter DNS queries and responses
   - `tcp.flags.syn == 1` – Identify TCP SYN packets (potential port scans)
   - `ip.addr == <target_ip>` – Filter by IP address
4. **Follow Streams** – Right-click on a packet → *Follow → TCP/HTTP Stream* to reconstruct sessions.
5. **Export Objects** – Use *File → Export Objects → HTTP* to extract transferred files.
6. **Analyze Statistics** – Review *Statistics → Protocol Hierarchy* and *Conversations*.
7. **Document Suspicious Activity** – Note any anomalies such as unusual ports, large data transfers, or unknown protocols.

---

## Findings

> *(Replace this section with actual findings from your capture.)*

| # | Finding | Protocol | Source IP | Destination IP | Description |
|---|---------|----------|-----------|----------------|-------------|
| 1 | [e.g., Cleartext credentials] | HTTP | x.x.x.x | x.x.x.x | Username/password sent unencrypted |
| 2 | [e.g., DNS tunneling suspected] | DNS | x.x.x.x | x.x.x.x | Unusually long TXT record queries |
| 3 | [e.g., Port scan detected] | TCP | x.x.x.x | x.x.x.x | Sequential SYN packets to multiple ports |

**Screenshot(s):** *(Add Wireshark screenshots to the `images/` folder and reference them here.)*

---

## Security Recommendations

1. **Encrypt Traffic** – Replace HTTP with HTTPS to prevent credential exposure.
2. **Monitor DNS Traffic** – Deploy DNS filtering to detect tunneling and data exfiltration.
3. **Implement IDS/IPS** – Deploy an Intrusion Detection System (e.g., Snort/Suricata) to alert on port scan activity.
4. **Segment Networks** – Use VLANs to limit lateral movement and reduce broadcast domain exposure.
5. **Log and Alert** – Forward packet captures to a SIEM for real-time alerting and historical analysis.

---

## Lessons Learned

- Wireshark display filters dramatically reduce analysis time by focusing on relevant traffic.
- Cleartext protocols (HTTP, FTP, Telnet) expose sensitive data that can be captured passively.
- Protocol hierarchy statistics provide a quick overview of traffic composition and reveal anomalies.
- Following TCP/HTTP streams is essential for reconstructing full communication sessions.
- Regular baseline captures help distinguish normal from abnormal network behavior.
