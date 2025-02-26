# Packet Sniffer in Python

## Overview
This project is a **Python-based packet sniffer** that captures and analyzes network traffic. It helps visualize how data packets are structured and transmitted across a network, making it useful for cybersecurity enthusiasts, ethical hackers, and network analysts.

## Features
- 🛜 **Captures live network packets** in real-time.
- 🕵️‍♂️ **Decodes Ethernet, IPv4, TCP, UDP, and ICMP headers**.
- 📊 **Displays source and destination MAC & IP addresses**.
- 🔍 **Analyzes protocol types (TCP, UDP, ICMP, etc.)**.
- 🔎 **Provides insights into network security vulnerabilities**.

## Requirements
Before running this project, make sure you have the following:
- Python 3.x installed.
- Administrator/root privileges (for capturing packets).
- `socket` and `struct` libraries (pre-installed with Python).

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/Peter-ConX/CodeAlpha_Project_Name.
   ```
2. Navigate to the project folder:
   ```sh
   cd CodeAlpha_Project_Name
   ```
3. Run the script:
   ```sh
   sudo python3 Packet_sniffer.py  # Linux/Mac
   python Packet_sniffer.py        # Windows (Admin Mode)
   ```

## Usage
Once the script runs, it will start listening to network traffic and display packet details, such as:
```
Ethernet Frame:
 - Destination: 00:1A:2B:3C:4D:5E, Source: 5E:4D:3C:2B:1A:00, Protocol: 8
IPv4 Packet:
 - Source IP: 192.168.1.10, Destination IP: 192.168.1.1, Protocol: TCP
TCP Segment:
 - Source Port: 443, Destination Port: 53210, Flags: SYN, ACK
```

## Limitations
- Requires **root/admin privileges** to access network traffic.
- Works best on **Linux/macOS** (Windows might need WinPcap/Npcap for full functionality).

## Future Improvements
- Add **support for packet filtering** (capture only specific protocols or IPs).
- Implement **packet logging to a file** for later analysis.
- Create a **GUI version** for easier analysis.

## Contributions
Contributions are welcome! Feel free to fork this repository, submit pull requests, or open issues.

## License
This project is open-source and available under the **MIT License**.

---
📌 **GitHub Repository:** [Click Here](https://github.com/Peter-ConX/CodeAlpha_Project_Name./blob/main/Packet_sniffer.py)

