# Lightweight Network-Based Intrusion Detection System (IDS)

A simple Python-based IDS designed to detect suspicious network activity like port scanning. Built using `scapy`, `rich`, and `netifaces`, this project is ideal for learning packet sniffing, TCP/IP fundamentals, and basic threat detection.

## Features

* Built in Python, runs on macOS (M1-friendly)
* Sniffs live network traffic using Scapy
* Detects port scanning behavior using SYN packet tracking
* Custom rule logic (e.g., alert when more than 20 ports are hit in 10 seconds)
* Logs alerts to a file (`logs/alerts.log`)
* Colored terminal output using Rich
* Modular design for future enhancements (e.g., suspicious ports, DNS abuse)

## How It Works

1. Captures live packets on your active network interface.
2. Monitors TCP SYN packets (used to initiate connections).
3. If a single IP tries to connect to too many ports too quickly, it flags it as a potential port scan.
4. Alerts are printed in real-time and logged to a file.

## Project Structure

```
network-ids/
├── sniffer.py           # Main IDS script
├── logs/
│   └── alerts.log       # Log file for alerts
├── venv/                # Python virtual environment
```

## Getting Started

```bash
# Clone this repo and enter it
cd network-ids

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the IDS (requires sudo for packet sniffing)
sudo python3 sniffer.py
```

## Test the Detection

Use `nmap` to simulate a port scan:

```bash
nmap 127.0.0.1 -p 1-100
```

You should see a red alert in the terminal and an entry in `logs/alerts.log`.

## Built With

* [scapy](https://scapy.net/) – for packet sniffing
* [rich](https://github.com/Textualize/rich) – for colored terminal output
* [netifaces](https://github.com/al45tair/netifaces) – for detecting your network interface

## Future Improvements

* Detect suspicious ports (e.g., Telnet, RDP, SMB)
* Add DNS tunneling detection
* Export logs to JSON or CSV
* Build a web dashboard (e.g., Flask or Streamlit)
* Blacklist integration (e.g., AbuseIPDB)
