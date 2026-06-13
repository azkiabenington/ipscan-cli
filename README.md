# IPSCAN-CLI (Python 3 Port)

A pure Python 3 port of the Angry IP Scanner CLI, designed for headless Linux environments.

## Why this exists?
The original Angry IP Scanner relies heavily on Java and SWT (GUI). Running it headlessly on Linux CLI often triggers dependency injection failures or `SWTError` related to X servers. Furthermore, the Java ICMP Pinger requires root raw sockets on Linux, causing ping detection to fail entirely in standard execution modes.

This Python script solves these issues by:
- Relying on native `ping` utility from the host OS (bypassing raw socket permission issues)
- Implementing `socket.create_connection` for fast port scanning
- Using pure UDP Python sockets for NetBIOS Node Status queries
- Using `avahi-resolve` and DNS reverse lookups for robust mDNS/Hostname resolution
- Running heavily concurrent threads via `ThreadPoolExecutor`

## Usage

```bash
# Scan a single IP
python3 ipscan.py --range 192.168.10.1 192.168.10.1

# Scan an entire subnet and resolve NetBIOS/mDNS hostnames automatically
python3 ipscan.py --range 192.168.10.0 192.168.10.254

# Scan an entire subnet and check if ports 80 and 443 are open
python3 ipscan.py --range 192.168.10.0 192.168.10.254 --ports 80,443

# Output to a file
python3 ipscan.py --range 192.168.10.0 192.168.10.254 --output hasil.txt
```

## Requirements
- Python 3
- Linux environment (utilizes OS `ping` and optionally `avahi-resolve` for mDNS resolving)
