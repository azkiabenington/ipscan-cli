#!/usr/bin/env python3
import argparse
import concurrent.futures
import ipaddress
import socket
import struct
import subprocess
import time
from datetime import datetime
import sys
import threading
import shlex

def is_alive(ip):
    # Ping the IP. 
    # -c 1 : Send 1 packet
    # -W 1 : Wait 1 second for response
    try:
        # Use subprocess with shell=False for security and portability
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5
        )
        return result.returncode == 0
    except Exception:
        return False

def get_netbios_name(ip, timeout=0.5):
    trn_id = b'\x12\x34'
    flags = b'\x00\x00'
    qdcount = b'\x00\x01'
    ancount = b'\x00\x00'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    query_name = b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
    qtype = b'\x00\x21'
    qclass = b'\x00\x01'
    packet = trn_id + flags + qdcount + ancount + nscount + arcount + query_name + qtype + qclass
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (str(ip), 137))
        data, _ = sock.recvfrom(1024)
        if len(data) > 56:
            num_names = data[56]
            offset = 57
            for i in range(num_names):
                if len(data) >= offset + 18:
                    name_bytes = data[offset:offset+15]
                    name_type = data[offset+15]
                    flags = struct.unpack('>H', data[offset+16:offset+18])[0]
                    name = name_bytes.decode('ascii', errors='ignore').strip()
                    if name_type == 0x00 and not (flags & 0x8000):
                        return name
                offset += 18
    except Exception:
        pass
    finally:
        sock.close()
    return None

def get_mdns_name(ip):
    try:
        result = subprocess.run(
            ['avahi-resolve', '-a', str(ip)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=1.0, text=True
        )
        if result.returncode == 0 and result.stdout:
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1]
    except Exception:
        pass
    return None

def get_hostname(ip):
    # 1. Try standard DNS reverse lookup
    try:
        hostname, _, _ = socket.gethostbyaddr(str(ip))
        if hostname and hostname != str(ip):
            return hostname
    except Exception:
        pass
        
    # 2. Try NetBIOS
    netbios = get_netbios_name(ip)
    if netbios:
        return netbios
        
    # 3. Try mDNS
    mdns = get_mdns_name(ip)
    if mdns:
        return mdns
        
    return "N/A"

def check_port(ip, port, timeout=1.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((str(ip), port))
        return result == 0
    except Exception:
        return False
    finally:
        sock.close()

def scan_ports(ip, ports):
    if not ports:
        return ""
    open_ports = []
    for port in ports:
        if check_port(ip, port):
            open_ports.append(str(port))
    return ",".join(open_ports) if open_ports else "None"

def scan_ip(ip, ports):
    # Core scanning logic for a single IP
    alive = is_alive(ip)
    if not alive:
        return None
    
    hostname = get_hostname(ip)
    open_ports_str = scan_ports(ip, ports)
    
    # Return formatted result tuple
    return (str(ip), "0ms", hostname, open_ports_str)

def main():
    parser = argparse.ArgumentParser(description="Python 3 CLI IP Scanner (Angry IP Scanner alternative)")
    parser.add_argument("--range", nargs=2, metavar=('START_IP', 'END_IP'), required=True, help="IP range to scan")
    parser.add_argument("--output", "-o", help="Output file path (optional, prints to screen if not provided)")
    parser.add_argument("--ports", "-p", help="Comma-separated list of ports to scan (e.g., 80,443,8080)")
    parser.add_argument("--threads", "-t", type=int, default=100, help="Number of parallel threads (default: 100)")
    
    args = parser.parse_args()
    
    try:
        start_ip = ipaddress.IPv4Address(args.range[0])
        end_ip = ipaddress.IPv4Address(args.range[1])
    except ValueError as e:
        print(f"Error parsing IP addresses: {e}")
        sys.exit(1)
        
    if int(start_ip) > int(end_ip):
        print("Error: Start IP must be less than or equal to End IP")
        sys.exit(1)
        
    ports = []
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',') if p.strip()]
        except ValueError:
            print("Error: Ports must be a comma-separated list of integers")
            sys.exit(1)

    ip_list = [ipaddress.IPv4Address(ip) for ip in range(int(start_ip), int(end_ip) + 1)]
    total_ips = len(ip_list)
    
    print(f"Starting scan of {total_ips} IP addresses...")
    
    results = []
    completed = 0
    lock = threading.Lock()
    
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit all tasks
        future_to_ip = {executor.submit(scan_ip, ip, ports): ip for ip in ip_list}
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"\nError scanning {ip}: {e}")
                
            with lock:
                completed += 1
                percent = int((completed / total_ips) * 100)
                sys.stdout.write(f"\rProgress: {percent}% [{completed}/{total_ips}]")
                sys.stdout.flush()

    elapsed = time.time() - start_time
    print(f"\nScan completed in {elapsed:.2f} seconds.")
    print(f"Found {len(results)} alive hosts.")
    
    # Sort results by IP address
    results.sort(key=lambda x: ipaddress.IPv4Address(x[0]))
    
    # Generate the output text
    output_lines = []
    output_lines.append("Generated by Python IP Scanner CLI")
    output_lines.append(f"Scanned {start_ip} - {end_ip}")
    output_lines.append(f"{datetime.now().strftime('%b %d, %Y, %I:%M:%S %p')}\n")
    
    header = f"{'IP':<15} {'Ping':<10} {'Hostname':<30} {'Ports':<15}"
    output_lines.append(header)
    
    for res in results:
        line = f"{res[0]:<15} {res[1]:<10} {res[2]:<30} {res[3]:<15}"
        output_lines.append(line)
        
    output_text = "\n".join(output_lines) + "\n"
    
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(output_text)
            print(f"Saved results to {args.output}")
        except IOError as e:
            print(f"Error saving results: {e}")
    else:
        print("\n" + "="*70)
        print(output_text)
        print("="*70)

if __name__ == "__main__":
    main()
