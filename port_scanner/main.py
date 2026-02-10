#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import socket
import sys
import time
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_service_banner(sock):
    """Try to read a banner from an open socket."""
    try:
        sock.settimeout(2.0)
        data = sock.recv(1024)
        if data:
            return data.decode(errors="ignore").strip()
        return None
    except Exception:
        return None


def parse_targets(target_arg):
    """
    Parse target argument into a list of IPs.
    Supports single IP, hostname, or CIDR notation (e.g. 192.168.1.0/24).
    """
    if '/' in target_arg:
        try:
            network = ipaddress.ip_network(target_arg, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            raise ValueError(f"Invalid CIDR notation: {target_arg}")
    return [target_arg]


def scan_port(target, port, timeout=1.0):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
    """
    result = {
        "target": target,
        "port": port,
        "state": "CLOSED",
        "time": None,
        "banner": None
    }

    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # Try to connect to target:port
        sock.connect((target, port))
        elapsed = (time.time() - start) * 1000

        result["state"] = "OPEN"
        result["time"] = round(elapsed, 2)
        result["banner"] = get_service_banner(sock)

    except ConnectionRefusedError:
        result["state"] = "CLOSED"

    except socket.timeout:
        result["state"] = "FILTERED"

    except Exception as e:
        result["state"] = f"ERROR: {type(e).__name__}"

    finally:
        # Close the socket
        sock.close()

    return result


def scan_range(target, start_port, end_port):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number

    Returns:
        list: List of open ports
    """
    open_ports = []
    ports = list(range(start_port, end_port + 1))
    total = len(ports)
    completed = 0

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] This may take a while...")

    # Use threading for better performance
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in ports}

        for future in as_completed(futures):
            result = future.result()
            completed += 1

            # If open, add to open_ports list and print immediately
            if result["state"] == "OPEN":
                open_ports.append(result)
                banner = f" | Banner: {result['banner']}" if result["banner"] else ""
                print(f"[+] Port {result['port']:5} is OPEN  ({result['time']} ms){banner}")

            # Print progress every 5%
            elif completed % max(1, total // 20) == 0 or completed == total:
                print(f"[*] Progress: {completed}/{total} ports scanned", end="\r")

    print()
    open_ports.sort(key=lambda r: r["port"])
    return open_ports


def main():
    """Main function"""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="TCP Port Scanner")
    parser.add_argument("--target", required=True,
                        help="Target IP, hostname, or CIDR (e.g., 172.20.0.0/24)")
    parser.add_argument("--ports", default="1-1024",
                        help="Port range to scan (e.g. 1-1024)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Socket timeout in seconds (default: 1.0)")
    args = parser.parse_args()

    # Validate inputs
    try:
        targets = parse_targets(args.target)
        start_port, end_port = map(int, args.ports.split("-"))
        if not (1 <= start_port <= end_port <= 65535):
            raise ValueError("Port range must be between 1 and 65535")
    except ValueError as e:
        parser.error(str(e))

    all_open = []
    scan_start = time.time()

    for target in targets:
        print(f"\n[*] Starting port scan on {target}")

        # Call scan_range() and collect results
        open_ports = scan_range(target, start_port, end_port)
        all_open.extend(open_ports)

    total_time = round(time.time() - scan_start, 2)

    # Display results
    print(f"\n[+] Scan complete!")
    print(f"[+] Found {len(all_open)} open ports in {total_time}s")
    print("=" * 50)
    for r in all_open:
        banner = r["banner"] if r["banner"] else "Unknown"
        print(f"    {r['target']:15}  Port {r['port']:5}: {banner}")


if __name__ == "__main__":
    main()