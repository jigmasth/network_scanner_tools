#!/usr/bin/env python3
"""
Network Scanner Tool - Windows Compatible
Educational Purpose Only - Learn Network Security Concepts
Runs on Windows without WSL or additional tools
"""

import argparse
import sys
import subprocess
import platform
import re
import socket
import ipaddress
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def print_banner():
    """Print tool banner"""
    banner = """
============================================================
NETWORK SCANNER TOOL v1.0.0 - Windows Compatible
Educational Purpose Only - Learn Network Security
============================================================
"""
    print(banner)

def print_disclaimer():
    """Print legal disclaimer"""
    disclaimer = """
============================================================
LEGAL DISCLAIMER
============================================================

This tool is for EDUCATIONAL PURPOSES ONLY.
By using this software you agree to:

1. Only scan networks you OWN or have EXPLICIT PERMISSION
2. Comply with all applicable laws
3. Accept FULL RESPONSIBILITY for your actions
4. NOT use this tool for malicious purposes

The author assumes NO LIABILITY for misuse.
============================================================
"""
    print(disclaimer)

def get_local_network():
    """Automatically detect local network on Windows"""
    try:
        # Get local IP address
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        if local_ip and local_ip != '127.0.0.1':
            ip_parts = local_ip.split('.')
            # Detect common private IP ranges
            if ip_parts[0] == '192' and ip_parts[1] == '168':
                return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            elif ip_parts[0] == '10':
                return f"{ip_parts[0]}.0.0.0/24"
            elif ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31:
                return f"{ip_parts[0]}.{ip_parts[1]}.0.0/24"
            else:
                return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    except Exception as e:
        print(f"[-] Error detecting network: {e}")
    
    return None

def ping_host(ip: str) -> bool:
    """Ping a host to check if it's alive (Windows compatible)"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-w', '1000', ip]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3)
        # Check for successful ping in output
        if platform.system().lower() == 'windows':
            return 'Reply from' in result.stdout
        else:
            return result.returncode == 0
    except:
        return False

def get_arp_table():
    """Get ARP table entries on Windows"""
    arp_entries = []
    
    try:
        # Run arp -a command
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        
        # Parse ARP table output
        # Windows arp -a output format:
        # Interface: 192.168.1.100 --- 0x3
        #   Internet Address      Physical Address      Type
        #   192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
        #   192.168.1.42          11-22-33-44-55-66     dynamic
        
        lines = result.stdout.split('\n')
        for line in lines:
            # Look for lines with IP addresses
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9\-]{17})', line)
            if ip_match:
                ip = ip_match.group(1)
                mac = ip_match.group(2).replace('-', ':').upper()
                if ip != '255.255.255.255' and ip != '224.0.0.22':
                    arp_entries.append({'ip': ip, 'mac': mac})
    except Exception as e:
        print(f"[-] Error reading ARP table: {e}")
    
    return arp_entries

def get_mac_vendor(mac: str) -> str:
    """Get vendor name from MAC address OUI"""
    vendors = {
        '00:00:0C': 'Cisco',
        '00:14:22': 'Dell',
        '00:1A:11': 'Intel',
        '00:1E:37': 'Samsung',
        '00:25:9C': 'Apple',
        '04:18:D6': 'Raspberry Pi',
        '08:00:27': 'VirtualBox',
        '0C:54:15': 'ASUS',
        '10:DD:B1': 'Google',
        '14:7D:DA': 'TP-Link',
        '18:56:80': 'Huawei',
        '24:0A:64': 'Netgear',
        '2C:54:CF': 'Xiaomi',
        '3C:07:54': 'Intel',
        '40:16:7E': 'Netflix',
        '44:38:39': 'HP',
        '4C:72:B9': 'Microsoft',
        '50:1A:C5': 'Acer',
        '54:27:1E': 'Sony',
        '5C:F3:FC': 'Amazon',
        '64:16:7F': 'Nintendo',
        '70:1C:E7': 'Philips',
        '78:44:76': 'LG',
        '80:1F:02': 'Belkin',
        '8C:89:A5': 'Ubiquiti',
        '90:2E:16': 'Synology',
        '9C:AD:EF': 'D-Link',
        'A0:CC:2B': 'Arris',
        'B0:7B:1C': 'Western Digital',
        'BC:EE:7B': 'Cradlepoint',
        'C0:3E:BA': 'Motorola',
        'C8:D9:D2': 'Zyxel',
        'CC:40:D0': 'Roku',
        'D0:50:99': 'Intel',
        'D8:80:39': 'HTC',
        'DC:A4:CA': 'Intel',
        'E0:26:FF': 'Lenovo',
        'E8:AB:FA': 'Hitachi',
        'F0:18:98': 'Nest',
        'F4:8C:50': 'Atheros',
        'FC:EC:DA': 'Toshiba'
    }
    
    # Check first 8 characters (XX:XX:XX format)
    mac_clean = mac.upper()
    if len(mac_clean) >= 8:
        oui = mac_clean[:8]
        return vendors.get(oui, 'Unknown')
    return 'Unknown'

def get_hostname(ip: str) -> str:
    """Get hostname from IP address"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return "Unknown"

# ============================================================
# NETWORK SCANNER CLASS
# ============================================================

class NetworkScanner:
    """Network scanner for Windows"""
    
    def __init__(self, network_cidr: str, scan_method: str = 'ping', max_threads: int = 50):
        """
        Initialize network scanner
        
        Args:
            network_cidr: Network in CIDR format (e.g., '192.168.1.0/24')
            scan_method: 'ping' or 'arp' (default: ping)
            max_threads: Maximum concurrent threads
        """
        self.network_cidr = network_cidr
        self.scan_method = scan_method
        self.max_threads = max_threads
        self.results = []
    
    def scan(self) -> List[Dict]:
        """Perform network scan"""
        
        print(f"\n[*] Target network: {self.network_cidr}")
        print(f"[*] Scan method: {self.scan_method.upper()}")
        print("[*] Scanning...\n")
        
        try:
            # Generate list of IPs to scan
            network = ipaddress.ip_network(self.network_cidr, strict=False)
            hosts = list(network.hosts())
            total_hosts = len(hosts)
            
            print(f"[*] Total hosts to scan: {total_hosts}")
            
            if self.scan_method == 'arp':
                # Use ARP table lookup (faster but only shows recent connections)
                devices = self._scan_arp()
            else:
                # Use ping sweep (slower but more thorough)
                devices = self._scan_ping_sweep(hosts)
            
            # Display results
            if devices:
                print("\n" + "-"*60)
                for device in devices:
                    print(f"[+] {device['ip']:<16} {device['mac']:<18} {device['vendor']}")
                    if device['hostname'] != 'Unknown':
                        print(f"    Hostname: {device['hostname']}")
                print("-"*60)
            else:
                print("[-] No devices found")
                print("[*] Tips:")
                print("    1. Run as Administrator for better results")
                print("    2. Try: python network_scanner.py --method arp")
                print("    3. Check your network connection")
            
            # Summary
            print("\n" + "="*60)
            print("SCAN SUMMARY")
            print("="*60)
            print(f"Target network: {self.network_cidr}")
            print(f"Active hosts found: {len(devices)}")
            
            self.results = devices
            return devices
            
        except Exception as e:
            print(f"[-] Scan error: {e}")
            return []
    
    def _scan_arp(self) -> List[Dict]:
        """Scan using ARP table"""
        devices = []
        arp_entries = get_arp_table()
        
        for entry in arp_entries:
            ip = entry['ip']
            mac = entry['mac']
            # Check if IP is in our network range
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(self.network_cidr):
                    vendor = get_mac_vendor(mac)
                    hostname = get_hostname(ip)
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'vendor': vendor,
                        'hostname': hostname
                    })
                    print(f"[*] Found: {ip} - {vendor}")
            except:
                pass
        
        return devices
    
    def _scan_ping_sweep(self, hosts: List) -> List[Dict]:
        """Scan using ping sweep with threading"""
        devices = []
        active_hosts = []
        
        print("[*] Pinging hosts (this may take a moment)...")
        
        # Use ThreadPoolExecutor for concurrent pings
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all ping tasks
            future_to_ip = {executor.submit(ping_host, str(ip)): str(ip) for ip in hosts}
            
            # Process results as they complete
            completed = 0
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1
                
                # Show progress
                if completed % 20 == 0:
                    print(f"  Progress: {completed}/{len(hosts)} hosts", end='\r')
                
                try:
                    if future.result():
                        active_hosts.append(ip)
                except:
                    pass
        
        print()  # New line after progress
        
        # Get details for active hosts
        print(f"\n[*] Found {len(active_hosts)} active hosts, gathering details...")
        
        for ip in active_hosts:
            # Try to get MAC from ARP cache first
            mac = self._get_mac_from_arp(ip)
            if not mac:
                mac = "Unknown"
            
            vendor = get_mac_vendor(mac) if mac != "Unknown" else "Unknown"
            hostname = get_hostname(ip)
            
            devices.append({
                'ip': ip,
                'mac': mac,
                'vendor': vendor,
                'hostname': hostname
            })
        
        return devices
    
    def _get_mac_from_arp(self, ip: str) -> str:
        """Get MAC address from ARP cache for a specific IP"""
        try:
            result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                # Windows format: 192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
                if ip in line:
                    mac_match = re.search(r'([a-fA-F0-9\-]{17})', line)
                    if mac_match:
                        return mac_match.group(1).replace('-', ':').upper()
        except:
            pass
        return "Unknown"
    
    def save_results(self, filename: str):
        """Save scan results to file"""
        try:
            with open(filename, 'w') as f:
                f.write(f"Network Scan Results\n")
                f.write(f"="*60 + "\n")
                f.write(f"Target: {self.network_cidr}\n")
                f.write(f"Scan Method: {self.scan_method}\n")
                f.write(f"Hosts Found: {len(self.results)}\n\n")
                f.write(f"{'IP Address':<16} {'MAC Address':<18} {'Vendor'}\n")
                f.write(f"-"*60 + "\n")
                
                for device in self.results:
                    f.write(f"{device['ip']:<16} {device['mac']:<18} {device['vendor']}\n")
                    if device['hostname'] != 'Unknown':
                        f.write(f"  Hostname: {device['hostname']}\n")
            
            print(f"\n[+] Results saved to {filename}")
        except Exception as e:
            print(f"[-] Error saving results: {e}")

# ============================================================
# MAIN FUNCTION
# ============================================================

def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description="Network Scanner Tool - Windows Compatible",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_scanner.py --auto
  python network_scanner.py -n 192.168.1.0/24
  python network_scanner.py --auto --method arp
  python network_scanner.py --auto -o results.txt
  python network_scanner.py --auto -q

Legal Notice:
  This tool is for EDUCATIONAL PURPOSES ONLY.
  Only scan networks you own or have permission to test.
        """
    )
    
    parser.add_argument('-n', '--network', 
                       help='Target network in CIDR format (e.g., 192.168.1.0/24)')
    parser.add_argument('-a', '--auto', action='store_true',
                       help='Automatically detect local network')
    parser.add_argument('-m', '--method', choices=['ping', 'arp'], default='ping',
                       help='Scan method: ping (thorough) or arp (fast) (default: ping)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Maximum threads for scanning (default: 50)')
    parser.add_argument('-o', '--output', default='',
                       help='Save results to file')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode (skip legal confirmation)')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    if not args.auto and not args.network:
        parser.print_help()
        sys.exit(1)
    
    # Legal confirmation
    if not args.quiet:
        print_disclaimer()
        response = input("\nDo you have permission to scan the target network? (yes/no): ")
        if response.lower() != 'yes':
            print("Exiting. Always obtain proper authorization first.")
            sys.exit(0)
    
    # Determine target network
    target_network = None
    if args.auto:
        target_network = get_local_network()
        if target_network:
            print(f"[+] Detected local network: {target_network}")
        else:
            print("[-] Could not detect network automatically")
            print("[*] Please specify network manually with -n option")
            print("[*] Example: python network_scanner.py -n 192.168.1.0/24")
            sys.exit(1)
    elif args.network:
        target_network = args.network
    
    # Run scanner
    scanner = NetworkScanner(target_network, scan_method=args.method, max_threads=args.threads)
    results = scanner.scan()
    
    # Save results if requested
    if args.output and results:
        scanner.save_results(args.output)
    
    # Admin tips
    if platform.system().lower() == 'windows' and args.method == 'arp' and not results:
        print("\n[*] Tip: Run as Administrator for better ARP results")
        print("    Right-click Command Prompt -> Run as Administrator")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
