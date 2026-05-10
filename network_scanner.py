#!/usr/bin/env python3

import argparse
import sys
import os
import subprocess
from scanner.core import ARPScanner
from scanner.utils import print_banner, print_disclaimer, get_local_network

def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description="ARP Network Scanner - Discover devices on local network",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 network_scanner.py --auto
  sudo python3 network_scanner.py -n 192.168.1.0/24
  sudo python3 network_scanner.py --auto -o results.txt
  
Legal Notice:
  This tool is for EDUCATIONAL PURPOSES ONLY.
  Only scan networks you own or have permission to test.
        """
    )
    
    parser.add_argument('-n', '--network', 
                       help='Target network in CIDR format (e.g., 192.168.1.0/24)')
    parser.add_argument('-a', '--auto', action='store_true',
                       help='Automatically detect local network')
    parser.add_argument('-o', '--output', default='',
                       help='Save results to file')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode (less output)')
    
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
            sys.exit(1)
    elif args.network:
        target_network = args.network
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("[-] ARP scan requires root privileges. Run with sudo.")
        sys.exit(1)
    
    # Check if arp-scan is installed
    try:
        subprocess.run(['arp-scan', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[-] arp-scan not found. Install with: sudo apt install arp-scan")
        sys.exit(1)
    
    # Run ARP scan
    scanner = ARPScanner(target_network, quiet=args.quiet)
    results = scanner.scan()
    
    # Save results if requested
    if args.output and results:
        scanner.save_results(args.output)
    
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