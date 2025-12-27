import sys
import argparse
import requests
from modules.scanner import scan_ports
from modules.hasher import identify_hash
from modules.enumerator import enumerate_subdomains
from utils.ui import print_banner, Colors

def get_ip_info(ip):
    """
    Fetches information about an IP address using ip-api.com.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            print(f"IP: {data['query']}")
            print(f"ISP: {data['isp']}")
            print(f"Organization: {data['org']}")
            print(f"Country: {data['country']}")
            print(f"City: {data['city']}")
            print(f"ZIP: {data['zip']}")
            print(f"Lat/Lon: {data['lat']}, {data['lon']}")
        else:
            print(f"Error: {data['message']}")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="K-SAK: Kali Swiss Army Knife CLI Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available tools")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan ports on a target")
    scan_parser.add_argument("target", help="Target IP or hostname")
    scan_parser.add_argument("-p", "--ports", nargs="+", type=int, default=[21, 22, 80, 443, 3306, 8080], help="Ports to scan")

    # Hash command
    hash_parser = subparsers.add_parser("hash", help="Identify a hash algorithm")
    hash_parser.add_argument("hash_string", help="The hash string to identify")

    # Subdomain command
    sub_parser = subparsers.add_parser("sub", help="Enumerate subdomains")
    sub_parser.add_argument("domain", help="The domain to enumerate")
    sub_parser.add_argument("-w", "--wordlist", nargs="+", default=["www", "mail", "dev", "test", "api", "smtp", "ftp"], help="Basic wordlist for subdomains")

    # IP command
    ip_parser = subparsers.add_parser("ip", help="Get info for an IP address")
    ip_parser.add_argument("ip", help="The IP address to lookup")

    args = parser.parse_args()

    if args.command == "scan":
        scan_ports(args.target, args.ports)
    elif args.command == "hash":
        algo = identify_hash(args.hash_string)
        print(f"Identified Algorithm: {algo}")
    elif args.command == "sub":
        enumerate_subdomains(args.domain, args.wordlist)
    elif args.command == "ip":
        get_ip_info(args.ip)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
