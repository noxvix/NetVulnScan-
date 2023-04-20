import nmap
import sys
import json
from ipaddress import IPv4Network, AddressValueError
import argparse


def parse_arguments():
    parser = argparse.ArgumentParser(description="Enhanced Vulnerability Scanner")
    parser.add_argument("target_range", help="Target IP range (CIDR notation)")
    parser.add_argument("ports", help="Comma-separated list of ports to scan")
    parser.add_argument("output_file", help="Output file to save the scan results (JSON format)")

    args = parser.parse_args()
    return args


def validate_ports(ports_str):
    try:
        ports = [int(p.strip()) for p in ports_str.split(',')]
    except ValueError:
        raise ValueError("Invalid ports format. Use a comma-separated list of integers.")
    return ports


def scan_ports(target, ports):
    scanner = nmap.PortScanner()
    scanner.scan(target, ','.join(map(str, ports)))

    scan_results = {
        'ip': target,
        'open_ports': [],
        'vulnerabilities': []
    }

    for port in scanner[target]['tcp']:
        state = scanner[target]['tcp'][port]['state']
        if state == 'open':
            scan_results['open_ports'].append(port)
            scan_results['vulnerabilities'].extend(check_vulnerabilities(port))

    return scan_results


def check_vulnerabilities(port):
    vulnerabilities = []

    if port == 21:
        vulnerabilities.append('Possible FTP vulnerability')
    elif port == 23:
        vulnerabilities.append('Possible Telnet vulnerability')
    elif port == 80 or port == 443:
        vulnerabilities.append('Possible web server vulnerability')

    return vulnerabilities


def save_results_to_file(results, filename):
    with open(filename, 'w') as outfile:
        json.dump(results, outfile, indent=4)


def main():
    args = parse_arguments()

    try:
        ip_range = IPv4Network(args.target_range, strict=False)
    except AddressValueError:
        print("Invalid IP range. Use CIDR notation (e.g., 192.168.1.0/24).")
        sys.exit(1)

    try:
        ports = validate_ports(args.ports)
    except ValueError as e:
        print(e)
        sys.exit(1)

    all_results = []

    for ip in ip_range:
        print(f"Scanning target {ip} for open ports and vulnerabilities...")
        scan_result = scan_ports(str(ip), ports)
        all_results.append(scan_result)

    print("Saving results to file...")
    save_results_to_file(all_results, args.output_file)
    print(f"Results saved to {args.output_file}.")


if __name__ == "__main__":
    main()
