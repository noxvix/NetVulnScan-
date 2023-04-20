# NetVulnScan-
NetVulnScan is an open-source network vulnerability scanner that detects open ports and common vulnerabilities in IP ranges. With a user-friendly command-line interface, it simplifies network security assessments and helps maintain a secure environment.
<pre>

## Features

- Scan a range of IP addresses
- Check for open ports and common vulnerabilities
- Save scan results to a JSON file for further analysis
- Validate input for IP ranges and ports
- Easy-to-use command-line interface

## Installation

1. Install the required dependencies:

pip install python-nmap
```

2. Clone the repository:

```bash
git clone https://github.com/noxvix/NetVulnScan.git
```

3. Navigate to the project folder:

```bash
cd NetVulnScan
```

## Usage

```bash
python enhanced_vuln_scanner.py <target_ip_range> <ports> <output_file>
```

- `target_ip_range`: The target IP range in CIDR notation (e.g., 192.168.1.0/24)
- `ports`: Comma-separated list of ports to scan (e.g., 21,23,80,443)
- `output_file`: Output file to save the scan results in JSON format (e.g., scan_results.json)

## Example

```bash
python enhanced_vuln_scanner.py 192.168.1.0/24 21,23,80,443 scan_results.json
```

This command will scan all IP addresses in the 192.168.1.0/24 subnet for open ports 21, 23, 80, and 443 and save the results to a JSON file named `scan_results.json`.

## Contributing

NetVulnScan is an open-source project, and we welcome contributions from the community. If you have suggestions, bug reports, or feature requests, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
</pre>
