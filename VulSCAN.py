import nmap
from termcolor import colored

def scan_ports(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-p 1-10000')
        return nm
    except nmap.nmap.PortScannerError as e:
        print(colored(f"Error: {e}", 'red'))
        return None

def get_host_info(nm, target):
    try:
        host_info = {
            'hostname': nm[target].hostname() if 'hostname' in nm[target] else 'N/A',
            'state': nm[target].state() if 'state' in nm[target] else 'N/A',
            'addresses': nm[target]['addresses'] if 'addresses' in nm[target] else 'N/A',
            'os': nm[target]['osclass'] if 'osclass' in nm[target] else 'N/A',
            'ports': nm[target]['tcp'] if 'tcp' in nm[target] else 'N/A',
        }
        return host_info
    except KeyError:
        print(colored(f"No information available for host: {target}", 'yellow'))
        return None

def print_vulnerabilities():
    vulnerabilities = {
        137: "NetBIOS over TCP (EternalBlue exploit)",
        139: "NetBIOS over TCP (EternalBlue exploit)",
        445: "Server Message Block (SMB) (EternalBlue exploit)",
        22: "SSH (brute force credentials, leaked SSH keys)",
        53: "DNS (DDoS attacks)",
        25: "SMTP (spam, spoofing)",
        3389: "Remote Desktop (brute force authentication)",
        80: "HTTP (SQL injections, XSS, DDoS)",
        443: "HTTPS (SQL injections, XSS, DDoS)",
        8080: "HTTP (SQL injections, XSS, DDoS)",
        8443: "HTTPS (SQL injections, XSS, DDoS)",
        20: "FTP (brute force password attacks)",
        21: "FTP (brute force password attacks)",
        23: "Telnet (brute force credentials)",
        1433: "DDoS, malware spreading (unprotected databases)",
        1434: "DDoS, malware spreading (unprotected databases)",
        3306: "DDoS, malware spreading (unprotected databases)"
    }
    print(colored("Port Vulnerabilities:", 'cyan'))
    for port, vulnerability in vulnerabilities.items():
        print(colored(f"Port {port}: {vulnerability}", 'yellow'))

def main():
    target = input("Enter the target host: ").strip()
    nm = scan_ports(target)
    if nm:
        host_info = get_host_info(nm, target)
        if host_info:
            print(colored("Host Information:", 'cyan'))
            for key, value in host_info.items():
                print(colored(f"{key}: {value}", 'yellow'))
        print_vulnerabilities()

if __name__ == "__main__":
    main()
