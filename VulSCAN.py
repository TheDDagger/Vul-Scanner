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
        1: "TCPMUX (unauthorized access)",
        5: "Remote Job Entry (RJE) service (unauthorized access)",
        7: "ECHO (potential for abuse in DDoS attacks)",
        9: "Discard (potential for abuse in DDoS attacks)",
        13: "Daytime (potential for abuse in DDoS attacks)",
        17: "Quote of the Day (QOTD) (potential for abuse in DDoS attacks)",
        19: "Character Generator (CHARGEN) (potential for abuse in DDoS attacks)",
        20: "FTP (brute force password attacks)",
        21: "FTP (brute force password attacks)",
        22: "SSH (brute force credentials, leaked SSH keys)",
        23: "Telnet (brute force credentials)",
        25: "SMTP (spam, spoofing)",
        53: "DNS (DDoS attacks)",
        67: "DHCP (potential for unauthorized access)",
        68: "DHCP (potential for unauthorized access)",
        69: "TFTP (potential for unauthorized access)",
        70: "Gopher (potential for unauthorized access)",
        79: "Finger (potential for unauthorized access)",
        80: "HTTP (SQL injections, XSS, DDoS)",
        81: "TorPark Onion Routing (TOR) (potential for unauthorized access)",
        88: "Kerberos (potential for unauthorized access)",
        110: "POP3 (potential for unauthorized access)",
        111: "RPCBind (potential for unauthorized access)",
        113: "Ident (potential for unauthorized access)",
        119: "NNTP (potential for unauthorized access)",
        123: "NTP (potential for DDoS amplification attacks)",
        135: "RPC (potential for unauthorized access)",
        137: "NetBIOS over TCP (EternalBlue exploit)",
        138: "NetBIOS over TCP (EternalBlue exploit)",
        139: "NetBIOS over TCP (EternalBlue exploit)",
        143: "IMAP (potential for unauthorized access)",
        161: "SNMP (potential for unauthorized access)",
        179: "BGP (potential for unauthorized access)",
        194: "IRC (potential for unauthorized access)",
        389: "LDAP (potential for unauthorized access)",
        443: "HTTPS (SQL injections, XSS, DDoS)",
        445: "Server Message Block (SMB) (EternalBlue exploit)",
        465: "SMTPS (spam, spoofing)",
        512: "Remote Shell (RSH) (potential for unauthorized access)",
        513: "rlogin (potential for unauthorized access)",
        514: "Syslog (potential for unauthorized access)",
        515: "Line Printer Daemon (LPD) (potential for unauthorized access)",
        520: "RIP (potential for unauthorized access)",
        554: "RTSP (potential for unauthorized access)",
        587: "SMTP (submission) (potential for unauthorized access)",
        623: "IPMI (potential for unauthorized access)",
        626: "ASIA (potential for unauthorized access)",
        631: "Internet Printing Protocol (IPP) (potential for unauthorized access)",
        636: "LDAP over SSL (potential for unauthorized access)",
        873: "rsync (potential for unauthorized access)",
        902: "VMware Server Management Interface (potential for unauthorized access)",
        989: "FTPS Data (potential for unauthorized access)",
        990: "FTPS Control (potential for unauthorized access)",
        993: "IMAPS (potential for unauthorized access)",
        995: "POP3S (potential for unauthorized access)",
        1080: "SOCKS Proxy (potential for unauthorized access)",
        1099: "Java RMI (potential for unauthorized access)",
        1194: "OpenVPN (potential for unauthorized access)",
        1214: "Kazaa (potential for unauthorized access)",
        1241: "Nessus (potential for unauthorized access)",
        1311: "Dell OpenManage (potential for unauthorized access)",
        1433: "Microsoft SQL Server (DDoS, malware spreading)",
        1434: "Microsoft SQL Server (DDoS, malware spreading)",
        1521: "Oracle Database Listener (potential for unauthorized access)",
        1723: "PPTP (potential for unauthorized access)",
        1725: "Steam (potential for unauthorized access)",
        1863: "Windows Live Messenger (potential for unauthorized access)",
        2049: "NFS (potential for unauthorized access)",
        2082: "cPanel (potential for unauthorized access)",
        2083: "cPanel (potential for unauthorized access)",
        2086: "WHM (Web Host Manager) (potential for unauthorized access)",
        2087: "WHM (Web Host Manager) (potential for unauthorized access)",
        2095: "cPanel Webmail (potential for unauthorized access)",
        2096: "cPanel Webmail (potential for unauthorized access)",
        2181: "ZooKeeper (potential for unauthorized access)",
        2222: "DirectAdmin (potential for unauthorized access)",
        2375: "Docker API (potential for unauthorized access)",
        2376: "Docker API (potential for unauthorized access)",
        3306: "MySQL (DDoS, malware spreading)",
        3389: "Remote Desktop (brute force authentication)",
        4200: "TeamViewer (potential for unauthorized access)",
        5432: "PostgreSQL (potential for unauthorized access)",
        5900: "VNC (Virtual Network Computing) (potential for unauthorized access)",
        5901: "VNC (Virtual Network Computing) (potential for unauthorized access)",
        5984: "CouchDB (potential for unauthorized access)",
        6379: "Redis (potential for unauthorized access)",
        6666: "IRC (potential for unauthorized access)",
        6667: "IRC (potential for unauthorized access)",
        6881: "BitTorrent (potential for unauthorized access)",
        8080: "HTTP (SQL injections, XSS, DDoS)",
        8443: "HTTPS (SQL injections, XSS, DDoS)",
        8888: "HTTP (SQL injections, XSS, DDoS)",
        9418: "Git (potential for unauthorized access)",
        9090: "Elasticsearch (potential for unauthorized access)",
        9200: "Elasticsearch (potential for unauthorized access)",
        9999: "Hydra (brute force password attacks)",
        10000: "Webmin (potential for unauthorized access)"
    }}
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
