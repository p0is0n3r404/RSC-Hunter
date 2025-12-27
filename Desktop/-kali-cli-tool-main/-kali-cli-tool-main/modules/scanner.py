import socket
from datetime import datetime

def scan_ports(target, ports):
    """
    Scans specified ports on a target IP or hostname.
    """
    print(f"Scanning target: {target}")
    print(f"Time started: {datetime.now()}")
    print("-" * 50)
    
    open_ports = []
    
    try:
        # Resolve hostname to IP
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {target}")
        return []

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        
        # returns an error indicator
        result = s.connect_ex((target_ip, port))
        if result == 0:
            print(f"Port {port}: Open")
            open_ports.append(port)
        s.close()
    
    return open_ports

if __name__ == "__main__":
    # Test scan on localhost
    scan_ports("127.0.0.1", [80, 443, 8080, 22])
