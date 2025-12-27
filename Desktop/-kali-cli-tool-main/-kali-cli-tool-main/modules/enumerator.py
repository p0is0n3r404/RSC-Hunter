import socket

def enumerate_subdomains(domain, subdomains):
    """
    Checks which subdomains from a list exist for a given domain.
    """
    found_subdomains = []
    print(f"Enumerating subdomains for: {domain}")
    print("-" * 50)
    
    for sub in subdomains:
        url = f"{sub}.{domain}"
        try:
            # Try to resolve the subdomain
            socket.gethostbyname(url)
            print(f"Found: {url}")
            found_subdomains.append(url)
        except socket.gaierror:
            # Subdomain does not exist or could not be resolved
            pass
            
    return found_subdomains

if __name__ == "__main__":
    # Test enumeration
    test_subs = ["www", "mail", "dev", "test", "api"]
    enumerate_subdomains("google.com", test_subs)
