import socket

def resolve_domain(domain):
    """Resolves a domain name to an IP address."""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def scan_subdomains(domain, limit=5):
    """Checks common subdomains for the given domain."""
    common_subs = ["www", "api", "mail", "dev", "admin", "test", "vpn", "portal"]
    found = []
    
    print("[*] Enumerating common subdomains for " + domain + "...")
    for sub in common_subs[:limit]:
        test_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(test_domain)
            found.append({"subdomain": test_domain, "ip": ip})
        except socket.gaierror:
            pass # Subdomain doesn't exist
            
    return found

if __name__ == "__main__":
    print(resolve_domain("google.com"))
    print(scan_subdomains("google.com"))
