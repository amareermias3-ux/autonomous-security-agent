import nmap

def run_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sV -T4')
    result = {"open_ports": [], "http_services": [], "tls_services": [], "hosts": []}
    for host in nm.all_hosts():
        result["hosts"].append(host)
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                if nm[host][proto][port]['state'] == 'open':
                    service = nm[host][proto][port].get('name', '')
                    result["open_ports"].append({
                        "host": host, "port": port, "service": service})
                    if service in ['http', 'https']:
                        result["http_services"].append(port)
                    if service in ['https', 'ssl'] or port == 443:
                        result["tls_services"].append(port)
    return result
