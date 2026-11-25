import nmap
import yaml

def run_scan(target):
    # Load config to check if NSE is enabled
    try:
        with open("config/settings.yaml") as f:
            cfg = yaml.safe_load(f)
        enable_nse = cfg.get("target", {}).get("enable_nse", False)
    except:
        enable_nse = False

    nm = nmap.PortScanner()
    
    # Base arguments
    args = '-sV -T4'
    
    # Add NSE vulnerability scripts if enabled
    if enable_nse:
        print("[*] Nmap NSE (Vulnerability Scripts) enabled. This may take longer...")
        args += ' --script vuln'

    nm.scan(hosts=target, arguments=args)
    
    result = {
        "open_ports": [], 
        "http_services": [], 
        "tls_services": [], 
        "hosts": [],
        "vulnerabilities": [] # <--- NSE ውጤቶችን ለማስቀመጥ
    }
    
    for host in nm.all_hosts():
        result["hosts"].append(host)
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                if nm[host][proto][port]['state'] == 'open':
                    service = nm[host][proto][port].get('name', '')
                    
                    result["open_ports"].append({
                        "host": host, "port": port, "service": service
                    })
                    
                    if service in ['http', 'https']:
                        result["http_services"].append(port)
                    if service in ['https', 'ssl'] or port == 443:
                        result["tls_services"].append(port)
                        
                    # --- NSE Output Parsing ---
                    script_output = nm[host][proto][port].get('script', {})
                    if script_output:
                        for script_name, output in script_output.items():
                            # የውጤቱን መጠን እንገድብ (ለ JSON እና AI እንዳይከብድ)
                            clean_output = str(output)[:500]
                            result["vulnerabilities"].append({
                                "host": host,
                                "port": port,
                                "script": script_name,
                                "output": clean_output
                            })
    return result
