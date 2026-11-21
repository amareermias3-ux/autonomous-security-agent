from core import llm

def generate_remediation(nmap_results, msf_results, ai_analysis, config_path="config/settings.yaml"):
    """
    Uses LLM to generate a self-healing script based on scan and threat intel.
    """
    if not nmap_results.get("open_ports"):
        return "✅ No open ports found. System appears secure based on current scan."

    context = "=== SCAN RESULTS ===\n"
    for port in nmap_results["open_ports"]:
        context += f"Host: {port['host']} | Port: {port['port']} | Service: {port['service']}\n"

    context += "\n=== AI THREAT ANALYSIS ===\n"
    context += ai_analysis + "\n"

    prompt = f"""
    You are an elite Cybersecurity Engineer (DevSecOps). 
    Based on the target scan and threat analysis below, write a remediation plan.
    
    CRITICAL RULES:
    1. The target might be a Linux Server, Windows Machine, OR a Network Router/IoT device.
    2. If it looks like a router (e.g., Huawei, Cisco, MikroTik), provide network-level firewall rules (e.g., iptables, router ACLs) instead of OS-specific commands like apt-get.
    3. Do NOT hallucinate commands. If unsure, provide general security advice (e.g., "Disable unused ports via the router's admin panel").
    4. Format as Markdown with clear steps.

    {context}
    
    ### Remediation Plan:
    """

    print("[*] AI is generating automated remediation scripts...")
    response = llm.query(prompt, config_path).strip()
    return response
