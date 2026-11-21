import yaml
from core import llm

def analyze_threats(nmap_results, threat_intel_results, config_path="config/settings.yaml"):
    """
    Takes Nmap scan results and recent Threat Intel, asks LLM to correlate them.
    """
    if not nmap_results.get("open_ports"):
        return "No open ports to analyze."

    # 1. Prepare the context for the AI
    context = "=== TARGET SCAN RESULTS ===\n"
    for port in nmap_results["open_ports"]:
        context += f"Host: {port['host']} | Port: {port['port']} | Service: {port['service']}\n"

    context += "\n=== RECENT GLOBAL THREAT INTELLIGENCE (CVEs) ===\n"
    for cve in threat_intel_results:
        context += f"- {cve['id']} (CVSS {cve['cvss']}): {cve['summary'][:150]}...\n"

    # 2. The Prompt (Shortened for CPU speed)
    prompt = f"""
    You are a Cybersecurity AI. 
    Here are the target open ports:
    {context}
    
    Based on the port names (e.g., http, ssh), write a brief 2-sentence risk assessment. Do not list CVEs.
    
    AI Assessment:
    """ 

    # 3. Ask the LLM
    print("[*] AI is correlating scan results with global threats...")
    response = llm.query(prompt, config_path).strip()
    
    return response
