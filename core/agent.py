import yaml
import ipaddress
import logging
import os
from datetime import datetime
from modules import (recon_nmap, exploit_msf, web_burp, pqc_checker, 
                     honeypot_gen, threat_intel, domain_recon)
from core import llm, reporter


def _setup_logger():
    os.makedirs("logs", exist_ok=True)
    log_file = "logs/agent_" + datetime.now().strftime("%Y%m%d") + ".log"
    logger = logging.getLogger("autonomous_agent")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(log_file)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setLevel(logging.WARNING)
    logger.addHandler(sh)
    return logger


class AutonomousAgent:
    def __init__(self, config_path="config/settings.yaml"):
        self.config_path = config_path
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)
        self.authorized = self.config["target"]["authorized_ips"]
        self.log = _setup_logger()
        self.log.info("Agent initialized")

    def _is_ip(self, target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def _is_authorized(self, target_ip):
        try:
            target = ipaddress.ip_address(target_ip)
            for net in self.authorized:
                try:
                    if target in ipaddress.ip_network(net):
                        return True
                except ValueError:
                    self.log.warning("Invalid network format in config: " + str(net))
            return False
        except ValueError:
            try:
                target_net = ipaddress.ip_network(target_ip, strict=False)
            except ValueError:
                self.log.error("Invalid target: " + target_ip)
                return False
            for net in self.authorized:
                try:
                    if target_net.subnet_of(ipaddress.ip_network(net)):
                        return True
                except ValueError:
                    self.log.warning("Invalid network format in config: " + str(net))
            return False

    def think(self, user_query):
        prompt = (
            "You are a security agent. Analyze this request and respond with "
            "EXACTLY ONE word: 'full_scan' or 'deploy_honeypot' or 'help'.\n"
            "Request: " + user_query + "\nAnswer:"
        )
        response = llm.query(prompt, self.config_path).strip().lower()
        if "honeypot" in response:
            return "deploy_honeypot"
        return "full_scan"

    def explain(self, results):
        summary = "A security scan completed with the following findings:\n"
        nmap = results.get("nmap", {})
        summary += "- Open ports: " + str(len(nmap.get("open_ports", []))) + "\n"
        for p in nmap.get("open_ports", [])[:10]:
            summary += "  * Port " + str(p["port"]) + " (" + p["service"] + ")\n"
        msf = results.get("msf", {})
        summary += "- Exploit candidates: " + str(msf.get("count", 0)) + "\n"
        
        if "ai_threat_analysis" in results:
            summary += "- AI Threat Analysis: " + results["ai_threat_analysis"] + "\n"

        prompt = (
            "You are a security analyst. Write a brief 3-5 sentence "
            "security assessment:\n\n" + summary
        )
        return llm.query(prompt, self.config_path)

    def execute(self, target_ip, user_intent="full_scan"):
        self.log.info("Starting scan: target=" + target_ip + " intent=" + user_intent)

        # --- 1. Resolve Domain First ---
        original_target = target_ip
        if not self._is_ip(target_ip):
            print("[*] Target is a domain. Resolving to IP...")
            resolved_ip = domain_recon.resolve_domain(target_ip)
            if not resolved_ip:
                return {"error": "Could not resolve domain: " + target_ip}
            print(f"[✓] Resolved {target_ip} to {resolved_ip}")
            target_ip = resolved_ip

        # --- 2. Check Authorization ---
        if not self._is_authorized(target_ip):
            self.log.warning("Unauthorized target: " + target_ip)
            return {"error": f"Resolved IP ({target_ip}) for {original_target} is not authorized. Add it to config/settings.yaml"}

        results = {}
        if original_target != target_ip:
            results["domain"] = original_target
            results["resolved_ip"] = target_ip
            print("[*] Enumerating subdomains...")
            results["subdomains"] = domain_recon.scan_subdomains(original_target)

        # --- 3. Main Scan Sequence ---
        print("[1/6] Running Nmap reconnaissance...")
        results["nmap"] = recon_nmap.run_scan(target_ip)

        if results["nmap"].get("open_ports"):
            print("[2/6] Checking Metasploit exploits...")
            results["msf"] = exploit_msf.check_exploits(target_ip, results["nmap"]["open_ports"])
            
            print("[3/6] Fetching global Threat Intelligence...")
            threats = threat_intel.fetch_latest_cves(limit=5)
            results["threat_intel"] = threats
            
            # --- 4. COMBINED AI PROMPT (Threat Analysis + Remediation) ---
            print("[4/6] AI generating combined threat analysis & remediation (Fast Mode)...")
            context = "=== SCAN RESULTS ===\n"
            for port in results["nmap"].get("open_ports", []):
                context += f"Host: {port['host']} | Port: {port['port']} | Service: {port['service']}\n"
            
            combined_prompt = f"""
            You are an elite Cybersecurity AI.
            Based on the scan results below, provide two things clearly separated:
            1. A 2-sentence Threat Analysis.
            2. A brief 3-step Remediation Plan.
            Keep the total response under 150 words.

            {context}
            """
            
            ai_response = llm.query(combined_prompt, self.config_path)
            
            # የመጣውን መልስ በሁለቱም ቁልፎች ስር እናስቀምጥ (ለ UI እና PDF)
            results["ai_threat_analysis"] = ai_response
            results["remediation_plan"] = "Please refer to the AI Analysis section for the remediation steps."
        else:
            print("[2/6] No open ports - skipping MSF")
            print("[3/6] No open ports - skipping AI Threat Analysis")
            print("[4/6] No open ports - skipping Remediation")

        if results["nmap"].get("http_services"):
            print("[5/6] Running Burp web scan...")
            results["burp"] = []
            for host in results["nmap"].get("hosts", [target_ip])[:5]:
                results["burp"].append({"host": host, "result": web_burp.scan_web(host)})
        else:
            print("[5/6] No HTTP - skipping Burp")

        if self.config["pqc"]["enabled"] and results["nmap"].get("tls_services"):
            print("[6/6] Checking PQC...")
            results["pqc"] = []
            for host in results["nmap"].get("hosts", [target_ip])[:5]:
                results["pqc"].append({"host": host, "result": pqc_checker.check_tls(host)})
        else:
            print("[6/6] No TLS - skipping PQC")

        if user_intent == "deploy_honeypot":
            print("[+] Deploying honeypot...")
            results["honeypot"] = honeypot_gen.deploy_deception_network(target_ip)

        self.log.info("Scan complete")
        return results

    def report(self, results, target):
        # 1. Generate JSON & HTML
        path_json = reporter.generate(results, target)
        
        # 2. Generate PDF
        from modules import pdf_reporter
        try:
            path_pdf = pdf_reporter.generate_pdf(results, target)
            print(f"[✓] PDF Report saved to: {path_pdf}")
        except Exception as e:
            print(f"[!] Failed to generate PDF: {e}")

        self.log.info("Reports saved: " + path_json)
        return path_json
