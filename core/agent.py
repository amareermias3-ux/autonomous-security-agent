import yaml
import ipaddress
import logging
import os
import concurrent.futures
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
    def _scan_single_target(self, target_ip):
        """Runs the scan logic for a single IP/Domain (Used for multi-threading)"""
        self.log.info(f"Starting parallel scan for: {target_ip}")
        
        # Authorization check
        if not self._is_authorized(target_ip):
            return {"target": target_ip, "error": "Not authorized"}

        res = {}
        print(f"[*] Scanning {target_ip}...")
        
        # 1. Nmap
        res["nmap"] = recon_nmap.run_scan(target_ip)
        
        # 2. MSF & AI
        if res["nmap"].get("open_ports"):
            res["msf"] = exploit_msf.check_exploits(target_ip, res["nmap"]["open_ports"])
            
            threats = threat_intel.fetch_latest_cves(limit=3)
            res["threat_intel"] = threats
            
            context = f"=== SCAN RESULTS for {target_ip} ===\n"
            for port in res["nmap"].get("open_ports", []):
                context += f"Port: {port['port']} | Service: {port['service']}\n"
            
            vulns = res["nmap"].get("vulnerabilities", [])
            if vulns:
                context += "\nNSE FINDINGS:\n"
                for v in vulns:
                    context += f"- {v['script']} on port {v['port']}\n"

            combined_prompt = f"You are an AI. Provide a 2-sentence Threat Analysis and a 3-step Remediation Plan for this scan. Keep under 100 words.\n\n{context}"
            ai_response = llm.query(combined_prompt, self.config_path)
            res["ai_threat_analysis"] = ai_response
            res["remediation_plan"] = "See AI Analysis."
        else:
            res["msf"] = {"candidates": [], "count": 0}
            res["ai_threat_analysis"] = "No open ports found."
            res["remediation_plan"] = "N/A"

        # 3. PQC
        if self.config["pqc"]["enabled"] and res["nmap"].get("tls_services"):
            res["pqc"] = [{"host": target_ip, "result": pqc_checker.check_tls(target_ip)}]
            
        return {"target": target_ip, "data": res}
    def execute(self, target_input, user_intent="full_scan"):
        self.log.info("Starting scan sequence: target=" + target_input)

        # 1. Parse targets (Comma separated or CIDR)
        targets_to_scan = []
        
        # If it's a domain, resolve it
        if not self._is_ip(target_input) and "/" not in target_input:
            print(f"[*] Resolving domain: {target_input}")
            resolved = domain_recon.resolve_domain(target_input)
            if not resolved:
                return {"error": f"Could not resolve {target_input}"}
            targets_to_scan = [resolved]
        elif "/" in target_input:
            # It's a CIDR, Nmap can handle it directly, but let's just pass it to Nmap for speed
            print(f"[*] CIDR range detected: {target_input}. Nmap will handle the expansion.")
            targets_to_scan = [target_input]
        else:
            # It's a single or comma-separated IP list
            targets_to_scan = [ip.strip() for ip in target_input.split(",") if ip.strip()]

        all_results = {}
        
        # If it's a single target, run normally to keep backward compatibility
        if len(targets_to_scan) == 1:
            single_res = self._scan_single_target(targets_to_scan[0])
            if "error" in single_res:
                return single_res
            return single_res["data"]

        # --- Multi-Target Execution ---
        print(f"[*] Starting parallel scan for {len(targets_to_scan)} targets...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(self._scan_single_target, t): t for t in targets_to_scan}
            
            for future in concurrent.futures.as_completed(futures):
                target_ip = futures[future]
                try:
                    res = future.result()
                    all_results[target_ip] = res.get("data", res)
                except Exception as exc:
                    print(f"[!] Target {target_ip} generated an exception: {exc}")
                    all_results[target_ip] = {"error": str(exc)}
                    
        return all_results
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
