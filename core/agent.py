import yaml
import ipaddress
import logging
import os
from datetime import datetime
from modules import recon_nmap, exploit_msf, web_burp, pqc_checker, honeypot_gen, threat_intel, ai_analyzer, remediation
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
    def _is_ip(self, target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
        return llm.query(prompt, self.config_path)

    def execute(self, target_ip, user_intent="full_scan"):
        self.log.info("Starting scan: target=" + target_ip + " intent=" + user_intent)

        if not self._is_authorized(target_ip):
            self.log.warning("Unauthorized target: " + target_ip)
            return {"error": "Target " + target_ip + " is not authorized."}

        results = {}

        print("[1/6] Running Nmap reconnaissance...")
        results["nmap"] = recon_nmap.run_scan(target_ip)

        if results["nmap"].get("open_ports"):
            print("[2/6] Checking Metasploit exploits...")
            results["msf"] = exploit_msf.check_exploits(target_ip, results["nmap"]["open_ports"])
            
            print("[3/6] Fetching global Threat Intelligence & AI Analysis...")
            threats = threat_intel.fetch_latest_cves(limit=5)
            results["threat_intel"] = threats
            
            ai_assessment = ai_analyzer.analyze_threats(results["nmap"], threats, self.config_path)
            results["ai_threat_analysis"] = ai_assessment

            print("[4/6] AI generating automated remediation plan...")
            rem_plan = remediation.generate_remediation(
                results["nmap"], results["msf"], ai_assessment, self.config_path
            )
            results["remediation_plan"] = rem_plan
        else:
            print("[2/6] No open ports - skipping MSF")
            print("[3/6] No open ports - skipping AI Threat Analysis")

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
        # --- NEW: Domain Resolution ---
        original_target = target_ip
        if not self._is_ip(target_ip):
            print("[*] Target is a domain. Resolving to IP...")
            from modules import domain_recon
            resolved_ip = domain_recon.resolve_domain(target_ip)
            if not resolved_ip:
                return {"error": "Could not resolve domain: " + target_ip}
            print(f"[✓] Resolved {target_ip} to {resolved_ip}")
            
            # Check if the resolved IP is authorized
            if not self._is_authorized(resolved_ip):
                return {"error": f"Resolved IP ({resolved_ip}) is not in authorized_ips."}
            
            target_ip = resolved_ip
            results = {"domain": original_target, "resolved_ip": resolved_ip}
            
            # Run subdomain enumeration
            subs = domain_recon.scan_subdomains(original_target)
            results["subdomains"] = subs
        else:
            results = {}
        # ------------------------------
        return results

    def report(self, results, target):
        path = reporter.generate(results, target)
        self.log.info("Report saved: " + path)
        return path
