import yaml
import ipaddress
import logging
import os
from datetime import datetime
from modules import recon_nmap, exploit_msf, web_burp, pqc_checker, honeypot_gen
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
                if target in ipaddress.ip_network(net):
                    return True
            return False
        except ValueError:
            try:
                target_net = ipaddress.ip_network(target_ip, strict=False)
            except ValueError:
                self.log.error("Invalid target: " + target_ip)
                return False
            for net in self.authorized:
                if target_net.subnet_of(ipaddress.ip_network(net)):
                    return True
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
        prompt = (
            "You are a security analyst. Write a brief 3-5 sentence "
            "security assessment:\n\n" + summary
        )
        return llm.query(prompt, self.config_path)

    def execute(self, target_ip, user_intent="full_scan"):
        self.log.info("Starting scan: target=" + target_ip +
                      " intent=" + user_intent)

        if not self._is_authorized(target_ip):
            self.log.warning("Unauthorized target: " + target_ip)
            return {"error": "Target " + target_ip + " is not authorized."}

        results = {}

        print("[1/4] Running Nmap reconnaissance...")
        self.log.info("Running nmap")
        results["nmap"] = recon_nmap.run_scan(target_ip)
        self.log.info("Nmap: " + str(len(results["nmap"].get("open_ports", []))) + " ports")

        # Collect individual hosts for per-host modules
        is_cidr = "/" in target_ip
        if is_cidr:
            hosts = results["nmap"].get("hosts", [])
            if not hosts:
                hosts = [target_ip]
        else:
            hosts = [target_ip]

        if results["nmap"].get("open_ports"):
            print("[2/4] Checking Metasploit exploits...")
            self.log.info("Checking MSF")
            results["msf"] = exploit_msf.check_exploits(
                target_ip, results["nmap"]["open_ports"])
            self.log.info("MSF: " + str(results["msf"].get("count", 0)) + " candidates")
        else:
            print("[2/4] No open ports - skipping MSF")
            self.log.info("Skipping MSF (no ports)")

        if results["nmap"].get("http_services"):
            print("[3/4] Running Burp web scan...")
            self.log.info("Running Burp")
            burp_results = []
            for host in hosts[:5]:
                burp_results.append({
                    "host": host,
                    "result": web_burp.scan_web(host)
                })
            results["burp"] = burp_results
        else:
            print("[3/4] No HTTP - skipping Burp")
            self.log.info("Skipping Burp")

        if self.config["pqc"]["enabled"] and results["nmap"].get("tls_services"):
            print("[4/4] Checking PQC...")
            self.log.info("Running PQC")
            pqc_results = []
            for host in hosts[:5]:
                pqc_results.append({
                    "host": host,
                    "result": pqc_checker.check_tls(host)
                })
            results["pqc"] = pqc_results
        else:
            print("[4/4] No TLS - skipping PQC")
            self.log.info("Skipping PQC")

        if user_intent == "deploy_honeypot":
            print("[+] Deploying honeypot...")
            self.log.info("Deploying honeypot")
            results["honeypot"] = honeypot_gen.deploy_deception_network(target_ip)

        self.log.info("Scan complete")
        return results

    def report(self, results, target):
        path = reporter.generate(results, target)
        self.log.info("Report saved: " + path)
        return path
