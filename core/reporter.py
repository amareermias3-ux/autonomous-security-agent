import json
import os
from datetime import datetime

def generate(results, target, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace("/", "_").replace(":", "_")
    filename = output_dir + "/report_" + safe_target + "_" + ts + ".json"

    report = {
        "target": target,
        "timestamp": ts,
        "summary": _summarize(results),
        "results": results,
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return filename

def _summarize(results):
    s = {}
    nmap = results.get("nmap", {})
    s["open_ports"] = len(nmap.get("open_ports", []))
    s["http_services"] = len(nmap.get("http_services", []))
    s["tls_services"] = len(nmap.get("tls_services", []))

    msf = results.get("msf", {})
    s["exploit_candidates"] = msf.get("count", 0)

    if "burp" in results:
        s["burp_scan"] = "completed" if "error" not in results["burp"] else "failed"

    if "pqc" in results:
        s["pqc_checked"] = True

    return s
