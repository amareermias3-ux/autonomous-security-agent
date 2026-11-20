import json
import os
import html
from datetime import datetime


def generate(results, target, output_dir="output"):
    """Generate both JSON and HTML reports. Returns JSON path."""
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace("/", "_").replace(":", "_")
    base = output_dir + "/report_" + safe_target + "_" + ts

    report = {
        "target": target,
        "timestamp": ts,
        "summary": _summarize(results),
        "results": results,
    }

    json_path = base + ".json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    html_path = base + ".html"
    with open(html_path, "w") as f:
        f.write(_to_html(report))

    return json_path


def _summarize(results):
    s = {}
    nmap = results.get("nmap", {})
    s["open_ports"] = len(nmap.get("open_ports", []))
    s["http_services"] = len(nmap.get("http_services", []))
    s["tls_services"] = len(nmap.get("tls_services", []))
    s["hosts"] = len(nmap.get("hosts", []))

    msf = results.get("msf", {})
    s["exploit_candidates"] = msf.get("count", 0)

    if "burp" in results:
        burp = results["burp"]
        if isinstance(burp, list):
            s["burp_hosts"] = len(burp)
        else:
            s["burp_scan"] = "completed" if "error" not in burp else "failed"

    if "pqc" in results:
        pqc = results["pqc"]
        if isinstance(pqc, list):
            s["pqc_hosts"] = len(pqc)
        else:
            s["pqc_checked"] = True

    if "honeypot" in results:
        s["honeypot"] = results["honeypot"].get("status", "?")

    return s


def _esc(v):
    return html.escape(str(v))


def _to_html(report):
    target = _esc(report["target"])
    ts = _esc(report["timestamp"])
    summary = report["summary"]
    results = report["results"]
    nmap = results.get("nmap", {})
    msf = results.get("msf", {})

    # Port rows
    port_rows = ""
    for p in nmap.get("open_ports", []):
        port_rows += (
            "<tr><td>" + _esc(p.get("host", "?")) + "</td>"
            "<td>" + _esc(p["port"]) + "</td>"
            "<td>" + _esc(p["service"]) + "</td></tr>"
        )
    if not port_rows:
        port_rows = "<tr><td colspan='3'>No open ports</td></tr>"

    # Exploit rows
    exp_rows = ""
    for e in msf.get("candidates", []):
        ports = ", ".join(str(x) for x in e.get("ports", []))
        hosts = ", ".join(e.get("hosts", []))
        score = e.get("score", 0)
        color = "#3fb950" if score >= 25 else "#d29922" if score >= 10 else "#8b949e"
        exp_rows += (
            "<tr><td>" + _esc(e.get("service", "")) + "</td>"
            "<td>" + _esc(hosts) + "</td>"
            "<td>" + _esc(ports) + "</td>"
            "<td><code>" + _esc(e["exploit"]) + "</code></td>"
            "<td><span style='color:" + color + ";font-weight:bold'>"
            + _esc(score) + "</span></td></tr>"
        )
    if not exp_rows:
        exp_rows = "<tr><td colspan='5'>No exploit candidates</td></tr>"

    # PQC rows
    pqc_rows = ""
    pqc = results.get("pqc", [])
    if isinstance(pqc, list):
        for item in pqc:
            host = _esc(item.get("host", "?"))
            res = item.get("result", {})
            info = res.get("tls_info") or res.get("error") or ""
            pqc_rows += (
                "<tr><td>" + host + "</td>"
                "<td><pre style='margin:0;font-size:.8em;white-space:pre-wrap'>"
                + _esc(info) + "</pre></td></tr>"
            )
    if not pqc_rows:
        pqc_rows = "<tr><td colspan='2'>No TLS data</td></tr>"

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Report — """ + target + """</title>
<style>
  body { font-family: -apple-system, Segoe UI, sans-serif;
         background:#0d1117; color:#c9d1d9; margin:0; padding:2rem; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { color:#58a6ff; border-bottom:2px solid #30363d; padding-bottom:.5rem; }
  h2 { color:#79c0ff; margin-top:2rem; }
  .meta { color:#8b949e; font-size:.9rem; }
  .cards { display:flex; gap:1rem; flex-wrap:wrap; margin:1rem 0; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:8px;
          padding:1rem 1.5rem; min-width:130px; }
  .card .num { font-size:2rem; font-weight:bold; color:#58a6ff; }
  .card .lbl { color:#8b949e; font-size:.85rem; }
  table { width:100%; border-collapse:collapse; margin:1rem 0; }
  th { background:#161b22; color:#79c0ff; text-align:left;
       padding:.6rem; border-bottom:2px solid #30363d; }
  td { padding:.5rem .6rem; border-bottom:1px solid #21262d;
       vertical-align:top; }
  code { background:#161b22; padding:2px 6px; border-radius:4px;
         color:#ffa657; font-size:.85em; }
  pre { background:#161b22; padding:.5rem; border-radius:4px;
        color:#c9d1d9; }
  .footer { color:#8b949e; text-align:center; margin-top:3rem;
            font-size:.8rem; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ Security Assessment Report</h1>
  <p class="meta">
    <strong>Target:</strong> """ + target + """ &nbsp;|&nbsp;
    <strong>Date:</strong> """ + ts + """
  </p>

  <h2>📊 Summary</h2>
  <div class="cards">
    <div class="card"><div class="num">""" + str(summary.get("hosts", 0)) + """</div><div class="lbl">Hosts</div></div>
    <div class="card"><div class="num">""" + str(summary.get("open_ports", 0)) + """</div><div class="lbl">Open Ports</div></div>
    <div class="card"><div class="num">""" + str(summary.get("http_services", 0)) + """</div><div class="lbl">HTTP Services</div></div>
    <div class="card"><div class="num">""" + str(summary.get("tls_services", 0)) + """</div><div class="lbl">TLS Services</div></div>
    <div class="card"><div class="num">""" + str(summary.get("exploit_candidates", 0)) + """</div><div class="lbl">Exploit Candidates</div></div>
  </div>

  <h2>🔍 Open Ports</h2>
  <table>
    <thead><tr><th>Host</th><th>Port</th><th>Service</th></tr></thead>
    <tbody>""" + port_rows + """</tbody>
  </table>

  <h2>💣 Exploit Candidates</h2>
  <table>
    <thead><tr><th>Service</th><th>Hosts</th><th>Ports</th><th>Exploit</th><th>Score</th></tr></thead>
    <tbody>""" + exp_rows + """</tbody>
  </table>

  <h2>🔐 TLS / PQC Analysis</h2>
  <table>
    <thead><tr><th>Host</th><th>TLS Info</th></tr></thead>
    <tbody>""" + pqc_rows + """</tbody>
  </table>

  <div class="footer">
    Generated by Autonomous Security Agent · For authorized testing only
  </div>
</div>
</body>
</html>"""
