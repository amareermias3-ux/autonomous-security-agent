import streamlit as st
import json
import os
import glob
from datetime import datetime
import yaml
import altair as alt
import pandas as pd

# ─── Page Config ───
st.set_page_config(
    page_title="Autonomous Security Agent",
    page_icon="🛡️",
    layout="wide",
)

# ─── Authentication Logic ───
with open("config/settings.yaml") as f:
    config = yaml.safe_load(f)
    
DASHBOARD_PASS = config.get("dashboard", {}).get("password", "admin123")

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("🔒 Secure Login")
    st.markdown("Please enter the dashboard password to access the security agent.")
    password = st.text_input("Password", type="password")
    if st.button("Login", type="primary"):
        if password == DASHBOARD_PASS:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("❌ Invalid Password")
    st.stop()  # Stops the rest of the app from loading

# ─── Main App (If Authenticated) ───
st.title("🛡️ Autonomous Security Agent")
st.caption("Multi-host pentest dashboard · For authorized testing only")

# ─── Sidebar ───
st.sidebar.header("🔧 Scan Control")

if st.sidebar.button("Logout"):
    st.session_state.authenticated = False
    st.rerun()

with st.sidebar.form("scan_form"):
    target = st.text_input("Target (IP or CIDR)", "192.168.8.1")
    intent = st.selectbox("Intent", ["full_scan", "deploy_honeypot"])
    use_llm = st.checkbox("LLM assessment (Ollama)", value=False)
    submitted = st.form_submit_button("🚀 Start Scan", type="primary")

if submitted:
    if not target:
        st.sidebar.error("Enter a target")
    else:
        st.session_state["scan_target"] = target
        st.session_state["scan_intent"] = intent
        st.session_state["scan_llm"] = use_llm
        # Clear previous results to trigger a fresh scan
        st.session_state.pop("scan_result", None)
        st.session_state.pop("scan_explain", None)
        st.session_state.pop("scan_report", None)
        st.rerun()

# ─── Run Scan ───
if "scan_target" in st.session_state and "scan_result" not in st.session_state:
    from core.agent import AutonomousAgent
    with st.spinner("Scanning " + st.session_state["scan_target"] + "... Please wait."):
        try:
            agent = AutonomousAgent()
            results = agent.execute(
                st.session_state["scan_target"],
                st.session_state["scan_intent"],
            )
            st.session_state["scan_result"] = results
            
            if st.session_state.get("scan_llm"):
                with st.spinner("Asking LLM for assessment..."):
                    st.session_state["scan_explain"] = agent.explain(results)
            
            report_path = agent.report(results, st.session_state["scan_target"])
            st.session_state["scan_report"] = report_path
        except Exception as e:
            st.error("Scan failed: " + str(e))

# ─── Show Current Scan ───
if "scan_result" in st.session_state:
    results = st.session_state["scan_result"]
    st.subheader("📊 Current Scan: " + st.session_state["scan_target"])

    nmap = results.get("nmap", {})
    msf = results.get("msf", {})

    # Metrics row
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Hosts", len(nmap.get("hosts", [])))
    c2.metric("Open Ports", len(nmap.get("open_ports", [])))
    c3.metric("HTTP Services", len(nmap.get("http_services", [])))
    c4.metric("Exploit Candidates", msf.get("count", 0))

    # --- NEW: Risk Visualization Chart ---
    st.markdown("### 📊 Risk Distribution")
    chart_data = pd.DataFrame({
        "Category": ["Open Ports", "HTTP Services", "Exploit Candidates"],
        "Count": [len(nmap.get("open_ports", [])), len(nmap.get("http_services", [])), msf.get("count", 0)]
    })
    
    # Create a bar chart using Altair
    chart = alt.Chart(chart_data).mark_bar(color="#ff4b4b").encode(
        x=alt.X('Category', sort=None, axis=alt.Axis(labelAngle=0)),
        y='Count',
        tooltip=['Category', 'Count']
    ).properties(height=250)
    
    st.altair_chart(chart, width="stretch")
    st.divider()
    # LLM assessment
    if "scan_explain" in st.session_state:
        st.info("🤖 **LLM Assessment**\n\n" + st.session_state["scan_explain"])

    # Tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["🔍 Ports", "💣 Exploits", "🚨 NSE Vulns", "🧠 AI Threat Intel", "🛠️ Remediation", "🔐 TLS/PQC", "📄 Raw JSON"])
    with tab1:
        ports = nmap.get("open_ports", [])
        if ports:
            # Show table
            st.dataframe(ports, width="stretch")
            
            # --- NEW: Port Distribution Pie Chart ---
            df_ports = pd.DataFrame(ports)
            if not df_ports.empty and 'service' in df_ports.columns:
                st.markdown("#### Port Services Distribution")
                service_counts = df_ports['service'].value_counts().reset_index()
                service_counts.columns = ['Service', 'Count']
                
                pie_chart = alt.Chart(service_counts).mark_arc(innerRadius=50).encode(
                    theta=alt.Theta(field="Count", type="quantitative"),
                    color=alt.Color(field="Service", type="nominal"),
                    tooltip=['Service', 'Count']
                ).properties(height=300)
                
                st.altair_chart(pie_chart, width="stretch")
        else:
            st.info("No open ports found")
    with tab2:
        cands = msf.get("candidates", [])
        if cands:
            display = []
            for c in cands:
                display.append({
                    "Service": c.get("service", ""),
                    "Hosts": ", ".join(c.get("hosts", [])),
                    "Ports": ", ".join(str(p) for p in c.get("ports", [])),
                    "Exploit": c.get("exploit", ""),
                    "Score": c.get("score", 0),
                })
            st.dataframe(display, width="stretch")
        else:
            st.info("No exploit candidates")
    with tab3:
        vulns = nmap.get("vulnerabilities", [])
        if vulns:
            st.warning(f"Found {len(vulns)} potential vulnerabilities via Nmap NSE.")
            for v in vulns:
                with st.expander(f"Port {v['port']} - {v['script']}"):
                    st.code(v['output'], language="text")
        else:
            st.success("No vulnerabilities detected by NSE scripts (or NSE is disabled).")
    with tab3:
        st.subheader("🤖 AI Security Assessment")
        ai_text = results.get("ai_threat_analysis", "No AI analysis available.")
        st.info(ai_text)
        
        st.subheader("🌍 Latest Threat Intelligence (CVEs)")
        intel = results.get("threat_intel", [])
        if isinstance(intel, list) and intel:
            for item in intel:
                st.markdown(f"**{item['id']}** (CVSS: {item['cvss']})")
                st.caption(item['summary'])
        else:
            st.warning("No threat intel data found.")

    with tab4:
        st.subheader("🛠️ Automated Remediation Plan")
        rem = results.get("remediation_plan", "No remediation plan generated.")
        st.markdown(rem)

    with tab5:
        pqc = results.get("pqc", [])
        if isinstance(pqc, list) and pqc:
            for item in pqc:
                host = item.get("host", "?")
                res = item.get("result", {})
                info = res.get("tls_info") or res.get("error") or ""
                with st.expander("Host: " + host):
                    st.code(info, language="text")
        else:
            st.info("No TLS data")

    with tab6:
        st.json(results)

    if "scan_report" in st.session_state:
        st.success("📄 Report saved: " + st.session_state["scan_report"])

    if st.button("🔄 Clear and start over"):
        for k in ["scan_target", "scan_intent", "scan_result", "scan_explain", "scan_report"]:
            st.session_state.pop(k, None)
        st.rerun()

# ─── Previous Reports ───
st.divider()
st.subheader("📁 Previous Reports")
reports = sorted(glob.glob("output/report_*.json"), reverse=True)[:10]

if not reports:
    st.info("No previous reports found.")
else:
    for r in reports:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write("**" + os.path.basename(r) + "**")
            try:
                with open(r) as f:
                    data = json.load(f)
                s = data.get("summary", {})
                st.caption(
                    "Hosts: " + str(s.get("hosts", 0))
                    + " · Ports: " + str(s.get("open_ports", 0))
                    + " · Exploits: " + str(s.get("exploit_candidates", 0))
                )
            except Exception:
                st.caption("(could not read)")
        with col2:
            html_file = r.replace(".json", ".html")
            if os.path.exists(html_file):
                st.write("🌐 HTML available")
