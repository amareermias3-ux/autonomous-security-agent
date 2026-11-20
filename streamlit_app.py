import streamlit as st
import json
import os
import glob
from datetime import datetime

st.set_page_config(
    page_title="Autonomous Security Agent",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Autonomous Security Agent")
st.caption("Multi-host pentest dashboard · For authorized testing only")

# ─── Sidebar ───
st.sidebar.header("🔧 Scan Control")
target = st.sidebar.text_input("Target (IP or CIDR)", "192.168.8.1")
intent = st.sidebar.selectbox("Intent", ["full_scan", "deploy_honeypot"])
use_llm = st.sidebar.checkbox("LLM assessment (Ollama)", value=False)

if st.sidebar.button("🚀 Start Scan", type="primary"):
    if not target:
        st.sidebar.error("Enter a target")
    else:
        st.session_state["scan_target"] = target
        st.session_state["scan_intent"] = intent
        st.session_state["scan_llm"] = use_llm
        st.rerun()

# ─── Run scan ───
if "scan_target" in st.session_state and "scan_result" not in st.session_state:
    from core.agent import AutonomousAgent
    with st.spinner("Scanning " + st.session_state["scan_target"] + "..."):
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

# ─── Show current scan ───
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

    # LLM assessment
    if "scan_explain" in st.session_state:
        st.info("🤖 **LLM Assessment**\n\n" + st.session_state["scan_explain"])

    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Ports", "💣 Exploits", "🔐 TLS/PQC", "📄 Raw JSON"])

    with tab1:
        ports = nmap.get("open_ports", [])
        if ports:
            st.dataframe(ports, width="stretch")
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

    with tab4:
        st.json(results)

    if "scan_report" in st.session_state:
        st.success("📄 Report saved: " + st.session_state["scan_report"])

    if st.button("🔄 Clear and start over"):
        for k in ["scan_target", "scan_intent", "scan_result", "scan_explain", "scan_report"]:
            st.session_state.pop(k, None)
        st.rerun()

# ─── Previous reports ───
st.divider()
st.subheader("📁 Previous Reports")
reports = sorted(glob.glob("output/report_*.json"), reverse=True)[:20]

if not reports:
    st.info("No reports yet")
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
