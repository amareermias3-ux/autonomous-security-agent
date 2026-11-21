import argparse
import json
import time
import sys
from core.agent import AutonomousAgent
from modules import monitor, alerts
import yaml

def run_monitor(agent, target):
    with open("config/settings.yaml") as f:
        cfg = yaml.safe_load(f)
    interval = cfg.get("monitor", {}).get("interval_minutes", 60) * 60
    
    print(f"[*] Starting Continuous Monitoring for {target} every {interval//60} minutes.")
    print("[*] Press Ctrl+C to stop.")
    
    try:
        while True:
            print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] Running scheduled scan on {target}...")
            
            # Run Nmap only for monitoring (faster)
            from modules import recon_nmap
            nmap_results = recon_nmap.run_scan(target)
            
            # Compare with previous
            old_state = monitor.get_previous_state(target)
            alert_msg = monitor.compare_states(old_state, nmap_results, target)
            
            if alert_msg:
                print("[!] Changes detected!")
                alerts.send_telegram_alert(alert_msg)
                # Save the new state
                monitor.save_current_state(target, nmap_results)
            else:
                if not old_state:
                    print("[*] Baseline scan completed. Saving initial state.")
                    monitor.save_current_state(target, nmap_results)
                else:
                    print("[✓] No changes detected. Network is stable.")
                    
            print(f"[*] Sleeping for {interval//60} minutes...")
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n[!] Continuous Monitoring stopped by user.")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Autonomous Security Agent")
    parser.add_argument("target", nargs="?", help="Target IP or domain")
    parser.add_argument("--intent", default="full_scan", choices=["full_scan", "deploy_honeypot"])
    parser.add_argument("--ask", help="Natural language query (uses LLM)")
    parser.add_argument("--explain", action="store_true", help="Use LLM to explain results")
    parser.add_argument("--monitor", action="store_true", help="Run continuous background monitoring")
    args = parser.parse_args()

    agent = AutonomousAgent()

    if args.ask:
        intent = agent.think(args.ask)
        print("[*] LLM interpreted intent: " + intent)
        if not args.target:
            print("[!] Please provide a target IP")
            return
        intent = args.intent if args.intent != "full_scan" else intent

    if not args.target:
        parser.print_help()
        return

    # --- New Monitor Mode ---
    if args.monitor:
        run_monitor(agent, args.target)
        return

    # --- Standard Single Scan Mode ---
    print("[*] Starting assessment on " + args.target)
    results = agent.execute(args.target, args.intent)

    print("\n[+] Results:")
    print(json.dumps(results, indent=2, ensure_ascii=False))

    report_file = agent.report(results, args.target)
    print("\n[✓] Report saved to: " + report_file)

    if args.explain:
        print("\n[*] LLM Security Assessment:")
        print(agent.explain(results))

if __name__ == "__main__":
    main()
