import argparse
import json
from core.agent import AutonomousAgent

def main():
    parser = argparse.ArgumentParser(description="Autonomous Security Agent")
    parser.add_argument("target", nargs="?", help="Target IP or domain")
    parser.add_argument("--intent", default="full_scan",
                        choices=["full_scan", "deploy_honeypot"])
    parser.add_argument("--ask", help="Natural language query (uses LLM)")
    parser.add_argument("--explain", action="store_true",
                        help="Use LLM to explain results")
    args = parser.parse_args()

    agent = AutonomousAgent()

    # Natural language mode
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

    print("[*] Starting assessment on " + args.target)
    results = agent.execute(args.target, args.intent)

    print("\n[+] Results:")
    print(json.dumps(results, indent=2, ensure_ascii=False))

    # Save report
    report_file = agent.report(results, args.target)
    print("\n[✓] Report saved to: " + report_file)

    # LLM explanation
    if args.explain:
        print("\n[*] LLM Security Assessment:")
        print(agent.explain(results))

if __name__ == "__main__":
    main()
