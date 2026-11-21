import requests
import json
import os

CACHE_FILE = "logs/threat_cache.json"

def fetch_latest_cves(limit=10):
    url = "https://cve.circl.lu/api/last"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            cves = []
            for item in data[:limit]:
                # CVSS Score logic
                cvss = "N/A"
                if "cvss3" in item and item["cvss3"]:
                    cvss = item["cvss3"].get("baseScore", "N/A")
                elif "cvss" in item and item["cvss"]:
                    cvss = item["cvss"]

                                # Summary logic (handling different API sources)
                summary = item.get("summary") or item.get("title") or item.get("description")
                if not summary:
                    summary = "Detailed description not provided."
                    # If it's a list (some sources return lists), take the first item
                    if isinstance(item.get("summary", []), list) and len(item["summary"]) > 0:
                        summary = item["summary"][0]
                    else:
                        summary = "Detailed description not provided by source."

                cves.append({
                    "id": item.get("id", "Unknown"),
                    "summary": summary,
                    "cvss": cvss
                })
            
            os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
            with open(CACHE_FILE, "w") as f:
                json.dump(cves, f, indent=2)
            return cves
            
    except Exception as e:
        print("[!] Network issue: " + str(e))
        print("[*] Attempting to load from local cache...")

    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            print("[✓] Loaded threat intel from local cache.")
            return json.load(f)

    return [{"id": "Offline", "summary": "No network or cache available.", "cvss": "N/A"}]

def print_threats():
    print("[*] Fetching latest global threat intelligence...")
    cves = fetch_latest_cves(5)
    for cve in cves:
        print("\n🔥 " + cve["id"] + " (CVSS: " + str(cve["cvss"]) + ")")
        print("   " + str(cve["summary"])[:200] + "...")

if __name__ == "__main__":
    print_threats()
