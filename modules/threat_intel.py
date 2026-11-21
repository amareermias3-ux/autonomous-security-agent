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
            for item in data[:limit]:
                # CVSS Score logic
                cvss = "N/A"
                if isinstance(item, dict):
                    if item.get("cvss3"):
                        cvss = item["cvss3"].get("baseScore", "N/A")
                    elif item.get("cvss"):
                        cvss = item["cvss"]

                    # Summary logic
                    summary = item.get("summary") or item.get("title") or item.get("description") or "No description provided."
                else:
                    summary = str(item) # Fallback if item is not a dict

                cves.append({
                    "id": item.get("id", "Unknown") if isinstance(item, dict) else "Unknown",
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
