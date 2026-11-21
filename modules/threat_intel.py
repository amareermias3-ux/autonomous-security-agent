import requests
import json
import os

CACHE_FILE = "logs/threat_cache.json"

# Fallback data if network fails and no cache exists
FALLBACK_CVES = [
    {"id": "CVE-2024-0001", "summary": "Offline Mode: Simulated critical vulnerability in network stack.", "cvss": 9.8},
    {"id": "CVE-2024-0002", "summary": "Offline Mode: Simulated authentication bypass in web server.", "cvss": 8.5}
]

def fetch_latest_cves(limit=10):
    """Fetch the latest CVEs with caching and offline fallback."""
    url = "https://cve.circl.lu/api/last"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            cves = []
            for item in data[:limit]:
                cvss = "N/A"
                if "cvss3" in item and item["cvss3"]:
                    cvss = item["cvss3"].get("baseScore", "N/A")
                elif "cvss" in item and item["cvss"]:
                    cvss = item["cvss"]

                cves.append({
                    "id": item.get("id", "Unknown"),
                    "summary": item.get("summary", "No summary available."),
                    "cvss": cvss
                })
            
            # Save to cache
            os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
            with open(CACHE_FILE, "w") as f:
                json.dump(cves, f, indent=2)
            return cves
            
    except Exception as e:
        print("[!] Network issue: " + str(e))
        print("[*] Attempting to load from local cache...")

    # Fallback to cache
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            print("[✓] Loaded threat intel from local cache.")
            return json.load(f)

    # Ultimate fallback
    print("[!] No cache found. Using simulated offline data.")
    return FALLBACK_CVES

def print_threats():
    """Utility to print threat intel to CLI."""
    print("[*] Fetching latest global threat intelligence...")
    cves = fetch_latest_cves(5)
    
    if isinstance(cves, dict) and "error" in cves:
        print("[!] " + cves["error"])
        return

    for cve in cves:
        print("\n🔥 " + cve["id"] + " (CVSS: " + str(cve["cvss"]) + ")")
        print("   " + cve["summary"][:200] + "...")

if __name__ == "__main__":
    print_threats()
