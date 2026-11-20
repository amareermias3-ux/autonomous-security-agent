import requests
import yaml
import time

def scan_web(target_ip):
    with open("config/settings.yaml") as f:
        cfg = yaml.safe_load(f)

    api_key = cfg["burp"].get("api_key", "")
    if not api_key or api_key == "YOUR_BURP_API_KEY":
        return {"skipped": "Burp API key not configured"}

    base = cfg["burp"]["api_url"]
    headers = {"Authorization": "Bearer " + api_key}
    scan_url = "http://" + target_ip

    try:
        resp = requests.post(base + "/v0.1/scan",
                             json={"urls": [scan_url]},
                             headers=headers, timeout=10)
    except requests.exceptions.ConnectionError:
        return {"skipped": "Burp REST API not running"}
    except Exception as e:
        return {"error": "Burp request failed: " + str(e)}

    if resp.status_code != 200:
        return {"error": "Burp API HTTP " + str(resp.status_code)}

    task_id = resp.json().get("task_id")
    if not task_id:
        return {"error": "No task_id returned"}

    for _ in range(10):
        time.sleep(5)
        try:
            status = requests.get(base + "/v0.1/scan/" + task_id,
                                  headers=headers, timeout=10).json()
        except Exception as e:
            return {"error": "Polling failed: " + str(e)}
        if status.get("status") == "completed":
            return status
    return {"error": "Scan timed out"}
