import requests
import yaml

def send_telegram_alert(message, config_path="config/settings.yaml"):
    """Sends a message to a Telegram chat using the Bot API."""
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        
        token = cfg.get("monitor", {}).get("telegram", {}).get("bot_token")
        chat_id = cfg.get("monitor", {}).get("telegram", {}).get("chat_id")
        
        if not token or token == "YOUR_TELEGRAM_BOT_TOKEN_HERE":
            print("[!] Telegram not configured. Skipping alert.")
            return False
            
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id, 
            "text": message,
            "parse_mode": "Markdown"
        }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            print("[✓] Telegram alert sent successfully.")
            return True
        else:
            print("[!] Failed to send Telegram alert: HTTP " + str(response.status_code))
            return False
    except Exception as e:
        print("[!] Alert error: " + str(e))
        return False
