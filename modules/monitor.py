import json
import os

STATE_DIR = "logs/state"

def get_previous_state(target_ip):
    os.makedirs(STATE_DIR, exist_ok=True)
    safe_target = target_ip.replace(".", "_").replace("/", "_")
    state_file = f"{STATE_DIR}/{safe_target}.json"
    
    if os.path.exists(state_file):
        with open(state_file, "r") as f:
            return json.load(f)
    return None

def save_current_state(target_ip, nmap_results):
    os.makedirs(STATE_DIR, exist_ok=True)
    safe_target = target_ip.replace(".", "_").replace("/", "_")
    state_file = f"{STATE_DIR}/{safe_target}.json"
    
    with open(state_file, "w") as f:
        json.dump(nmap_results, f, indent=2)

def compare_states(old_state, new_state, target_ip):
    """Compares old and new Nmap results, returns alert message if changes exist."""
    if not old_state:
        return None  # First run, no alert needed
        
    old_ports = {p['port'] for p in old_state.get("open_ports", [])}
    new_ports = {p['port'] for p in new_state.get("open_ports", [])}
    
    new_opened = new_ports - old_ports
    new_closed = old_ports - new_ports
    
    if not new_opened and not new_closed:
        return None  # No changes
        
    msg = f"🚨 *Security Alert for {target_ip}* 🚨\n\n"
    if new_opened:
        msg += "⚠️ *New Open Ports Detected:*\n"
        for port in new_opened:
            service = next((p['service'] for p in new_state['open_ports'] if p['port'] == port), 'Unknown')
            msg += f"  - Port {port} ({service})\n"
            
    if new_closed:
        msg += "\n✅ *Ports Closed:*\n"
        for port in new_closed:
            msg += f"  - Port {port}\n"
            
    return msg
