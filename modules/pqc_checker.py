import subprocess
import re

def check_tls(target_ip):
    cmd = [
        "openssl", "s_client",
        "-connect", target_ip + ":443",
        "-brief",
        "-servername", target_ip,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            input="", 
        )
        output = (result.stdout or "") + (result.stderr or "")
        output = output.strip()

        # --- Quantum Threat Analysis ---
        threat_level = "SAFE"
        threat_reason = "Unknown or unparseable TLS configuration."
        
        if "Peer Temp Key: X25519" in output or "secp256r1" in output or "prime256v1" in output:
            threat_level = "CRITICAL"
            threat_reason = "Uses classical ECDHE (X25519/prime256v1). Vulnerable to Shor's algorithm (Quantum Computers)."
        elif "Peer Temp Key: X448" in output or "secp384r1" in output:
            threat_level = "WARNING"
            threat_reason = "Uses stronger classical ECDHE. Still theoretically vulnerable to future quantum computers."
        elif "ML-KEM" in output or "Kyber" in output or "PQC" in output:
            threat_level = "SAFE"
            threat_reason = "Uses Post-Quantum Cryptography (Hybrid). Safe from quantum attacks."
        elif "CONNECTION ESTABLISHED" in output:
            threat_level = "WARNING"
            threat_reason = "Connection established but temporary key info not found."
        elif "timed out" in output.lower() or "error" in output.lower() and "Connection" not in output:
             threat_level = "UNKNOWN"
             threat_reason = "Could not establish TLS handshake."

        return {
            "raw_info": output if output else "(no output)",
            "threat_level": threat_level,
            "threat_reason": threat_reason
        }
    except subprocess.TimeoutExpired:
        return {"error": "TLS handshake timed out", "threat_level": "UNKNOWN"}
    except FileNotFoundError:
        return {"error": "openssl not installed", "threat_level": "UNKNOWN"}
    except Exception as e:
        return {"error": "TLS check failed: " + str(e), "threat_level": "UNKNOWN"}
