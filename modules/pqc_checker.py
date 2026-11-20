import subprocess


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
            timeout=8,
            input="",  # close stdin immediately
        )
        output = (result.stdout or "") + (result.stderr or "")
        output = output.strip()
        if not output:
            return {"tls_info": "(no output - handshake may have failed)"}
        return {"tls_info": output}
    except subprocess.TimeoutExpired:
        return {"error": "TLS handshake timed out"}
    except FileNotFoundError:
        return {"error": "openssl not installed"}
    except Exception as e:
        return {"error": "TLS check failed: " + str(e)}
