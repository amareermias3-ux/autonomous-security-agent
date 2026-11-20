import socket
import threading

def _fake_ssh_server(port=2222):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    while True:
        conn, addr = server.accept()
        conn.send(b"SSH-2.0-OpenSSH_8.9p1\r\n")
        conn.close()

def deploy_deception_network(target_subnet):
    t = threading.Thread(target=_fake_ssh_server, args=(2222,), daemon=True)
    t.start()
    return {"status": "honeypot_active", "port": 2222}
