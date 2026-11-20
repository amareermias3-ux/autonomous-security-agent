import sys
import time
from modules.honeypot_gen import _fake_ssh_server

port = int(sys.argv[1]) if len(sys.argv) > 1 else 2222
print("Starting honeypot on port " + str(port) + "...")
print("Press Ctrl+C to stop.")
try:
    _fake_ssh_server(port)
except KeyboardInterrupt:
    print("\nHoneypot stopped.")
