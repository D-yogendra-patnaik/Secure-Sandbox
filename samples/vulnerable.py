#!/usr/bin/env python3

import os
import subprocess
import pickle
import socket

password = "admin123"
API_KEY = "secret_key_12345"

def execute_command(cmd):
    os.system(cmd)
    
    subprocess.call(cmd, shell=True)

def deserialize_data(data):
    return pickle.loads(data)

def dynamic_code_execution(code):
    eval(code)
    exec(code)

def create_network_connection():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("malicious.example.com", 8080))
    return sock

if __name__ == "__main__":
    print("This is a vulnerable script for testing purposes only!")