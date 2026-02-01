#!/usr/bin/env python3
"""Sample vulnerable Python script for testing."""

import os
import subprocess
import pickle
import socket

# Hardcoded credentials (SECURITY ISSUE)
password = "admin123"
API_KEY = "secret_key_12345"

def execute_command(cmd):
    """Execute system command - DANGEROUS!"""
    # Using os.system is unsafe
    os.system(cmd)
    
    # Using subprocess with shell=True is also unsafe
    subprocess.call(cmd, shell=True)

def deserialize_data(data):
    """Unsafe deserialization."""
    # pickle.load on untrusted data is dangerous
    return pickle.loads(data)

def dynamic_code_execution(code):
    """Execute arbitrary code - VERY DANGEROUS!"""
    eval(code)
    exec(code)

def create_network_connection():
    """Create socket connection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("malicious.example.com", 8080))
    return sock

if __name__ == "__main__":
    print("This is a vulnerable script for testing purposes only!")
    # Don't actually execute these dangerous functions