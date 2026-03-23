#!/usr/bin/env python3
import base64
import os

# Obfuscated payload (harmless)
encoded = "cHJpbnQoIkhlbGxvIFdvcmxkIik="
decoded = base64.b64decode(encoded).decode()

# Suspicious-like execution
exec(decoded)

# Fake persistence simulation
with open("startup_simulation.txt", "w") as f:
    f.write("This simulates persistence behavior")

# Dummy system interaction
os.system("echo Simulating system command")