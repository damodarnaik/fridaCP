"""
Frida Childs Play - Configuration
"""
import os

# Server Settings
HOST = "0.0.0.0"
PORT = 5000
DEBUG = False

# Device Monitoring
DEVICE_POLL_INTERVAL = 2  # seconds

# Frida Settings
FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
FRIDA_GITHUB_API = "https://api.github.com/repos/frida/frida/releases/latest"
FRIDA_DOWNLOAD_URL = "https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{arch}.xz"

# ADB Settings
ADB_TIMEOUT = 10  # seconds
ADB_LONG_TIMEOUT = 30  # for file operations

# File Operations
DOWNLOAD_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "downloads")

# Architecture Mapping
ARCH_MAP = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}

# Ensure download directory exists
os.makedirs(DOWNLOAD_DIRECTORY, exist_ok=True)
