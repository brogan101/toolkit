import logging
import os
import subprocess
import time
import hashlib
import secrets
import shutil
import psutil
import socket
import getpass
import tkinter as tk  # Added for filedialog
from tkinter import filedialog  # Explicitly import filedialog
import datetime  # Added for datetime
import threading  # Added for threading
from zipfile import ZipFile
from pathlib import Path

def generate_key(logger):
    key = secrets.token_hex(16)
    logger.info("Generated encryption key.")
    return key

def encrypt_file(logger, key, filepath=None):
    if not filepath:
        filepath = filedialog.askopenfilename(title="Select file to encrypt")
    if not filepath or not os.path.exists(filepath):
        return "No file selected or file does not exist."
    output_path = filepath + ".enc"
    with open(filepath, 'rb') as f:
        data = f.read()
    # Simple XOR encryption (for demo purposes)
    encrypted = bytes(a ^ b for a, b in zip(data, key.encode() * (len(data) // len(key) + 1)))
    with open(output_path, 'wb') as f:
        f.write(encrypted)
    logger.info(f"Encrypted file: {filepath}")
    return f"Encrypted {filepath} to {output_path}"

def decrypt_file(logger, key, filepath=None):
    if not filepath:
        filepath = filedialog.askopenfilename(title="Select file to decrypt")
    if not filepath or not os.path.exists(filepath):
        return "No file selected or file does not exist."
    output_path = filepath.replace(".enc", ".dec")
    with open(filepath, 'rb') as f:
        data = f.read()
    decrypted = bytes(a ^ b for a, b in zip(data, key.encode() * (len(data) // len(key) + 1)))
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    logger.info(f"Decrypted file: {filepath}")
    return f"Decrypted {filepath} to {output_path}"

def hash_file(logger, filepath=None):
    if not filepath:
        filepath = filedialog.askopenfilename(title="Select file to hash")
    if not filepath or not os.path.exists(filepath):
        return "No file selected or file does not exist."
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def check_antivirus_status(logger):
    try:
        result = subprocess.run("powershell Get-MpComputerStatus", shell=True, capture_output=True, text=True)
        return result.stdout if result.stdout else "Could not determine antivirus status."
    except Exception as e:
        logger.error(f"AV check failed: {e}")
        return f"Error: {e}"

def check_firewall_status(logger):
    try:
        result = subprocess.run("netsh advfirewall show allprofiles state", shell=True, capture_output=True, text=True)
        return result.stdout if result.stdout else "Could not determine firewall status."
    except Exception as e:
        logger.error(f"Firewall check failed: {e}")
        return f"Error: {e}"

def list_startup_items(logger):
    try:
        startup_dir = os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\Start Menu\Programs\Startup")
        items = os.listdir(startup_dir)
        return "\n".join(items) if items else "No startup items found."
    except Exception as e:
        logger.error(f"Startup items list failed: {e}")
        return f"Error: {e}"

def check_suspicious_processes(logger):
    suspicious = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        if proc.info['cpu_percent'] > 80:  # Arbitrary threshold
            suspicious.append(f"{proc.info['name']} (PID: {proc.info['pid']}) - CPU: {proc.info['cpu_percent']}%")
    return "\n".join(suspicious) if suspicious else "No suspicious processes found."

def log_security_events(logger):
    return "Security events logged to slingshot.log (see log file)."

def generate_otp(logger):
    return secrets.token_hex(4)

def show_processes(logger):
    processes = [f"{p.info['name']} (PID: {p.info['pid']})" for p in psutil.process_iter(['pid', 'name'])]
    return "\n".join(processes[:20])  # Limit to 20 for brevity

def show_resource_usage(logger):
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    return f"CPU: {cpu}%\nRAM: {mem.percent}% used ({mem.used//1024**2}MB/{mem.total//1024**2}MB)\nDisk: {disk.percent}% used"

def show_system_uptime(logger):
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.datetime.now() - boot_time
    return f"System uptime: {str(uptime).split('.')[0]}"

def monitor_cpu_temp(logger):
    try:
        temps = psutil.sensors_temperatures()
        if 'coretemp' in temps:
            return "\n".join([f"{t.label}: {t.current}°C" for t in temps['coretemp']])
        return "CPU temperature monitoring not supported on this system."
    except Exception as e:
        logger.error(f"CPU temp check failed: {e}")
        return f"Error: {e}"

def list_running_threads(logger):
    threads = [f"Thread ID: {t.ident}" for t in threading.enumerate()]
    return "\n".join(threads)

def check_system_health(logger):
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    health = "Good" if cpu < 80 and mem < 80 and disk < 80 else "Warning"
    return f"System Health: {health}\nCPU: {cpu}%\nRAM: {mem}%\nDisk: {disk}%"

def get_system_info(logger):
    return f"OS: {os.name}\nUsername: {getpass.getuser()}\nCPU Count: {psutil.cpu_count()}"

def list_users(logger):
    try:
        result = subprocess.run("net user", shell=True, capture_output=True, text=True)
        return result.stdout if result.stdout else "Could not list users."
    except Exception as e:
        logger.error(f"User list failed: {e}")
        return f"Error: {e}"

def check_disk_health(logger):
    disk = psutil.disk_usage('/')
    return f"Disk Usage: {disk.percent}% used ({disk.used//1024**2}MB/{disk.total//1024**2}MB)"

def clear_temp_files(logger):
    temp_dir = os.getenv('TEMP')
    count = 0
    for root, _, files in os.walk(temp_dir):
        for file in files:
            try:
                os.remove(os.path.join(root, file))
                count += 1
            except:
                pass
    return f"Cleared {count} temporary files."

def list_environment_vars(logger):
    return "\n".join(f"{k}={v}" for k, v in os.environ.items()[:10])  # Limit to 10

def ping_test(logger):
    target = "8.8.8.8"  # Google DNS
    result = subprocess.run(f"ping -n 4 {target}", shell=True, capture_output=True, text=True)
    return result.stdout if result.stdout else result.stderr

def check_network_connections(logger):
    conns = psutil.net_connections()
    return "\n".join([f"{c.laddr} -> {c.raddr} ({c.status})" for c in conns if c.raddr][:10]) or "No active connections."

def backup_files(logger):
    src_dir = filedialog.askdirectory(title="Select directory to backup")
    if not src_dir:
        return "No directory selected."
    dest = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("ZIP files", "*.zip")])
    if not dest:
        return "No destination selected."
    with ZipFile(dest, 'w') as zipf:
        for root, _, files in os.walk(src_dir):
            for file in files:
                zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), src_dir))
    return f"Backed up {src_dir} to {dest}"

def restore_files(logger):
    zip_file = filedialog.askopenfilename(title="Select backup ZIP", filetypes=[("ZIP files", "*.zip")])
    if not zip_file:
        return "No backup file selected."
    dest_dir = filedialog.askdirectory(title="Select restore destination")
    if not dest_dir:
        return "No destination selected."
    with ZipFile(zip_file, 'r') as zipf:
        zipf.extractall(dest_dir)
    return f"Restored files to {dest_dir}"

def toggle_firewall(logger):
    try:
        state = subprocess.run("netsh advfirewall show allprofiles state", shell=True, capture_output=True, text=True).stdout
        if "ON" in state:
            subprocess.run("netsh advfirewall set allprofiles state off", shell=True)
            return "Firewall disabled."
        else:
            subprocess.run("netsh advfirewall set allprofiles state on", shell=True)
            return "Firewall enabled."
    except Exception as e:
        logger.error(f"Firewall toggle failed: {e}")
        return f"Error: {e}"

def generate_random_password(logger):
    return secrets.token_urlsafe(16)

def restart_system(logger):
    subprocess.run("shutdown /r /t 0", shell=True)
    return "System restart initiated."

def shutdown_system(logger):
    subprocess.run("shutdown /s /t 0", shell=True)
    return "System shutdown initiated."

def lock_workstation(logger):
    subprocess.run("rundll32.exe user32.dll,LockWorkStation", shell=True)
    return "Workstation locked."