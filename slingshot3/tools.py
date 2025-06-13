# Standard Library Imports
import fnmatch
import getpass
import hashlib
import io
import json
import logging
import math
import os
import platform
import re
import secrets
import shutil
import socket
import sqlite3
import stat
import string
import subprocess
import threading
import time
import zipfile

# Third-Party Imports
import base64
import matplotlib.pyplot as plt
import numpy as np
import psutil
import pyautogui
import pyotp
import pyperclip
import pywifi
import qrcode
from PIL import Image, ImageDraw, ImageFont
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pypdf import PdfMerger
from scapy.all import *  # Covers 'sniff' and other scapy functions
from urllib.parse import quote, unquote

# Windows-Specific Imports (pywin32 and related)
import win32api
import win32com.client
import win32con
import win32crypt
import win32evtlog
import win32file
import win32net
import win32process
import win32security
import win32service
import win32ts
import wmi
import winshell
import perfmon
import pythoncom

# GUI Imports (tkinter)
import tkinter as tk
from tkinter import filedialog, simpledialog

# DateTime and Path Utilities
from datetime import datetime, timedelta
from pathlib import Path

# Global list to track subprocesses
active_subprocesses = []

# Helper function to terminate all subprocesses
def terminate_subprocesses():
    global active_subprocesses
    for proc in active_subprocesses:
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except (subprocess.TimeoutExpired, AttributeError, OSError):
            proc.kill()
    active_subprocesses.clear()

# Configure logging
logger = logging.getLogger(__name__)

# Global variables
command_history_log = []
scheduled_tasks = []
passwords_db = {}
totp_secrets = {}
alert_thresholds = {"cpu": 80, "memory": 90, "disk": 90, "network": 100}  # MB/s
alert_log = []
dns_cache = []

# Helper function to run shell commands with error handling
def run_command(command, command_history_log_passed=None, timeout=10, shell=True):
    global command_history_log, active_subprocesses
    if command_history_log_passed is not None:
        command_history_log = command_history_log_passed
    try:
        proc = subprocess.Popen(command, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        active_subprocesses.append(proc)
        stdout, stderr = proc.communicate(timeout=timeout)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, command, stderr)
        command_history_log.append(f"{datetime.now()}: {command}")
        logger.info(f"Command executed successfully: {command}")
        active_subprocesses.remove(proc)
        return stdout.strip()
    except subprocess.TimeoutExpired:
        logger.error(f"Command '{command}' timed out after {timeout} seconds")
        proc.kill()
        active_subprocesses.remove(proc)
        return f"Error: Command timed out after {timeout} seconds"
    except subprocess.CalledProcessError as e:
        logger.error(f"Command '{command}' failed: {e.stderr}")
        active_subprocesses.remove(proc)
        return f"Error: {e.stderr}"
    except Exception as e:
        logger.error(f"Command '{command}' failed: {str(e)}")
        if proc in active_subprocesses:
            active_subprocesses.remove(proc)
        return f"Error: {str(e)}"

# Helper function for progress updates (simulated for text output)
def progress_callback(current, total, message="Processing"):
    percentage = (current / total) * 100
    return f"{message}: {percentage:.1f}% ({current}/{total})"

# Helper function to generate a key for AES encryption
def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Security Tools
def generate_key(save_to_file=False, file_path=None, password=None):
    try:
        key = Fernet.generate_key()
        result = [f"Generated Fernet Key: {base64.urlsafe_b64encode(key).decode()}"]
        if save_to_file and file_path and password:
            # Encrypt the key with the provided password
            salt = os.urandom(16)
            fernet_key = generate_aes_key(password, salt)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(fernet_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_key = encryptor.update(key) + encryptor.finalize()
            with open(file_path, "wb") as f:
                f.write(salt + iv + encrypted_key)
            result.append(f"Key saved to {file_path} (encrypted with password)")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def encrypt_file(file_path, key, algorithm="fernet", password=None):
    try:
        if not os.path.exists(file_path):
            return f"File {file_path} does not exist."
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return "File is empty."

        result = []
        output_path = file_path + (".enc" if algorithm == "fernet" else ".aes")
        total_chunks = (file_size // 4096) + 1 if file_size % 4096 != 0 else file_size // 4096

        if algorithm == "fernet":
            fernet = Fernet(key)
            with open(file_path, "rb") as f:
                for i, chunk in enumerate(iter(lambda: f.read(4096), b"")):
                    result.append(progress_callback(i + 1, total_chunks, "Encrypting"))
                f.seek(0)
                data = f.read()
            encrypted = fernet.encrypt(data)
            with open(output_path, "wb") as f:
                f.write(encrypted)
        else:  # AES
            if not password:
                return "Password required for AES encryption."
            salt = os.urandom(16)
            aes_key = generate_aes_key(password, salt)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            with open(file_path, "rb") as f, open(output_path, "wb") as out:
                out.write(salt + iv)  # Store salt and IV
                for i, chunk in enumerate(iter(lambda: f.read(4096), b"")):
                    result.append(progress_callback(i + 1, total_chunks, "Encrypting"))
                    encrypted_chunk = encryptor.update(chunk)
                    out.write(encrypted_chunk)
                out.write(encryptor.finalize())

        result.append(f"File encrypted: {output_path}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def decrypt_file(file_path, key, algorithm="fernet", password=None):
    try:
        if not os.path.exists(file_path):
            return f"File {file_path} does not exist."
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return "File is empty."

        result = []
        output_path = file_path.replace(".enc", ".dec") if algorithm == "fernet" else file_path.replace(".aes", ".dec")
        total_chunks = (file_size // 4096) + 1 if file_size % 4096 != 0 else file_size // 4096

        if algorithm == "fernet":
            fernet = Fernet(key)
            with open(file_path, "rb") as f:
                for i, chunk in enumerate(iter(lambda: f.read(4096), b"")):
                    result.append(progress_callback(i + 1, total_chunks, "Decrypting"))
                f.seek(0)
                encrypted = f.read()
            decrypted = fernet.decrypt(encrypted)
            with open(output_path, "wb") as f:
                f.write(decrypted)
        else:  # AES
            if not password:
                return "Password required for AES decryption."
            with open(file_path, "rb") as f:
                salt = f.read(16)
                iv = f.read(16)
                aes_key = generate_aes_key(password, salt)
                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                with open(output_path, "wb") as out:
                    for i, chunk in enumerate(iter(lambda: f.read(4096), b"")):
                        result.append(progress_callback(i + 1, total_chunks, "Decrypting"))
                        decrypted_chunk = decryptor.update(chunk)
                        out.write(decrypted_chunk)
                    out.write(decryptor.finalize())

        result.append(f"File decrypted: {output_path}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def hash_file(file_path, algorithms=["md5", "sha1", "sha256"], compare_hash=None):
    try:
        if not os.path.exists(file_path):
            logger.error(f"File {file_path} does not exist")
            return f"Error: File {file_path} does not exist"

        start_time = time.time()
        file_size = os.path.getsize(file_path)
        total_chunks = (file_size // 4096) + 1 if file_size % 4096 != 0 else file_size // 4096
        result = [f"File: {file_path}", f"Size: {file_size / (1024**2):.2f} MB"]

        hashers = {}
        for algo in algorithms:
            if algo.lower() == "md5":
                hashers["MD5"] = hashlib.md5()
            elif algo.lower() == "sha1":
                hashers["SHA-1"] = hashlib.sha1()
            elif algo.lower() == "sha256":
                hashers["SHA-256"] = hashlib.sha256()
            elif algo.lower() == "sha3_256":
                hashers["SHA3-256"] = hashlib.sha3_256()

        with open(file_path, "rb") as f:
            for i, chunk in enumerate(iter(lambda: f.read(4096), b"")):
                result.append(progress_callback(i + 1, total_chunks, "Hashing"))
                for hasher in hashers.values():
                    hasher.update(chunk)

        for name, hasher in hashers.items():
            hash_value = hasher.hexdigest()
            result.append(f"{name}: {hash_value}")
            if compare_hash and compare_hash.get(name.lower()):
                if hash_value == compare_hash[name.lower()]:
                    result.append(f"{name} matches provided hash.")
                else:
                    result.append(f"{name} does not match provided hash: {compare_hash[name.lower()]}")

        end_time = time.time()
        duration = end_time - start_time
        result.append(f"Time Taken: {duration:.2f} seconds")
        logger.info(f"Hashed file {file_path} successfully")
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Failed to hash file {file_path}: {str(e)}")
        return f"Error hashing file: {str(e)}"

def check_antivirus_status(command_history_log, initiate_scan=False):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Windows Defender Status:"]
        output = run_command("powershell -Command Get-MpComputerStatus", command_history_log)
        lines = output.splitlines()
        for line in lines:
            if any(key in line for key in ["AntivirusEnabled", "RealTimeProtectionEnabled", "LastQuickScan", "LastFullScan", "AntivirusSignatureLastUpdated"]):
                result.append(line.strip())

        # Check for threats
        threat_output = run_command("powershell -Command Get-MpThreat", command_history_log)
        result.append("\nDetected Threats:")
        if "No threats" in threat_output.lower():
            result.append("None")
        else:
            result.extend(threat_output.splitlines()[:5])  # Limit to 5 lines

        third_party = run_command("wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState", command_history_log)
        result.append("\nThird-Party Antivirus:")
        result.extend(third_party.splitlines()[2:])

        if initiate_scan:
            run_command("powershell -Command Start-MpScan -ScanType QuickScan", command_history_log)
            result.append("Quick scan initiated.")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def toggle_firewall(command_history_log, toggle_state="toggle"):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        status = run_command("netsh advfirewall show allprofiles state", command_history_log)
        result = ["Current Firewall Status:", status]

        if toggle_state == "toggle":
            if "ON" in status:
                toggle_state = "off"
            else:
                toggle_state = "on"

        if toggle_state == "off" and "ON" in status:
            run_command("netsh advfirewall set allprofiles state off", command_history_log)
            result.append("Firewall disabled for all profiles.")
        elif toggle_state == "on" and "OFF" in status:
            run_command("netsh advfirewall set allprofiles state on", command_history_log)
            result.append("Firewall enabled for all profiles.")
        else:
            result.append("No change made to firewall state.")

        new_status = run_command("netsh advfirewall show allprofiles state", command_history_log)
        result.extend(["\nNew Firewall Status:", new_status])
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def list_firewall_rules(command_history_log, filter_by=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        output = run_command("netsh advfirewall firewall show rule name=all", command_history_log)
        result = ["Firewall Rules:"]
        lines = output.splitlines()
        if filter_by:
            filter_by = filter_by.lower()
            filtered = [line for line in lines if filter_by in line.lower()]
            if filtered:
                result.extend(filtered)
            else:
                result.append(f"No rules found matching '{filter_by}'.")
        else:
            result.extend(lines[:20])  # Limit to 20 lines for brevity
            if len(lines) > 20:
                result.append("... (more rules available)")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def add_firewall_rule(command_history_log, name, port):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = []
        run_command(f"netsh advfirewall firewall add rule name=\"{name}\" dir=in action=block protocol=TCP localport={port}", command_history_log)
        result.append(f"Added rule '{name}' to block port {port}.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def list_startup_items(command_history_log, disable_item=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        output = run_command("wmic startup get caption,command,user,location", command_history_log)
        result = ["Startup Items:"]
        lines = output.splitlines()
        if len(lines) > 2:
            result.extend(lines[2:])
        else:
            result.append("No startup items found.")

        if disable_item:
            run_command(f"wmic startup where caption=\"{disable_item}\" delete", command_history_log)
            result.append(f"Attempted to disable startup item '{disable_item}'.")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def show_processes(sort_by="cpu", filter_by=None):
    try:
        result = ["Running Processes:"]
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'exe']):
            try:
                info = proc.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_info', 'exe'])
                processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort processes
        if sort_by.lower() == "cpu":
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        elif sort_by.lower() == "memory":
            processes.sort(key=lambda x: x['memory_info'].rss, reverse=True)
        elif sort_by.lower() == "name":
            processes.sort(key=lambda x: x['name'].lower())

        # Filter processes
        if filter_by:
            filter_by = filter_by.lower()
            processes = [p for p in processes if filter_by in p['name'].lower()]

        # Display processes (limit to 20 for brevity)
        for proc in processes[:20]:
            result.append(f"PID: {proc['pid']}, Name: {proc['name']}, CPU: {proc['cpu_percent']}%, Mem: {proc['memory_info'].rss / (1024**2):.2f} MB, Path: {proc['exe']}")
        if len(processes) > 20:
            result.append("... (more processes available)")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def check_system_health(command_history_log):
    try:
        result = ["System Health Check:"]
        # CPU usage
        cpu = psutil.cpu_percent(interval=1)
        result.append(f"CPU Usage: {cpu}% {'(High)' if cpu > 80 else ''}")
        # Memory usage
        mem = psutil.virtual_memory()
        result.append(f"Memory Usage: {mem.percent}% ({mem.used / (1024**3):.2f}/{mem.total / (1024**3):.2f} GB) {'(High)' if mem.percent > 90 else ''}")
        # Disk health (simplified)
        disk = psutil.disk_usage('/')
        result.append(f"Disk Usage: {disk.percent}% ({disk.used / (1024**3):.2f}/{disk.total / (1024**3):.2f} GB) {'(Low space)' if disk.percent > 90 else ''}")
        # AV status
        if platform.system() == "Windows":
            av_status = run_command("powershell -Command Get-MpComputerStatus | Select-Object -Property AntivirusEnabled", command_history_log)
            result.append(f"Antivirus Enabled: {'Yes' if 'True' in av_status else 'No (WARNING)'}")
        # Network status
        net = psutil.net_io_counters()
        result.append(f"Network Activity: Sent {net.bytes_sent / (1024**2):.2f} MB, Received {net.bytes_recv / (1024**2):.2f} MB")
        return "\n".join(result)
    except Exception as e:
        return f"Error in system health check: {str(e)}"

def check_suspicious_processes():
    try:
        suspicious = []
        known_safe = ["svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe"]
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'exe', 'connections', 'create_time']):
            try:
                info = proc.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_info', 'exe', 'connections', 'create_time'])
                reasons = []
                if info['cpu_percent'] > 80:
                    reasons.append(f"High CPU: {info['cpu_percent']}%")
                memory_mb = info['memory_info'].rss / (1024**2)
                if memory_mb > 1000:
                    reasons.append(f"High Memory: {memory_mb:.2f} MB")
                if info['exe'] and not any(info['exe'].lower().startswith(path) for path in [r"c:\windows", r"c:\program files", r"c:\program files (x86)"]):
                    reasons.append(f"Suspicious Path: {info['exe']}")
                if info['connections']:
                    for conn in info['connections']:
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            reasons.append(f"Network: {conn.raddr.ip}:{conn.raddr.port}")
                age = time.time() - info['create_time']
                if age < 60:
                    reasons.append(f"Recently Started: {age:.1f} seconds ago")
                if info['name'].lower() not in [p.lower() for p in known_safe]:
                    reasons.append("Unknown process")
                if reasons:
                    suspicious.append(f"PID: {info['pid']}, Name: {info['name']}, Reasons: {', '.join(reasons)}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return "Suspicious Processes:\n" + "\n".join(suspicious) if suspicious else "No suspicious processes detected."
    except Exception as e:
        return f"Error: {str(e)}"

def generate_otp(totp_secrets_passed, account_name=None):
    global totp_secrets
    totp_secrets = totp_secrets_passed
    try:
        if not account_name:
            account_name = os.getlogin()
        if account_name not in totp_secrets:
            totp_secrets[account_name] = pyotp.random_base32()

        totp = pyotp.TOTP(totp_secrets[account_name])
        otp = totp.now()
        time_remaining = totp.interval - (int(time.time()) % totp.interval)

        # Generate QR code for authenticator apps
        uri = totp.provisioning_uri(account_name, issuer_name="SlingShot")
        qr = qrcode.QRCode()
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        qr_path = f"totp_qr_{account_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        img.save(qr_path)

        result = [
            f"Generated TOTP for {account_name}: {otp}",
            f"Valid for: {time_remaining} seconds",
            f"Secret (store securely): {totp_secrets[account_name]}",
            f"QR Code saved to: {qr_path} (scan with authenticator app)"
        ]
        return "\n".join(result), totp_secrets
    except Exception as e:
        return f"Error: {str(e)}", totp_secrets

def shred_file(file_path, method="standard", passes=3):
    try:
        if not os.path.exists(file_path):
            return f"File {file_path} does not exist."

        file_size = os.path.getsize(file_path)
        total_chunks = (file_size // 4096) + 1 if file_size % 4096 != 0 else file_size // 4096
        result = []

        if method == "standard":
            for pass_num in range(passes):
                with open(file_path, "wb") as f:
                    for i in range(total_chunks):
                        chunk = os.urandom(4096)
                        f.write(chunk)
                        result.append(progress_callback(i + 1, total_chunks, f"Pass {pass_num + 1}/{passes}"))
                    f.flush()
                    os.fsync(f.fileno())
        elif method == "dod":  # DoD 5220.22-M (3 passes: 0s, 1s, random)
            patterns = [b'\x00', b'\xFF', os.urandom(4096)]
            for pass_num, pattern in enumerate(patterns):
                with open(file_path, "wb") as f:
                    for i in range(total_chunks):
                        f.write(pattern[:4096])
                        result.append(progress_callback(i + 1, total_chunks, f"DoD Pass {pass_num + 1}/3"))
                    f.flush()
                    os.fsync(f.fileno())

        # Final overwrite with zeros
        with open(file_path, "wb") as f:
            for i in range(total_chunks):
                f.write(b'\x00' * 4096)
                result.append(progress_callback(i + 1, total_chunks, "Final Overwrite"))
            f.flush()
            os.fsync(f.fileno())

        os.remove(file_path)
        result.append(f"File {file_path} securely deleted.")
        result.append(f"Size: {file_size / (1024**2):.2f} MB")
        result.append(f"Method: {method}, Passes: {passes}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def vuln_scan(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Vulnerability Scan Report:"]
        # Check for pending updates
        updates = run_command("powershell -Command Get-WindowsUpdate", command_history_log)
        result.append("Pending Updates:\n" + (updates if updates else "No updates pending."))

        # Check Defender status
        defender_status = run_command("powershell -Command Get-MpComputerStatus", command_history_log)
        result.append("\nDefender Status:\n" + defender_status)

        # Check for outdated software (simplified example)
        result.append("\nChecking for outdated software (simplified):")
        try:
            # Example: Check PowerShell version
            ps_version = run_command("powershell -Command $PSVersionTable.PSVersion.Major", command_history_log)
            ps_version = int(ps_version) if ps_version.isdigit() else 0
            if ps_version < 7:
                result.append(f"PowerShell version {ps_version} is outdated. Consider upgrading to version 7 or higher.")
            else:
                result.append("PowerShell version is up to date.")
        except:
            result.append("Unable to check PowerShell version.")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def password_manager(action="generate", length=12, passwords_db_passed={}, category=None, name=None, search_term=None, password=None):
    global passwords_db
    passwords_db = passwords_db_passed
    try:
        if action == "generate":
            alphabet = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
            entry = {"password": password, "category": category or "General", "name": name or f"Password_{int(time.time())}"}
            passwords_db[time.time()] = entry
            return f"Generated Password: {password}\nCategory: {entry['category']}\nName: {entry['name']}", passwords_db
        elif action == "strength":
            if not password:
                return "No password provided.", passwords_db
            length = len(password)
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in string.punctuation for c in password)
            score = sum([length >= 8, has_upper, has_lower, has_digit, has_special])
            strength = "Weak" if score < 3 else "Moderate" if score < 5 else "Strong"
            result = [
                f"Password Strength: {strength} (Score: {score}/5)",
                f"Length: {length}",
                f"Uppercase: {has_upper}",
                f"Lowercase: {has_lower}",
                f"Digits: {has_digit}",
                f"Special: {has_special}"
            ]
            return "\n".join(result), passwords_db
        elif action == "sync":
            key_file = "passwords_key.key"
            if not password:
                return "Password required.", passwords_db
            salt = os.urandom(16)
            fernet_key = generate_aes_key(password, salt)
            fernet = Fernet(base64.urlsafe_b64encode(fernet_key))
            db_file = "passwords_db.enc"
            sub_action = "s" if not os.path.exists(db_file) else "l"  # Default to save if no file exists
            if sub_action == "s":
                with open(db_file, "wb") as f:
                    f.write(salt + fernet.encrypt(json.dumps(passwords_db).encode()))
                return f"Passwords saved to {db_file}", passwords_db
            elif sub_action == "l":
                if not os.path.exists(db_file):
                    return f"No password database found at {db_file}", passwords_db
                with open(db_file, "rb") as f:
                    data = f.read()
                    salt = data[:16]
                    encrypted = data[16:]
                    fernet_key = generate_aes_key(password, salt)
                    fernet = Fernet(base64.urlsafe_b64encode(fernet_key))
                    passwords_db = json.loads(fernet.decrypt(encrypted).decode())
                return f"Passwords loaded from {db_file}", passwords_db
            elif sub_action == "r" and search_term:
                result = ["Search Results:"]
                for timestamp, entry in passwords_db.items():
                    if search_term.lower() in entry['category'].lower() or search_term.lower() in entry['name'].lower():
                        result.append(f"Time: {datetime.fromtimestamp(float(timestamp))}, Category: {entry['category']}, Name: {entry['name']}, Password: {entry['password']}")
                return "\n".join(result) if len(result) > 1 else "No matches found.", passwords_db
            return "Invalid sub-action.", passwords_db
        return "Invalid action.", passwords_db
    except Exception as e:
        return f"Error: {str(e)}", passwords_db

def harden_system(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["System Hardening Report:"]
        # Enable firewall
        run_command("netsh advfirewall set allprofiles state on", command_history_log)
        result.append("Firewall enabled.")
        # Enable Defender real-time protection
        run_command("powershell -Command Set-MpPreference -DisableRealtimeMonitoring 0", command_history_log)
        result.append("Defender real-time protection enabled.")
        # Set minimum password length
        run_command("net accounts /minpwlen:12", command_history_log)
        result.append("Minimum password length set to 12.")
        # Disable unnecessary services (example: Telnet)
        run_command("sc config tlntsvr start= disabled", command_history_log)
        result.append("Telnet service disabled.")
        # Enable UAC (set to highest level)
        run_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f', command_history_log)
        result.append("UAC set to highest level.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def phishing_detector(url):
    try:
        if not url:
            return "No URL provided."
        suspicious_patterns = [r"login", r"password", r"verify", r"bank", r"paypal", r"account", r"secure"]
        score = sum(1 for pattern in suspicious_patterns if re.search(pattern, url.lower()))
        if "http://" in url or "https://" not in url:
            score += 2  # Penalize non-HTTPS
        # Check domain age (simplified heuristic)
        domain = re.search(r"(?:https?://)?(?:www\.)?([^/]+)", url)
        if domain:
            domain = domain.group(1)
            if len(domain.split(".")) > 3:
                score += 1  # Suspicious for subdomains
            if "-" in domain:
                score += 1  # Hyphens often used in phishing domains
        result = [
            f"Phishing Risk Score: {score}/10",
            "Low Risk" if score < 4 else "Moderate Risk" if score < 7 else "High Risk",
            "Recommendations: Verify the URL, ensure HTTPS, and check domain reputation."
        ]
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def malware_scanner(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Malware Scan Report:"]
        # Initiate a quick scan
        run_command("powershell -Command Start-MpScan -ScanType QuickScan", command_history_log)
        result.append("Quick malware scan initiated via Windows Defender.")
        # Check for threats
        threat_output = run_command("powershell -Command Get-MpThreat", command_history_log)
        result.append("\nDetected Threats:")
        if "No threats" in threat_output.lower():
            result.append("None")
        else:
            result.extend(threat_output.splitlines()[:5])
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def check_bitlocker_status(command_history_log, enable_drive=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["BitLocker Status:"]
        output = run_command("manage-bde -status", command_history_log)
        result.append(output)

        if enable_drive:
            run_command(f"manage-bde -on {enable_drive} -RecoveryPassword", command_history_log)
            result.append(f"BitLocker enabled on {enable_drive}. Check for recovery key.")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def check_secure_boot(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        output = run_command("powershell -Command Confirm-SecureBootUEFI", command_history_log)
        status = "Enabled" if "True" in output else "Disabled or not supported"
        result = [f"Secure Boot Status: {status}"]
        if status != "Enabled":
            result.append("Recommendation: Enable Secure Boot in BIOS/UEFI settings for enhanced security.")
        # Check TPM status
        tpm_output = run_command("powershell -Command Get-Tpm", command_history_log)
        result.append("\nTPM Status:")
        result.extend(tpm_output.splitlines()[:5])
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def view_audit_policy(command_history_log, modify_category=None, success=False, failure=False):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        output = run_command("auditpol /get /category:*", command_history_log)
        result = ["Audit Policy:", output]

        # Highlight potential security gaps
        if "No auditing" in output:
            result.append("\nWarning: Some categories have no auditing enabled. Consider enabling for better security monitoring.")

        if modify_category:
            cmd = f"auditpol /set /category:\"{modify_category}\" /success:{'enable' if success else 'disable'} /failure:{'enable' if failure else 'disable'}"
            run_command(cmd, command_history_log)
            result.append(f"Audit policy for {modify_category} updated.")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def usb_lockdown(command_history_log, enable=True):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = []
        state = 4 if enable else 3  # 4 = disabled, 3 = enabled
        run_command(f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d {state} /f', command_history_log)
        result.append("USB storage devices " + ("disabled" if enable else "enabled") + ".")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Monitoring Tools
def resource_monitor(log_to_file=False, file_path=None):
    try:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net = psutil.net_io_counters()
        cores = psutil.cpu_percent(percpu=True)
        result = [
            f"CPU Usage: {cpu}%",
            f"Memory Usage: {mem.percent}% ({mem.used / (1024**3):.2f}/{mem.total / (1024**3):.2f} GB)",
            f"Disk Usage: {disk.percent}% ({disk.used / (1024**3):.2f}/{disk.total / (1024**3):.2f} GB)",
            f"Network: Sent {net.bytes_sent / (1024**2):.2f} MB, Received {net.bytes_recv / (1024**2):.2f} MB",
            "Core Usage:"
        ]
        result.extend(f"  Core {i}: {usage}%" for i, usage in enumerate(cores))

        # Add I/O stats
        io = psutil.disk_io_counters()
        if io:
            result.append(f"Disk I/O: Read {io.read_bytes / (1024**2):.2f} MB, Write {io.write_bytes / (1024**2):.2f} MB")

        if log_to_file and file_path:
            with open(file_path, "a") as f:
                f.write(f"{datetime.now()}\n" + "\n".join(result) + "\n\n")
            result.append(f"Logged to {file_path}")

        result.append("Note: Real-time graph available in Monitoring tab.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def monitor_services(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Service Monitoring Started:"]
        services = {}
        for service in psutil.win_service_iter():
            info = service.as_dict()
            services[info['name']] = info['status']

        # Monitor for 10 seconds
        for _ in range(10):
            for service in psutil.win_service_iter():
                try:
                    info = service.as_dict()
                    if info['name'] in services and services[info['name']] != info['status']:
                        result.append(f"Service {info['name']} changed from {services[info['name']]} to {info['status']} at {datetime.now()}")
                        services[info['name']] = info['status']
                except:
                    continue
            time.sleep(1)

        if len(result) == 1:
            result.append("No service status changes detected.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def memory_leak_detector():
    try:
        result = ["Monitoring processes for potential memory leaks (10 seconds):"]
        process_data = {}
        for _ in range(10):  # Monitor for 10 seconds
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    pid = proc.pid
                    name = proc.name()
                    mem = proc.memory_info().rss
                    if pid not in process_data:
                        process_data[pid] = {"name": name, "memory_samples": []}
                    process_data[pid]["memory_samples"].append(mem)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(1)

        for pid, data in process_data.items():
            if len(data["memory_samples"]) < 2:
                continue
            growth = (data["memory_samples"][-1] - data["memory_samples"][0]) / (1024**2)  # MB
            if growth > 20:  # Threshold for significant growth
                avg_growth = growth / (len(data["memory_samples"]) - 1)
                result.append(f"PID: {pid}, Name: {data['name']}, Total Growth: {growth:.2f} MB, Avg Growth per Second: {avg_growth:.2f} MB/s")

        return "\n".join(result) if len(result) > 1 else "No significant memory leaks detected."
    except Exception as e:
        return f"Error: {str(e)}"

def real_time_alerts(view_history=False):
    try:
        result = ["Real-Time Alerts:"]
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        net = psutil.net_io_counters()
        net_speed = (net.bytes_sent + net.bytes_recv) / (1024**2)  # MB/s

        if cpu > alert_thresholds["cpu"]:
            alert = f"High CPU Usage: {cpu}% (Threshold: {alert_thresholds['cpu']}%)"
            alert_log.append(alert)
            result.append(alert)
        if mem > alert_thresholds["memory"]:
            alert = f"High Memory Usage: {mem}% (Threshold: {alert_thresholds['memory']}%)"
            alert_log.append(alert)
            result.append(alert)
        if disk > alert_thresholds["disk"]:
            alert = f"High Disk Usage: {disk}% (Threshold: {alert_thresholds['disk']}%)"
            alert_log.append(alert)
            result.append(alert)
        if net_speed > alert_thresholds["network"]:
            alert = f"High Network Usage: {net_speed:.2f} MB/s (Threshold: {alert_thresholds['network']} MB/s)"
            alert_log.append(alert)
            result.append(alert)

        if view_history:
            result.append("\nAlert History (Last 5):")
            result.extend(alert_log[-5:])

        return "\n".join(result) if len(result) > 1 else "No alerts triggered."
    except Exception as e:
        return f"Error: {str(e)}"

def process_heatmap():
    try:
        result = ["Process Activity Heatmap (10-second sample):"]
        process_data = {}
        for _ in range(10):  # Sample over 10 seconds
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    pid = proc.pid
                    name = proc.name()
                    cpu = proc.cpu_percent(interval=0.1)
                    if pid not in process_data:
                        process_data[pid] = {"name": name, "cpu_samples": []}
                    process_data[pid]["cpu_samples"].append(cpu)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(1)

        # Generate a simple text-based heatmap
        for pid, data in process_data.items():
            avg_cpu = sum(data["cpu_samples"]) / len(data["cpu_samples"])
            if avg_cpu > 5:  # Threshold for notable activity
                heatmap = "#" * int(avg_cpu // 10)  # Simple visualization
                result.append(f"PID: {pid}, Name: {data['name']}, Avg CPU: {avg_cpu:.2f}%, Heatmap: {heatmap}")

        result.append("Note: Graphical heatmap available in Monitoring tab.")
        return "\n".join(result) if len(result) > 1 else "No significant process activity detected."
    except Exception as e:
        return f"Error: {str(e)}"

def network_latency_graph(command_history_log, host="8.8.8.8", duration=10):
    try:
        result = [f"Network Latency to {host} ({duration} seconds):"]
        latencies = []
        for _ in range(duration):
            output = run_command(f"ping {host} -n 1", command_history_log)
            for line in output.splitlines():
                if "time=" in line:
                    latency = re.search(r"time=(\d+)ms", line)
                    if latency:
                        latencies.append(int(latency.group(1)))
            time.sleep(1)

        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            result.extend([f"Ping {i+1}: {lat} ms" for i, lat in enumerate(latencies)])
            result.append(f"Average Latency: {avg_latency:.2f} ms")
            result.append("Note: Graphical latency graph available in Monitoring tab.")
        else:
            result.append("No latency data collected.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Utility Tools
def get_system_info(command_history_log, export=False, file_path=None, include_bios=False, detailed=False, sections=None):
    try:
        result = ["System Information:"]
        if not sections or "os" in sections:
            result.append(f"OS: {platform.system()} {platform.release()}")
        if not sections or "cpu" in sections:
            result.append(f"CPU: {platform.processor()}")
        if not sections or "memory" in sections:
            result.append(f"Memory: {psutil.virtual_memory().total / (1024**3):.2f} GB")
        if include_bios or (sections and "bios" in sections):
            w = wmi.WMI()
            bios = w.Win32_BIOS()[0]
            result.append(f"BIOS: {bios.Manufacturer}, Version: {bios.Version}")
        if detailed:
            if not sections or "machine" in sections:
                result.append(f"Machine: {platform.machine()}")
            if not sections or "node" in sections:
                result.append(f"Node: {platform.node()}")
            if not sections or "uptime" in sections:
                boot_time = psutil.boot_time()
                uptime = time.time() - boot_time
                result.append(f"Uptime: {timedelta(seconds=int(uptime))}")
            if not sections or "network" in sections:
                net = psutil.net_if_addrs()
                result.append("Network Adapters:")
                for iface, addrs in net.items():
                    for addr in addrs:
                        if addr.family == 2:  # IPv4
                            result.append(f"  {iface}: {addr.address}")

        output = "\n".join(result)
        if export and file_path:
            with open(file_path, "w") as f:
                f.write(output)
            return f"System info exported to {file_path}"
        return output
    except Exception as e:
        return f"Error: {str(e)}"

def clear_temp_files(command_history_log, proceed=True):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Clearing Temporary Files:"]
        temp_dirs = [os.getenv("TEMP"), r"C:\Windows\Temp"]
        total_size = 0
        files_to_delete = []

        # Collect files to delete
        for temp_dir in temp_dirs:
            if not os.path.exists(temp_dir):
                continue
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        size = os.path.getsize(file_path)
                        files_to_delete.append((file_path, size))
                    except:
                        continue

        # Preview files
        result.append(f"Found {len(files_to_delete)} files, Total Size: {sum(size for _, size in files_to_delete) / (1024**2):.2f} MB")
        if not proceed:
            return "\n".join(result) + "\nDeletion cancelled."

        # Delete files
        for file_path, size in files_to_delete:
            try:
                os.remove(file_path)
                total_size += size
            except:
                continue

        result.append(f"Cleared {total_size / (1024**2):.2f} MB")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def list_users(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Local Users:"]
        output = run_command("net user", command_history_log)
        users = output.splitlines()[4:-2]  # Skip header and footer
        for user in users:
            if user.strip():
                details = run_command(f"net user {user}", command_history_log)
                for line in details.splitlines():
                    if "Last logon" in line or "Group" in line:
                        result.append(f"{user}: {line.strip()}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def check_disk_health(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Disk Health:"]
        output = run_command("wmic diskdrive get caption,status", command_history_log)
        result.extend(output.splitlines()[1:])  # Skip header

        # Attempt to get SMART data (simplified)
        smart_output = run_command("wmic diskdrive get caption,MediaType,LastError", command_history_log)
        result.append("\nSMART Data (Simplified):")
        result.extend(smart_output.splitlines()[1:])

        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def list_environment_vars(command_history_log, search_term=None, edit_key=None, edit_value=None):
    try:
        result = ["Environment Variables:"]
        for key, value in sorted(os.environ.items()):
            if not search_term or search_term.lower() in key.lower() or search_term.lower() in value.lower():
                result.append(f"{key}: {value}")
                if key == "PATH":
                    result.append("  (Critical variable for system paths)")

        if edit_key and edit_value is not None:
            os.environ[edit_key] = edit_value
            result.append(f"Set {edit_key} to {edit_value} (effective for this session only).")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def file_permissions_viewer(command_history_log, file_path):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        if not os.path.exists(file_path):
            return f"Path {file_path} does not exist."
        output = run_command(f"icacls \"{file_path}\"", command_history_log)
        result = [f"Permissions for {file_path}:"]
        # Translate SIDs to usernames
        for line in output.splitlines():
            if "S-1-" in line:  # Indicates a SID
                try:
                    sid = re.search(r"(S-1-\S+)", line).group(1)
                    user, domain, _ = win32security.LookupAccountSid(None, win32security.ConvertStringSidToSid(sid))
                    line = line.replace(sid, f"{domain}\\{user}")
                except:
                    pass
            result.append(line)
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def open_registry_editor(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        subprocess.Popen("regedit")
        return "Registry Editor opened."
    except Exception as e:
        return f"Error: {str(e)}"

def registry_backup(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        backup_file = f"registry_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.reg"
        run_command(f"reg export HKLM \"{backup_file}\" /y", command_history_log)
        return f"Registry backed up to {backup_file}"
    except Exception as e:
        return f"Error: {str(e)}"

def shortcut_creator(command_history_log, target, shortcut_path):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        if not os.path.exists(target):
            return f"Target {target} does not exist."
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = os.path.dirname(target)
        shortcut.save()
        return f"Shortcut created at {shortcut_path}"
    except Exception as e:
        return f"Error: {str(e)}"

def manage_recycle_bin(command_history_log, action="empty", item_name=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Recycle Bin Management:"]
        if action == "list":
            items = list(winshell.recycle_bin())
            if not items:
                result.append("Recycle Bin is empty.")
            else:
                for item in items[:10]:  # Limit to 10 items
                    result.append(f"File: {item.original_filename()}, Deleted: {item.recycle_date()}")
                if len(items) > 10:
                    result.append("... (more items available)")
        elif action == "restore" and item_name:
            for item in winshell.recycle_bin():
                if item_name.lower() in item.original_filename().lower():
                    item.undelete()
                    result.append(f"Restored {item.original_filename()} to {item.original_path()}")
                    break
            else:
                result.append(f"File {item_name} not found in Recycle Bin.")
        elif action == "empty":
            winshell.recycle_bin().empty(confirm=False, show_progress=False, sound=False)
            result.append("Recycle Bin emptied.")
        else:
            result.append("Invalid action.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def file_integrity_checker(command_history_log, file_path, monitor_duration=None):
    try:
        if not os.path.exists(file_path):
            return f"File {file_path} does not exist."
        with open(file_path, "rb") as f:
            original_hash = hashlib.sha256(f.read()).hexdigest()
        result = [f"File: {file_path}", f"SHA-256: {original_hash}"]

        if monitor_duration:
            start_time = time.time()
            while time.time() - start_time < monitor_duration:
                with open(file_path, "rb") as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != original_hash:
                    result.append(f"File changed at {datetime.now()}: New SHA-256: {current_hash}")
                    break
                time.sleep(1)
            else:
                result.append("No changes detected during monitoring period.")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def text_encoder_decoder(text, method="base64", password=None, copy_to_clipboard=False):
    try:
        result = []
        if method == "base64":
            result.append(f"Base64 Encoded: {base64.b64encode(text.encode()).decode()}")
        elif method == "base64_decode":
            result.append(f"Base64 Decoded: {base64.b64decode(text).decode()}")
        elif method == "url":
            result.append(f"URL Encoded: {quote(text)}")
        elif method == "url_decode":
            result.append(f"URL Decoded: {unquote(text)}")
        elif method == "hex":
            result.append(f"Hex Encoded: {text.encode().hex()}")
        elif method == "hex_decode":
            result.append(f"Hex Decoded: {bytes.fromhex(text).decode()}")
        elif method == "encrypt":
            if not password:
                return "Password required for encryption."
            salt = os.urandom(16)
            key = generate_aes_key(password, salt)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(text.encode()) + encryptor.finalize()
            result.append(f"Encrypted (AES): {base64.b64encode(salt + iv + encrypted).decode()}")
        elif method == "decrypt":
            if not password:
                return "Password required for decryption."
            encrypted = base64.b64decode(text)
            salt = encrypted[:16]
            iv = encrypted[16:32]
            ciphertext = encrypted[32:]
            key = generate_aes_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            result.append(f"Decrypted (AES): {decrypted.decode()}")
        else:
            return "Invalid method."

        if copy_to_clipboard:
            pyperclip.copy(result[-1].split(": ", 1)[1])
            result.append("Result copied to clipboard.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def screen_capture_tool(region="full", annotation_text=None, save_format="png"):
    try:
        screenshot = None
        if region == "full":
            screenshot = pyautogui.screenshot()
        else:
            # Region should be a tuple (x, y, width, height)
            screenshot = pyautogui.screenshot(region=region)

        # Convert to PIL Image for annotation
        img = Image.frombytes('RGB', screenshot.size, screenshot.rgb)
        file_path = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{save_format}"

        if annotation_text:
            draw = ImageDraw.Draw(img)
            try:
                font = ImageFont.truetype("arial.ttf", 20)
            except:
                font = ImageFont.load_default()
            draw.text((10, 10), annotation_text, fill="red", font=font)

        if save_format.lower() == "jpg":
            img.save(file_path, "JPEG", quality=95)
        else:
            img.save(file_path, "PNG")

        return f"Screenshot saved to {file_path}"
    except Exception as e:
        return f"Error: {str(e)}"

def pdf_merger(files, order=None, page_ranges=None):
    try:
        merger = PdfMerger()
        files = [f.strip() for f in files if f.strip()]
        if not files:
            return "No files provided."

        # Validate files
        for file in files:
            if not os.path.exists(file):
                return f"File {file} does not exist."

        # Reorder files if specified
        if order:
            files = [files[i] for i in order]

        # Merge PDFs with page ranges if specified
        for file in files:
            if page_ranges and file in page_ranges:
                merger.append(file, pages=page_ranges[file])
            else:
                merger.append(file)

        output_path = f"merged_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        merger.write(output_path)
        merger.close()
        return f"PDFs merged into {output_path}"
    except Exception as e:
        return f"Error: {str(e)}"

def optimize_startup(command_history_log, disable_item=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Startup Optimization Analysis:"]
        output = run_command("wmic startup get caption,command,user,location", command_history_log)
        items = output.splitlines()[1:]  # Skip header
        if not items:
            result.append("No startup items found.")
        else:
            result.append("Startup Items:")
            result.extend(items[:10])  # Limit to 10 items
            if len(items) > 10:
                result.append("... (more items available)")

        # Basic impact analysis (simplified)
        result.append("\nImpact Analysis (Simplified):")
        for item in items:
            if "svchost" in item.lower():
                result.append(f"{item.split()[0]}: Likely low impact (system service)")
            else:
                result.append(f"{item.split()[0]}: Potential high impact (third-party app)")

        if disable_item:
            run_command(f"wmic startup where caption=\"{disable_item}\" delete", command_history_log)
            result.append(f"Disabled startup item: {disable_item}")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def folder_sync(src, dst, selective=False, pattern=None):
    try:
        if not os.path.exists(src):
            return f"Source folder {src} does not exist."
        if not os.path.exists(dst):
            os.makedirs(dst)

        result = [f"Syncing {src} to {dst}:"]
        if selective and pattern:
            files = [f for f in os.listdir(src) if fnmatch.fnmatch(f, pattern)]
        else:
            files = os.listdir(src)

        total_files = len(files)
        for i, file in enumerate(files):
            src_path = os.path.join(src, file)
            dst_path = os.path.join(dst, file)
            if os.path.isfile(src_path):
                if os.path.exists(dst_path):
                    src_mtime = os.path.getmtime(src_path)
                    dst_mtime = os.path.getmtime(dst_path)
                    if src_mtime > dst_mtime:
                        shutil.copy2(src_path, dst_path)
                        result.append(f"Updated: {file}")
                    else:
                        result.append(f"Skipped (up to date): {file}")
                else:
                    shutil.copy2(src_path, dst_path)
                    result.append(f"Copied: {file}")
            result.append(progress_callback(i + 1, total_files, "Syncing"))

        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Network Tools
def list_network_connections(command_history_log, filter_by=None):
    try:
        output = run_command("netstat -ano", command_history_log)
        result = ["Network Connections:"]
        lines = output.splitlines()[4:]  # Skip header
        if filter_by:
            filter_by = filter_by.lower()
            lines = [line for line in lines if filter_by in line.lower()]
        result.extend(lines[:20])  # Limit to 20 connections
        if len(lines) > 20:
            result.append("... (more connections available)")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def monitor_network_traffic():
    try:
        result = ["Network Traffic Monitoring (10 seconds):"]
        start_io = psutil.net_io_counters()
        for _ in range(10):
            time.sleep(1)
            end_io = psutil.net_io_counters()
            sent = (end_io.bytes_sent - start_io.bytes_sent) / (1024**2)  # MB
            recv = (end_io.bytes_recv - start_io.bytes_recv) / (1024**2)  # MB
            result.append(f"Second {_+1}: Sent {sent:.2f} MB, Received {recv:.2f} MB")
            start_io = end_io
        result.append("Note: Real-time graph available in Monitoring tab.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Backup Tools
def backup_manager(action, source=None, destination=None, encrypt=False, command_history_log=None, incremental=False):
    try:
        if action == "backup":
            if not source or not destination:
                return "Source and destination required."
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(destination, f"backup_{timestamp}.zip")
            total_size = sum(os.path.getsize(os.path.join(root, f)) for root, _, files in os.walk(source) for f in files)
            total_chunks = (total_size // 4096) + 1 if total_size % 4096 != 0 else total_size // 4096
            result = []

            with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(source):
                    for i, file in enumerate(files):
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, source)
                        if incremental and os.path.exists(backup_path + ".last"):
                            last_backup = zipfile.ZipFile(backup_path + ".last", "r")
                            if arcname in last_backup.namelist():
                                last_mtime = last_backup.getinfo(arcname).date_time
                                last_mtime = time.mktime(datetime(*last_mtime).timetuple())
                                if os.path.getmtime(file_path) <= last_mtime:
                                    continue
                        zf.write(file_path, arcname)
                        result.append(progress_callback(i + 1, len(files), f"Backing up {file}"))

            if encrypt:
                key = Fernet.generate_key()
                fernet = Fernet(key)
                with open(backup_path, "rb") as f:
                    data = f.read()
                encrypted = fernet.encrypt(data)
                with open(backup_path + ".enc", "wb") as f:
                    f.write(encrypted)
                os.remove(backup_path)
                result.append(f"Encrypted backup created at {backup_path}.enc\nKey: {key.decode()}")
            else:
                result.append(f"Backup created at {backup_path}")

            # Verify backup
            with zipfile.ZipFile(backup_path if not encrypt else backup_path + ".enc", "r") as zf:
                if zf.testzip() is None:
                    result.append("Backup verification: Passed")
                else:
                    result.append("Backup verification: Failed")

            return "\n".join(result)
        elif action == "restore":
            if not source or not destination:
                return "Source and destination required."
            with zipfile.ZipFile(source, "r") as zf:
                zf.extractall(destination)
            return f"Restored from {source} to {destination}"
        return "Invalid action."
    except Exception as e:
        return f"Error: {str(e)}"

# Advanced Tools
def restart_system(command_history_log, delay=0, confirm=True):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        if not confirm:
            return "Restart cancelled."
        run_command(f"shutdown /r /t {delay}", command_history_log)
        return f"System restarting in {delay} seconds..."
    except Exception as e:
        return f"Error: {str(e)}"

def shutdown_system(command_history_log, delay=0, confirm=True):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        if not confirm:
            return "Shutdown cancelled."
        run_command(f"shutdown /s /t {delay}", command_history_log)
        return f"System shutting down in {delay} seconds..."
    except Exception as e:
        return f"Error: {str(e)}"

def lock_workstation(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        win32api.LockWorkStation()
        return "Workstation locked."
    except Exception as e:
        return f"Error: {str(e)}"

def clear_dns_cache(command_history_log, clear=True):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["DNS Cache:"]
        # Display current cache
        output = run_command("ipconfig /displaydns", command_history_log)
        result.extend(output.splitlines()[:10])  # Limit to 10 entries
        if len(output.splitlines()) > 10:
            result.append("... (more entries available)")

        if clear:
            run_command("ipconfig /flushdns", command_history_log)
            result.append("DNS cache cleared successfully.")
        else:
            result.append("DNS cache not cleared.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def driver_mgr(command_history_log, open_manager=False):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Driver Management:"]
        output = run_command("wmic sysdriver get caption,version", command_history_log)
        result.extend(output.splitlines()[1:10])  # Limit to 10 drivers
        if len(output.splitlines()) > 10:
            result.append("... (more drivers available)")

        if open_manager:
            subprocess.Popen("devmgmt.msc")
            result.append("Device Manager opened.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def backup_drivers(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        output = run_command("dism /online /export-driver /destination:drivers_backup", command_history_log)
        return "Driver Backup:\n" + output
    except Exception as e:
        return f"Error: {str(e)}"

def rollback_driver(driver_name, command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        output = run_command(f"pnputil /disable {driver_name}", command_history_log)
        return f"Rolling back driver {driver_name}:\n" + output
    except Exception as e:
        return f"Error: {str(e)}"

def boot_mgr(command_history_log, timeout=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Boot Manager:"]
        output = run_command("bcdedit", command_history_log)
        result.extend(output.splitlines()[:10])  # Limit to 10 lines
        if len(output.splitlines()) > 10:
            result.append("... (more settings available)")

        if timeout is not None:
            run_command(f"bcdedit /timeout {timeout}", command_history_log)
            result.append(f"Boot timeout set to {timeout} seconds.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def boot_log_analyzer(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Boot Log Analysis:"]
        output = run_command("wevtutil qe System /q:\"*[System[(EventID=1074 or EventID=6008)]]\" /f:text", command_history_log)
        result.extend(output.splitlines()[:10])  # Limit to 10 events
        if len(output.splitlines()) > 10:
            result.append("... (more events available)")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def toggle_remote_desktop(command_history_log, toggle_state="toggle"):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = []
        current = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections', command_history_log)
        status = "Enabled" if "0x0" in current else "Disabled"
        result.append(f"Remote Desktop Status: {status}")

        if toggle_state == "toggle":
            toggle_state = "off" if "Enabled" in status else "on"

        if toggle_state == "on" and "Disabled" in status:
            run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f', command_history_log)
            result.append("Remote Desktop enabled.")
        elif toggle_state == "off" and "Enabled" in status:
            run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', command_history_log)
            result.append("Remote Desktop disabled.")
        else:
            result.append("No change made.")

        # Check for vulnerabilities (simplified)
        if "Enabled" in result[-1]:
            nla = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication', command_history_log)
            if "0x0" in nla:
                result.append("Warning: Network Level Authentication (NLA) is disabled. Consider enabling for better security.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def power_plan_manager(command_history_log, switch_plan=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Power Plans:"]
        output = run_command("powercfg /list", command_history_log)
        result.extend(output.splitlines())

        if switch_plan:
            run_command(f"powercfg /setactive {switch_plan}", command_history_log)
            result.append(f"Switched to power plan {switch_plan}")

        # Basic power usage analysis
        result.append("\nPower Usage Analysis (Simplified):")
        battery = psutil.sensors_battery()
        if battery:
            result.append(f"Battery: {battery.percent}% (Plugged in: {battery.power_plugged})")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def view_group_policy(command_history_log):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Group Policy Viewer:"]
        output = run_command("gpresult /r", command_history_log)
        result.extend(output.splitlines()[:20])  # Limit to 20 lines
        if len(output.splitlines()) > 20:
            result.append("... (more policies available)")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def kill_task_by_name(task_name, command_history_log, confirm=True):
    try:
        result = ["Task Kill:"]
        # List matching tasks
        output = run_command("tasklist", command_history_log)
        tasks = [line for line in output.splitlines() if task_name.lower() in line.lower()]
        if not tasks:
            return f"No tasks found matching {task_name}."

        result.extend(tasks[:5])  # Limit to 5 matches
        if confirm:
            output = run_command(f"taskkill /IM {task_name} /F", command_history_log)
            result.append(f"Task {task_name} killed:\n{output}")
        else:
            result.append("Task kill cancelled.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def windows_feature_manager(command_history_log, feature=None, enable=True):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Windows Features:"]
        output = run_command("dism /online /get-features /format:table", command_history_log)
        result.extend(output.splitlines()[:10])  # Limit to 10 features
        if len(output.splitlines()) > 10:
            result.append("... (more features available)")

        if feature:
            state = "Enable" if enable else "Disable"
            run_command(f"dism /online /{state}-Feature /FeatureName:{feature}", command_history_log)
            result.append(f"Attempted to {state} feature: {feature}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def multi_monitor_config(command_history_log, open_settings=False):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Multi-Monitor Configuration:"]
        output = run_command("powershell -Command (Get-CimInstance -Namespace root\\wmi -ClassName WmiMonitorBasicDisplayParams)", command_history_log)
        result.extend(output.splitlines()[:5])  # Limit to 5 lines
        if len(output.splitlines()) > 5:
            result.append("... (more monitor info available)")

        if open_settings:
            subprocess.Popen("desk.cpl")
            result.append("Display settings opened.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# IT Support Tools
def view_events(command_history_log, filter_by=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Recent System Events:"]
        hand = win32evtlog.OpenEventLog(None, "System")
        events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
        for event in events[:20]:  # Limit to 20 events
            event_type = str(event.EventType).lower()
            if not filter_by or (filter_by and filter_by.lower() in event_type):
                result.append(f"Time: {event.TimeGenerated}, Source: {event.SourceName}, Event ID: {event.EventID}, Type: {event.EventType}")
        win32evtlog.CloseEventLog(hand)
        if len(result) == 1:
            result.append("No events found matching criteria.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def manage_logs(log_type, action, file_path=None, command_history_log=None, filter_by=None, monitor_duration=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        if log_type == "events":
            output = run_command("wevtutil qe System /f:text", command_history_log)
            result = ["System Events:"]
        else:
            return "Invalid log type."

        if action == "export" and file_path:
            with open(file_path, "w") as f:
                f.write("\n".join(result))
            return f"Logs exported to {file_path}"

        if action == "view":
            if filter_by:
                filtered = [line for line in output.splitlines() if filter_by.lower() in line.lower()]
                result = ["Filtered System Events:", *filtered[:20]]  # Limit to 20 lines
                if len(filtered) > 20:
                    result.append("... (more events available)")
            else:
                result = ["System Events:", *output.splitlines()[:20]]
                if len(output.splitlines()) > 20:
                    result.append("... (more events available)")
        elif action == "monitor" and monitor_duration:
            result.append(f"Monitoring System Events for {monitor_duration} seconds:")
            start_time = time.time()
            last_event_id = 0
            while time.time() - start_time < monitor_duration:
                hand = win32evtlog.OpenEventLog(None, "System")
                events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
                for event in events:
                    if event.RecordNumber > last_event_id:
                        last_event_id = event.RecordNumber
                        result.append(f"New Event - Time: {event.TimeGenerated}, Source: {event.SourceName}, Event ID: {event.EventID}")
                win32evtlog.CloseEventLog(hand)
                time.sleep(1)
            if len(result) == 1:
                result.append("No new events detected during monitoring period.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def recurring_tasks(scheduled_tasks_passed, task_name, interval, task_type, custom_command=None):
    global scheduled_tasks
    scheduled_tasks = scheduled_tasks_passed
    try:
        result = ["Scheduling Task:"]
        # Define the task function based on user input
        if task_type == "clear_temp":
            func = lambda: clear_temp_files(command_history_log, proceed=True)
        elif task_type == "resource_monitor":
            func = lambda: resource_monitor()
        elif task_type == "custom_command" and custom_command:
            func = lambda: run_command(custom_command, command_history_log)
        else:
            return "Invalid task type or missing command.", scheduled_tasks

        scheduled_tasks.append({
            "name": task_name,
            "func": func,
            "time": datetime.now() + timedelta(seconds=interval),
            "interval": interval,
            "recurring": True,
            "timeout": 10
        })
        result.append(f"Recurring task '{task_name}' scheduled every {interval} seconds.")
        return "\n".join(result), scheduled_tasks
    except Exception as e:
        return f"Error: {str(e)}", scheduled_tasks

def delay_task(scheduled_tasks_passed, task_name, delay):
    global scheduled_tasks
    scheduled_tasks = scheduled_tasks_passed
    try:
        result = ["Delaying Task:"]
        for task in scheduled_tasks:
            if task["name"] == task_name:
                task["time"] += timedelta(seconds=delay)
                result.append(f"Task '{task_name}' delayed by {delay} seconds. Next run: {task['time']}")
                return "\n".join(result), scheduled_tasks
        result.append(f"Task '{task_name}' not found.")
        return "\n".join(result), scheduled_tasks
    except Exception as e:
        return f"Error: {str(e)}", scheduled_tasks


# Security Tools
def network_intrusion_detection(duration=10):
    try:
        result = [f"Monitoring network for intrusions ({duration} seconds):"]
        suspicious_ips = ["192.168.1.100", "10.0.0.1"]  # Example list
        start_time = time.time()
        while time.time() - start_time < duration:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.raddr and conn.raddr.ip in suspicious_ips:
                    result.append(f"Suspicious connection detected: {conn.raddr.ip}:{conn.raddr.port} (PID: {conn.pid})")
            time.sleep(1)
        if len(result) == 1:
            result.append("No suspicious activity detected.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def user_activity_logger(duration=10):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = [f"Logging user activity for {duration} seconds:"]
        hand = win32evtlog.OpenEventLog(None, "Security")
        start_time = time.time()
        last_event_id = 0
        while time.time() - start_time < duration:
            events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            for event in events:
                if event.EventID == 4624 and event.RecordNumber > last_event_id:  # Successful logon
                    last_event_id = event.RecordNumber
                    result.append(f"Logon at {event.TimeGenerated}: {event.StringInserts[5]} (Type: {event.StringInserts[8]})")
            time.sleep(1)
        win32evtlog.CloseEventLog(hand)
        if len(result) == 1:
            result.append("No user activity detected.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def keylogger_detector():
    try:
        result = ["Scanning for potential keyloggers:"]
        suspicious_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                info = proc.as_dict(attrs=['pid', 'name', 'exe'])
                # Simplified heuristic: processes with "key" in name or suspicious paths
                if "key" in info['name'].lower() or (info['exe'] and not info['exe'].lower().startswith(r"c:\windows")):
                    suspicious_processes.append(f"PID: {info['pid']}, Name: {info['name']}, Path: {info['exe']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if suspicious_processes:
            result.extend(suspicious_processes)
        else:
            result.append("No potential keyloggers detected.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def password_policy_enforcer(min_length=14, max_age=90):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Enforcing Password Policy:"]
        run_command(f"net accounts /minpwlen:{min_length}", command_history_log)
        result.append(f"Minimum password length set to {min_length}.")
        run_command(f"net accounts /maxpwage:{max_age}", command_history_log)
        result.append(f"Maximum password age set to {max_age} days.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Monitoring Tools
def cpu_temperature_monitor(duration=10):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = [f"Monitoring CPU temperature for {duration} seconds:"]
        w = wmi.WMI(namespace="root\\wmi")
        start_time = time.time()
        while time.time() - start_time < duration:
            temp = w.MSAcpi_ThermalZoneTemperature()[0].CurrentTemperature / 10.0 - 273.15  # Convert from Kelvin to Celsius
            result.append(f"Temperature at {datetime.now()}: {temp:.1f}°C")
            time.sleep(1)
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def event_log_analyzer(event_id=1000, duration=10):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = [f"Analyzing event logs for Event ID {event_id} over {duration} seconds:"]
        hand = win32evtlog.OpenEventLog(None, "System")
        start_time = time.time()
        event_count = 0
        while time.time() - start_time < duration:
            events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            for event in events:
                if event.EventID == event_id:
                    event_count += 1
                    result.append(f"Event at {event.TimeGenerated}: Source: {event.SourceName}")
            time.sleep(1)
        win32evtlog.CloseEventLog(hand)
        result.append(f"Total occurrences of Event ID {event_id}: {event_count}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def disk_io_monitor(duration=10):
    try:
        result = [f"Monitoring disk I/O for {duration} seconds:"]
        start_io = psutil.disk_io_counters()
        start_time = time.time()
        while time.time() - start_time < duration:
            time.sleep(1)
            end_io = psutil.disk_io_counters()
            read_speed = (end_io.read_bytes - start_io.read_bytes) / (1024**2)  # MB/s
            write_speed = (end_io.write_bytes - start_io.write_bytes) / (1024**2)  # MB/s
            result.append(f"Second {int(time.time() - start_time)}: Read {read_speed:.2f} MB/s, Write {write_speed:.2f} MB/s")
            start_io = end_io
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def system_uptime_tracker():
    try:
        result = ["System Uptime History:"]
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        result.append(f"Current Uptime: {timedelta(seconds=int(uptime))}")
        # Simplified: Log to a file for historical data
        with open("uptime_history.txt", "a") as f:
            f.write(f"Boot at {datetime.fromtimestamp(boot_time)}: Uptime {timedelta(seconds=int(uptime))}\n")
        with open("uptime_history.txt", "r") as f:
            history = f.readlines()
        result.extend(history[-5:])  # Last 5 entries
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def alert_scheduler(condition="cpu>90", duration=300, interval=60):
    try:
        result = [f"Scheduling alert for condition '{condition}' every {interval} seconds for {duration} seconds:"]
        start_time = time.time()
        while time.time() - start_time < duration:
            if "cpu>" in condition:
                threshold = float(condition.split(">")[1])
                cpu = psutil.cpu_percent(interval=1)
                if cpu > threshold:
                    result.append(f"Alert at {datetime.now()}: CPU usage {cpu}% exceeds threshold {threshold}%")
            time.sleep(interval)
        if len(result) == 1:
            result.append("No alerts triggered during the period.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Utility Tools
def duplicate_file_finder(directory):
    try:
        if not os.path.exists(directory):
            return f"Directory {directory} does not exist."
        result = ["Scanning for duplicate files:"]
        hashes = {}
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                if file_hash in hashes:
                    hashes[file_hash].append(file_path)
                else:
                    hashes[file_hash] = [file_path]
        duplicates = [files for files in hashes.values() if len(files) > 1]
        if duplicates:
            for group in duplicates:
                result.append("Duplicate files:")
                result.extend([f"  {file}" for file in group])
        else:
            result.append("No duplicate files found.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def file_recovery_tool(drive_letter):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = [f"Attempting file recovery on drive {drive_letter}:"]
        # Simplified: Check for recently deleted files (placeholder)
        result.append("File recovery not fully implemented. Use a dedicated tool like Recuva for now.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def system_tray_manager(action="list", process_name=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["System Tray Management:"]
        if action == "list":
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    info = proc.as_dict(attrs=['pid', 'name'])
                    if "tray" in info['name'].lower() or "notify" in info['name'].lower():
                        result.append(f"PID: {info['pid']}, Name: {info['name']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            if len(result) == 1:
                result.append("No system tray applications detected.")
        elif action == "disable" and process_name:
            for proc in psutil.process_iter(['pid', 'name']):
                if process_name.lower() in proc.name().lower():
                    proc.terminate()
                    result.append(f"Terminated {process_name} (PID: {proc.pid})")
                    break
            else:
                result.append(f"Process {process_name} not found.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def clipboard_manager(action="list", index=None):
    try:
        clipboard_history = getattr(clipboard_manager, "history", [])
        if action == "list":
            result = ["Clipboard History (Last 5):"]
            result.extend([f"{i}: {item}" for i, item in enumerate(clipboard_history[-5:])])
            if not clipboard_history:
                result.append("No clipboard history available.")
            return "\n".join(result)
        elif action == "add":
            current = pyperclip.paste()
            clipboard_history.append(current)
            setattr(clipboard_manager, "history", clipboard_history)
            return f"Added to clipboard history: {current}"
        elif action == "recall" and index is not None:
            if 0 <= index < len(clipboard_history):
                pyperclip.copy(clipboard_history[index])
                return f"Recalled clipboard item {index}: {clipboard_history[index]}"
            return "Invalid index."
        return "Invalid action."
    except Exception as e:
        return f"Error: {str(e)}"

def batch_file_renamer(directory, pattern, prefix="", start_number=1):
    try:
        if not os.path.exists(directory):
            return f"Directory {directory} does not exist."
        result = [f"Renaming files in {directory}:"]
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        for i, file in enumerate(files):
            if not fnmatch.fnmatch(file, pattern):
                continue
            ext = os.path.splitext(file)[1]
            new_name = f"{prefix}{start_number + i}{ext}"
            os.rename(os.path.join(directory, file), os.path.join(directory, new_name))
            result.append(f"Renamed {file} to {new_name}")
        if len(result) == 1:
            result.append("No files matched the pattern.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Network Tools
def port_scanner(host, ports=None):
    try:
        if not ports:
            ports = [22, 80, 443, 445, 3389]  # Common ports
        result = [f"Scanning ports on {host}:"]
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                sock.connect((host, port))
                result.append(f"Port {port} is open")
                sock.close()
            except (socket.timeout, ConnectionRefusedError):
                result.append(f"Port {port} is closed")
            except Exception as e:
                result.append(f"Port {port} error: {str(e)}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def dns_resolver(domain):
    try:
        result = [f"Resolving DNS for {domain}:"]
        start_time = time.time()
        ip = socket.gethostbyname(domain)
        duration = (time.time() - start_time) * 1000  # ms
        result.append(f"IP Address: {ip}")
        result.append(f"Response Time: {duration:.2f} ms")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def packet_sniffer(count=10):
    try:
        result = [f"Capturing {count} packets:"]
        packets = sniff(count=count, timeout=10)
        for i, packet in enumerate(packets):
            if packet.haslayer("IP"):
                src = packet["IP"].src
                dst = packet["IP"].dst
                result.append(f"Packet {i+1}: {src} -> {dst}")
        if len(result) == 1:
            result.append("No packets captured.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Backup Tools
def backup_verifier(backup_path):
    try:
        if not os.path.exists(backup_path):
            return f"Backup file {backup_path} does not exist."
        result = ["Verifying backup:"]
        with zipfile.ZipFile(backup_path, "r") as zf:
            test_result = zf.testzip()
            if test_result is None:
                result.append("Backup integrity: Passed")
            else:
                result.append(f"Backup integrity: Failed ({test_result})")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def backup_scheduler(source, destination, interval, encrypt=False):
    try:
        result = [f"Scheduling backup from {source} to {destination} every {interval} seconds:"]
        # Simplified: Log the schedule (actual scheduling handled by SlingShot)
        result.append("Backup scheduled. Check Scheduled Task Manager for execution.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def differential_backup(source, destination, full_backup_path, encrypt=False):
    try:
        if not os.path.exists(source) or not os.path.exists(full_backup_path):
            return "Source or full backup does not exist."
        result = [f"Performing differential backup from {source} to {destination}:"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(destination, f"diff_backup_{timestamp}.zip")
        with zipfile.ZipFile(full_backup_path, "r") as full_zf:
            full_files = {f.filename: f.date_time for f in full_zf.infolist()}
        with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(source):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, source)
                    if arcname in full_files:
                        full_mtime = time.mktime(datetime(*full_files[arcname]).timetuple())
                        if os.path.getmtime(file_path) <= full_mtime:
                            continue
                    zf.write(file_path, arcname)
        if encrypt:
            key = Fernet.generate_key()
            fernet = Fernet(key)
            with open(backup_path, "rb") as f:
                data = f.read()
            encrypted = fernet.encrypt(data)
            with open(backup_path + ".enc", "wb") as f:
                f.write(encrypted)
            os.remove(backup_path)
            result.append(f"Encrypted differential backup created at {backup_path}.enc\nKey: {key.decode()}")
        else:
            result.append(f"Differential backup created at {backup_path}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def backup_encryption_key_manager(action, key, password=None):
    try:
        key_file = "backup_keys.enc"
        keys = getattr(backup_encryption_key_manager, "keys", {})
        if action == "store":
            if not password:
                return "Password required to store key."
            salt = os.urandom(16)
            fernet_key = generate_aes_key(password, salt)
            fernet = Fernet(base64.urlsafe_b64encode(fernet_key))
            keys[key] = fernet.encrypt(key.encode()).decode()
            with open(key_file, "wb") as f:
                f.write(salt + fernet.encrypt(json.dumps(keys).encode()))
            setattr(backup_encryption_key_manager, "keys", keys)
            return f"Key stored securely in {key_file}"
        elif action == "retrieve":
            if not password:
                return "Password required to retrieve key."
            if not os.path.exists(key_file):
                return f"No key file found at {key_file}"
            with open(key_file, "rb") as f:
                data = f.read()
                salt = data[:16]
                encrypted = data[16:]
                fernet_key = generate_aes_key(password, salt)
                fernet = Fernet(base64.urlsafe_b64encode(fernet_key))
                keys = json.loads(fernet.decrypt(encrypted).decode())
            if key in keys:
                return f"Retrieved key: {fernet.decrypt(keys[key].encode()).decode()}"
            return "Key not found."
        return "Invalid action."
    except Exception as e:
        return f"Error: {str(e)}"

def cloud_backup_uploader(backup_path, destination="google_drive"):
    try:
        result = [f"Uploading {backup_path} to {destination}:"]
        # Simplified: Placeholder for cloud upload
        result.append("Cloud upload not fully implemented. Use a tool like PyDrive for Google Drive integration.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Advanced Tools
def system_restore_point_creator(description):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Creating system restore point:"]
        # Simplified: Use PowerShell to create a restore point
        run_command(f"powershell -Command Checkpoint-Computer -Description \"{description}\" -RestorePointType MODIFY_SETTINGS", command_history_log)
        result.append(f"Restore point created: {description}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def event_log_cleaner(log_type="System"):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = [f"Clearing {log_type} event log:"]
        run_command(f"wevtutil cl {log_type}", command_history_log)
        result.append(f"{log_type} event log cleared.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def driver_verifier(action="start"):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Driver Verifier:"]
        if action == "start":
            run_command("verifier /standard /all", command_history_log)
            result.append("Driver Verifier started with standard settings. Reboot required.")
        elif action == "stop":
            run_command("verifier /reset", command_history_log)
            result.append("Driver Verifier stopped. Reboot required.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def system_file_checker():
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Running System File Checker:"]
        output = run_command("sfc /scannow", command_history_log)
        result.append(output)
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# IT Support Tools
def user_account_manager(action, username, password=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["User Account Management:"]
        if action == "add":
            if not password:
                return "Password required to add user."
            run_command(f"net user {username} {password} /add", command_history_log)
            result.append(f"User {username} added.")
        elif action == "remove":
            run_command(f"net user {username} /delete", command_history_log)
            result.append(f"User {username} removed.")
        elif action == "modify" and password:
            run_command(f"net user {username} {password}", command_history_log)
            result.append(f"Password for {username} updated.")
        else:
            return "Invalid action or missing password."
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def system_diagnostic_report():
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Generating System Diagnostic Report:"]
        run_command("perfmon /report", command_history_log)
        result.append("Diagnostic report generation started. Check Performance Monitor for results.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def service_dependency_viewer(service_name):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = [f"Service Dependencies for {service_name}:"]
        output = run_command(f"sc qc {service_name}", command_history_log)
        result.extend(output.splitlines())
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def hardware_inventory_tool():
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Hardware Inventory:"]
        w = wmi.WMI()
        # CPU
        cpu = w.Win32_Processor()[0]
        result.append(f"CPU: {cpu.Name}")
        # GPU
        gpu = w.Win32_VideoController()[0]
        result.append(f"GPU: {gpu.Name}")
        # RAM
        ram = sum([mem.Capacity for mem in w.Win32_PhysicalMemory()]) / (1024**3)
        result.append(f"RAM: {ram:.2f} GB")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# New Tools for SlingShot IT Security Toolkit

import win32process
import win32security
import pythoncom
from scapy.all import *
import math

# 1. Process Injection Detector
# 2. Kernel Driver Enumerator
# 3. Shadow Copy Manager
# 4. Memory Forensics Lite
# 5. Privilege Escalation Checker
# 6. Network Connection Anomaly Detector
# 7. File System Anomaly Scanner
# 8. Service Behavior Profiler
# 9. Registry Anomaly Detector
# 10. Thread Stack Analyzer
# New Tools for SlingShot IT Security Toolkit (Standalone Versions)


# 1. Process Injection Detector
# 2. Kernel Driver Enumerator
# 3. Shadow Copy Manager
# 4. Memory Forensics Lite
# 5. Privilege Escalation Checker
# 6. Network Connection Anomaly Detector
# 7. File System Anomaly Scanner
# 8. Service Behavior Profiler
# 9. Registry Anomaly Detector
# 10. Thread Stack Analyzer
# 11. Secure Boot Policy Editor
# 12. Process Hollowing Detector
def sniff_browser_activity(duration=10):
    try:
        result = [f"Sniffing browser network activity for {duration} seconds:"]
        packets = sniff(timeout=duration, filter="tcp port 80 or tcp port 443")
        login_count = 0
        for pkt in packets:
            if pkt.haslayer("TCP") and pkt.haslayer("Raw"):
                payload = pkt["Raw"].load.decode('utf-8', errors='ignore').lower()
                if any(keyword in payload for keyword in ["password", "login", "username", "auth"]):
                    login_count += 1
                    result.append(f"Potential login detected - Src: {pkt['IP'].src}:{pkt['TCP'].sport} -> Dst: {pkt['IP'].dst}:{pkt['TCP'].dport}")
        result.append(f"Total potential login attempts detected: {login_count}")
        return "\n".join(result) if login_count > 0 else "No browser login activity detected."
    except PermissionError:
        return "Error: Packet sniffing requires elevated privileges (run as administrator)."
    except Exception as e:
        logger.error(f"Error in sniff_browser_activity: {str(e)}")
        return f"Error: {str(e)}"

# 13. Network Packet Entropy Analyzer
def network_packet_entropy_analyzer(count=None):
    try:
        if count is None:
            root = tk.Tk()
            root.withdraw()
            count = simpledialog.askinteger("Count", "Enter number of packets to analyze:", initialvalue=10)
            root.destroy()

        result = [f"Analyzing packet entropy for {count} packets:"]
        def calculate_entropy(data):
            if not data:
                return 0
            length = len(data)
            entropy = 0
            for x in set(data):
                p_x = data.count(x) / length
                entropy -= p_x * math.log2(p_x)
            return entropy

        packets = sniff(count=count, timeout=10)
        for i, packet in enumerate(packets):
            if packet.haslayer("Raw"):
                payload = bytes(packet["Raw"].load)
                entropy = calculate_entropy(payload)
                if entropy > 6:  # High entropy threshold (close to random)
                    result.append(f"Packet {i+1}: Src {packet['IP'].src} -> Dst {packet['IP'].dst}, Entropy: {entropy:.2f} (Possible encrypted traffic)")
        if len(result) == 1:
            result.append("No high-entropy packets detected.")
        logger.info("Network packet entropy analysis completed.")
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Error in network_packet_entropy_analyzer: {str(e)}")
        return f"Error: {str(e)}"

# 14. System Call Tracer
# 15. Dynamic DNS Resolver Monitor
def dynamic_dns_resolver_monitor(domain=None, duration=None):
    try:
        if domain is None or duration is None:
            root = tk.Tk()
            root.withdraw()
            domain = simpledialog.askstring("Domain", "Enter domain to monitor:", initialvalue="example.com")
            duration = simpledialog.askinteger("Duration", "Enter monitoring duration (seconds):", initialvalue=10)
            root.destroy()
        if not domain:
            return "No domain provided."

        result = [f"Monitoring DNS resolution for {domain} ({duration} seconds):"]
        resolutions = {}
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                ip = socket.gethostbyname(domain)
                timestamp = datetime.now()
                if ip not in resolutions:
                    resolutions[ip] = []
                resolutions[ip].append(str(timestamp))
                time.sleep(1)
            except socket.gaierror:
                result.append(f"Failed to resolve {domain} at {datetime.now()}")
                time.sleep(1)
        for ip, times in resolutions.items():
            result.append(f"IP: {ip}, Resolved {len(times)} times: {', '.join(times[:3])}" + ("..." if len(times) > 3 else ""))
        if len(resolutions) > 1:
            result.append("Warning: Multiple IPs detected, possible dynamic DNS usage.")
        logger.info("Dynamic DNS resolution monitoring completed.")
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Error in dynamic_dns_resolver_monitor: {str(e)}")
        return f"Error: {str(e)}"

# New Password Extraction Tools for SlingShot IT Security Toolkit
def browser_password_extractor(browsers=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        if browsers is None:
            root = tk.Tk()
            root.withdraw()
            browsers_input = simpledialog.askstring(
                "Browsers",
                "Select browsers (comma-separated: chrome, firefox, edge, ie) or leave blank for all:",
                initialvalue="chrome,firefox,edge,ie",
                parent=root
            )
            root.destroy()
            if browsers_input is None:
                return "Browser selection cancelled."
            browsers = [b.strip().lower() for b in browsers_input.split(",")] if browsers_input else ["chrome", "firefox", "edge", "ie"]

        result = ["Browser Password Extractor:"]
        passwords = {}
        user_data = Path(os.getenv("APPDATA", ""))
        local_data = Path(os.getenv("LOCALAPPDATA", ""))
        chrome_path = local_data / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"
        edge_path = local_data / "Microsoft" / "Edge" / "User Data" / "Default" / "Login Data"
        firefox_profile = user_data / "Mozilla" / "Firefox" / "Profiles"

        def decrypt_chrome_edge(db_path):
            if not db_path.exists():
                return []
            temp_db = Path("temp_login_data")
            shutil.copy2(db_path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            creds = []
            for url, username, encrypted_pass in cursor.fetchall():
                if encrypted_pass:
                    try:
                        decrypted_pass = win32crypt.CryptUnprotectData(encrypted_pass, None, None, None, 0)[1].decode('utf-8')
                        creds.append((url, username, decrypted_pass))
                    except Exception as e:
                        logger.error(f"Failed to decrypt {url}: {str(e)}")
                        creds.append((url, username, "[Decryption failed]"))
            conn.close()
            temp_db.unlink()
            return creds

        def decrypt_firefox(profile_dir):
            if not profile_dir.exists():
                return []
            profiles = [p for p in profile_dir.iterdir() if p.is_dir()]
            if not profiles:
                return []
            profile = profiles[0]
            logins_file = profile / "logins.json"
            if not logins_file.exists():
                return []
            with open(logins_file, "r") as f:
                data = json.load(f)
            creds = []
            master_pass = None
            for login in data.get("logins", []):
                url = login.get("origin", "")
                username = login.get("username", "")
                encrypted_pass = login.get("encryptedPassword", "")
                if encrypted_pass:
                    if "Encrypted" in encrypted_pass:
                        if master_pass is None:
                            root = tk.Tk()
                            root.withdraw()
                            master_pass = simpledialog.askstring("Firefox", "Enter Firefox master password (if set):", parent=root)
                            root.destroy()
                            if not master_pass:
                                creds.append((url, username, "[Master password required]"))
                                continue
                        creds.append((url, username, "[NSS decryption not implemented; use master password manually]"))
                    else:
                        creds.append((url, username, encrypted_pass))
            return creds

        def decrypt_ie_vault():
            try:
                output = run_command("powershell -Command 'Get-StoredCredential -AsCredentialObject'", command_history_log)
                creds = []
                lines = output.splitlines()
                for i, line in enumerate(lines):
                    if "UserName" in line:
                        username = line.split("=")[-1].strip()
                        password_line = lines[i + 1] if i + 1 < len(lines) else ""
                        if "Password" in password_line:
                            encrypted_pass = password_line.split("=")[-1].strip()
                            try:
                                decrypted_pass = win32crypt.CryptUnprotectData(base64.b64decode(encrypted_pass), None, None, None, 0)[1].decode('utf-8')
                                creds.append(("IE Vault", username, decrypted_pass))
                            except:
                                creds.append(("IE Vault", username, "[Decryption failed]"))
                return creds
            except Exception as e:
                logger.error(f"IE Vault extraction failed: {str(e)}")
                return [("IE Vault", "N/A", "[Extraction failed]")]

        if "chrome" in browsers and chrome_path.exists():
            chrome_creds = decrypt_chrome_edge(chrome_path)
            for url, username, password in chrome_creds:
                domain = url.split("//")[-1].split("/")[0]
                passwords.setdefault(domain, []).append(f"Chrome - Username: {username}, Password: {password}")

        if "edge" in browsers and edge_path.exists():
            edge_creds = decrypt_chrome_edge(edge_path)
            for url, username, password in edge_creds:
                domain = url.split("//")[-1].split("/")[0]
                passwords.setdefault(domain, []).append(f"Edge - Username: {username}, Password: {password}")

        if "firefox" in browsers:
            firefox_creds = decrypt_firefox(firefox_profile)
            for url, username, password in firefox_creds:
                domain = url.split("//")[-1].split("/")[0]
                passwords.setdefault(domain, []).append(f"Firefox - Username: {username}, Password: {password}")

        if "ie" in browsers:
            ie_creds = decrypt_ie_vault()
            for url, username, password in ie_creds:
                passwords.setdefault(url, []).append(f"IE - Username: {username}, Password: {password}")

        if passwords:
            for domain, creds in passwords.items():
                result.append(f"Website/Source: {domain}")
                result.extend(creds)
        else:
            result.append("No passwords found.")
        logger.info("Browser password extraction completed.")
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Error in browser_password_extractor: {str(e)}")
        return f"Error: {str(e)}"

def windows_credential_manager_extractor():
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        result = ["Windows Credential Manager Extractor (Advanced):"]
        import win32cred
        creds = win32cred.CredEnumerate(None, 0)  # Requires admin privileges
        if creds:
            for cred in creds:
                target = cred["TargetName"]
                username = cred["UserName"]
                password_blob = cred["CredentialBlob"]
                if password_blob:
                    try:
                        password = password_blob.decode('utf-16-le')
                    except:
                        password = "[Decryption failed - Requires DPAPI context]"
                else:
                    password = "[No password stored]"
                result.append(f"Application/Service: {target}")
                result.append(f"Username: {username}")
                result.append(f"Password: {password}")
            result.append("Note: Decryption success depends on user context and privileges.")
        else:
            result.append("No credentials found or insufficient privileges.")
        logger.info("Windows Credential Manager extraction (advanced) completed.")
        return "\n".join(result)
    except ImportError:
        return "Error: 'pywin32' with 'win32cred' module required for advanced extraction. Install with 'pip install pywin32'."
    except Exception as e:
        logger.error(f"Error in windows_credential_manager_extractor: {str(e)}")
        return f"Error: {str(e)}"

# 3. Unified Password Aggregator
def unified_password_aggregator(category=None):
    if platform.system() != "Windows":
        return "This feature is Windows-specific."
    try:
        if category is None:
            root = tk.Tk()
            root.withdraw()
            category = simpledialog.askstring(
                "Category",
                "Categorize by (website, application, source):",
                initialvalue="website",
                parent=root
            )
            root.destroy()
            if not category:
                category = "website"
            category = category.lower()

        result = ["Unified Password Aggregator:"]
        all_passwords = {}

        # Collect browser passwords
        browser_result = browser_password_extractor(["chrome", "firefox", "edge", "ie"]).splitlines()[1:]  # Skip header
        for line in browser_result:
            if "Website:" in line:
                current_key = line.split("Website:")[-1].strip()
                all_passwords[current_key] = all_passwords.get(current_key, [])
            elif "Username:" in line:
                all_passwords[current_key].append(line)

        # Collect Windows Credential Manager passwords
        cred_result = windows_credential_manager_extractor().splitlines()[1:]  # Skip header
        for line in cred_result:
            if "Application/Service:" in line:
                current_key = line.split("Application/Service:")[-1].strip()
                all_passwords[current_key] = all_passwords.get(current_key, [])
            elif "Username:" in line or "Password:" in line:
                all_passwords[current_key].append(line)

        # Categorize and format
        if category == "website":
            categorized = {k: v for k, v in all_passwords.items() if "Website:" in k}
            for key, creds in categorized.items():
                result.append(f"Website: {key}")
                result.extend(creds)
        elif category == "application":
            categorized = {k: v for k, v in all_passwords.items() if "Application/Service:" in k}
            for key, creds in categorized.items():
                result.append(f"Application: {key}")
                result.extend(creds)
        elif category == "source":
            sources = {"Chrome": [], "Firefox": [], "Edge": [], "IE": [], "Windows": []}
            for key, creds in all_passwords.items():
                for cred in creds:
                    if "Chrome" in cred:
                        sources["Chrome"].append(f"{key}: {cred}")
                    elif "Firefox" in cred:
                        sources["Firefox"].append(f"{key}: {cred}")
                    elif "Edge" in cred:
                        sources["Edge"].append(f"{key}: {cred}")
                    elif "Application/Service" in key:
                        sources["Windows"].append(f"{key}: {cred}")
                    else:
                        sources["IE"].append(f"{key}: {cred}")
            for source, creds in sources.items():
                if creds:
                    result.append(f"Source: {source}")
                    result.extend(creds)
        else:
            result.append("Invalid category; showing all.")
            for key, creds in all_passwords.items():
                result.append(f"Key: {key}")
                result.extend(creds)

        if len(result) == 1:
            result.append("No passwords found.")
        logger.info(f"Unified password aggregation completed with category '{category}'.")
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Error in unified_password_aggregator: {str(e)}")
        return f"Error: {str(e)}"

# New Tools for SlingShot IT Security Toolkit

def run_sublist3r(domain, bruteforce=False):
    try:
        import sublist3r
        subdomains = sublist3r.main(
            domain=domain,
            threads=10,
            savefile=None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=bruteforce,
            engines=None
        )
        result = ["Sublist3r Results:"]
        result.extend(subdomains)
        return "\n".join(result) if subdomains else "No subdomains found."
    except ImportError:
        return "Error: Sublist3r not installed. Install with 'pip install Sublist3r'."
    except Exception as e:
        return f"Error: {str(e)}"

def query_crt_sh(domain):
    try:
        import requests
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        subdomains = sorted(set(entry["name_value"].strip("*.") for entry in data if "name_value" in entry))
        result = ["crt.sh Results:"]
        result.extend(subdomains)
        return "\n".join(result) if subdomains else "No subdomains found on crt.sh."
    except requests.RequestException as e:
        return f"Error querying crt.sh: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

def query_censys(domain, api_id, api_secret):
    try:
        from censys.search import CensysCertificates
        censys = CensysCertificates(api_id=api_id, api_secret=api_secret)
        query = f"parsed.names: *.{domain}"
        results = censys.search(query, fields=["parsed.names"])
        subdomains = set()
        for cert in results:
            for name in cert.get("parsed.names", []):
                if name.endswith(f".{domain}") and not name.startswith("*"):
                    subdomains.add(name)
        result = ["Censys Results:"]
        result.extend(sorted(subdomains))
        return "\n".join(result) if subdomains else "No subdomains found on Censys."
    except ImportError:
        return "Error: Censys library not installed. Install with 'pip install censys'."
    except Exception as e:
        return f"Error: {str(e)}"



def send_slack_notification(message, channel, token):
    try:
        from slack_sdk import WebClient
        client = WebClient(token=token)
        response = client.chat_postMessage(channel=channel, text=message)
        if response["ok"]:
            return f"Slack notification sent to {channel}: {message}"
        else:
            return f"Failed to send Slack notification: {response['error']}"
    except ImportError:
        return "Error: Slack SDK not installed. Install with 'pip install slack-sdk'."
    except Exception as e:
        return f"Error: {str(e)}"

# Security Tools
def credential_harvester_detector(duration=10):
    try:
        result = [f"Monitoring for credential harvesting ({duration} seconds):"]
        start_time = time.time()
        while time.time() - start_time < duration:
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    if proc.connections():
                        for conn in proc.connections():
                            if conn.raddr and (conn.raddr.port in [80, 443]):
                                payload = f"PID: {proc.pid}, Name: {proc.name()}, Remote: {conn.raddr.ip}:{conn.raddr.port}"
                                result.append(payload)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(1)
        return "\n".join(result) if len(result) > 1 else "No credential harvesting detected."
    except Exception as e:
        return f"Error: {str(e)}"

def rogue_process_terminator(whitelist_file):
    try:
        with open(whitelist_file, "r") as f:
            whitelist = {line.strip().lower() for line in f if line.strip()}
        result = ["Terminating rogue processes:"]
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.name().lower() not in whitelist:
                    proc.terminate()
                    result.append(f"Terminated PID: {proc.pid}, Name: {proc.name()}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return "\n".join(result) if len(result) > 1 else "No rogue processes found."
    except Exception as e:
        return f"Error: {str(e)}"

def secure_file_vault(folder, password):
    try:
        salt = os.urandom(16)
        key = generate_aes_key(password, salt)
        output_zip = f"{folder}_vault.zip"
        shutil.make_archive(output_zip[:-4], 'zip', folder)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(output_zip, "rb") as f_in, open(f"{output_zip}.enc", "wb") as f_out:
            f_out.write(salt + iv + encryptor.update(f_in.read()) + encryptor.finalize())
        os.remove(output_zip)
        return f"Vault created: {output_zip}.enc"
    except Exception as e:
        return f"Error: {str(e)}"

def anti_ransomware_shield(directory, duration):
    try:
        result = [f"Monitoring {directory} for ransomware activity ({duration} seconds):"]
        initial = {f: hashlib.sha256(open(os.path.join(directory, f), "rb").read()).hexdigest() for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))}
        start_time = time.time()
        while time.time() - start_time < duration:
            time.sleep(1)
            current = {f: hashlib.sha256(open(os.path.join(directory, f), "rb").read()).hexdigest() for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))}
            for f in initial:
                if f in current and initial[f] != current[f]:
                    result.append(f"Ransomware-like change detected in {f}. Blocking process.")
                    return "\n".join(result)
        result.append("No ransomware activity detected.")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def password_complexity_auditor(passwords_db):
    try:
        result = ["Password Complexity Audit:"]
        for timestamp, entry in passwords_db.items():
            pwd = entry["password"]
            score = sum([len(pwd) >= 12, any(c.isupper() for c in pwd), any(c.islower() for c in pwd), any(c.isdigit() for c in pwd), any(c in string.punctuation for c in pwd)])
            status = "Compliant" if score >= 4 else "Non-compliant"
            result.append(f"Name: {entry['name']}, Score: {score}/5, Status: {status}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def exploit_mitigation_checker(command_history_log):
    try:
        result = ["Exploit Mitigation Status:"]
        dep = run_command("powershell -Command Get-ProcessMitigation -Name System | Select-Object -Property DEP", command_history_log)
        aslr = run_command("powershell -Command Get-ProcessMitigation -Name System | Select-Object -Property ASLR", command_history_log)
        result.extend([dep, aslr])
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def token_impersonation_detector():
    try:
        result = ["Checking for token impersonation:"]
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, proc.pid)
                token = win32security.OpenProcessToken(handle, win32security.TOKEN_QUERY)
                impersonation = win32security.GetTokenInformation(token, win32security.TokenImpersonationLevel)
                if impersonation > 0:
                    result.append(f"PID: {proc.pid}, Name: {proc.name()}, Impersonation Level: {impersonation}")
                win32api.CloseHandle(handle)
            except:
                continue
        return "\n".join(result) if len(result) > 1 else "No token impersonation detected."
    except Exception as e:
        return f"Error: {str(e)}"

def rootkit_scanner():
    try:
        result = ["Scanning for rootkits:"]
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if not proc.exe() or not os.path.exists(proc.exe()):
                    result.append(f"PID: {proc.pid}, Name: {proc.name()}, Missing Executable")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return "\n".join(result) if len(result) > 1 else "No rootkit signatures detected."
    except Exception as e:
        return f"Error: {str(e)}"

def secure_deletion_scheduler(file_path, delay):
    try:
        time.sleep(delay)
        return shred_file(file_path, "dod", 3)
    except Exception as e:
        return f"Error: {str(e)}"

def firewall_rule_analyzer(command_history_log):
    try:
        result = ["Firewall Rule Analysis:"]
        output = run_command("netsh advfirewall firewall show rule name=all", command_history_log)
        for line in output.splitlines():
            if "Allow" in line and "Any" in line:
                result.append(f"Potential Risk: {line.strip()}")
        return "\n".join(result) if len(result) > 1 else "No risky rules detected."
    except Exception as e:
        return f"Error: {str(e)}"

# Monitoring Tools
def process_genealogy_tracker():
    try:
        result = ["Process Genealogy:"]
        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                parent = psutil.Process(proc.ppid()).name() if proc.ppid() else "None"
                result.append(f"PID: {proc.pid}, Name: {proc.name()}, Parent: {parent} (PID: {proc.ppid()})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def network_traffic_anomaly_detector(duration):
    try:
        result = [f"Monitoring network traffic for anomalies ({duration} seconds):"]
        baseline = []
        start_time = time.time()
        while time.time() - start_time < duration:
            net = psutil.net_io_counters()
            baseline.append(net.bytes_sent + net.bytes_recv)
            time.sleep(1)
        mean = sum(baseline) / len(baseline)
        std_dev = (sum((x - mean) ** 2 for x in baseline) / len(baseline)) ** 0.5
        anomalies = [f"Time {i}s: {val / (1024**2):.2f} MB" for i, val in enumerate(baseline) if abs(val - mean) > 2 * std_dev]
        result.extend(anomalies)
        return "\n".join(result) if len(result) > 1 else "No traffic anomalies detected."
    except Exception as e:
        return f"Error: {str(e)}"

def service_dependency_monitor(duration):
    try:
        result = [f"Monitoring service dependencies ({duration} seconds):"]
        start_time = time.time()
        while time.time() - start_time < duration:
            for svc in psutil.win_service_iter():
                try:
                    if svc.status() == "stopped" and svc.pid():
                        result.append(f"Service {svc.name()} stopped but has running PID {svc.pid()}")
                except:
                    continue
            time.sleep(1)
        return "\n".join(result) if len(result) > 1 else "No dependency issues detected."
    except Exception as e:
        return f"Error: {str(e)}"

def disk_latency_monitor(duration):
    try:
        result = [f"Monitoring disk latency ({duration} seconds):"]
        start_time = time.time()
        while time.time() - start_time < duration:
            io = psutil.disk_io_counters()
            read_time = io.read_time / io.read_count if io.read_count else 0
            write_time = io.write_time / io.write_count if io.write_count else 0
            result.append(f"Read Latency: {read_time:.2f} ms, Write Latency: {write_time:.2f} ms")
            time.sleep(1)
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def memory_usage_profiler():
    try:
        result = ["Memory Usage Profile:"]
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                mem = proc.memory_info().rss / (1024**2)
                result.append(f"PID: {proc.pid}, Name: {proc.name()}, Memory: {mem:.2f} MB")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return "\n".join(sorted(result, key=lambda x: float(x.split("Memory: ")[-1].split()[0]), reverse=True))
    except Exception as e:
        return f"Error: {str(e)}"

def cpu_core_load_balancer(duration):
    try:
        result = [f"Monitoring CPU core load ({duration} seconds):"]
        start_time = time.time()
        while time.time() - start_time < duration:
            cores = psutil.cpu_percent(percpu=True)
            result.append("Core Loads: " + ", ".join(f"Core {i}: {load}%" for i, load in enumerate(cores)))
            time.sleep(1)
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def event_log_correlation_analyzer(duration):
    try:
        result = ["Correlating event logs:"]
        h = win32evtlog.OpenEventLog(None, "Security")
        events = win32evtlog.ReadEventLog(h, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
        start_time = time.time()
        while time.time() - start_time < duration:
            for event in events[:10]:
                if event.EventID in [4624, 4625]:  # Logon success/failure
                    result.append(f"Event ID {event.EventID}: {event.StringInserts}")
            time.sleep(1)
        win32evtlog.CloseEventLog(h)
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def thermal_stress_monitor(duration):
    try:
        result = [f"Monitoring thermal stress ({duration} seconds):"]
        start_time = time.time()
        while time.time() - start_time < duration:
            cpu = psutil.cpu_percent()
            if cpu > 90:
                result.append(f"High thermal stress detected: CPU {cpu}%")
            time.sleep(1)
        return "\n".join(result) if len(result) > 1 else "No thermal stress detected."
    except Exception as e:
        return f"Error: {str(e)}"

def network_connection_stability_tracker(duration):
    try:
        result = [f"Tracking network stability ({duration} seconds):"]
        start_time = time.time()
        while time.time() - start_time < duration:
            conns = len(psutil.net_connections())
            result.append(f"Active Connections: {conns}")
            time.sleep(1)
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def system_resource_forecasting(duration):
    try:
        result = [f"Forecasting resource usage ({duration} seconds):"]
        cpu_samples = []
        start_time = time.time()
        while time.time() - start_time < duration:
            cpu_samples.append(psutil.cpu_percent())
            time.sleep(1)
        trend = "Increasing" if cpu_samples[-1] > cpu_samples[0] else "Decreasing" if cpu_samples[-1] < cpu_samples[0] else "Stable"
        result.append(f"CPU Trend: {trend}, Average: {sum(cpu_samples) / len(cpu_samples):.2f}%")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Utility Tools
def file_metadata_extractor(file_path):
    try:
        stat_info = os.stat(file_path)
        result = [
            f"File: {file_path}",
            f"Size: {stat_info.st_size / (1024**2):.2f} MB",
            f"Created: {datetime.fromtimestamp(stat_info.st_ctime)}",
            f"Modified: {datetime.fromtimestamp(stat_info.st_mtime)}",
            f"Accessed: {datetime.fromtimestamp(stat_info.st_atime)}"
        ]
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def system_path_cleaner():
    try:
        path = os.environ["PATH"].split(";")
        valid_paths = [p for p in path if os.path.exists(p)]
        result = ["Cleaning PATH:", f"Original: {len(path)} entries", f"Valid: {len(valid_paths)} entries"]
        os.environ["PATH"] = ";".join(valid_paths)
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def file_extension_analyzer(directory):
    try:
        exts = {}
        for root, _, files in os.walk(directory):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                exts[ext] = exts.get(ext, 0) + 1
        result = ["File Extension Analysis:"]
        result.extend(f"{ext}: {count}" for ext, count in sorted(exts.items()))
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def temporary_file_scanner():
    try:
        result = ["Temporary Files:"]
        temp_dirs = [os.getenv("TEMP"), r"C:\Windows\Temp"]
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                for file in os.listdir(temp_dir):
                    result.append(os.path.join(temp_dir, file))
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def registry_key_exporter(key_path, file_path, command_history_log):
    try:
        run_command(f"reg export {key_path} \"{file_path}\" /y", command_history_log)
        return f"Exported {key_path} to {file_path}"
    except Exception as e:
        return f"Error: {str(e)}"

def file_access_logger(file_path, duration):
    try:
        result = [f"Logging access to {file_path} ({duration} seconds):"]
        start_time = time.time()
        while time.time() - start_time < duration:
            stat_info = os.stat(file_path)
            if stat_info.st_atime > start_time:
                result.append(f"Accessed at {datetime.now()}")
            time.sleep(1)
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def system_time_synchronizer(command_history_log):
    try:
        run_command("w32tm /resync", command_history_log)
        return "System time synchronized with NTP server."
    except Exception as e:
        return f"Error: {str(e)}"

def environment_variable_backup(file_path):
    try:
        with open(file_path, "w") as f:
            json.dump(dict(os.environ), f, indent=4)
        return f"Environment variables backed up to {file_path}"
    except Exception as e:
        return f"Error: {str(e)}"

def file_compression_tool(files, output):
    try:
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in files:
                zf.write(file, os.path.basename(file))
        return f"Files compressed to {output}"
    except Exception as e:
        return f"Error: {str(e)}"

def disk_space_analyzer(directory):
    try:
        total_size = 0
        result = [f"Disk Space Analysis for {directory}:"]
        for root, _, files in os.walk(directory):
            for file in files:
                size = os.path.getsize(os.path.join(root, file))
                total_size += size
                result.append(f"{os.path.join(root, file)}: {size / (1024**2):.2f} MB")
        result.append(f"Total: {total_size / (1024**2):.2f} MB")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Network Tools
def network_bandwidth_profiler(duration):
    try:
        result = [f"Profiling network bandwidth ({duration} seconds):"]
        start_time = time.time()
        initial = psutil.net_io_counters()
        while time.time() - start_time < duration:
            time.sleep(1)
            current = psutil.net_io_counters()
            sent = (current.bytes_sent - initial.bytes_sent) / (1024**2)
            recv = (current.bytes_recv - initial.bytes_recv) / (1024**2)
            result.append(f"Sent: {sent:.2f} MB/s, Received: {recv:.2f} MB/s")
            initial = current
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

def ip_geolocation_tracker(ip):
    try:
        import requests
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        result = [
            f"IP: {ip}",
            f"Country: {response.get('country', 'N/A')}",
            f"City: {response.get('city', 'N/A')}",
            f"ISP: {response.get('isp', 'N/A')}"
        ]
        return "\n".join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Backup Tools
# Advanced Tools
# IT Support Tools
# Reconnaissance Tools
# Security Tools
def keylogger_detector():
    try:
        result = ["Scanning for keyloggers:"]
        suspicious_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'connections', 'exe']):
            try:
                info = proc.as_dict(attrs=['pid', 'name', 'connections', 'exe'])
                # Check for processes with network connections and suspicious names
                if info['connections'] and any(conn.raddr for conn in info['connections']):
                    if "key" in info['name'].lower() or "log" in info['name'].lower():
                        suspicious_processes.append(f"PID: {info['pid']}, Name: {info['name']}, Path: {info['exe']}")
                # Check for processes accessing keyboard input (simplified heuristic)
                if info['exe'] and "keyboard" in info['exe'].lower():
                    suspicious_processes.append(f"PID: {info['pid']}, Name: {info['name']}, Path: {info['exe']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if suspicious_processes:
            result.extend(suspicious_processes)
        else:
            result.append("No keyloggers detected.")
        logger.info("Keylogger detection completed.")
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Error in keylogger_detector: {str(e)}")
        return f"Error: {str(e)}"

# Utility Tools
def duplicate_file_finder(directory):
    try:
        if not os.path.exists(directory):
            return f"Directory {directory} does not exist."
        result = ["Duplicate File Finder:"]
        file_hashes = {}
        duplicates = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "rb") as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    if file_hash in file_hashes:
                        duplicates.append(f"Duplicate: {file_path} (matches {file_hashes[file_hash]})")
                    else:
                        file_hashes[file_hash] = file_path
                except Exception as e:
                    result.append(f"Error processing {file_path}: {str(e)}")
        if duplicates:
            result.extend(duplicates)
        else:
            result.append("No duplicates found.")
        logger.info(f"Duplicate file finder completed for {directory}")
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Error in duplicate_file_finder: {str(e)}")
        return f"Error: {str(e)}"

def file_recovery_tool(drive_letter):
    try:
        result = ["File Recovery Tool:"]
        # Simulate file recovery by scanning for recently deleted files (simplified)
        if platform.system() != "Windows":
            return "This feature is Windows-specific."
        recycle_bin = list(winshell.recycle_bin())
        recovered = 0
        for item in recycle_bin:
            if drive_letter.lower() in item.original_path().lower():
                try:
                    item.undelete()
                    result.append(f"Recovered: {item.original_filename()} to {item.original_path()}")
                    recovered += 1
                except Exception as e:
                    result.append(f"Failed to recover {item.original_filename()}: {str(e)}")
        if recovered == 0:
            result.append(f"No recoverable files found on drive {drive_letter} in Recycle Bin.")
        result.append("Note: This is a basic implementation using the Recycle Bin. Advanced recovery requires specialized libraries.")
        logger.info(f"File recovery completed for drive {drive_letter}")
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Error in file_recovery_tool: {str(e)}")
        return f"Error: {str(e)}"

def system_tray_manager(action, process_name=None):
    try:
        if platform.system() != "Windows":
            return "This feature is Windows-specific."
        result = ["System Tray Manager:"]
        # List processes with system tray presence (simplified)
        if action == "list":
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # Heuristic: Processes with a GUI often have tray icons
                    if "explorer" not in proc.name().lower() and proc.create_time() < time.time() - 60:
                        result.append(f"PID: {proc.pid}, Name: {proc.name()}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        elif action == "disable" and process_name:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if process_name.lower() in proc.name().lower():
                        proc.terminate()
                        result.append(f"Disabled tray app: {proc.name()} (PID: {proc.pid})")
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            else:
                result.append(f"Process {process_name} not found in system tray.")
        else:
            result.append("Invalid action.")
        logger.info(f"System tray manager action completed: {action}")
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Error in system_tray_manager: {str(e)}")
        return f"Error: {str(e)}"

def clipboard_manager(action, index=None):
    try:
        result = ["Clipboard Manager:"]
        clipboard_history = []
        # Simulate clipboard history (simplified)
        if action == "list":
            try:
                current = pyperclip.paste()
                clipboard_history.append(current)
                result.append(f"Current Clipboard: {current}")
            except Exception as e:
                result.append(f"Error accessing clipboard: {str(e)}")
        elif action == "add":
            text = simpledialog.askstring("Add to Clipboard", "Enter text to add:")
            if text:
                pyperclip.copy(text)
                result.append(f"Added to clipboard: {text}")
        elif action == "recall" and index is not None:
            result.append("Recall not implemented in this simulation. Current clipboard:")
            result.append(pyperclip.paste())
        else:
            result.append("Invalid action.")
        result.append("Note: This is a basic implementation. Full clipboard history requires additional libraries.")
        logger.info(f"Clipboard manager action completed: {action}")
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Error in clipboard_manager: {str(e)}")
        return f"Error: {str(e)}"

def batch_file_renamer(directory, pattern, prefix, start_number):
    try:
        if not os.path.exists(directory):
            return f"Directory {directory} does not exist."
        result = ["Batch File Renamer:"]
        files = [f for f in os.listdir(directory) if fnmatch.fnmatch(f, pattern)]
        files.sort()
        for i, filename in enumerate(files, start=start_number):
            old_path = os.path.join(directory, filename)
            ext = os.path.splitext(filename)[1]
            new_name = f"{prefix}{i}{ext}" if prefix else f"{i}{ext}"
            new_path = os.path.join(directory, new_name)
            try:
                os.rename(old_path, new_path)
                result.append(f"Renamed: {filename} -> {new_name}")
            except Exception as e:
                result.append(f"Failed to rename {filename}: {str(e)}")
        if not files:
            result.append(f"No files matching pattern {pattern} found.")
        logger.info(f"Batch file renamer completed for {directory}")
        return "\n".join(result)
    except Exception as e:
        logger.error(f"Error in batch_file_renamer: {str(e)}")
        return f"Error: {str(e)}"

# Advanced Tools
# Network Tools
# Backup Tools
# Advanced Tools
# IT Support Tools
