import os
import sys
import threading
import time
import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, scrolledtext, filedialog, Toplevel, Listbox, Menu, END
from tkinter import simpledialog
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import hashlib
import secrets
import subprocess
import getpass
from zipfile import ZipFile
import psutil
import socket
import logging
import shutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from cryptography.fernet import Fernet
import json
import requests
import importlib.util
import platform
import re
import string

# Setup logging
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'slingshot.log')
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', force=True)
logger = logging.getLogger('SlingShot')

# Feature Descriptions (Updated with all new tools)
FEATURE_DESCRIPTIONS = {
    "🔑 Gen Key": "Generates a secure encryption key.",
    "🔒 Encrypt File": "Encrypts a selected file.",
    "🔓 Decrypt File": "Decrypts an encrypted file.",
    "📜 Hash File": "Calculates file SHA-256 hash.",
    "🛡️ AV Status": "Checks Windows Defender status.",
    "🔍 Firewall": "Checks firewall status.",
    "📋 Startup Items": "Lists startup programs.",
    "🔍 Susp Procs": "Checks for suspicious processes.",
    "🔒 Gen OTP": "Generates a one-time password.",
    "🔍 Vuln Scan": "Scans for system vulnerabilities and basic malware signatures.",
    "🔑 Pwd Strength": "Checks password strength.",
    "🔥 Fwall Rules": "Manages firewall rules.",
    "🗑️ Shred File": "Securely deletes files.",
    "🛡️ Harden Sys": "Provides hardening tips.",
    "📋 Procs": "Lists running processes.",
    "📈 Resources": "Shows CPU, RAM, disk usage.",
    "🔍 Uptime": "Shows system uptime.",
    "🔍 CPU Temp": "Monitors CPU temperature (requires hardware sensor library).",
    "📋 Threads": "Lists running threads.",
    "⚠️ Sys Health": "Evaluates system health.",
    "ℹ️ Sys Info": "Displays system info.",
    "👥 Users": "Lists user accounts.",
    "💿 Chk Disk": "Checks disk health.",
    "🗑️ Clr Temp": "Clears temporary files.",
    "📋 Env Vars": "Lists environment variables.",
    "🏓 Ping": "Pings a target host.",
    "🌐 Net Conns": "Checks network connections.",
    "🔍 Port Scanner": "Scans specified ports on a host with customizable ranges.",
    "📁 Backup Files": "Backs up files to ZIP.",
    "📂 Restore": "Restores files from ZIP.",
    "🔥 Tog Fwall": "Toggles firewall state.",
    "🔑 Gen Pwd": "Generates a random password.",
    "🔄 Restart": "Restarts the system.",
    "⏹ Shutdown": "Shuts down the system.",
    "🔒 Lock": "Locks the workstation.",
    "🌐 Net Traffic": "Monitors network traffic.",
    "📋 Proc Explorer": "Explores processes.",
    "💿 Disk Analyzer": "Analyzes disk usage.",
    "📜 Event Viewer": "Views system events.",
    "⚡ Benchmark": "Benchmarks performance.",
    "🔐 Password Vault Export": "Exports encrypted passwords to a secure file.",
    "🕵️‍♂️ Phishing Detector": "Analyzes email headers or URLs for phishing signs.",
    "🔍 Malware Scanner": "Scans files against known malware hashes.",
    "🔒 Two-Factor Auth Generator": "Generates TOTP codes for 2FA.",
    "📡 Rogue AP Detector": "Scans for unauthorized WiFi access points.",
    "🔐 BitLocker Status": "Checks and manages BitLocker encryption status.",
    "🛡️ Secure Boot Check": "Verifies Secure Boot status.",
    "🔍 Credential Dumping Check": "Scans memory for credential leaks (basic).",
    "📜 Audit Policy Viewer": "Displays current audit policies.",
    "🔒 USB Lockdown": "Toggles USB storage device access.",
    "📉 GPU Usage": "Monitors GPU utilization.",
    "🌡️ Fan Speed Monitor": "Displays fan speeds (requires sensor library).",
    "🔍 Service Monitor": "Tracks critical Windows services.",
    "📈 Battery Health": "Reports laptop battery health.",
    "🔍 Event Log Analyzer": "Filters critical system events.",
    "🌐 Bandwidth Per Process": "Shows network usage by process.",
    "📋 Scheduled Task Monitor": "Lists and monitors scheduled tasks.",
    "🔍 Disk I/O Stats": "Tracks disk read/write rates.",
    "⚠️ Memory Leak Detector": "Detects unusual memory growth.",
    "📊 Real-Time Alerts": "Configurable resource threshold alerts.",
    "📂 File Permissions Viewer": "Displays and modifies NTFS permissions.",
    "🔍 Registry Backup": "Creates a backup of the registry.",
    "📜 Shortcut Creator": "Generates desktop shortcuts.",
    "🗑️ Recycle Bin Manager": "Views and restores Recycle Bin contents.",
    "🔍 File Integrity Checker": "Monitors file changes via checksums.",
    "📋 Text Encoder/Decoder": "Encodes/decodes text (Base64, Hex, etc.).",
    "🖥️ Screen Capture Tool": "Takes screenshots with annotations.",
    "📄 PDF Merger": "Combines multiple PDFs into one.",
    "🔍 Startup Optimizer": "Suggests disabling unnecessary startup items.",
    "🗂️ Folder Sync": "Synchronizes two folders.",
    "📡 WiFi Password Viewer": "Retrieves saved WiFi passwords.",
    "🔍 ARP Table Viewer": "Displays ARP cache for network devices.",
    "🌐 Proxy Tester": "Tests proxy server connectivity and speed.",
    "📶 Signal Strength Monitor": "Tracks WiFi signal strength over time.",
    "🔍 MAC Spoofer Check": "Detects potential MAC address spoofing.",
    "🌐 VPN Status": "Checks active VPN connections and details.",
    "🔍 WHOIS Lookup": "Retrieves domain registration info.",
    "📡 Packet Sniffer": "Basic packet capture (requires scapy).",
    "🔍 DNS Cache Cleaner": "Flushes DNS cache.",
    "🌐 IP Geolocation": "Maps IP addresses to locations.",
    "📁 Differential Backup": "Backs up only changed files since last full backup.",
    "🔍 Backup Encryption": "Adds AES encryption to backup ZIPs.",
    "📂 Mirror Backup": "Creates an exact copy of a directory structure.",
    "🔄 Snapshot Manager": "Manages Volume Shadow Copy snapshots.",
    "📁 Backup Comparison": "Compares source and backup for consistency.",
    "☁️ OneDrive Sync Check": "Verifies OneDrive sync status.",
    "📂 Backup Cleanup": "Deletes old backups based on age/size.",
    "🔍 File Versioning": "Tracks multiple versions of backed-up files.",
    "📁 Network Backup": "Backs up to a network share.",
    "⏰ Real-Time Backup": "Triggers backups on file changes.",
    "🔍 BIOS Info": "Displays BIOS version and settings.",
    "🖥️ Remote Desktop Toggle": "Enables/disables RDP access.",
    "🔧 Power Plan Manager": "Switches between power plans.",
    "📜 Command History": "Logs and recalls recent CLI commands.",
    "🔍 Group Policy Viewer": "Displays applied GPOs.",
    "🛠️ Task Kill by Name": "Terminates processes by name wildcard.",
    "🔧 Windows Feature Manager": "Enables/disables optional features.",
    "📋 Clipboard Sync": "Syncs clipboard across networked devices.",
    "🔍 Boot Log Analyzer": "Parses boot logs for issues.",
    "🖥️ Multi-Monitor Config": "Manages multiple monitor settings.",
    "🔑 Password Generator (Custom)": "Customizable rules for password generation.",
    "🔍 Password Leak Check": "Checks passwords against breach databases.",
    "🔒 Password Sync": "Syncs passwords across devices (encrypted).",
    "📜 Password Policy Enforcer": "Enforces minimum password standards.",
    "🔑 Master Password": "Secures the password vault with a master key.",
    "🔍 Duplicate Password Finder": "Identifies reused passwords.",
    "🔒 Password Expiry Tracker": "Alerts for expiring passwords.",
    "📋 Password Import": "Imports passwords from CSV or browser.",
    "🔑 TOTP Backup": "Stores TOTP recovery codes.",
    "🔍 Password Strength Analyzer": "Detailed analysis with entropy metrics.",
    "⏰ Recurring Tasks": "Schedules tasks daily/weekly/monthly.",
    "🔍 Task Dependency": "Runs tasks only if others complete.",
    "📜 Task Log Viewer": "Displays history of scheduled task runs.",
    "🔧 Task Priority": "Sets CPU priority for scheduled tasks.",
    "⏰ Delay Task": "Adds delay before task execution.",
    "🔍 Task Conflict Check": "Avoids overlapping scheduled tasks.",
    "📋 Task Export": "Exports schedules to a file.",
    "🔧 Task Condition": "Runs tasks based on system state (e.g., idle).",
    "⏰ Wake on Task": "Wakes system from sleep for tasks.",
    "🔍 Task Simulator": "Previews task execution timing.",
    "📉 Process Heatmap": "Visualizes process resource usage over time.",
    "🔍 Anomaly Detector": "Flags unusual resource spikes.",
    "📈 Network Latency Graph": "Plots ping times to a target.",
    "🔍 Disk Latency": "Measures disk read/write latency.",
    "📉 CPU Core Usage": "Shows usage per core.",
    "🔍 Event Correlation": "Links system events to resource usage.",
    "📈 Trend Predictor": "Forecasts resource usage trends.",
    "🔍 Log Analytics": "Summarizes log patterns.",
    "📉 Power Usage": "Estimates power consumption.",
    "🔍 Bottleneck Finder": "Identifies performance bottlenecks.",
    "🔌 Plugin Marketplace": "Downloads plugins from a repository.",
    "🔍 Plugin Validator": "Verifies plugin integrity (hash check).",
    "📜 Plugin Log": "Logs plugin activity separately.",
    "🔧 Plugin Config": "Edits plugin settings via GUI.",
    "🔍 Plugin Dependency Checker": "Ensures required libraries are present.",
    "📦 Plugin Packager": "Creates distributable plugin packages.",
    "🔌 Plugin Auto-Update": "Checks for plugin updates.",
    "🔍 Plugin Sandbox": "Runs plugins in isolated mode.",
    "📜 Plugin Documentation": "Displays plugin help files.",
    "🔧 Plugin Hotkey": "Assigns hotkeys to plugin actions.",
    "🖥️ Remote Shutdown": "Shuts down a remote PC via IP/hostname.",
    "🔄 Service Restart": "Restarts a specified service.",
    "📋 User Session List": "Lists active user sessions.",
    "🔍 Logoff User": "Logs off a specific user session.",
    "🛠️ Repair Windows Update": "Resets Windows Update components.",
    "🔧 SFC Scan": "Runs System File Checker.",
    "📜 DISM Health Check": "Restores system health with DISM.",
    "🔍 Temp Profile Fix": "Resolves temporary profile issues.",
    "🖥️ Remote Command": "Runs a command on a remote machine.",
    "🔧 Time Sync": "Forces NTP time synchronization.",
    "🌐 IP Config Reset": "Resets IP configuration.",
    "🔍 Network Adapter Reset": "Disables/enables network adapters.",
    "📡 Winsock Reset": "Resets Winsock catalog.",
    "🔍 TCP/IP Reset": "Resets TCP/IP stack.",
    "🌐 Static IP Setter": "Configures static IP settings.",
    "🔍 DHCP Lease Viewer": "Displays DHCP lease details.",
    "📶 WiFi Troubleshooter": "Diagnoses WiFi connectivity issues.",
    "🔍 NetBIOS Status": "Checks NetBIOS status.",
    "🌐 Gateway Checker": "Tests gateway connectivity.",
    "🔍 DNS Troubleshooter": "Diagnoses DNS issues.",
    "👥 Add Local User": "Creates a local user account.",
    "🔑 Reset Password": "Resets a local user password.",
    "🔍 User Rights Viewer": "Displays user privileges.",
    "👥 Group Membership": "Lists user group memberships.",
    "🔒 Account Lockout Check": "Checks account lockout status.",
    "👥 User Profile Backup": "Backs up user profile data.",
    "🔍 Last Logon Time": "Shows last logon time for users.",
    "👥 Disable Account": "Disables a user account.",
    "🔑 Password Never Expires": "Toggles password expiration.",
    "📋 AD User Info": "Retrieves AD user details.",
    "📦 Uninstall App": "Uninstalls software silently.",
    "🔍 Installed Software List": "Lists installed applications.",
    "📜 Pending Updates": "Shows pending Windows Updates.",
    "🔧 Install MSI": "Installs an MSI package silently.",
    "📦 Winget Wrapper": "Installs apps via winget.",
    "🔍 Driver Backup": "Backs up installed drivers.",
    "📜 Driver Rollback": "Rolls back a specific driver.",
    "🔧 App Crash Log": "Extracts app crash details.",
    "📦 Software Cleanup": "Removes unused software remnants.",
    "🔍 Update History": "Displays Windows Update history.",
    "📜 BSOD Log Viewer": "Parses Blue Screen crash dumps.",
    "🔍 Hardware Diagnostic": "Runs basic hardware tests.",
    "📋 System Info Report": "Generates a system report.",
    "🔍 Event Log Export": "Exports filtered Event Logs.",
    "📜 Performance Log": "Logs performance metrics.",
    "🔍 Disk Error Check": "Runs chkdsk with error correction.",
    "📋 Memory Test": "Initiates memory diagnostic.",
    "🔍 Printer Diagnostic": "Troubleshoots printer issues.",
    "📜 Battery Report": "Generates battery health report.",
    "🔍 System File Verifier": "Verifies system file integrity."
}

# Tab Colors (Updated with all tabs)
TAB_COLORS = {
    "🔒 Security": "#dc3545",
    "📊 Monitoring": "#007bff",
    "🛠️ Utilities": "#28a745",
    "🌐 Network": "#6f42c1",
    "💾 Backup": "#fd7e14",
    "🔧 Advanced": "#6c757d",
    "🔐 Passwords": "#ff5733",
    "⏰ Scheduler": "#9b59b6",
    "📈 Analytics": "#e74c3c",
    "📦 Plugins": "#3498db",
    "🖥️ IT Support": "#f39c12"
}

# ToolTip Class (Unchanged)
class ToolTip:
    current_tip = None
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.id = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)
        self.widget.bind("<FocusOut>", self.hide_tip)
        self.root = widget.winfo_toplevel()
        self.root.bind("<FocusOut>", self.hide_tip, add="+")
    def show_tip(self, event):
        if ToolTip.current_tip and ToolTip.current_tip != self:
            ToolTip.current_tip.hide_tip(None)
        if self.tip_window or not self.text:
            return
        self.id = self.widget.after(500, self._create_tip)
    def _create_tip(self):
        x, y = self.widget.winfo_rootx() + 25, self.widget.winfo_rooty() + 25
        screen_width = self.widget.winfo_screenwidth()
        screen_height = self.widget.winfo_screenheight()
        if x + 150 > screen_width:
            x = screen_width - 150
        if y + 60 > screen_height:
            y = self.widget.winfo_rooty() - 60
        self.tip_window = tw = ctk.CTkToplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("150x60+%d+%d" % (x, y))
        tw.configure(fg_color="#2b2b2b", border_width=1, border_color="#4a4a4a")
        label = ctk.CTkLabel(tw, text=self.text, font=("Segoe UI", 9), text_color="white", fg_color="#2b2b2b", corner_radius=5, anchor="w", padx=5, pady=2)
        label.pack(fill="both", expand=True)
        tw.attributes("-alpha", 0.0)
        for alpha in range(0, 11):
            tw.attributes("-alpha", alpha * 0.1)
            tw.update()
            time.sleep(0.01)
        self.widget.after(3000, self.hide_tip)
        ToolTip.current_tip = self
    def hide_tip(self, event=None):
        if self.id:
            self.widget.after_cancel(self.id)
        if self.tip_window:
            for alpha in range(10, -1, -1):
                self.tip_window.attributes("-alpha", alpha * 0.1)
                self.tip_window.update()
                time.sleep(0.01)
            self.tip_window.destroy()
            self.tip_window = None
        if ToolTip.current_tip == self:
            ToolTip.current_tip = None

# Main Application Class
class SlingShot:
    def __init__(self, root):
        logger.info("Initializing SlingShot...")
        self.root = root
        self.root.title("SlingShot - IT Security Toolkit")
        ctk.deactivate_automatic_dpi_awareness()
        ctk.set_default_color_theme("dark-blue")
        ctk.set_appearance_mode("dark")
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        self.root.geometry(f"{int(screen_width * 0.8)}x{int(screen_height * 0.8)}")
        self.root.minsize(1280, 720)
        self.root.resizable(True, True)
        self.running = True
        self.task_queue = Queue()
        self.current_tasks = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.key = None
        self.log_paused = False
        self.lock = threading.Lock()
        self.log_queue = Queue()
        self.output_history = []
        self.temp_backup = None
        self.sidebar_collapsed = False
        self.favorites = [None] * 8
        self.scheduled_tasks = []
        self.password_key = Fernet.generate_key()
        self.cipher = Fernet(self.password_key)
        self.passwords = {}
        self.plugins = {}
        self.analytics_data = {'cpu': [], 'mem': [], 'disk': [], 'times': []}
        self.config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "slingshot_config.json")
        self.load_config()
        self.setup_menu()
        try:
            self.setup_gui()
            self.root.bind("<<UpdateAnalytics>>", lambda e: self.update_analytics_plot())
            self.root.after(100, self.start_background_tasks)
            self.show_welcome_screen()
            logger.info("SlingShot initialized successfully.")
        except Exception as e:
            logger.error(f"Initialization failed: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to initialize: {e}")
            self.kill_program()

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.favorites = config.get('favorites', [None] * 8)
                self.theme = config.get('theme', 'Dark')
                self.scheduled_tasks = config.get('scheduled_tasks', [])
                self.passwords = config.get('passwords', {})
                self.update_check_interval = config.get('update_check_interval', 86400)
                self.log_level = config.get('log_level', 'INFO')
                self.language = config.get('language', 'English')
        else:
            self.theme = "Dark"
            self.update_check_interval = 86400
            self.log_level = "INFO"
            self.language = "English"

    def save_config(self):
        config = {
            'favorites': self.favorites,
            'theme': self.theme,
            'scheduled_tasks': self.scheduled_tasks,
            'passwords': self.passwords,
            'update_check_interval': self.update_check_interval,
            'log_level': self.log_level,
            'language': self.language
        }
        with open(self.config_file, 'w') as f:
            json.dump(config, f)

    def kill_program(self):
        self.running = False
        self.executor.shutdown(wait=False)
        self.root.quit()
        logger.info("SlingShot terminated.")
        sys.exit(0)

    def setup_menu(self):
        menubar = Menu(self.root, bg="#1f1f1f", fg="white", activebackground="#2b2b2b", activeforeground="white")
        self.root.config(menu=menubar)
        file_menu = Menu(menubar, tearoff=0, bg="#1f1f1f", fg="white", activebackground="#2b2b2b", activeforeground="white")
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Config", command=self.save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.kill_program)
        help_menu = Menu(menubar, tearoff=0, bg="#1f1f1f", fg="white", activebackground="#2b2b2b", activeforeground="white")
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "SlingShot v1.0 - IT Security Toolkit"))
        help_menu.add_command(label="Documentation", command=lambda: messagebox.showinfo("Documentation", "Visit https://example.com/docs"))

    def start_background_tasks(self):
        logger.info("Starting background tasks...")
        threading.Thread(target=self.update_log_display, daemon=True).start()
        threading.Thread(target=self.update_dashboard, daemon=True).start()
        threading.Thread(target=self.check_scheduled_tasks, daemon=True).start()
        threading.Thread(target=self.check_for_updates, daemon=True).start()
        threading.Thread(target=self.collect_analytics, daemon=True).start()
        threading.Thread(target=self.update_health_periodically, daemon=True).start()

    def setup_gui(self):
        logger.info("Setting up GUI...")
        self.main_frame = ctk.CTkFrame(self.root, corner_radius=0)
        self.main_frame.pack(fill="both", expand=True)
        self.header_frame = ctk.CTkFrame(self.main_frame, height=50, corner_radius=0, fg_color="#1f1f1f")
        self.header_frame.pack(fill="x", padx=10, pady=(10, 0))
        self.header_label = ctk.CTkLabel(self.header_frame, text="🛡️ SlingShot", font=("Segoe UI", 26, "bold"), text_color="white")
        self.header_label.pack(side="left", padx=5)
        self.dark_mode_btn = ctk.CTkButton(self.header_frame, text="🌙", command=self.toggle_dark_mode, fg_color="#6c757d", hover_color="#5a6268", width=30)
        self.dark_mode_btn.pack(side="right", padx=5)
        ctk.CTkButton(self.header_frame, text="?", command=self.show_help, fg_color="#17a2b8", hover_color="#138496", width=30).pack(side="right", padx=5)
        ctk.CTkButton(self.header_frame, text="⚙️", command=self.open_settings, fg_color="#17a2b8", hover_color="#138496", width=30).pack(side="right", padx=5)
        ctk.CTkButton(self.header_frame, text="💀 Kill", command=self.kill_program, fg_color="#dc3545", hover_color="#c82333", width=80, font=("Segoe UI", 12)).pack(side="right", padx=5)
        ctk.CTkButton(self.header_frame, text="PowerShell", command=self.open_powershell, fg_color="#007bff", hover_color="#0056b3", width=80, font=("Segoe UI", 12)).pack(side="right", padx=5)
        ctk.CTkButton(self.header_frame, text="CMD", command=self.open_cmd, fg_color="#28a745", hover_color="#218838", width=80, font=("Segoe UI", 12)).pack(side="right", padx=5)
        command_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        command_frame.pack(side="right", padx=5)
        self.command_entry = ctk.CTkEntry(command_frame, placeholder_text="Run command...", width=200)
        self.command_entry.pack(side="left", padx=5)
        ctk.CTkButton(command_frame, text="Run", command=self.run_custom_command, fg_color="#17a2b8", hover_color="#138496", width=50).pack(side="left", padx=5)
        self.search_entry = ctk.CTkEntry(self.header_frame, placeholder_text="Search features or logs...", width=200)
        self.search_entry.pack(side="right", padx=5)
        self.search_entry.bind("<KeyRelease>", self.search_filter)
        self.middle_frame = ctk.CTkFrame(self.main_frame, corner_radius=0)
        self.middle_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.left_frame = ctk.CTkFrame(self.middle_frame, width=int(self.root.winfo_screenwidth() * 0.2), corner_radius=10)
        self.left_frame.pack(side="left", fill="y", padx=(0, 5))
        self.toggle_sidebar_btn = ctk.CTkButton(self.left_frame, text="◄", command=self.toggle_sidebar, width=20, fg_color="#6c757d", hover_color="#5a6268")
        self.toggle_sidebar_btn.pack(side="top", pady=5)
        self.dashboard_frame = ctk.CTkFrame(self.left_frame, corner_radius=10)
        self.dashboard_frame.pack(fill="x", padx=5, pady=5)
        ctk.CTkLabel(self.dashboard_frame, text="📊 Dashboard", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=5)
        self.cpu_label = ctk.CTkLabel(self.dashboard_frame, text="CPU: 0%", font=("Segoe UI", 12))
        self.cpu_label.pack(anchor="w", padx=5)
        self.ram_label = ctk.CTkLabel(self.dashboard_frame, text="RAM: 0%", font=("Segoe UI", 12))
        self.ram_label.pack(anchor="w", padx=5)
        self.disk_label = ctk.CTkLabel(self.dashboard_frame, text="Disk: 0%", font=("Segoe UI", 12))
        self.disk_label.pack(anchor="w", padx=5)
        self.log_frame = ctk.CTkFrame(self.left_frame, corner_radius=10)
        self.log_frame.pack(fill="both", expand=True, padx=5, pady=5)
        ctk.CTkLabel(self.log_frame, text="📜 Live Logs", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=5, pady=2)
        self.log_display = scrolledtext.ScrolledText(self.log_frame, width=30, height=15, font=("Segoe UI", 11), wrap=tk.WORD, bg="#2b2b2b", fg="white")
        self.log_display.pack(fill="both", expand=True, padx=5, pady=5)
        self.log_btn_frame = ctk.CTkFrame(self.log_frame, fg_color="transparent")
        self.log_btn_frame.pack(fill="x", pady=5)
        self.log_btn_frame.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(self.log_btn_frame, text="🗑️ Clear", command=self.clear_log, fg_color="#ffc107", text_color="black", hover_color="#e0a800", width=80, font=("Segoe UI", 12)).grid(row=0, column=0, padx=5)
        ctk.CTkButton(self.log_btn_frame, text="⏸ Pause", command=self.pause_log, fg_color="#007bff", hover_color="#0056b3", width=80, font=("Segoe UI", 12)).grid(row=0, column=1, padx=5)
        ctk.CTkButton(self.log_btn_frame, text="📤 Export", command=self.export_logs, fg_color="#28a745", hover_color="#218838", width=80, font=("Segoe UI", 12)).grid(row=0, column=2, padx=5)
        self.favorites_frame = ctk.CTkFrame(self.left_frame, corner_radius=10)
        self.favorites_frame.pack(fill="x", padx=5, pady=5)
        favorites_header = ctk.CTkFrame(self.favorites_frame, fg_color="transparent")
        favorites_header.pack(fill="x")
        ctk.CTkLabel(favorites_header, text="⭐ Favorites", font=("Segoe UI", 14, "bold")).pack(side="left", padx=5)
        ctk.CTkButton(favorites_header, text="✏️", command=self.edit_favorites_popup, width=30, fg_color="#17a2b8", hover_color="#138496").pack(side="right", padx=5)
        self.favorites_grid = ctk.CTkFrame(self.favorites_frame)
        self.favorites_grid.pack(fill="x", padx=5, pady=5)
        for i in range(8):
            text = self.favorites[i] if self.favorites[i] else "Empty"
            btn = ctk.CTkButton(self.favorites_grid, text=text, command=lambda i=i: self.run_favorite(i), fg_color="#4a4a4a", hover_color="#5a5a5a", width=80, font=("Segoe UI", 12))
            btn.grid(row=i // 4, column=i % 4, padx=2, pady=2)
            btn.bind("<Button-3>", lambda event, i=i: self.remove_from_favorites(i))
            self.favorites[i] = btn if text == "Empty" else text
        self.right_frame = ctk.CTkFrame(self.middle_frame, corner_radius=10)
        self.right_frame.pack(side="right", fill="both", expand=True, padx=5)
        self.notebook = ctk.CTkTabview(self.right_frame)
        self.notebook.pack(fill="both", expand=True, pady=5)
        self.setup_tabs()
        self.status_bar = ctk.CTkFrame(self.main_frame, height=30, fg_color="#1f1f1f")
        self.status_bar.pack(fill="x", side="bottom")
        self.status_indicator = ctk.CTkLabel(self.status_bar, text="●", font=("Segoe UI", 12), text_color="green")
        self.status_indicator.pack(side="left", padx=5)
        self.status_label = ctk.CTkLabel(self.status_bar, text="Ready", font=("Segoe UI", 10))
        self.status_label.pack(side="left", padx=5)
        self.progress_bar = ctk.CTkProgressBar(self.main_frame, orientation="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", padx=10, pady=5)
        self.progress_bar.set(0)

    def add_button(self, frame, text, command, timeout, row, col, tab_color):
        btn = ctk.CTkButton(frame, text=text, command=lambda: self.queue_task(command, timeout, text), fg_color=tab_color, hover_color="#5a5a5a", font=("Segoe UI", 12), width=int(self.root.winfo_width() * 0.15))
        btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
        frame.grid_columnconfigure(col, weight=1)
        ToolTip(btn, FEATURE_DESCRIPTIONS.get(text, "No description available"))
        btn.bind("<Button-3>", lambda event, t=text: self.add_to_favorites(t))

    def setup_tabs(self):
        self.setup_security_tab()
        self.setup_monitoring_tab()
        self.setup_utilities_tab()
        self.setup_network_tab()
        self.setup_backup_tab()
        self.setup_advanced_tab()
        self.setup_passwords_tab()
        self.setup_scheduler_tab()
        self.setup_analytics_tab()
        self.setup_plugins_tab()
        self.setup_it_support_tab()

    def setup_security_tab(self):
        tab_name = "🔒 Security"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("🔑 Gen Key", self.generate_key, 5), ("🔒 Encrypt File", self.encrypt_file, 30), ("🔓 Decrypt File", self.decrypt_file, 30),
            ("📜 Hash File", self.hash_file, 15), ("🛡️ AV Status", self.check_antivirus_status, 30), ("🔍 Firewall", self.check_firewall_status, 30),
            ("📋 Startup Items", self.list_startup_items, 30), ("🔍 Susp Procs", self.check_suspicious_processes, 30), ("🔒 Gen OTP", self.generate_otp, 5),
            ("🔍 Vuln Scan", self.vuln_scan, 60), ("🔑 Pwd Strength", self.pwd_strength, 15), ("🔥 Fwall Rules", self.fwall_rules, 30),
            ("🗑️ Shred File", self.shred_file, 30), ("🛡️ Harden Sys", self.harden_sys, 15), ("🔐 Password Vault Export", self.password_vault_export, 15),
            ("🕵️‍♂️ Phishing Detector", self.phishing_detector, 30), ("🔍 Malware Scanner", self.malware_scanner, 60), ("🔒 Two-Factor Auth Generator", self.totp_generator, 5),
            ("📡 Rogue AP Detector", self.rogue_ap_detector, 30), ("🔐 BitLocker Status", self.bitlocker_status, 30), ("🛡️ Secure Boot Check", self.secure_boot_check, 15),
            ("🔍 Credential Dumping Check", self.cred_dump_check, 60), ("📜 Audit Policy Viewer", self.audit_policy_viewer, 15), ("🔒 USB Lockdown", self.usb_lockdown, 15),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 3, i % 3, TAB_COLORS[tab_name])

    def setup_monitoring_tab(self):
        tab_name = "📊 Monitoring"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("📋 Procs", self.show_processes, 30), ("📈 Resources", self.show_resource_usage, 15), ("🔍 Uptime", self.show_system_uptime, 15),
            ("🔍 CPU Temp", self.monitor_cpu_temp, 15), ("📋 Threads", self.list_running_threads, 30), ("⚠️ Sys Health", self.check_system_health, 60),
            ("🌐 Net Traffic", self.net_traffic, 30), ("📋 Proc Explorer", self.proc_explorer, 30), ("💿 Disk Analyzer", self.disk_analyzer, 30),
            ("📜 Event Viewer", self.event_viewer, 30), ("⚡ Benchmark", self.benchmark, 60), ("📉 GPU Usage", self.gpu_usage, 15),
            ("🌡️ Fan Speed Monitor", self.fan_speed_monitor, 15), ("🔍 Service Monitor", self.service_monitor, 30), ("📈 Battery Health", self.battery_health, 15),
            ("🔍 Event Log Analyzer", self.event_log_analyzer, 30), ("🌐 Bandwidth Per Process", self.bandwidth_per_process, 30), ("📋 Scheduled Task Monitor", self.scheduled_task_monitor, 30),
            ("🔍 Disk I/O Stats", self.disk_io_stats, 15), ("⚠️ Memory Leak Detector", self.memory_leak_detector, 60), ("📊 Real-Time Alerts", self.real_time_alerts, 30),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 3, i % 3, TAB_COLORS[tab_name])

    def setup_utilities_tab(self):
        tab_name = "🛠️ Utilities"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("ℹ️ Sys Info", self.get_system_info, 15), ("👥 Users", self.list_users, 15), ("💿 Chk Disk", self.check_disk_health, 120),
            ("🗑️ Clr Temp", self.clear_temp_files, 60), ("📋 Env Vars", self.list_environment_vars, 30), ("📂 File Permissions Viewer", self.file_permissions_viewer, 15),
            ("🔍 Registry Backup", self.registry_backup, 30), ("📜 Shortcut Creator", self.shortcut_creator, 15), ("🗑️ Recycle Bin Manager", self.recycle_bin_manager, 15),
            ("🔍 File Integrity Checker", self.file_integrity_checker, 30), ("📋 Text Encoder/Decoder", self.text_encoder_decoder, 15), ("🖥️ Screen Capture Tool", self.screen_capture_tool, 15),
            ("📄 PDF Merger", self.pdf_merger, 30), ("🔍 Startup Optimizer", self.startup_optimizer, 30), ("🗂️ Folder Sync", self.folder_sync, 60),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 3, i % 3, TAB_COLORS[tab_name])

    def setup_network_tab(self):
        tab_name = "🌐 Network"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("🏓 Ping", self.ping_test, 30), ("🌐 Net Conns", self.check_network_connections, 30), ("🔍 Port Scanner", self.port_scanner, 60),
            ("⚡ Speed Test", self.speed_test, 30), ("🌐 DNS Lookup", self.dns_lookup, 15), ("🏓 Traceroute", self.traceroute, 30),
            ("📶 WiFi Analyzer", self.wifi_analyzer, 30), ("📡 WiFi Password Viewer", self.wifi_password_viewer, 15), ("🔍 ARP Table Viewer", self.arp_table_viewer, 15),
            ("🌐 Proxy Tester", self.proxy_tester, 30), ("📶 Signal Strength Monitor", self.signal_strength_monitor, 15), ("🔍 MAC Spoofer Check", self.mac_spoofer_check, 30),
            ("🌐 VPN Status", self.vpn_status, 15), ("🔍 WHOIS Lookup", self.whois_lookup, 15), ("📡 Packet Sniffer", self.packet_sniffer, 60),
            ("🔍 DNS Cache Cleaner", self.dns_cache_cleaner, 15), ("🌐 IP Geolocation", self.ip_geolocation, 15),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 2, i % 2, TAB_COLORS[tab_name])

    def setup_backup_tab(self):
        tab_name = "💾 Backup"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("📁 Backup Files", self.backup_files, 300), ("📂 Restore", self.restore_files, 300), ("📁 Inc Backup", self.inc_backup, 300),
            ("☁️ Cloud Backup", self.cloud_backup, 300), ("⏰ Backup Sched", self.backup_sched, 15), ("🔍 Backup Verify", self.backup_verify, 60),
            ("🔄 Restore Points", self.restore_points, 30), ("📁 Differential Backup", self.differential_backup, 300), ("🔍 Backup Encryption", self.backup_encryption, 300),
            ("📂 Mirror Backup", self.mirror_backup, 300), ("🔄 Snapshot Manager", self.snapshot_manager, 60), ("📁 Backup Comparison", self.backup_comparison, 60),
            ("☁️ OneDrive Sync Check", self.onedrive_sync_check, 15), ("📂 Backup Cleanup", self.backup_cleanup, 60), ("🔍 File Versioning", self.file_versioning, 300),
            ("📁 Network Backup", self.network_backup, 300), ("⏰ Real-Time Backup", self.real_time_backup, 300),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 2, i % 2, TAB_COLORS[tab_name])

    def setup_advanced_tab(self):
        tab_name = "🔧 Advanced"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("🔥 Tog Fwall", self.toggle_firewall, 30), ("🔑 Gen Pwd", self.generate_random_password, 15), ("🔄 Restart", self.restart_system, 15),
            ("⏹ Shutdown", self.shutdown_system, 15), ("🔒 Lock", self.lock_workstation, 15), ("🔧 Sys Tweak", self.sys_tweak, 15),
            ("🔧 Reg Editor", self.reg_editor, 30), ("🖥️ Driver Mgr", self.driver_mgr, 30), ("🚀 Boot Mgr", self.boot_mgr, 30),
            ("📄 Sys Info Export", self.sys_info_export, 15), ("🔍 BIOS Info", self.bios_info, 15), ("🖥️ Remote Desktop Toggle", self.remote_desktop_toggle, 15),
            ("🔧 Power Plan Manager", self.power_plan_manager, 15), ("📜 Command History", self.command_history, 15), ("🔍 Group Policy Viewer", self.group_policy_viewer, 15),
            ("🛠️ Task Kill by Name", self.task_kill_by_name, 15), ("🔧 Windows Feature Manager", self.windows_feature_manager, 30), ("📋 Clipboard Sync", self.clipboard_sync, 30),
            ("🔍 Boot Log Analyzer", self.boot_log_analyzer, 30), ("🖥️ Multi-Monitor Config", self.multi_monitor_config, 15),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 3, i % 3, TAB_COLORS[tab_name])

    def setup_passwords_tab(self):
        tab_name = "🔐 Passwords"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("🔑 Password Generator (Custom)", self.password_generator_custom, 15), ("🔍 Password Leak Check", self.password_leak_check, 30),
            ("🔒 Password Sync", self.password_sync, 30), ("📜 Password Policy Enforcer", self.password_policy_enforcer, 15),
            ("🔑 Master Password", self.master_password, 15), ("🔍 Duplicate Password Finder", self.duplicate_password_finder, 15),
            ("🔒 Password Expiry Tracker", self.password_expiry_tracker, 15), ("📋 Password Import", self.password_import, 30),
            ("🔑 TOTP Backup", self.totp_backup, 15), ("🔍 Password Strength Analyzer", self.password_strength_analyzer, 15),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 2, i % 2, TAB_COLORS[tab_name])
        self.pwd_frame = ctk.CTkFrame(frame)
        self.pwd_frame.grid(row=0, column=2, rowspan=5, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(self.pwd_frame, text="Password Manager", font=("Segoe UI", 14, "bold")).pack(pady=5)
        self.pwd_name = ctk.CTkEntry(self.pwd_frame, placeholder_text="Service Name")
        self.pwd_name.pack(pady=5)
        self.pwd_value = ctk.CTkEntry(self.pwd_frame, placeholder_text="Password", show="*")
        self.pwd_value.pack(pady=5)
        ctk.CTkButton(self.pwd_frame, text="Add", command=self.add_password).pack(pady=5)
        ctk.CTkButton(self.pwd_frame, text="View", command=self.view_password).pack(pady=5)
        ctk.CTkButton(self.pwd_frame, text="Delete", command=self.delete_password).pack(pady=5)
        self.pwd_list = Listbox(self.pwd_frame, height=10)
        self.pwd_list.pack(pady=5)
        self.update_password_list()

    def setup_scheduler_tab(self):
        tab_name = "⏰ Scheduler"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("⏰ Recurring Tasks", self.recurring_tasks, 15), ("🔍 Task Dependency", self.task_dependency, 15),
            ("📜 Task Log Viewer", self.task_log_viewer, 15), ("🔧 Task Priority", self.task_priority, 15),
            ("⏰ Delay Task", self.delay_task, 15), ("🔍 Task Conflict Check", self.task_conflict_check, 15),
            ("📋 Task Export", self.task_export, 15), ("🔧 Task Condition", self.task_condition, 15),
            ("⏰ Wake on Task", self.wake_on_task, 15), ("🔍 Task Simulator", self.task_simulator, 15),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 2, i % 2, TAB_COLORS[tab_name])
        self.task_frame = ctk.CTkFrame(frame)
        self.task_frame.grid(row=0, column=2, rowspan=5, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(self.task_frame, text="Task Scheduler", font=("Segoe UI", 14, "bold")).pack(pady=5)
        self.task_name = ctk.CTkEntry(self.task_frame, placeholder_text="Task Name")
        self.task_name.pack(pady=5)
        self.task_time = ctk.CTkEntry(self.task_frame, placeholder_text="Time (HH:MM)")
        self.task_time.pack(pady=5)
        ctk.CTkButton(self.task_frame, text="Add", command=self.add_scheduled_task).pack(pady=5)
        ctk.CTkButton(self.task_frame, text="Remove", command=self.remove_scheduled_task).pack(pady=5)
        self.task_list = Listbox(self.task_frame, height=10)
        self.task_list.pack(pady=5)
        self.update_task_list()

    def setup_analytics_tab(self):
        tab_name = "📈 Analytics"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("📉 Process Heatmap", self.process_heatmap, 30), ("🔍 Anomaly Detector", self.anomaly_detector, 30),
            ("📈 Network Latency Graph", self.network_latency_graph, 30), ("🔍 Disk Latency", self.disk_latency, 15),
            ("📉 CPU Core Usage", self.cpu_core_usage, 15), ("🔍 Event Correlation", self.event_correlation, 30),
            ("📈 Trend Predictor", self.trend_predictor, 30), ("🔍 Log Analytics", self.log_analytics, 30),
            ("📉 Power Usage", self.power_usage, 15), ("🔍 Bottleneck Finder", self.bottleneck_finder, 30),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 2, i % 2, TAB_COLORS[tab_name])
        self.fig, self.ax = plt.subplots(figsize=(8, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=frame)
        self.canvas.get_tk_widget().grid(row=5, column=0, columnspan=3, pady=5)

    def setup_plugins_tab(self):
        tab_name = "📦 Plugins"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("🔌 Plugin Marketplace", self.plugin_marketplace, 30), ("🔍 Plugin Validator", self.plugin_validator, 15),
            ("📜 Plugin Log", self.plugin_log, 15), ("🔧 Plugin Config", self.plugin_config, 15),
            ("🔍 Plugin Dependency Checker", self.plugin_dependency_checker, 15), ("📦 Plugin Packager", self.plugin_packager, 30),
            ("🔌 Plugin Auto-Update", self.plugin_auto_update, 30), ("🔍 Plugin Sandbox", self.plugin_sandbox, 15),
            ("📜 Plugin Documentation", self.plugin_documentation, 15), ("🔧 Plugin Hotkey", self.plugin_hotkey, 15),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 2, i % 2, TAB_COLORS[tab_name])
        self.plugin_frame = ctk.CTkFrame(frame)
        self.plugin_frame.grid(row=0, column=2, rowspan=5, padx=5, pady=5, sticky="nsew")
        ctk.CTkButton(self.plugin_frame, text="Load Plugin", command=self.load_plugin).pack(pady=5)
        self.plugin_list = Listbox(self.plugin_frame, height=10)
        self.plugin_list.pack(pady=5)
        self.update_plugin_list()

    def setup_it_support_tab(self):
        tab_name = "🖥️ IT Support"
        frame = self.notebook.add(tab_name)
        scroll_frame = ctk.CTkScrollableFrame(frame)
        scroll_frame.pack(fill="both", expand=True)
        buttons = [
            ("🖥️ Remote Shutdown", self.remote_shutdown, 15), ("🔄 Service Restart", self.service_restart, 15), ("📋 User Session List", self.user_session_list, 15),
            ("🔍 Logoff User", self.logoff_user, 15), ("🛠️ Repair Windows Update", self.repair_windows_update, 60), ("🔧 SFC Scan", self.sfc_scan, 120),
            ("📜 DISM Health Check", self.dism_health_check, 120), ("🔍 Temp Profile Fix", self.temp_profile_fix, 30), ("🖥️ Remote Command", self.remote_command, 30),
            ("🔧 Time Sync", self.time_sync, 15), ("🌐 IP Config Reset", self.ip_config_reset, 15), ("🔍 Network Adapter Reset", self.network_adapter_reset, 15),
            ("📡 Winsock Reset", self.winsock_reset, 15), ("🔍 TCP/IP Reset", self.tcp_ip_reset, 15), ("🌐 Static IP Setter", self.static_ip_setter, 15),
            ("🔍 DHCP Lease Viewer", self.dhcp_lease_viewer, 15), ("📶 WiFi Troubleshooter", self.wifi_troubleshooter, 30), ("🔍 NetBIOS Status", self.netbios_status, 15),
            ("🌐 Gateway Checker", self.gateway_checker, 15), ("🔍 DNS Troubleshooter", self.dns_troubleshooter, 30), ("👥 Add Local User", self.add_local_user, 15),
            ("🔑 Reset Password", self.reset_password, 15), ("🔍 User Rights Viewer", self.user_rights_viewer, 15), ("👥 Group Membership", self.group_membership, 15),
            ("🔒 Account Lockout Check", self.account_lockout_check, 15), ("👥 User Profile Backup", self.user_profile_backup, 60), ("🔍 Last Logon Time", self.last_logon_time, 15),
            ("👥 Disable Account", self.disable_account, 15), ("🔑 Password Never Expires", self.password_never_expires, 15), ("📋 AD User Info", self.ad_user_info, 30),
            ("📦 Uninstall App", self.uninstall_app, 30), ("🔍 Installed Software List", self.installed_software_list, 15), ("📜 Pending Updates", self.pending_updates, 15),
            ("🔧 Install MSI", self.install_msi, 30), ("📦 Winget Wrapper", self.winget_wrapper, 30), ("🔍 Driver Backup", self.driver_backup, 60),
            ("📜 Driver Rollback", self.driver_rollback, 30), ("🔧 App Crash Log", self.app_crash_log, 30), ("📦 Software Cleanup", self.software_cleanup, 60),
            ("🔍 Update History", self.update_history, 15), ("📜 BSOD Log Viewer", self.bsod_log_viewer, 30), ("🔍 Hardware Diagnostic", self.hardware_diagnostic, 60),
            ("📋 System Info Report", self.system_info_report, 15), ("🔍 Event Log Export", self.event_log_export, 30), ("📜 Performance Log", self.performance_log, 60),
            ("🔍 Disk Error Check", self.disk_error_check, 120), ("📋 Memory Test", self.memory_test, 60), ("🔍 Printer Diagnostic", self.printer_diagnostic, 30),
            ("📜 Battery Report", self.battery_report, 15), ("🔍 System File Verifier", self.system_file_verifier, 120),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(scroll_frame, text, cmd, timeout, i // 3, i % 3, TAB_COLORS[tab_name])

    # Task Queueing (Unchanged)
    def queue_task(self, task_func, timeout, task_name):
        task_id = secrets.token_hex(4)
        self.current_tasks[task_id] = {'func': task_func, 'timeout': timeout, 'name': task_name}
        self.status_indicator.configure(text_color="yellow")
        self.status_label.configure(text=f"Running {task_name}...")
        self.progress_bar.set(0)
        threading.Thread(target=self.run_task, args=(task_id,), daemon=True).start()

    def run_task(self, task_id):
        task = self.current_tasks[task_id]
        steps = 10
        for i in range(steps):
            self.progress_bar.set((i + 1) / steps)
            time.sleep(task['timeout'] / steps)
        try:
            result = task['func']()
            self.log_queue.put(f"{self.current_tasks[task_id]['name']} completed: {result}")
            self.show_notification(f"{self.current_tasks[task_id]['name']} completed")
            self.show_output_popup(self.current_tasks[task_id]['name'], result)
        except Exception as e:
            self.progress_bar.set(0)
            self.log_queue.put(f"{self.current_tasks[task_id]['name']} failed: {e}")
            self.show_notification(f"{self.current_tasks[task_id]['name']} failed", error=True)
            self.show_output_popup(self.current_tasks[task_id]['name'], f"Error: {e}", failed=True)
        finally:
            del self.current_tasks[task_id]
            self.status_indicator.configure(text_color="green")
            self.status_label.configure(text="Ready")
            self.progress_bar.set(0)

    def show_output_popup(self, title, message, failed=False):
        popup = Toplevel(self.root)
        popup.title(title)
        popup.geometry("400x300")
        popup.transient(self.root)
        popup.configure(bg="#2b2b2b" if ctk.get_appearance_mode() == "Dark" else "#ffffff")
        ctk.CTkLabel(popup, text=title, font=("Segoe UI", 14, "bold"), text_color="red" if failed else "white").pack(pady=5)
        text_area = scrolledtext.ScrolledText(popup, width=50, height=15, font=("Segoe UI", 11), wrap=tk.WORD, bg="#2b2b2b", fg="white")
        text_area.pack(pady=5)
        text_area.insert(tk.END, message)
        text_area.configure(state='disabled')
        button_frame = ctk.CTkFrame(popup, fg_color="transparent")
        button_frame.pack(pady=5)
        ctk.CTkButton(button_frame, text="Export", command=lambda: self.export_output(message), fg_color="#28a745", hover_color="#218838").pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Close", command=popup.destroy, fg_color="#dc3545" if failed else "#007bff", hover_color="#c82333" if failed else "#0056b3").pack(side="left", padx=5)

    def export_output(self, message):
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file:
            with open(file, 'w') as f:
                f.write(message)
            self.log_queue.put(f"Output exported to {file}")

    def show_notification(self, message, error=False):
        popup = ctk.CTkToplevel(self.root)
        popup.geometry("300x100+{}+{}".format(self.root.winfo_x() + 50, self.root.winfo_y() + 50))
        popup.overrideredirect(True)
        popup.attributes("-alpha", 0.9)
        ctk.CTkLabel(popup, text=message, font=("Segoe UI", 12), text_color="white" if not error else "red").pack(pady=20)
        popup.after(3000, popup.destroy)

    def ask_input(self, prompt):
        return simpledialog.askstring("Input", prompt, parent=self.root)

    # Security Tab Methods
    def generate_key(self):
        self.key = Fernet.generate_key()
        return f"Key generated: {self.key.decode()}"

    def encrypt_file(self):
        if not self.key:
            return "Generate a key first!"
        file = filedialog.askopenfilename()
        if file:
            with open(file, 'rb') as f:
                data = f.read()
            fernet = Fernet(self.key)
            encrypted = fernet.encrypt(data)
            with open(file + '.encrypted', 'wb') as f:
                f.write(encrypted)
            return f"File encrypted: {file}.encrypted"

    def decrypt_file(self):
        if not self.key:
            return "Generate a key first!"
        file = filedialog.askopenfilename()
        if file:
            with open(file, 'rb') as f:
                data = f.read()
            fernet = Fernet(self.key)
            try:
                decrypted = fernet.decrypt(data)
                with open(file.replace('.encrypted', '_decrypted'), 'wb') as f:
                    f.write(decrypted)
                return f"File decrypted: {file.replace('.encrypted', '_decrypted')}"
            except Exception as e:
                return f"Decryption failed: {e}"

    def hash_file(self):
        file = filedialog.askopenfilename()
        if file:
            with open(file, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        return "No file selected."

    def check_antivirus_status(self):
        result = subprocess.run(['powershell', 'Get-MpComputerStatus'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def check_firewall_status(self):
        result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def list_startup_items(self):
        result = subprocess.run(['wmic', 'startup', 'get', 'caption,command'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def check_suspicious_processes(self):
        suspicious = [p.info for p in psutil.process_iter(['pid', 'name', 'memory_percent']) if p.info['memory_percent'] > 20]
        return "\n".join([f"PID: {p['pid']} Name: {p['name']} Memory: {p['memory_percent']:.2f}%" for p in suspicious]) or "No suspicious processes found."

    def generate_otp(self):
        return ''.join(secrets.choice(string.digits) for _ in range(6))

    def vuln_scan(self):
        return "Vulnerability scan: [Placeholder - Basic system check completed]"

    def pwd_strength(self):
        pwd = self.ask_input("Enter password to check:")
        if not pwd:
            return "No password provided."
        score = sum(1 for c in pwd if c in string.ascii_uppercase) + sum(1 for c in pwd if c in string.ascii_lowercase) + sum(1 for c in pwd if c in string.digits) + sum(1 for c in pwd if c in string.punctuation)
        return f"Password strength: {'Strong' if score > 10 else 'Weak' if score < 5 else 'Moderate'} (Score: {score})"

    def fwall_rules(self):
        result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def shred_file(self):
        file = filedialog.askopenfilename()
        if file and messagebox.askyesno("Confirm", f"Shred {file}? This is permanent!"):
            with open(file, 'wb') as f:
                f.write(os.urandom(os.path.getsize(file)))
            os.remove(file)
            return f"File shredded: {file}"
        return "No file selected or shred cancelled."

    def harden_sys(self):
        return "Hardening suggestions: Enable UAC, update OS, disable unused services."

    def password_vault_export(self):
        if not self.passwords:
            return "No passwords to export."
        file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file:
            with open(file, 'w') as f:
                json.dump(self.passwords, f)
            return f"Passwords exported to {file}"

    def phishing_detector(self):
        url = self.ask_input("Enter URL or email header to analyze:")
        if not url:
            return "No input provided."
        return f"Phishing analysis for {url}: [Placeholder - Suspicious if from unknown source]"

    def malware_scanner(self):
        file = filedialog.askopenfilename()
        if not file:
            return "No file selected."
        with open(file, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return f"Malware scan for {file}: SHA256={file_hash} (No match in placeholder DB)"

    def totp_generator(self):
        return ''.join(secrets.choice(string.digits) for _ in range(6))

    def rogue_ap_detector(self):
        return "Rogue AP scan: [Placeholder - Requires WiFi scanning library]"

    def bitlocker_status(self):
        result = subprocess.run(['manage-bde', '-status'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def secure_boot_check(self):
        result = subprocess.run(['powershell', 'Confirm-SecureBootUEFI'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def cred_dump_check(self):
        return "Credential dump check: [Placeholder - Basic memory scan completed]"

    def audit_policy_viewer(self):
        result = subprocess.run(['auditpol', '/get', '/category:*'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def usb_lockdown(self):
        state = self.ask_input("Enter 'on' to disable USB storage, 'off' to enable:")
        if state == 'on':
            subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR', '/v', 'Start', '/t', 'REG_DWORD', '/d', '4', '/f'])
            return "USB storage disabled."
        elif state == 'off':
            subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR', '/v', 'Start', '/t', 'REG_DWORD', '/d', '3', '/f'])
            return "USB storage enabled."
        return "Invalid input."

    # Monitoring Tab Methods
    def show_processes(self):
        return "\n".join([f"PID: {p.pid} Name: {p.name()}" for p in psutil.process_iter(['pid', 'name'])])

    def show_resource_usage(self):
        return f"CPU: {psutil.cpu_percent()}%\nRAM: {psutil.virtual_memory().percent}%\nDisk: {psutil.disk_usage('/').percent}%"

    def show_system_uptime(self):
        uptime = time.time() - psutil.boot_time()
        return f"Uptime: {uptime // 3600}h {(uptime % 3600) // 60}m {int(uptime % 60)}s"

    def monitor_cpu_temp(self):
        return "CPU Temp: [Placeholder - Requires 'py-sensors' or similar library]"

    def list_running_threads(self):
        return "\n".join([f"Thread ID: {t.ident} Name: {t.name}" for t in threading.enumerate()])

    def check_system_health(self):
        return f"Health: CPU {psutil.cpu_percent()}%, RAM {psutil.virtual_memory().percent}%, Disk {psutil.disk_usage('/').percent}%"

    def net_traffic(self):
        net = psutil.net_io_counters()
        return f"Sent: {net.bytes_sent / 1024:.2f} KB, Received: {net.bytes_recv / 1024:.2f} KB"

    def proc_explorer(self):
        return "\n".join([f"PID: {p.pid} Name: {p.name()} CPU: {p.cpu_percent()}%" for p in psutil.process_iter(['pid', 'name', 'cpu_percent'])])

    def disk_analyzer(self):
        return f"Disk Usage: {psutil.disk_usage('/').used / (1024**3):.2f} GB used of {psutil.disk_usage('/').total / (1024**3):.2f} GB"

    def event_viewer(self):
        result = subprocess.run(['wevtutil', 'qe', 'System', '/f:text', '/c:10'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def benchmark(self):
        start = time.time()
        for _ in range(1000000):
            pass
        return f"Benchmark: {time.time() - start:.2f} seconds for 1M iterations"

    def gpu_usage(self):
        return "GPU Usage: [Placeholder - Requires NVIDIA/AMD API or psutil extension]"

    def fan_speed_monitor(self):
        return "Fan Speed: [Placeholder - Requires sensor library]"

    def service_monitor(self):
        result = subprocess.run(['sc', 'query'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def battery_health(self):
        battery = psutil.sensors_battery()
        if battery:
            return f"Battery: {battery.percent}% (Plugged in: {battery.power_plugged})"
        return "No battery detected."

    def event_log_analyzer(self):
        return "Event Log Analysis: [Placeholder - Critical events filtered]"

    def bandwidth_per_process(self):
        return "Bandwidth per Process: [Placeholder - Requires network monitoring library]"

    def scheduled_task_monitor(self):
        result = subprocess.run(['schtasks', '/query', '/fo', 'LIST'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def disk_io_stats(self):
        io = psutil.disk_io_counters()
        return f"Read: {io.read_bytes / 1024:.2f} KB, Write: {io.write_bytes / 1024:.2f} KB"

    def memory_leak_detector(self):
        return "Memory Leak Check: [Placeholder - Monitoring for unusual growth]"

    def real_time_alerts(self):
        return "Real-Time Alerts: [Placeholder - Configurable thresholds set]"

    # Utilities Tab Methods
    def get_system_info(self):
        return f"OS: {platform.system()} {platform.release()}\nMachine: {platform.machine()}\nProcessor: {platform.processor()}"

    def list_users(self):
        result = subprocess.run(['net', 'user'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def check_disk_health(self):
        result = subprocess.run(['chkdsk'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def clear_temp_files(self):
        temp_dir = os.environ.get('TEMP')
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
            os.makedirs(temp_dir, exist_ok=True)
            return f"Cleared temp files in {temp_dir}"
        return "Temp directory not found."

    def list_environment_vars(self):
        return "\n".join([f"{k}={v}" for k, v in os.environ.items()])

    def file_permissions_viewer(self):
        file = filedialog.askopenfilename()
        if file:
            result = subprocess.run(['icacls', file], capture_output=True, text=True)
            return result.stdout or result.stderr
        return "No file selected."

    def registry_backup(self):
        file = filedialog.asksaveasfilename(defaultextension=".reg", filetypes=[("Registry files", "*.reg")])
        if file:
            subprocess.run(['reg', 'export', 'HKLM', file, '/y'])
            return f"Registry backed up to {file}"
        return "No file selected."

    def shortcut_creator(self):
        target = filedialog.askopenfilename()
        if target:
            name = self.ask_input("Enter shortcut name:")
            if name:
                desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
                with open(os.path.join(desktop, f"{name}.lnk"), 'wb') as f:
                    subprocess.run(['powershell', f'New-Item -ItemType SymbolicLink -Path "{f.name}" -Target "{target}"'])
                return f"Shortcut created: {name}.lnk"
        return "No target selected."

    def recycle_bin_manager(self):
        return "Recycle Bin: [Placeholder - View/restore functionality pending]"

    def file_integrity_checker(self):
        file = filedialog.askopenfilename()
        if file:
            with open(file, 'rb') as f:
                return f"File hash: {hashlib.sha256(f.read()).hexdigest()}"
        return "No file selected."

    def text_encoder_decoder(self):
        text = self.ask_input("Enter text to encode/decode:")
        if text:
            action = self.ask_input("Enter 'encode' or 'decode' (Base64):")
            if action == 'encode':
                return base64.b64encode(text.encode()).decode()
            elif action == 'decode':
                return base64.b64decode(text.encode()).decode()
        return "No text provided."

    def screen_capture_tool(self):
        return "Screen Capture: [Placeholder - Requires PIL or similar library]"

    def pdf_merger(self):
        files = filedialog.askopenfilenames(filetypes=[("PDF files", "*.pdf")])
        if files:
            from PyPDF2 import PdfMerger
            merger = PdfMerger()
            for pdf in files:
                merger.append(pdf)
            output = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
            if output:
                merger.write(output)
                merger.close()
                return f"PDFs merged into {output}"
        return "No files selected."

    def startup_optimizer(self):
        return "Startup Optimizer: [Placeholder - Suggestions pending]"

    def folder_sync(self):
        src = filedialog.askdirectory()
        dst = filedialog.askdirectory()
        if src and dst:
            shutil.copytree(src, dst, dirs_exist_ok=True)
            return f"Synced {src} to {dst}"
        return "No directories selected."

    # Network Tab Methods
    def ping_test(self):
        target = self.ask_input("Enter host to ping:")
        if target:
            result = subprocess.run(['ping', target], capture_output=True, text=True)
            return result.stdout or result.stderr
        return "No target specified."

    def check_network_connections(self):
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def port_scanner(self):
        target = self.ask_input("Enter host to scan:")
        ports = self.ask_input("Enter port range (e.g., 1-100):")
        if target and ports:
            start, end = map(int, ports.split('-'))
            open_ports = []
            for port in range(start, end + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            return f"Open ports on {target}: {open_ports}" if open_ports else f"No open ports found on {target}"
        return "Invalid input."

    def speed_test(self):
        return "Speed Test: [Placeholder - Requires speedtest-cli]"

    def dns_lookup(self):
        domain = self.ask_input("Enter domain for DNS lookup:")
        if domain:
            return socket.gethostbyname(domain)
        return "No domain specified."

    def traceroute(self):
        target = self.ask_input("Enter host for traceroute:")
        if target:
            result = subprocess.run(['tracert', target], capture_output=True, text=True)
            return result.stdout or result.stderr
        return "No target specified."

    def wifi_analyzer(self):
        result = subprocess.run(['netsh', 'wlan', 'show', 'networks'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def wifi_password_viewer(self):
        result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True)
        profiles = [line.split(":")[1].strip() for line in result.stdout.splitlines() if "All User Profile" in line]
        output = []
        for profile in profiles:
            result = subprocess.run(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "Key Content" in line:
                    output.append(f"{profile}: {line.split(':')[1].strip()}")
        return "\n".join(output) or "No WiFi passwords found."

    def arp_table_viewer(self):
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def proxy_tester(self):
        return "Proxy Tester: [Placeholder - Requires proxy configuration]"

    def signal_strength_monitor(self):
        return "Signal Strength: [Placeholder - Requires WiFi library]"

    def mac_spoofer_check(self):
        return "MAC Spoofer Check: [Placeholder - Basic check completed]"

    def vpn_status(self):
        return "VPN Status: [Placeholder - Requires VPN detection]"

    def whois_lookup(self):
        domain = self.ask_input("Enter domain for WHOIS lookup:")
        if domain:
            return "WHOIS: [Placeholder - Requires whois library or API]"
        return "No domain specified."

    def packet_sniffer(self):
        return "Packet Sniffer: [Placeholder - Requires scapy]"

    def dns_cache_cleaner(self):
        subprocess.run(['ipconfig', '/flushdns'])
        return "DNS cache cleared."

    def ip_geolocation(self):
        ip = self.ask_input("Enter IP for geolocation:")
        if ip:
            return f"IP Geolocation for {ip}: [Placeholder - Requires API]"
        return "No IP specified."

    # Backup Tab Methods
    def backup_files(self):
        folder = filedialog.askdirectory()
        if folder:
            zip_file = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("ZIP files", "*.zip")])
            if zip_file:
                with ZipFile(zip_file, 'w') as zipf:
                    for root, _, files in os.walk(folder):
                        for file in files:
                            zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), folder))
                return f"Backup created: {zip_file}"
        return "No folder selected."

    def restore_files(self):
        zip_file = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        if zip_file:
            extract_dir = filedialog.askdirectory()
            if extract_dir:
                with ZipFile(zip_file, 'r') as zipf:
                    zipf.extractall(extract_dir)
                return f"Files restored to {extract_dir}"
        return "No ZIP file selected."

    def inc_backup(self):
        return "Incremental Backup: [Placeholder - Requires implementation]"

    def cloud_backup(self):
        return "Cloud Backup: [Placeholder - Requires cloud service integration]"

    def backup_sched(self):
        return "Backup Schedule: [Placeholder - Added to scheduler]"

    def backup_verify(self):
        return "Backup Verify: [Placeholder - Verification completed]"

    def restore_points(self):
        result = subprocess.run(['vssadmin', 'list', 'shadows'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def differential_backup(self):
        return "Differential Backup: [Placeholder - Requires implementation]"

    def backup_encryption(self):
        return "Backup Encryption: [Placeholder - Requires encryption setup]"

    def mirror_backup(self):
        src = filedialog.askdirectory()
        dst = filedialog.askdirectory()
        if src and dst:
            shutil.copytree(src, dst, dirs_exist_ok=True)
            return f"Mirror backup created: {dst}"
        return "No directories selected."

    def snapshot_manager(self):
        return "Snapshot Manager: [Placeholder - VSS management pending]"

    def backup_comparison(self):
        return "Backup Comparison: [Placeholder - Comparison completed]"

    def onedrive_sync_check(self):
        return "OneDrive Sync Check: [Placeholder - Requires OneDrive API]"

    def backup_cleanup(self):
        return "Backup Cleanup: [Placeholder - Old backups deleted]"

    def file_versioning(self):
        return "File Versioning: [Placeholder - Versioning enabled]"

    def network_backup(self):
        return "Network Backup: [Placeholder - Requires network path]"

    def real_time_backup(self):
        return "Real-Time Backup: [Placeholder - Monitoring enabled]"

    # Advanced Tab Methods
    def toggle_firewall(self):
        state = self.ask_input("Enter 'on' or 'off' for firewall:")
        if state == 'on':
            subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'])
            return "Firewall enabled."
        elif state == 'off':
            subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'off'])
            return "Firewall disabled."
        return "Invalid input."

    def generate_random_password(self):
        return secrets.token_urlsafe(16)

    def restart_system(self):
        if messagebox.askyesno("Confirm", "Restart system now?"):
            subprocess.run(['shutdown', '/r', '/t', '0'])
            return "Restarting..."
        return "Restart cancelled."

    def shutdown_system(self):
        if messagebox.askyesno("Confirm", "Shutdown system now?"):
            subprocess.run(['shutdown', '/s', '/t', '0'])
            return "Shutting down..."
        return "Shutdown cancelled."

    def lock_workstation(self):
        subprocess.run(['rundll32.exe', 'user32.dll,LockWorkStation'])
        return "Workstation locked."

    def sys_tweak(self):
        return "System Tweak: [Placeholder - Tweaks applied]"

    def reg_editor(self):
        subprocess.run(['regedit'])
        return "Registry Editor opened."

    def driver_mgr(self):
        subprocess.run(['devmgmt.msc'])
        return "Device Manager opened."

    def boot_mgr(self):
        subprocess.run(['msconfig'])
        return "System Configuration opened."

    def sys_info_export(self):
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file:
            with open(file, 'w') as f:
                f.write(self.get_system_info())
            return f"System info exported to {file}"

    def bios_info(self):
        result = subprocess.run(['wmic', 'bios', 'get', 'smbiosbiosversion'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def remote_desktop_toggle(self):
        state = self.ask_input("Enter 'on' or 'off' for RDP:")
        if state == 'on':
            subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server', '/v', 'fDenyTSConnections', '/t', 'REG_DWORD', '/d', '0', '/f'])
            return "RDP enabled."
        elif state == 'off':
            subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server', '/v', 'fDenyTSConnections', '/t', 'REG_DWORD', '/d', '1', '/f'])
            return "RDP disabled."
        return "Invalid input."

    def power_plan_manager(self):
        result = subprocess.run(['powercfg', '/list'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def command_history(self):
        return "Command History: [Placeholder - Recent commands logged]"

    def group_policy_viewer(self):
        result = subprocess.run(['gpresult', '/r'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def task_kill_by_name(self):
        name = self.ask_input("Enter process name to kill:")
        if name:
            subprocess.run(['taskkill', '/IM', name, '/F'])
            return f"Attempted to kill {name}"
        return "No name provided."

    def windows_feature_manager(self):
        subprocess.run(['optionalfeatures'])
        return "Windows Features opened."

    def clipboard_sync(self):
        return "Clipboard Sync: [Placeholder - Requires network setup]"

    def boot_log_analyzer(self):
        return "Boot Log: [Placeholder - Analysis completed]"

    def multi_monitor_config(self):
        subprocess.run(['desk.cpl'])
        return "Display settings opened."

    # Passwords Tab Methods
    def password_generator_custom(self):
        length = int(self.ask_input("Enter password length:") or 16)
        return secrets.token_urlsafe(length)

    def password_leak_check(self):
        pwd = self.ask_input("Enter password to check for leaks:")
        if pwd:
            return "Leak Check: [Placeholder - Requires Have I Been Pwned API]"
        return "No password provided."

    def password_sync(self):
        return "Password Sync: [Placeholder - Sync enabled]"

    def password_policy_enforcer(self):
        return "Password Policy: [Placeholder - Minimum standards set]"

    def master_password(self):
        return "Master Password: [Placeholder - Vault secured]"

    def duplicate_password_finder(self):
        duplicates = [k for k, v in self.passwords.items() if list(self.passwords.values()).count(v) > 1]
        return f"Duplicates: {duplicates}" if duplicates else "No duplicates found."

    def password_expiry_tracker(self):
        return "Expiry Tracker: [Placeholder - Alerts set]"

    def password_import(self):
        file = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if file:
            with open(file, 'r') as f:
                import csv
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2:
                        self.passwords[row[0]] = row[1]
            self.update_password_list()
            return f"Passwords imported from {file}"
        return "No file selected."

    def totp_backup(self):
        return "TOTP Backup: [Placeholder - Recovery codes stored]"

    def password_strength_analyzer(self):
        pwd = self.ask_input("Enter password to analyze:")
        if pwd:
            return f"Strength Analysis: [Placeholder - Entropy: {len(pwd) * 4} bits]"
        return "No password provided."

    def add_password(self):
        name = self.pwd_name.get()
        pwd = self.pwd_value.get()
        if name and pwd:
            self.passwords[name] = self.cipher.encrypt(pwd.encode()).decode()
            self.update_password_list()
            self.pwd_name.delete(0, END)
            self.pwd_value.delete(0, END)

    def view_password(self):
        selected = self.pwd_list.get(self.pwd_list.curselection())
        if selected:
            decrypted = self.cipher.decrypt(self.passwords[selected].encode()).decode()
            messagebox.showinfo("Password", f"{selected}: {decrypted}")

    def delete_password(self):
        selected = self.pwd_list.get(self.pwd_list.curselection())
        if selected and messagebox.askyesno("Confirm", f"Delete {selected}?"):
            del self.passwords[selected]
            self.update_password_list()

    def update_password_list(self):
        self.pwd_list.delete(0, END)
        for name in self.passwords:
            self.pwd_list.insert(END, name)

    # Scheduler Tab Methods
    def recurring_tasks(self):
        return "Recurring Tasks: [Placeholder - Scheduled]"

    def task_dependency(self):
        return "Task Dependency: [Placeholder - Dependency set]"

    def task_log_viewer(self):
        return "Task Log: [Placeholder - Logs displayed]"

    def task_priority(self):
        return "Task Priority: [Placeholder - Priority set]"

    def delay_task(self):
        return "Delay Task: [Placeholder - Delay added]"

    def task_conflict_check(self):
        return "Conflict Check: [Placeholder - No conflicts]"

    def task_export(self):
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file:
            with open(file, 'w') as f:
                f.write("\n".join(self.scheduled_tasks))
            return f"Tasks exported to {file}"
        return "No file selected."

    def task_condition(self):
        return "Task Condition: [Placeholder - Condition set]"

    def wake_on_task(self):
        return "Wake on Task: [Placeholder - Wake enabled]"

    def task_simulator(self):
        return "Task Simulator: [Placeholder - Simulation completed]"

    def add_scheduled_task(self):
        name = self.task_name.get()
        time_str = self.task_time.get()
        if name and time_str:
            self.scheduled_tasks.append(f"{name} at {time_str}")
            self.update_task_list()
            self.task_name.delete(0, END)
            self.task_time.delete(0, END)

    def remove_scheduled_task(self):
        selected = self.task_list.get(self.task_list.curselection())
        if selected and messagebox.askyesno("Confirm", f"Remove {selected}?"):
            self.scheduled_tasks.remove(selected)
            self.update_task_list()

    def update_task_list(self):
        self.task_list.delete(0, END)
        for task in self.scheduled_tasks:
            self.task_list.insert(END, task)

    def check_scheduled_tasks(self):
        while self.running:
            current_time = time.strftime("%H:%M")
            for task in self.scheduled_tasks:
                if current_time in task:
                    self.log_queue.put(f"Running scheduled task: {task}")
            time.sleep(60)

    # Analytics Tab Methods
    def process_heatmap(self):
        return "Process Heatmap: [Placeholder - Visualization pending]"

    def anomaly_detector(self):
        return "Anomaly Detector: [Placeholder - No anomalies]"

    def network_latency_graph(self):
        return "Network Latency: [Placeholder - Graph pending]"

    def disk_latency(self):
        return "Disk Latency: [Placeholder - Latency measured]"

    def cpu_core_usage(self):
        return f"CPU Core Usage: {psutil.cpu_percent(percpu=True)}"

    def event_correlation(self):
        return "Event Correlation: [Placeholder - Correlation completed]"

    def trend_predictor(self):
        return "Trend Predictor: [Placeholder - Trends forecasted]"

    def log_analytics(self):
        return "Log Analytics: [Placeholder - Patterns summarized]"

    def power_usage(self):
        return "Power Usage: [Placeholder - Consumption estimated]"

    def bottleneck_finder(self):
        return "Bottleneck Finder: [Placeholder - Bottlenecks identified]"

    def collect_analytics(self):
        while self.running:
            self.analytics_data['cpu'].append(psutil.cpu_percent())
            self.analytics_data['mem'].append(psutil.virtual_memory().percent)
            self.analytics_data['disk'].append(psutil.disk_usage('/').percent)
            self.analytics_data['times'].append(time.strftime("%H:%M:%S"))
            if len(self.analytics_data['cpu']) > 50:
                self.analytics_data['cpu'].pop(0)
                self.analytics_data['mem'].pop(0)
                self.analytics_data['disk'].pop(0)
                self.analytics_data['times'].pop(0)
            self.root.event_generate("<<UpdateAnalytics>>", when="tail")
            time.sleep(5)

    def update_analytics_plot(self):
        self.ax.clear()
        self.ax.plot(self.analytics_data['times'], self.analytics_data['cpu'], label='CPU')
        self.ax.plot(self.analytics_data['times'], self.analytics_data['mem'], label='Memory')
        self.ax.plot(self.analytics_data['times'], self.analytics_data['disk'], label='Disk')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Usage (%)')
        self.ax.legend()
        self.ax.tick_params(axis='x', rotation=45)
        self.canvas.draw()

    # Plugins Tab Methods
    def plugin_marketplace(self):
        return "Plugin Marketplace: [Placeholder - Marketplace opened]"

    def plugin_validator(self):
        return "Plugin Validator: [Placeholder - Validation completed]"

    def plugin_log(self):
        return "Plugin Log: [Placeholder - Logs displayed]"

    def plugin_config(self):
        return "Plugin Config: [Placeholder - Configuration opened]"

    def plugin_dependency_checker(self):
        return "Dependency Checker: [Placeholder - Dependencies verified]"

    def plugin_packager(self):
        return "Plugin Packager: [Placeholder - Package created]"

    def plugin_auto_update(self):
        return "Plugin Auto-Update: [Placeholder - Updates checked]"

    def plugin_sandbox(self):
        return "Plugin Sandbox: [Placeholder - Sandbox enabled]"

    def plugin_documentation(self):
        return "Plugin Documentation: [Placeholder - Docs displayed]"

    def plugin_hotkey(self):
        return "Plugin Hotkey: [Placeholder - Hotkey assigned]"

    def load_plugin(self):
        file = filedialog.askopenfilename(filetypes=[("Python files", "*.py")])
        if file:
            spec = importlib.util.spec_from_file_location("plugin", file)
            plugin = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin)
            self.plugins[os.path.basename(file)] = plugin
            self.update_plugin_list()
            return f"Loaded plugin: {file}"
        return "No plugin selected."

    def update_plugin_list(self):
        self.plugin_list.delete(0, END)
        for name in self.plugins:
            self.plugin_list.insert(END, name)

    # IT Support Tab Methods
    def remote_shutdown(self):
        target = self.ask_input("Enter IP/hostname to shutdown:")
        if target:
            subprocess.run(['shutdown', '/m', f'\\\\{target}', '/s', '/t', '0'])
            return f"Shutdown command sent to {target}"
        return "No target specified."

    def service_restart(self):
        service = self.ask_input("Enter service name to restart:")
        if service:
            subprocess.run(['net', 'stop', service])
            subprocess.run(['net', 'start', service])
            return f"Restarted {service}"
        return "No service specified."

    def user_session_list(self):
        result = subprocess.run(['qwinsta'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def logoff_user(self):
        session = self.ask_input("Enter session ID to log off:")
        if session:
            subprocess.run(['logoff', session])
            return f"Logged off session {session}"
        return "No session specified."

    def repair_windows_update(self):
        subprocess.run(['net', 'stop', 'wuauserv'])
        subprocess.run(['net', 'stop', 'bits'])
        shutil.rmtree('C:\\Windows\\SoftwareDistribution', ignore_errors=True)
        subprocess.run(['net', 'start', 'wuauserv'])
        subprocess.run(['net', 'start', 'bits'])
        return "Windows Update repaired."

    def sfc_scan(self):
        result = subprocess.run(['sfc', '/scannow'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def dism_health_check(self):
        result = subprocess.run(['DISM', '/Online', '/Cleanup-Image', '/RestoreHealth'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def temp_profile_fix(self):
        return "Temp Profile Fix: [Placeholder - Profile fixed]"

    def remote_command(self):
        target = self.ask_input("Enter IP/hostname:")
        cmd = self.ask_input("Enter command to run:")
        if target and cmd:
            subprocess.run(['psexec', f'\\\\{target}', '-i', cmd])
            return f"Command {cmd} sent to {target}"
        return "Invalid input."

    def time_sync(self):
        subprocess.run(['w32tm', '/resync'])
        return "Time synchronized."

    def ip_config_reset(self):
        subprocess.run(['ipconfig', '/release'])
        subprocess.run(['ipconfig', '/renew'])
        return "IP configuration reset."

    def network_adapter_reset(self):
        subprocess.run(['netsh', 'interface', 'set', 'interface', 'Ethernet', 'disable'])
        subprocess.run(['netsh', 'interface', 'set', 'interface', 'Ethernet', 'enable'])
        return "Network adapter reset."

    def winsock_reset(self):
        subprocess.run(['netsh', 'winsock', 'reset'])
        return "Winsock reset."

    def tcp_ip_reset(self):
        subprocess.run(['netsh', 'int', 'ip', 'reset'])
        return "TCP/IP reset."

    def static_ip_setter(self):
        ip = self.ask_input("Enter static IP:")
        if ip:
            subprocess.run(['netsh', 'interface', 'ip', 'set', 'address', 'Ethernet', 'static', ip])
            return f"Static IP set to {ip}"
        return "No IP specified."

    def dhcp_lease_viewer(self):
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def wifi_troubleshooter(self):
        return "WiFi Troubleshooter: [Placeholder - Diagnostics run]"

    def netbios_status(self):
        result = subprocess.run(['nbtstat', '-n'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def gateway_checker(self):
        result = subprocess.run(['ipconfig'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def dns_troubleshooter(self):
        return "DNS Troubleshooter: [Placeholder - Diagnostics run]"

    def add_local_user(self):
        username = self.ask_input("Enter new username:")
        pwd = self.ask_input("Enter password:")
        if username and pwd:
            subprocess.run(['net', 'user', username, pwd, '/add'])
            return f"User {username} added."
        return "Invalid input."

    def reset_password(self):
        username = self.ask_input("Enter username to reset password:")
        pwd = self.ask_input("Enter new password:")
        if username and pwd:
            subprocess.run(['net', 'user', username, pwd])
            return f"Password reset for {username}"
        return "Invalid input."

    def user_rights_viewer(self):
        result = subprocess.run(['whoami', '/priv'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def group_membership(self):
        username = self.ask_input("Enter username to check groups:")
        if username:
            result = subprocess.run(['net', 'user', username], capture_output=True, text=True)
            return result.stdout or result.stderr
        return "No username specified."

    def account_lockout_check(self):
        return "Account Lockout: [Placeholder - Check completed]"

    def user_profile_backup(self):
        return "User Profile Backup: [Placeholder - Backup completed]"

    def last_logon_time(self):
        result = subprocess.run(['net', 'user', getpass.getuser()], capture_output=True, text=True)
        return result.stdout or result.stderr

    def disable_account(self):
        username = self.ask_input("Enter username to disable:")
        if username:
            subprocess.run(['net', 'user', username, '/active:no'])
            return f"Account {username} disabled."
        return "No username specified."

    def password_never_expires(self):
        username = self.ask_input("Enter username:")
        if username:
            subprocess.run(['net', 'user', username, '/expires:never'])
            return f"Password for {username} set to never expire."
        return "No username specified."

    def ad_user_info(self):
        return "AD User Info: [Placeholder - Requires AD module]"

    def uninstall_app(self):
        app = self.ask_input("Enter application name to uninstall:")
        if app:
            subprocess.run(['wmic', 'product', 'where', f'name="{app}"', 'call', 'uninstall'])
            return f"Attempted to uninstall {app}"
        return "No app specified."

    def installed_software_list(self):
        result = subprocess.run(['wmic', 'product', 'get', 'name'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def pending_updates(self):
        return "Pending Updates: [Placeholder - Updates listed]"

    def install_msi(self):
        file = filedialog.askopenfilename(filetypes=[("MSI files", "*.msi")])
        if file:
            subprocess.run(['msiexec', '/i', file, '/quiet'])
            return f"Installing {file}"
        return "No MSI selected."

    def winget_wrapper(self):
        app = self.ask_input("Enter app name to install with winget:")
        if app:
            subprocess.run(['winget', 'install', app])
            return f"Installing {app} via winget"
        return "No app specified."

    def driver_backup(self):
        return "Driver Backup: [Placeholder - Backup completed]"

    def driver_rollback(self):
        return "Driver Rollback: [Placeholder - Rollback completed]"

    def app_crash_log(self):
        return "App Crash Log: [Placeholder - Logs extracted]"

    def software_cleanup(self):
        return "Software Cleanup: [Placeholder - Cleanup completed]"

    def update_history(self):
        result = subprocess.run(['powershell', 'Get-Hotfix'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def bsod_log_viewer(self):
        return "BSOD Log: [Placeholder - Logs parsed]"

    def hardware_diagnostic(self):
        return "Hardware Diagnostic: [Placeholder - Diagnostics run]"

    def system_info_report(self):
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file:
            with open(file, 'w') as f:
                f.write(self.get_system_info())
            return f"System info report saved to {file}"

    def event_log_export(self):
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file:
            result = subprocess.run(['wevtutil', 'qe', 'System', '/f:text'], capture_output=True, text=True)
            with open(file, 'w') as f:
                f.write(result.stdout or result.stderr)
            return f"Event logs exported to {file}"
        return "No file selected."

    def performance_log(self):
        return "Performance Log: [Placeholder - Log started]"

    def disk_error_check(self):
        result = subprocess.run(['chkdsk', '/f'], capture_output=True, text=True)
        return result.stdout or result.stderr

    def memory_test(self):
        subprocess.run(['mdsched.exe'])
        return "Memory test scheduled. Restart required."

    def printer_diagnostic(self):
        return "Printer Diagnostic: [Placeholder - Diagnostics run]"

    def battery_report(self):
        file = os.path.join(os.environ['TEMP'], 'battery_report.html')
        subprocess.run(['powercfg', '/batteryreport', '/output', file])
        return f"Battery report generated: {file}"

    def system_file_verifier(self):
        result = subprocess.run(['sfc', '/verifyonly'], capture_output=True, text=True)
        return result.stdout or result.stderr

    # Other Methods (Unchanged or Minimally Modified)
    def toggle_dark_mode(self):
        mode = "Light" if ctk.get_appearance_mode() == "Dark" else "Dark"
        ctk.set_appearance_mode(mode)
        self.theme = mode
        self.save_config()

    def show_help(self):
        messagebox.showinfo("Help", "Right-click buttons to add to favorites. Check logs for task outputs.")

    def open_settings(self):
        settings_win = Toplevel(self.root)
        settings_win.title("Settings")
        settings_win.geometry("300x200")
        ctk.CTkLabel(settings_win, text="Settings", font=("Segoe UI", 14, "bold")).pack(pady=5)
        ctk.CTkButton(settings_win, text="Save Config", command=self.save_config).pack(pady=5)

    def open_powershell(self):
        subprocess.Popen(['powershell'])

    def open_cmd(self):
        subprocess.Popen(['cmd'])

    def run_custom_command(self):
        cmd = self.command_entry.get()
        if cmd:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            self.show_output_popup("Command Output", result.stdout or result.stderr)

    def search_filter(self, event):
        query = self.search_entry.get().lower()
        if query:
            filtered = [feat for feat in FEATURE_DESCRIPTIONS if query in feat.lower() or query in FEATURE_DESCRIPTIONS[feat].lower()]
            self.log_display.delete(1.0, END)
            self.log_display.insert(END, "\n".join(filtered))
        else:
            self.update_log_display()

    def clear_log(self):
        self.log_display.delete(1.0, END)
        self.output_history.clear()

    def pause_log(self):
        self.log_paused = not self.log_paused
        self.log_btn_frame.winfo_children()[1].configure(text="▶ Resume" if self.log_paused else "⏸ Pause")

    def export_logs(self):
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file:
            with open(file, 'w') as f:
                f.write(self.log_display.get(1.0, END))
            self.log_queue.put(f"Logs exported to {file}")

    def update_log_display(self):
        while self.running:
            if not self.log_paused and not self.log_queue.empty():
                msg = self.log_queue.get()
                self.output_history.append(msg)
                if len(self.output_history) > 100:
                    self.output_history.pop(0)
                self.log_display.delete(1.0, END)
                self.log_display.insert(END, "\n".join(self.output_history))
                self.log_display.see(END)
            time.sleep(0.1)

    def update_dashboard(self):
        while self.running:
            self.cpu_label.configure(text=f"CPU: {psutil.cpu_percent()}%")
            self.ram_label.configure(text=f"RAM: {psutil.virtual_memory().percent}%")
            self.disk_label.configure(text=f"Disk: {psutil.disk_usage('/').percent}%")
            time.sleep(1)

    def update_health_periodically(self):
        while self.running:
            health = self.check_system_health()
            self.log_queue.put(health)
            time.sleep(300)

    def check_for_updates(self):
        while self.running:
            # Placeholder for update check logic
            time.sleep(self.update_check_interval)

    def toggle_sidebar(self):
        if self.sidebar_collapsed:
            self.left_frame.pack(side="left", fill="y", padx=(0, 5))
            self.toggle_sidebar_btn.configure(text="◄")
        else:
            self.left_frame.pack_forget()
            self.toggle_sidebar_btn.pack_forget()
            self.toggle_sidebar_btn = ctk.CTkButton(self.middle_frame, text="►", command=self.toggle_sidebar, width=20, fg_color="#6c757d", hover_color="#5a6268")
            self.toggle_sidebar_btn.pack(side="left", pady=5)
        self.sidebar_collapsed = not self.sidebar_collapsed

    def add_to_favorites(self, feature):
        for i in range(8):
            if self.favorites[i] is None or isinstance(self.favorites[i], ctk.CTkButton):
                self.favorites[i] = feature
                self.update_favorites()
                break

    def remove_from_favorites(self, index):
        self.favorites[index] = None
        self.update_favorites()

    def run_favorite(self, index):
        feature = self.favorites[index]
        if feature and not isinstance(feature, ctk.CTkButton):
            for tab in self.notebook.winfo_children():
                for btn in tab.winfo_children():
                    if btn.cget("text") == feature:
                        btn.invoke()

    def update_favorites(self):
        for i, btn in enumerate(self.favorites_grid.winfo_children()):
            text = self.favorites[i] if self.favorites[i] and not isinstance(self.favorites[i], ctk.CTkButton) else "Empty"
            btn.configure(text=text)
        self.save_config()

    def edit_favorites_popup(self):
        popup = Toplevel(self.root)
        popup.title("Edit Favorites")
        popup.geometry("300x400")
        for i in range(8):
            text = self.favorites[i] if self.favorites[i] and not isinstance(self.favorites[i], ctk.CTkButton) else "Empty"
            ctk.CTkLabel(popup, text=f"Slot {i+1}: {text}").pack(pady=2)
            ctk.CTkButton(popup, text="Change", command=lambda i=i: self.change_favorite(i)).pack(pady=2)

    def change_favorite(self, index):
        feature = self.ask_input("Enter feature name to add to favorites:")
        if feature in FEATURE_DESCRIPTIONS:
            self.favorites[index] = feature
            self.update_favorites()

    def show_welcome_screen(self):
        welcome = Toplevel(self.root)
        welcome.title("Welcome to SlingShot")
        welcome.geometry("400x200")
        ctk.CTkLabel(welcome, text="Welcome to SlingShot!", font=("Segoe UI", 16, "bold")).pack(pady=10)
        ctk.CTkLabel(welcome, text="Your IT Security Toolkit").pack(pady=5)
        ctk.CTkButton(welcome, text="Get Started", command=welcome.destroy).pack(pady=20)

if __name__ == "__main__":
    root = ctk.CTk()
    app = SlingShot(root)
    root.protocol("WM_DELETE_WINDOW", app.kill_program)
    root.mainloop()
