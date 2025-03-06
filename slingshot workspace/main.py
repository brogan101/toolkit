import os
import sys
import threading
import time
import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, scrolledtext, filedialog, Toplevel, Listbox, END
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

# Setup logging in the same directory as the script
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'slingshot.log')
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    force=True
)
logger = logging.getLogger('SlingShot')

# Feature Descriptions
FEATURE_DESCRIPTIONS = {
    "🔑 Gen Key": "Generates a secure encryption key.",
    "🔒 Encrypt File": "Encrypts a selected file with a key.",
    "🔓 Decrypt File": "Decrypts an encrypted file with a key.",
    "📜 Hash File": "Calculates the SHA-256 hash of a file.",
    "🛡️ AV Status": "Checks the status of Windows Defender.",
    "🔍 Firewall": "Checks firewall status.",
    "📋 Startup Items": "Lists startup programs.",
    "🔍 Susp Procs": "Checks for suspicious processes.",
    "📜 Log Events": "Logs recent security events.",
    "🔒 Gen OTP": "Generates a one-time password.",
    "📋 Procs": "Lists all running processes.",
    "📈 Resources": "Shows CPU, RAM, and disk usage.",
    "🔍 Uptime": "Shows system uptime.",
    "🔍 CPU Temp": "Monitors CPU temperature (if supported).",
    "📋 Threads": "Lists running threads.",
    "⚠️ Sys Health": "Evaluates overall system health.",
    "ℹ️ Sys Info": "Displays detailed system info.",
    "👥 Users": "Lists all user accounts.",
    "💿 Chk Disk": "Checks disk health.",
    "🗑️ Clr Temp": "Clears temporary files.",
    "📋 Env Vars": "Lists environment variables.",
    "🏓 Ping": "Pings a target host.",
    "🌐 Net Conns": "Checks network connections.",
    "🔍 Scan Ports": "Scans for open ports on localhost.",
    "📁 Backup Files": "Backs up files to a ZIP archive.",
    "📂 Restore": "Restores files from a ZIP archive.",
    "🔥 Tog Fwall": "Toggles firewall state.",
    "🔑 Gen Pwd": "Generates a random password.",
    "🔄 Restart": "Restarts the system.",
    "⏹ Shutdown": "Shuts down the system.",
    "🔒 Lock": "Locks the workstation.",
    "🔍 Vuln Scan": "Scans for system vulnerabilities.",
    "🔑 Pwd Strength": "Checks password strength.",
    "🔥 Fwall Rules": "Manages firewall rules.",
    "🗑️ Shred File": "Securely deletes files.",
    "🛡️ Harden Sys": "Provides system hardening tips.",
    "🌐 Net Traffic": "Monitors real-time network traffic.",
    "📋 Proc Explorer": "Explores and manages processes.",
    "💿 Disk Analyzer": "Analyzes disk usage.",
    "📜 Event Viewer": "Views system events.",
    "⚡ Benchmark": "Benchmarks system performance.",
    "📄 File Convert": "Converts file formats.",
    "✏️ Batch Rename": "Renames multiple files.",
    "🔍 Dupe Finder": "Finds duplicate files.",
    "🧹 Sys Cleaner": "Cleans system junk.",
    "📋 Clip Manager": "Manages clipboard history.",
    "🔍 Port Scan": "Scans ports on a host.",
    "⚡ Speed Test": "Tests network speed.",
    "🌐 DNS Lookup": "Looks up DNS records.",
    "🏓 Traceroute": "Traces network routes.",
    "📶 WiFi Analyzer": "Analyzes WiFi networks.",
    "📁 Inc Backup": "Performs incremental backups.",
    "☁️ Cloud Backup": "Backs up to cloud services.",
    "⏰ Backup Sched": "Schedules backups.",
    "🔍 Backup Verify": "Verifies backup integrity.",
    "🔄 Restore Points": "Manages system restore points.",
    "⚙️ Sys Tweak": "Tweaks system settings.",
    "🔧 Reg Editor": "Edits the registry.",
    "🖥️ Driver Mgr": "Manages device drivers.",
    "🚀 Boot Mgr": "Manages boot options.",
    "📄 Sys Info Export": "Exports system information."
}

# Tab Colors
TAB_COLORS = {
    "🔒 Security": "#dc3545",
    "📊 Monitoring": "#007bff",
    "🛠️ Utilities": "#28a745",
    "🌐 Network": "#6f42c1",
    "💾 Backup": "#fd7e14",
    "⚙️ Advanced": "#6c757d",
    "🔐 Passwords": "#ff5733",
    "⏰ Scheduler": "#9b59b6",
    "📈 Analytics": "#e74c3c",
    "📦 Plugins": "#3498db",
    "📊 Dashboard": "#2ecc71"
}

# ToolTip Class for Hover Descriptions
class ToolTip:
    current_tip = None

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event):
        if ToolTip.current_tip and ToolTip.current_tip != self:
            ToolTip.current_tip.hide_tip(None)
        if self.tip_window or not self.text:
            return
        x, y = self.widget.winfo_rootx() + 25, self.widget.winfo_rooty() + 25
        self.tip_window = tw = ctk.CTkToplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tw.configure(fg_color="#2b2b2b", border_width=1, border_color="#4a4a4a")
        label = ctk.CTkLabel(tw, text=self.text, font=("Segoe UI", 10), text_color="white", fg_color="#2b2b2b", corner_radius=5, anchor="w", padx=5, pady=2)
        label.pack()
        tw.update_idletasks()
        ToolTip.current_tip = self

    def hide_tip(self, event):
        if self.tip_window:
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
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        ctk.set_appearance_mode("dark")
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
        try:
            self.setup_gui()
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
        else:
            self.theme = "Dark"

    def save_config(self):
        config = {
            'favorites': self.favorites,
            'theme': self.theme,
            'scheduled_tasks': self.scheduled_tasks,
            'passwords': self.passwords
        }
        with open(self.config_file, 'w') as f:
            json.dump(config, f)

    def start_background_tasks(self):
        logger.info("Starting background tasks...")
        threading.Thread(target=self.update_log_display, daemon=True).start()
        threading.Thread(target=self.update_dashboard, daemon=True).start()
        threading.Thread(target=self.check_scheduled_tasks, daemon=True).start()
        threading.Thread(target=self.check_for_updates, daemon=True).start()
        threading.Thread(target=self.collect_analytics, daemon=True).start()
        self.update_health_periodically()

    def setup_gui(self):
        logger.info("Setting up GUI...")
        self.main_frame = ctk.CTkFrame(self.root, corner_radius=0)
        self.main_frame.pack(fill="both", expand=True)

        # Header
        self.header_frame = ctk.CTkFrame(self.main_frame, height=50, corner_radius=0, fg_color="#1f1f1f")
        self.header_frame.pack(fill="x", padx=10, pady=(10, 0))
        self.header_label = ctk.CTkLabel(self.header_frame, text="🛡️ SlingShot", font=("Segoe UI", 26, "bold"), text_color="white")
        self.header_label.pack(side="left", padx=5)
        self.dark_mode_btn = ctk.CTkButton(self.header_frame, text="🌙", command=self.toggle_dark_mode, fg_color="#6c757d", hover_color="#5a6268", width=30)
        self.dark_mode_btn.pack(side="right", padx=5)
        ctk.CTkButton(self.header_frame, text="?", command=self.show_help, fg_color="#17a2b8", hover_color="#138496", width=30).pack(side="right", padx=5)
        # Restored settings button
        ctk.CTkButton(self.header_frame, text="⚙️", command=self.open_settings, fg_color="#17a2b8", hover_color="#138496", width=30).pack(side="right", padx=5)
        ctk.CTkButton(self.header_frame, text="💀 Kill", command=self.kill_program, fg_color="#dc3545", hover_color="#c82333", width=80, font=("Segoe UI", 12)).pack(side="right", padx=5)
        ctk.CTkButton(self.header_frame, text="PowerShell", command=self.open_powershell, fg_color="#007bff", hover_color="#0056b3", width=80, font=("Segoe UI", 12)).pack(side="right", padx=5)
        ctk.CTkButton(self.header_frame, text="CMD", command=self.open_cmd, fg_color="#28a745", hover_color="#218838", width=80, font=("Segoe UI", 12)).pack(side="right", padx=5)

        # Command entry and run button in a frame for better positioning
        command_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        command_frame.pack(side="right", padx=5)
        self.command_entry = ctk.CTkEntry(command_frame, placeholder_text="Run command...", width=200)
        self.command_entry.pack(side="left", padx=5)
        ctk.CTkButton(command_frame, text="Run", command=self.run_custom_command, fg_color="#17a2b8", hover_color="#138496", width=50).pack(side="left", padx=5)

        self.search_entry = ctk.CTkEntry(self.header_frame, placeholder_text="Search features or logs...", width=200)
        self.search_entry.pack(side="right", padx=5)
        self.search_entry.bind("<KeyRelease>", self.search_filter)

        # Middle Frame
        self.middle_frame = ctk.CTkFrame(self.main_frame, corner_radius=0)
        self.middle_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Sidebar
        self.left_frame = ctk.CTkFrame(self.middle_frame, width=300, corner_radius=10)
        self.left_frame.pack(side="left", fill="y", padx=(0, 5))
        self.toggle_sidebar_btn = ctk.CTkButton(self.left_frame, text="◄", command=self.toggle_sidebar, width=20, fg_color="#6c757d", hover_color="#5a6268")
        self.toggle_sidebar_btn.pack(side="top", pady=5)

        # Dashboard
        self.dashboard_frame = ctk.CTkFrame(self.left_frame, corner_radius=10)
        self.dashboard_frame.pack(fill="x", padx=5, pady=5)
        ctk.CTkLabel(self.dashboard_frame, text="📊 Dashboard", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=5)
        self.cpu_label = ctk.CTkLabel(self.dashboard_frame, text="CPU: 0%", font=("Segoe UI", 12))
        self.cpu_label.pack(anchor="w", padx=5)
        self.ram_label = ctk.CTkLabel(self.dashboard_frame, text="RAM: 0%", font=("Segoe UI", 12))
        self.ram_label.pack(anchor="w", padx=5)
        self.disk_label = ctk.CTkLabel(self.dashboard_frame, text="Disk: 0%", font=("Segoe UI", 12))
        self.disk_label.pack(anchor="w", padx=5)

        # Logs
        self.log_frame = ctk.CTkFrame(self.left_frame, corner_radius=10)
        self.log_frame.pack(fill="both", expand=True, padx=5, pady=5)
        ctk.CTkLabel(self.log_frame, text="📜 Live Logs", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=5, pady=2)
        self.log_display = scrolledtext.ScrolledText(self.log_frame, width=30, height=15, font=("Segoe UI", 11), wrap=tk.WORD, bg="#2b2b2b", fg="white")
        self.log_display.pack(fill="both", expand=True, padx=5, pady=5)
        self.log_btn_frame = ctk.CTkFrame(self.log_frame, fg_color="transparent")
        self.log_btn_frame.pack(fill="x", pady=5)
        ctk.CTkButton(self.log_btn_frame, text="🗑️ Clear", command=self.clear_log, fg_color="#ffc107", text_color="black", hover_color="#e0a800", width=80, font=("Segoe UI", 12)).pack(side="left", padx=2)
        ctk.CTkButton(self.log_btn_frame, text="⏸ Pause", command=self.pause_log, fg_color="#007bff", hover_color="#0056b3", width=80, font=("Segoe UI", 12)).pack(side="left", padx=2)
        ctk.CTkButton(self.log_btn_frame, text="📤 Export", command=self.export_logs, fg_color="#28a745", hover_color="#218838", width=80, font=("Segoe UI", 12)).pack(side="left", padx=2)

        # Favorites Area
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

        # Right Frame (Tabs)
        self.right_frame = ctk.CTkFrame(self.middle_frame, corner_radius=10)
        self.right_frame.pack(side="right", fill="both", expand=True, padx=5)
        self.notebook = ctk.CTkTabview(self.right_frame)
        self.notebook.pack(fill="both", expand=True, pady=5)
        self.setup_tabs()

        # Status Bar
        self.status_bar = ctk.CTkFrame(self.main_frame, height=20, fg_color="#1f1f1f")
        self.status_bar.pack(fill="x", side="bottom")
        self.status_label = ctk.CTkLabel(self.status_bar, text="Ready", font=("Segoe UI", 10))
        self.status_label.pack(side="left", padx=5)
        self.font_slider = ctk.CTkSlider(self.status_bar, from_=8, to=16, command=self.adjust_font_size)
        self.font_slider.set(11)
        self.font_slider.pack(side="right", padx=5)
        ctk.CTkLabel(self.status_bar, text="Font Size", font=("Segoe UI", 10)).pack(side="right", padx=(5, 0))

    def add_button(self, frame, text, command, timeout, row, col, tab_color):
        btn = ctk.CTkButton(
            frame,
            text=text,
            command=lambda: self.queue_task(command, timeout, text),
            fg_color=tab_color,
            hover_color="#5a5a5a",
            font=("Segoe UI", 12),
            width=100
        )
        btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
        frame.grid_columnconfigure(col, weight=1)
        ToolTip(btn, FEATURE_DESCRIPTIONS.get(text, "No description available"))
        btn.bind("<Button-3>", lambda event, t=text: self.add_to_favorites(t))

    def setup_security_tab(self):
        tab_name = "🔒 Security"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("🔑 Gen Key", self.generate_key, 5),
            ("🔒 Encrypt File", self.encrypt_file, 30),
            ("🔓 Decrypt File", self.decrypt_file, 30),
            ("📜 Hash File", self.hash_file, 15),
            ("🛡️ AV Status", self.check_antivirus_status, 30),
            ("🔍 Firewall", self.check_firewall_status, 30),
            ("📋 Startup Items", self.list_startup_items, 30),
            ("🔍 Susp Procs", self.check_suspicious_processes, 30),
            ("📜 Log Events", self.log_security_events, 60),
            ("🔒 Gen OTP", self.generate_otp, 5),
            ("🔍 Vuln Scan", self.vuln_scan, 60),
            ("🔑 Pwd Strength", self.pwd_strength, 15),
            ("🔥 Fwall Rules", self.fwall_rules, 30),
            ("🗑️ Shred File", self.shred_file, 30),
            ("🛡️ Harden Sys", self.harden_sys, 15),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 3, i % 3, TAB_COLORS[tab_name])

    def setup_monitoring_tab(self):
        tab_name = "📊 Monitoring"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("📋 Procs", self.show_processes, 30),
            ("📈 Resources", self.show_resource_usage, 15),
            ("🔍 Uptime", self.show_system_uptime, 15),
            ("🔍 CPU Temp", self.monitor_cpu_temp, 15),
            ("📋 Threads", self.list_running_threads, 30),
            ("⚠️ Sys Health", self.check_system_health, 60),
            ("🌐 Net Traffic", self.net_traffic, 30),
            ("📋 Proc Explorer", self.proc_explorer, 30),
            ("💿 Disk Analyzer", self.disk_analyzer, 60),
            ("📜 Event Viewer", self.event_viewer, 30),
            ("⚡ Benchmark", self.benchmark, 60),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 3, i % 3, TAB_COLORS[tab_name])

    def setup_utilities_tab(self):
        tab_name = "🛠️ Utilities"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("ℹ️ Sys Info", self.get_system_info, 15),
            ("👥 Users", self.list_users, 15),
            ("💿 Chk Disk", self.check_disk_health, 120),
            ("🗑️ Clr Temp", self.clear_temp_files, 60),
            ("📋 Env Vars", self.list_environment_vars, 30),
            ("📄 File Convert", self.file_convert, 30),
            ("✏️ Batch Rename", self.batch_rename, 30),
            ("🔍 Dupe Finder", self.dupe_finder, 60),
            ("🧹 Sys Cleaner", self.sys_cleaner, 60),
            ("📋 Clip Manager", self.clip_manager, 15),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 3, i % 3, TAB_COLORS[tab_name])

    def setup_network_tab(self):
        tab_name = "🌐 Network"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("🏓 Ping", self.ping_test, 30),
            ("🌐 Net Conns", self.check_network_connections, 30),
            ("🔍 Scan Ports", self.scan_ports, 60),
            ("🔍 Port Scan", self.port_scan, 60),
            ("⚡ Speed Test", self.speed_test, 30),
            ("🌐 DNS Lookup", self.dns_lookup, 15),
            ("🏓 Traceroute", self.traceroute, 30),
            ("📶 WiFi Analyzer", self.wifi_analyzer, 30),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 2, i % 2, TAB_COLORS[tab_name])

    def setup_backup_tab(self):
        tab_name = "💾 Backup"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("📁 Backup Files", self.backup_files, 300),
            ("📂 Restore", self.restore_files, 300),
            ("📁 Inc Backup", self.inc_backup, 300),
            ("☁️ Cloud Backup", self.cloud_backup, 300),
            ("⏰ Backup Sched", self.backup_sched, 15),
            ("🔍 Backup Verify", self.backup_verify, 60),
            ("🔄 Restore Points", self.restore_points, 30),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 2, i % 2, TAB_COLORS[tab_name])

    def setup_advanced_tab(self):
        tab_name = "⚙️ Advanced"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("🔥 Tog Fwall", self.toggle_firewall, 30),
            ("🔑 Gen Pwd", self.generate_random_password, 15),
            ("🔄 Restart", self.restart_system, 15),
            ("⏹ Shutdown", self.shutdown_system, 15),
            ("🔒 Lock", self.lock_workstation, 15),
            ("⚙️ Sys Tweak", self.sys_tweak, 15),
            ("🔧 Reg Editor", self.reg_editor, 30),
            ("🖥️ Driver Mgr", self.driver_mgr, 30),
            ("🚀 Boot Mgr", self.boot_mgr, 30),
            ("📄 Sys Info Export", self.sys_info_export, 15),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 3, i % 3, TAB_COLORS[tab_name])

    def setup_passwords_tab(self):
        tab_name = "🔐 Passwords"
        frame = self.notebook.add(tab_name)
        ctk.CTkLabel(frame, text="Password Manager", font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=5)
        self.pwd_name = ctk.CTkEntry(frame, placeholder_text="Service Name")
        self.pwd_name.grid(row=1, column=0, padx=5, pady=5)
        self.pwd_value = ctk.CTkEntry(frame, placeholder_text="Password", show="*")
        self.pwd_value.grid(row=1, column=1, padx=5, pady=5)
        ctk.CTkButton(frame, text="Add", command=self.add_password, fg_color=TAB_COLORS[tab_name]).grid(row=2, column=0, columnspan=2, pady=5)
        self.pwd_list = tk.Listbox(frame, height=10, bg="#2b2b2b", fg="white", font=("Segoe UI", 12))
        self.pwd_list.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")
        ctk.CTkButton(frame, text="View", command=self.view_password, fg_color="#007bff").grid(row=4, column=0, pady=5)
        ctk.CTkButton(frame, text="Delete", command=self.delete_password, fg_color="#dc3545").grid(row=4, column=1, pady=5)
        self.update_password_list()

    def setup_scheduler_tab(self):
        tab_name = "⏰ Scheduler"
        frame = self.notebook.add(tab_name)
        ctk.CTkLabel(frame, text="Task Scheduler", font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=5)
        self.task_name = ctk.CTkEntry(frame, placeholder_text="Task Name")
        self.task_name.grid(row=1, column=0, padx=5, pady=5)
        self.task_time = ctk.CTkEntry(frame, placeholder_text="Time (HH:MM)")
        self.task_time.grid(row=1, column=1, padx=5, pady=5)
        ctk.CTkButton(frame, text="Add Task", command=self.add_scheduled_task, fg_color=TAB_COLORS[tab_name]).grid(row=2, column=0, columnspan=2, pady=5)
        self.task_list = tk.Listbox(frame, height=10, bg="#2b2b2b", fg="white", font=("Segoe UI", 12))
        self.task_list.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")
        ctk.CTkButton(frame, text="Remove", command=self.remove_scheduled_task, fg_color="#dc3545").grid(row=4, column=0, columnspan=2, pady=5)
        self.update_task_list()

    def setup_analytics_tab(self):
        tab_name = "📈 Analytics"
        frame = self.notebook.add(tab_name)
        self.fig, self.ax = plt.subplots(figsize=(5, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self.update_analytics_plot()

    def setup_plugins_tab(self):
        tab_name = "📦 Plugins"
        frame = self.notebook.add(tab_name)
        ctk.CTkLabel(frame, text="Plugin Manager", font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=5)
        ctk.CTkButton(frame, text="Load Plugin", command=self.load_plugin, fg_color=TAB_COLORS[tab_name]).grid(row=1, column=0, columnspan=2, pady=5)
        self.plugin_list = tk.Listbox(frame, height=10, bg="#2b2b2b", fg="white", font=("Segoe UI", 12))
        self.plugin_list.grid(row=2, column=0, columnspan=2, pady=5, sticky="ew")
        self.update_plugin_list()

    def setup_dashboard_tab(self):
        tab_name = "📊 Dashboard"
        frame = self.notebook.add(tab_name)
        ctk.CTkLabel(frame, text="System Metrics", font=("Segoe UI", 16, "bold")).pack(pady=10)

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
        self.setup_dashboard_tab()
        # Removed self.setup_settings_tab()

    # Header Functions
    def open_cmd(self):
        subprocess.Popen("cmd.exe", creationflags=subprocess.CREATE_NEW_CONSOLE)
        logger.info("Opened Command Prompt.")

    def open_powershell(self):
        subprocess.Popen("powershell.exe", creationflags=subprocess.CREATE_NEW_CONSOLE)
        logger.info("Opened PowerShell.")

    def run_custom_command(self):
        cmd = self.command_entry.get()
        if cmd:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                output = result.stdout or result.stderr
                self.log_queue.put(f"Custom command '{cmd}' output:\n{output}")
                self.show_output_popup("Custom Command", output)
            except Exception as e:
                self.log_queue.put(f"Custom command failed: {e}")
                self.show_output_popup("Custom Command", f"Error: {e}", failed=True)

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

    def search_filter(self, event):
        term = self.search_entry.get().lower()
        if not term:
            for tab_name in self.notebook._tab_dict:
                tab = self.notebook._tab_dict[tab_name]
                for widget in tab.winfo_children():
                    if isinstance(widget, ctk.CTkButton):
                        widget.configure(fg_color=TAB_COLORS[tab_name])
            self.update_log_display()
            return
        for tab_name in self.notebook._tab_dict:
            tab = self.notebook._tab_dict[tab_name]
            for widget in tab.winfo_children():
                if isinstance(widget, ctk.CTkButton):
                    if term in widget.cget("text").lower():
                        widget.configure(fg_color="#ffff00")
                    else:
                        widget.configure(fg_color=TAB_COLORS[tab_name])
        with self.lock:
            self.log_display.delete("1.0", tk.END)
            with open(log_file, 'r') as f:
                for line in f:
                    if term in line.lower():
                        self.log_display.insert(tk.END, line)

    def toggle_dark_mode(self):
        current_mode = ctk.get_appearance_mode()
        new_mode = "Light" if current_mode == "Dark" else "Dark"
        self.change_theme(new_mode)

    def change_theme(self, mode):
        ctk.set_appearance_mode(mode)
        self.theme = mode
        self.save_config()
        self.update_analytics_plot()

    def show_help(self):
        help_window = Toplevel(self.root)
        help_window.title("Help")
        help_window.geometry("400x300")
        ctk.CTkLabel(help_window, text="SlingShot Help", font=("Segoe UI", 16, "bold")).pack(pady=10)
        ctk.CTkLabel(help_window, text="Use the search bar to find features or logs.\nRight-click buttons to add to favorites.", font=("Segoe UI", 12)).pack(pady=10)
        ctk.CTkButton(help_window, text="Close", command=help_window.destroy).pack(pady=10)

    def open_settings(self):
        settings_window = Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("300x200")
        ctk.CTkLabel(settings_window, text="Theme", font=("Segoe UI", 14, "bold")).pack(pady=5)
        theme_options = ["Dark", "Light", "System"]
        self.theme_var = tk.StringVar(value=self.theme)
        ctk.CTkOptionMenu(settings_window, values=theme_options, variable=self.theme_var, command=self.change_theme).pack(pady=5)
        ctk.CTkButton(settings_window, text="Close", command=settings_window.destroy).pack(pady=10)

    # Core Functionality
    def queue_task(self, func, timeout, name):
        task_id = secrets.token_hex(4)
        self.current_tasks[task_id] = {'name': name, 'timeout': timeout}
        self.task_queue.put((task_id, func))
        self.status_label.configure(text=f"Running: {name}")
        threading.Thread(target=self.process_task_queue, daemon=True).start()

    def process_task_queue(self):
        while not self.task_queue.empty() and self.running:
            task_id, func = self.task_queue.get()
            if task_id in self.current_tasks:
                try:
                    result = self.executor.submit(func).result(timeout=self.current_tasks[task_id]['timeout'])
                    self.log_queue.put(f"{self.current_tasks[task_id]['name']} completed: {result}")
                    self.show_output_popup(self.current_tasks[task_id]['name'], result)
                except Exception as e:
                    self.log_queue.put(f"{self.current_tasks[task_id]['name']} failed: {e}")
                    self.show_output_popup(self.current_tasks[task_id]['name'], f"Error: {e}", failed=True)
                finally:
                    del self.current_tasks[task_id]
                    self.status_label.configure(text="Ready")

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
        ctk.CTkButton(button_frame, text="Close", command=popup.destroy, fg_color="#dc3545" if failed else "#17a2b8").pack(side="left", padx=5)

    def export_output(self, message):
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file:
            with open(file, 'w') as f:
                f.write(message)
            logger.info(f"Output exported to {file}")

    def update_log_display(self):
        while self.running:
            if not self.log_paused and not self.log_queue.empty():
                with self.lock:
                    message = self.log_queue.get()
                    self.log_display.insert(tk.END, message + "\n")
                    self.log_display.see(tk.END)
                    logger.info(message)
            time.sleep(0.1)

    def pause_log(self):
        self.log_paused = not self.log_paused
        self.log_btn_frame.winfo_children()[1].configure(text="▶️ Resume" if self.log_paused else "⏸ Pause")

    def clear_log(self):
        with self.lock:
            self.log_display.delete("1.0", tk.END)
            open(log_file, 'w').close()
        logger.info("Log cleared.")

    def export_logs(self):
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file:
            with self.lock:
                with open(file, 'w') as f:
                    f.write(self.log_display.get("1.0", tk.END))
            logger.info(f"Logs exported to {file}")

    def adjust_font_size(self, value):
        font_size = int(value)
        self.log_display.configure(font=("Segoe UI", font_size))
        for tab_name in self.notebook._tab_dict:
            tab = self.notebook._tab_dict[tab_name]
            for widget in tab.winfo_children():
                if isinstance(widget, ctk.CTkButton):
                    widget.configure(font=("Segoe UI", font_size))

    def show_welcome_screen(self):
        welcome = Toplevel(self.root)
        welcome.title("Welcome to SlingShot")
        welcome.geometry("300x200")
        welcome.transient(self.root)
        ctk.CTkLabel(welcome, text="Welcome to SlingShot!", font=("Segoe UI", 16, "bold")).pack(pady=10)
        ctk.CTkLabel(welcome, text="Your IT Security Toolkit", font=("Segoe UI", 12)).pack(pady=5)
        ctk.CTkButton(welcome, text="Start", command=welcome.destroy, fg_color="#17a2b8").pack(pady=20)

    # Favorites Editing Popup
    def edit_favorites_popup(self):
        popup = Toplevel(self.root)
        popup.title("Edit Favorites")
        popup.geometry("400x600")
        popup.configure(bg="#2b2b2b" if ctk.get_appearance_mode() == "Dark" else "#ffffff")
        features = ["Empty"] + list(FEATURE_DESCRIPTIONS.keys())
        vars = [tk.StringVar(value=self.favorites[i] if self.favorites[i] else "Empty") for i in range(8)]
        for i in range(8):
            ctk.CTkLabel(popup, text=f"Favorite {i+1}:", font=("Segoe UI", 12)).grid(row=i, column=0, padx=5, pady=5, sticky="e")
            ctk.CTkOptionMenu(popup, values=features, variable=vars[i]).grid(row=i, column=1, padx=5, pady=5, sticky="w")
        def save():
            for i in range(8):
                selected = vars[i].get()
                self.favorites[i] = selected if selected != "Empty" else None
            for i in range(8):
                text = self.favorites[i] if self.favorites[i] else "Empty"
                btn = self.favorites_grid.grid_slaves(row=i // 4, column=i % 4)[0]
                btn.configure(text=text)
            self.save_config()
            popup.destroy()
        ctk.CTkButton(popup, text="Save", command=save, fg_color="#17a2b8", hover_color="#138496").grid(row=8, column=0, columnspan=2, pady=10)

    # Security Functions
    def generate_key(self):
        self.key = Fernet.generate_key()
        return f"Generated key: {self.key.decode()}"

    def encrypt_file(self):
        if not self.key:
            return "No key generated. Generate a key first."
        file = filedialog.askopenfilename()
        if file:
            with open(file, 'rb') as f:
                data = f.read()
            fernet = Fernet(self.key)
            encrypted = fernet.encrypt(data)
            with open(file + '.encrypted', 'wb') as f:
                f.write(encrypted)
            return f"Encrypted {file} to {file}.encrypted"

    def decrypt_file(self):
        if not self.key:
            return "No key generated. Generate a key first."
        file = filedialog.askopenfilename()
        if file:
            with open(file, 'rb') as f:
                data = f.read()
            fernet = Fernet(self.key)
            decrypted = fernet.decrypt(data)
            with open(file.replace('.encrypted', '_decrypted'), 'wb') as f:
                f.write(decrypted)
            return f"Decrypted {file} to {file.replace('.encrypted', '_decrypted')}"

    def hash_file(self):
        file = filedialog.askopenfilename()
        if file:
            hasher = hashlib.sha256()
            with open(file, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return f"SHA-256 hash of {file}: {hasher.hexdigest()}"

    def check_antivirus_status(self):
        try:
            result = subprocess.run(['powershell', 'Get-MpComputerStatus'], capture_output=True, text=True)
            return result.stdout or result.stderr
        except Exception as e:
            return f"Error checking AV status: {e}"

    def check_firewall_status(self):
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True)
            return result.stdout or result.stderr
        except Exception as e:
            return f"Error checking firewall status: {e}"

    def list_startup_items(self):
        try:
            result = subprocess.run(['wmic', 'startup', 'get', 'caption,command'], capture_output=True, text=True)
            return result.stdout or result.stderr
        except Exception as e:
            return f"Error listing startup items: {e}"

    def check_suspicious_processes(self):
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            if proc.info['cpu_percent'] > 90 or proc.info['memory_percent'] > 90:
                suspicious.append(f"PID: {proc.info['pid']}, Name: {proc.info['name']}, CPU: {proc.info['cpu_percent']}%, Mem: {proc.info['memory_percent']}%")
        return "Suspicious processes:\n" + "\n".join(suspicious) if suspicious else "No suspicious processes found."

    def log_security_events(self):
        return "Security events logged (placeholder)."

    def generate_otp(self):
        return f"One-time password: {secrets.token_hex(4)}"

    def vuln_scan(self):
        return "Vulnerability scan completed (placeholder)."

    def pwd_strength(self):
        pwd = self.ask_input("Enter password to check:")
        if not pwd:
            return "No password entered."
        if len(pwd) < 8:
            return "Password strength: Weak (too short)"
        return "Password strength: Strong"

    def fwall_rules(self):
        return "Firewall rules managed (placeholder)."

    def shred_file(self):
        file = filedialog.askopenfilename()
        if file:
            with open(file, 'wb') as f:
                f.write(os.urandom(os.path.getsize(file)))
            os.remove(file)
            return f"File {file} securely shredded."

    def harden_sys(self):
        return "System hardening tips: Use strong passwords, enable firewall, update software."

    # Monitoring Functions
    def show_processes(self):
        processes = [f"PID: {p.pid}, Name: {p.name()}" for p in psutil.process_iter(['pid', 'name'])]
        return "Running processes:\n" + "\n".join(processes[:20]) + "\n(Showing top 20)"

    def show_resource_usage(self):
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        return f"CPU: {cpu}%, Memory: {mem}%, Disk: {disk}%"

    def show_system_uptime(self):
        uptime = time.time() - psutil.boot_time()
        return f"System uptime: {uptime // 3600} hours, {(uptime % 3600) // 60} minutes"

    def monitor_cpu_temp(self):
        return "CPU temperature monitoring not fully implemented (requires additional libraries)."

    def list_running_threads(self):
        threads = [f"Thread ID: {t.ident}" for t in threading.enumerate()]
        return "Running threads:\n" + "\n".join(threads)

    def check_system_health(self):
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        return f"System health: CPU {cpu}%, Memory {mem}% - {'Healthy' if cpu < 80 and mem < 80 else 'Unhealthy'}"

    def net_traffic(self):
        net_io = psutil.net_io_counters()
        return f"Network traffic - Sent: {net_io.bytes_sent / 1024:.2f} KB, Received: {net_io.bytes_recv / 1024:.2f} KB"

    def proc_explorer(self):
        return "Process explorer opened (placeholder)."

    def disk_analyzer(self):
        disk = psutil.disk_usage('/')
        return f"Disk analysis - Total: {disk.total / (1024**3):.2f} GB, Used: {disk.used / (1024**3):.2f} GB, Free: {disk.free / (1024**3):.2f} GB"

    def event_viewer(self):
        return "System events viewed (placeholder)."

    def benchmark(self):
        return "System benchmark completed (placeholder)."

    # Utilities Functions
    def get_system_info(self):
        return f"OS: {platform.system()} {platform.release()}, CPU: {psutil.cpu_count()} cores"

    def list_users(self):
        try:
            result = subprocess.run(['net', 'user'], capture_output=True, text=True)
            return result.stdout or result.stderr
        except Exception as e:
            return f"Error listing users: {e}"

    def check_disk_health(self):
        return "Disk health check completed (placeholder)."

    def clear_temp_files(self):
        temp_dir = os.getenv('TEMP')
        if temp_dir:
            for file in os.listdir(temp_dir):
                path = os.path.join(temp_dir, file)
                try:
                    if os.path.isfile(path):
                        os.unlink(path)
                except Exception:
                    pass
            return f"Cleared temporary files in {temp_dir}"
        return "No TEMP directory found."

    def list_environment_vars(self):
        return "\n".join(f"{k}={v}" for k, v in os.environ.items())

    def file_convert(self):
        return "File converted (placeholder)."

    def batch_rename(self):
        return "Files renamed (placeholder)."

    def dupe_finder(self):
        return "Duplicate files found (placeholder)."

    def sys_cleaner(self):
        return "System cleaned (placeholder)."

    def clip_manager(self):
        return "Clipboard history managed (placeholder)."

    # Network Functions
    def ping_test(self):
        host = self.ask_input("Enter host to ping:")
        if not host:
            return "No host entered."
        result = subprocess.run(['ping', host], capture_output=True, text=True)
        return result.stdout or result.stderr

    def check_network_connections(self):
        conns = [f"Proto: {c.type}, Local: {c.laddr}, Remote: {c.raddr}, Status: {c.status}" for c in psutil.net_connections()]
        return "Network connections:\n" + "\n".join(conns[:20]) + "\n(Showing top 20)"

    def scan_ports(self):
        open_ports = []
        for port in range(1, 1000):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex(('localhost', port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return "Open ports:\n" + "\n".join(map(str, open_ports))

    def port_scan(self):
        return "Port scan completed (placeholder)."

    def speed_test(self):
        return "Network speed test completed (placeholder)."

    def dns_lookup(self):
        host = self.ask_input("Enter host for DNS lookup:")
        if not host:
            return "No host entered."
        try:
            ip = socket.gethostbyname(host)
            return f"DNS lookup for {host}: {ip}"
        except Exception as e:
            return f"DNS lookup failed: {e}"

    def traceroute(self):
        return "Traceroute completed (placeholder)."

    def wifi_analyzer(self):
        return "WiFi analysis completed (placeholder)."

    # Backup Functions
    def backup_files(self):
        folder = filedialog.askdirectory()
        if folder:
            backup_file = f"backup_{time.strftime('%Y%m%d_%H%M%S')}.zip"
            with ZipFile(backup_file, 'w') as zipf:
                for root, _, files in os.walk(folder):
                    for file in files:
                        zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), folder))
            return f"Backed up {folder} to {backup_file}"

    def restore_files(self):
        backup_file = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        if backup_file:
            extract_dir = filedialog.askdirectory()
            if extract_dir:
                with ZipFile(backup_file, 'r') as zipf:
                    zipf.extractall(extract_dir)
                return f"Restored {backup_file} to {extract_dir}"
        return "Restore cancelled."

    def inc_backup(self):
        return "Incremental backup completed (placeholder)."

    def cloud_backup(self):
        return "Cloud backup completed (placeholder)."

    def backup_sched(self):
        return "Backup scheduled (placeholder)."

    def backup_verify(self):
        return "Backup verified (placeholder)."

    def restore_points(self):
        return "Restore points managed (placeholder)."

    # Advanced Functions
    def toggle_firewall(self):
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'toggle'], capture_output=True, text=True)
            return result.stdout or result.stderr
        except Exception as e:
            return f"Error toggling firewall: {e}"

    def generate_random_password(self):
        return f"Generated password: {secrets.token_urlsafe(12)}"

    def restart_system(self):
        os.system("shutdown /r /t 5")
        return "System will restart in 5 seconds."

    def shutdown_system(self):
        os.system("shutdown /s /t 5")
        return "System will shut down in 5 seconds."

    def lock_workstation(self):
        os.system("rundll32.exe user32.dll,LockWorkStation")
        return "Workstation locked."

    def sys_tweak(self):
        return "System tweaked (placeholder)."

    def reg_editor(self):
        return "Registry edited (placeholder)."

    def driver_mgr(self):
        return "Drivers managed (placeholder)."

    def boot_mgr(self):
        return "Boot options managed (placeholder)."

    def sys_info_export(self):
        return "System info exported (placeholder)."

    # Dashboard and Analytics
    def update_dashboard(self):
        while self.running:
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            self.cpu_label.configure(text=f"CPU: {cpu:.1f}%")
            self.ram_label.configure(text=f"RAM: {ram:.1f}%")
            self.disk_label.configure(text=f"Disk: {disk:.1f}%")
            time.sleep(1)

    def collect_analytics(self):
        while self.running:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            timestamp = time.strftime("%H:%M:%S")
            self.analytics_data['cpu'].append(cpu)
            self.analytics_data['mem'].append(mem)
            self.analytics_data['disk'].append(disk)
            self.analytics_data['times'].append(timestamp)
            if len(self.analytics_data['times']) > 20:
                self.analytics_data['cpu'].pop(0)
                self.analytics_data['mem'].pop(0)
                self.analytics_data['disk'].pop(0)
                self.analytics_data['times'].pop(0)
            self.update_analytics_plot()
            time.sleep(5)

    def update_analytics_plot(self):
        bg_color = "#2b2b2b" if ctk.get_appearance_mode() == "Dark" else "#ffffff"
        fg_color = "white" if ctk.get_appearance_mode() == "Dark" else "black"
        self.fig.patch.set_facecolor(bg_color)
        self.ax.set_facecolor(bg_color)
        self.ax.clear()
        self.ax.plot(self.analytics_data['times'], self.analytics_data['cpu'], label="CPU %", color="red")
        self.ax.plot(self.analytics_data['times'], self.analytics_data['mem'], label="Memory %", color="blue")
        self.ax.plot(self.analytics_data['times'], self.analytics_data['disk'], label="Disk %", color="green")
        self.ax.legend()
        self.ax.set_title("System Metrics Over Time", color=fg_color)
        self.ax.set_xlabel("Time", color=fg_color)
        self.ax.set_ylabel("Usage (%)", color=fg_color)
        self.ax.tick_params(colors=fg_color)
        plt.xticks(rotation=45)
        self.canvas.draw()

    # Favorites
    def add_to_favorites(self, feature):
        for i in range(8):
            if self.favorites[i] is None:
                self.favorites[i] = feature
                btn = self.favorites_grid.grid_slaves(row=i // 4, column=i % 4)[0]
                btn.configure(text=feature)
                self.save_config()
                break

    def remove_from_favorites(self, index):
        self.favorites[index] = None
        btn = self.favorites_grid.grid_slaves(row=index // 4, column=index % 4)[0]
        btn.configure(text="Empty")
        self.save_config()

    def run_favorite(self, index):
        feature = self.favorites[index]
        if feature and feature != "Empty":
            func = self.get_feature_function(feature)
            if func:
                self.queue_task(func, 30, feature)

    def get_feature_function(self, feature):
        feature_map = {
            "🔑 Gen Key": self.generate_key,
            "🔒 Encrypt File": self.encrypt_file,
            "🔓 Decrypt File": self.decrypt_file,
            "📜 Hash File": self.hash_file,
            "🛡️ AV Status": self.check_antivirus_status,
            "🔍 Firewall": self.check_firewall_status,
            "📋 Startup Items": self.list_startup_items,
            "🔍 Susp Procs": self.check_suspicious_processes,
            "📜 Log Events": self.log_security_events,
            "🔒 Gen OTP": self.generate_otp,
            "📋 Procs": self.show_processes,
            "📈 Resources": self.show_resource_usage,
            "🔍 Uptime": self.show_system_uptime,
            "🔍 CPU Temp": self.monitor_cpu_temp,
            "📋 Threads": self.list_running_threads,
            "⚠️ Sys Health": self.check_system_health,
            "ℹ️ Sys Info": self.get_system_info,
            "👥 Users": self.list_users,
            "💿 Chk Disk": self.check_disk_health,
            "🗑️ Clr Temp": self.clear_temp_files,
            "📋 Env Vars": self.list_environment_vars,
            "🏓 Ping": self.ping_test,
            "🌐 Net Conns": self.check_network_connections,
            "🔍 Scan Ports": self.scan_ports,
            "📁 Backup Files": self.backup_files,
            "📂 Restore": self.restore_files,
            "🔥 Tog Fwall": self.toggle_firewall,
            "🔑 Gen Pwd": self.generate_random_password,
            "🔄 Restart": self.restart_system,
            "⏹ Shutdown": self.shutdown_system,
            "🔒 Lock": self.lock_workstation,
            "🔍 Vuln Scan": self.vuln_scan,
            "🔑 Pwd Strength": self.pwd_strength,
            "🔥 Fwall Rules": self.fwall_rules,
            "🗑️ Shred File": self.shred_file,
            "🛡️ Harden Sys": self.harden_sys,
            "🌐 Net Traffic": self.net_traffic,
            "📋 Proc Explorer": self.proc_explorer,
            "💿 Disk Analyzer": self.disk_analyzer,
            "📜 Event Viewer": self.event_viewer,
            "⚡ Benchmark": self.benchmark,
            "📄 File Convert": self.file_convert,
            "✏️ Batch Rename": self.batch_rename,
            "🔍 Dupe Finder": self.dupe_finder,
            "🧹 Sys Cleaner": self.sys_cleaner,
            "📋 Clip Manager": self.clip_manager,
            "🔍 Port Scan": self.port_scan,
            "⚡ Speed Test": self.speed_test,
            "🌐 DNS Lookup": self.dns_lookup,
            "🏓 Traceroute": self.traceroute,
            "📶 WiFi Analyzer": self.wifi_analyzer,
            "📁 Inc Backup": self.inc_backup,
            "☁️ Cloud Backup": self.cloud_backup,
            "⏰ Backup Sched": self.backup_sched,
            "🔍 Backup Verify": self.backup_verify,
            "🔄 Restore Points": self.restore_points,
            "⚙️ Sys Tweak": self.sys_tweak,
            "🔧 Reg Editor": self.reg_editor,
            "🖥️ Driver Mgr": self.driver_mgr,
            "🚀 Boot Mgr": self.boot_mgr,
            "📄 Sys Info Export": self.sys_info_export
        }
        return feature_map.get(feature)

    # Password Manager
    def add_password(self):
        name = self.pwd_name.get()
        value = self.pwd_value.get()
        if name and value:
            encrypted = self.cipher.encrypt(value.encode()).decode()
            self.passwords[name] = encrypted
            self.update_password_list()
            self.pwd_name.delete(0, tk.END)
            self.pwd_value.delete(0, tk.END)
            self.save_config()

    def view_password(self):
        selected = self.pwd_list.curselection()
        if selected:
            name = self.pwd_list.get(selected[0])
            encrypted = self.passwords[name]
            decrypted = self.cipher.decrypt(encrypted.encode()).decode()
            messagebox.showinfo("Password", f"{name}: {decrypted}")

    def delete_password(self):
        selected = self.pwd_list.curselection()
        if selected:
            name = self.pwd_list.get(selected[0])
            del self.passwords[name]
            self.update_password_list()
            self.save_config()

    def update_password_list(self):
        self.pwd_list.delete(0, tk.END)
        for name in self.passwords:
            self.pwd_list.insert(tk.END, name)

    # Scheduler
    def add_scheduled_task(self):
        name = self.task_name.get()
        time_str = self.task_time.get()
        if name and time_str:
            self.scheduled_tasks.append({"name": name, "time": time_str})
            self.update_task_list()
            self.task_name.delete(0, tk.END)
            self.task_time.delete(0, tk.END)
            self.save_config()

    def remove_scheduled_task(self):
        selected = self.task_list.curselection()
        if selected:
            del self.scheduled_tasks[selected[0]]
            self.update_task_list()
            self.save_config()

    def update_task_list(self):
        self.task_list.delete(0, tk.END)
        for task in self.scheduled_tasks:
            self.task_list.insert(tk.END, f"{task['name']} @ {task['time']}")

    def check_scheduled_tasks(self):
        while self.running:
            current_time = time.strftime("%H:%M")
            for task in self.scheduled_tasks:
                if task['time'] == current_time:
                    func = self.get_feature_function(task['name'])
                    if func:
                        self.queue_task(func, 30, task['name'])
            time.sleep(60)

    # Plugins
    def load_plugin(self):
        file = filedialog.askopenfilename(filetypes=[("Python files", "*.py")])
        if file:
            spec = importlib.util.spec_from_file_location("plugin", file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.plugins[os.path.basename(file)] = module
            self.update_plugin_list()

    def update_plugin_list(self):
        self.plugin_list.delete(0, tk.END)
        for plugin in self.plugins:
            self.plugin_list.insert(tk.END, plugin)

    # Miscellaneous
    def customize_layout(self):
        messagebox.showinfo("Customize Layout", "Layout customization not fully implemented yet.")

    def update_health_periodically(self):
        self.root.after(60000, self.update_health_periodically)
        self.check_system_health()

    def check_for_updates(self):
        while self.running:
            time.sleep(3600)  # Check every hour

    def ask_input(self, prompt):
        return simpledialog.askstring("Input", prompt)

    def kill_program(self):
        self.running = False
        self.executor.shutdown(wait=False)
        self.root.quit()
        logger.info("SlingShot terminated.")
        sys.exit(0)

if __name__ == "__main__":
    root = ctk.CTk()
    app = SlingShot(root)
    root.mainloop()