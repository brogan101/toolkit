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
    "🔒 Encrypt File": "Encrypts a selected file.",
    "🔓 Decrypt File": "Decrypts an encrypted file.",
    "📜 Hash File": "Calculates file SHA-256 hash.",
    "🛡️ AV Status": "Checks Windows Defender status.",
    "🔍 Firewall": "Checks firewall status.",
    "📋 Startup Items": "Lists startup programs.",
    "🔍 Susp Procs": "Checks for suspicious processes.",
    "📜 Log Events": "Logs security events.",
    "🔒 Gen OTP": "Generates a one-time password.",
    "🔍 Vuln Scan": "Scans for system vulnerabilities (basic placeholder).",
    "🔑 Pwd Strength": "Checks password strength.",
    "🔥 Fwall Rules": "Manages firewall rules.",
    "🗑️ Shred File": "Securely deletes files.",
    "🛡️ Harden Sys": "Provides hardening tips.",
    "📋 Procs": "Lists running processes.",
    "📈 Resources": "Shows CPU, RAM, disk usage.",
    "🔍 Uptime": "Shows system uptime.",
    "🔍 CPU Temp": "Monitors CPU temperature.",
    "📋 Threads": "Lists running threads.",
    "⚠️ Sys Health": "Evaluates system health.",
    "ℹ️ Sys Info": "Displays system info.",
    "👥 Users": "Lists user accounts.",
    "💿 Chk Disk": "Checks disk health.",
    "🗑️ Clr Temp": "Clears temporary files.",
    "📋 Env Vars": "Lists environment variables.",
    "🏓 Ping": "Pings a target host.",
    "🌐 Net Conns": "Checks network connections.",
    "🔍 Scan Ports": "Scans common ports on a host.",
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
    "☁️ Cloud Backup": "Backs up to cloud.",
    "⏰ Backup Sched": "Schedules backups.",
    "🔍 Backup Verify": "Verifies backup integrity.",
    "🔄 Restore Points": "Manages restore points.",
    "🔧 Sys Tweak": "Tweaks system settings.",
    "🔧 Reg Editor": "Edits the registry.",
    "🖥️ Driver Mgr": "Manages device drivers.",
    "🚀 Boot Mgr": "Manages boot options.",
    "📄 Sys Info Export": "Exports system info."
}

# Tab Colors
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
    "📊 Dashboard": "#2ecc71"
}

# ToolTip Class
class ToolTip:
    current_tip = None

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.id = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)
        self.widget.bind("<FocusOut>", self.hide_tip)  # Hide on focus loss
        self.root = widget.winfo_toplevel()  # Track the root window for focus events
        self.root.bind("<FocusOut>", self.hide_tip, add="+")  # Hide when root loses focus

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
        self.widget.after(3000, self.hide_tip)  # Auto-hide after 3 seconds
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
            # Bind custom event for analytics updates
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
                self.update_check_interval = config.get('update_check_interval', 86400)  # Default: daily
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
        file_menu.add_command(label="Save Config", command=self.save_config, background="#1f1f1f", foreground="white")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.kill_program, background="#1f1f1f", foreground="white")
        help_menu = Menu(menubar, tearoff=0, bg="#1f1f1f", fg="white", activebackground="#2b2b2b", activeforeground="white")
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "SlingShot v1.0 - IT Security Toolkit"), background="#1f1f1f", foreground="white")
        help_menu.add_command(label="Documentation", command=lambda: messagebox.showinfo("Documentation", "Visit https://example.com/docs"), background="#1f1f1f", foreground="white")

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

        # Header
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

        # Command entry and run button
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
        self.left_frame = ctk.CTkFrame(self.middle_frame, width=int(self.root.winfo_screenwidth() * 0.2), corner_radius=10)
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
        self.log_btn_frame.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(self.log_btn_frame, text="🗑️ Clear", command=self.clear_log, fg_color="#ffc107", text_color="black", hover_color="#e0a800", width=80, font=("Segoe UI", 12)).grid(row=0, column=0, padx=5)
        ctk.CTkButton(self.log_btn_frame, text="⏸ Pause", command=self.pause_log, fg_color="#007bff", hover_color="#0056b3", width=80, font=("Segoe UI", 12)).grid(row=0, column=1, padx=5)
        ctk.CTkButton(self.log_btn_frame, text="📤 Export", command=self.export_logs, fg_color="#28a745", hover_color="#218838", width=80, font=("Segoe UI", 12)).grid(row=0, column=2, padx=5)

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

        # Status Bar with Indicator
        self.status_bar = ctk.CTkFrame(self.main_frame, height=30, fg_color="#1f1f1f")
        self.status_bar.pack(fill="x", side="bottom")
        self.status_indicator = ctk.CTkLabel(self.status_bar, text="●", font=("Segoe UI", 12), text_color="green")
        self.status_indicator.pack(side="left", padx=5)
        self.status_label = ctk.CTkLabel(self.status_bar, text="Ready", font=("Segoe UI", 10))
        self.status_label.pack(side="left", padx=5)

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self.main_frame, orientation="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", padx=10, pady=5)
        self.progress_bar.set(0)

    def add_button(self, frame, text, command, timeout, row, col, tab_color):
        btn = ctk.CTkButton(
            frame,
            text=text,
            command=lambda: self.queue_task(command, timeout, text),
            fg_color=tab_color,
            hover_color="#5a5a5a",
            font=("Segoe UI", 12),
            width=int(self.root.winfo_width() * 0.15)
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
            ("💿 Disk Analyzer", self.disk_analyzer, 30),
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
            ("📋 Clip Manager", self.clip_manager, 30),
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
        tab_name = "🔧 Advanced"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("🔥 Tog Fwall", self.toggle_firewall, 30),
            ("🔑 Gen Pwd", self.generate_random_password, 15),
            ("🔄 Restart", self.restart_system, 15),
            ("⏹ Shutdown", self.shutdown_system, 15),
            ("🔒 Lock", self.lock_workstation, 15),
            ("🔧 Sys Tweak", self.sys_tweak, 15),
            ("🔧 Reg Editor", self.reg_editor, 30),
            ("🖥️ Driver Mgr", self.driver_mgr, 30),
            ("🚀 Boot Mgr", self.boot_mgr, 30),
            ("📄 Sys Info Export", self.sys_info_export, 15),
        ]
        for i, (text, cmd, timeout) in enumerate(buttons):
            self.add_button(frame, text, cmd, timeout, i // 3, i % 3, TAB_COLORS[tab_name])

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
    "🔒 Encrypt File": "Encrypts a selected file.",
    "🔓 Decrypt File": "Decrypts an encrypted file.",
    "📜 Hash File": "Calculates file SHA-256 hash.",
    "🛡️ AV Status": "Checks Windows Defender status.",
    "🔍 Firewall": "Checks firewall status.",
    "📋 Startup Items": "Lists startup programs.",
    "🔍 Susp Procs": "Checks for suspicious processes.",
    "📜 Log Events": "Logs security events.",
    "🔒 Gen OTP": "Generates a one-time password.",
    "🔍 Vuln Scan": "Scans for system vulnerabilities (basic placeholder).",
    "🔑 Pwd Strength": "Checks password strength.",
    "🔥 Fwall Rules": "Manages firewall rules.",
    "🗑️ Shred File": "Securely deletes files.",
    "🛡️ Harden Sys": "Provides hardening tips.",
    "📋 Procs": "Lists running processes.",
    "📈 Resources": "Shows CPU, RAM, disk usage.",
    "🔍 Uptime": "Shows system uptime.",
    "🔍 CPU Temp": "Monitors CPU temperature.",
    "📋 Threads": "Lists running threads.",
    "⚠️ Sys Health": "Evaluates system health.",
    "ℹ️ Sys Info": "Displays system info.",
    "👥 Users": "Lists user accounts.",
    "💿 Chk Disk": "Checks disk health.",
    "🗑️ Clr Temp": "Clears temporary files.",
    "📋 Env Vars": "Lists environment variables.",
    "🏓 Ping": "Pings a target host.",
    "🌐 Net Conns": "Checks network connections.",
    "🔍 Scan Ports": "Scans common ports on a host.",
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
    "☁️ Cloud Backup": "Backs up to cloud.",
    "⏰ Backup Sched": "Schedules backups.",
    "🔍 Backup Verify": "Verifies backup integrity.",
    "🔄 Restore Points": "Manages restore points.",
    "🔧 Sys Tweak": "Tweaks system settings.",
    "🔧 Reg Editor": "Edits the registry.",
    "🖥️ Driver Mgr": "Manages device drivers.",
    "🚀 Boot Mgr": "Manages boot options.",
    "📄 Sys Info Export": "Exports system info."
}

# Tab Colors
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
    "📊 Dashboard": "#2ecc71"
}

# ToolTip Class
class ToolTip:
    current_tip = None

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.id = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)
        self.widget.bind("<FocusOut>", self.hide_tip)  # Hide on focus loss
        self.root = widget.winfo_toplevel()  # Track the root window for focus events
        self.root.bind("<FocusOut>", self.hide_tip, add="+")  # Hide when root loses focus

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
        self.widget.after(3000, self.hide_tip)  # Auto-hide after 3 seconds
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
            # Bind custom event for analytics updates
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
                self.update_check_interval = config.get('update_check_interval', 86400)  # Default: daily
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
        file_menu.add_command(label="Save Config", command=self.save_config, background="#1f1f1f", foreground="white")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.kill_program, background="#1f1f1f", foreground="white")
        help_menu = Menu(menubar, tearoff=0, bg="#1f1f1f", fg="white", activebackground="#2b2b2b", activeforeground="white")
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "SlingShot v1.0 - IT Security Toolkit"), background="#1f1f1f", foreground="white")
        help_menu.add_command(label="Documentation", command=lambda: messagebox.showinfo("Documentation", "Visit https://example.com/docs"), background="#1f1f1f", foreground="white")

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

        # Header
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

        # Command entry and run button
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
        self.left_frame = ctk.CTkFrame(self.middle_frame, width=int(self.root.winfo_screenwidth() * 0.2), corner_radius=10)
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
        self.log_btn_frame.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(self.log_btn_frame, text="🗑️ Clear", command=self.clear_log, fg_color="#ffc107", text_color="black", hover_color="#e0a800", width=80, font=("Segoe UI", 12)).grid(row=0, column=0, padx=5)
        ctk.CTkButton(self.log_btn_frame, text="⏸ Pause", command=self.pause_log, fg_color="#007bff", hover_color="#0056b3", width=80, font=("Segoe UI", 12)).grid(row=0, column=1, padx=5)
        ctk.CTkButton(self.log_btn_frame, text="📤 Export", command=self.export_logs, fg_color="#28a745", hover_color="#218838", width=80, font=("Segoe UI", 12)).grid(row=0, column=2, padx=5)

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

        # Status Bar with Indicator
        self.status_bar = ctk.CTkFrame(self.main_frame, height=30, fg_color="#1f1f1f")
        self.status_bar.pack(fill="x", side="bottom")
        self.status_indicator = ctk.CTkLabel(self.status_bar, text="●", font=("Segoe UI", 12), text_color="green")
        self.status_indicator.pack(side="left", padx=5)
        self.status_label = ctk.CTkLabel(self.status_bar, text="Ready", font=("Segoe UI", 10))
        self.status_label.pack(side="left", padx=5)

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self.main_frame, orientation="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", padx=10, pady=5)
        self.progress_bar.set(0)

    def add_button(self, frame, text, command, timeout, row, col, tab_color):
        btn = ctk.CTkButton(
            frame,
            text=text,
            command=lambda: self.queue_task(command, timeout, text),
            fg_color=tab_color,
            hover_color="#5a5a5a",
            font=("Segoe UI", 12),
            width=int(self.root.winfo_width() * 0.15)
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
            ("💿 Disk Analyzer", self.disk_analyzer, 30),
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
            ("📋 Clip Manager", self.clip_manager, 30),
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
        tab_name = "🔧 Advanced"
        frame = self.notebook.add(tab_name)
        buttons = [
            ("🔥 Tog Fwall", self.toggle_firewall, 30),
            ("🔑 Gen Pwd", self.generate_random_password, 15),
            ("🔄 Restart", self.restart_system, 15),
            ("⏹ Shutdown", self.shutdown_system, 15),
            ("🔒 Lock", self.lock_workstation, 15),
            ("🔧 Sys Tweak", self.sys_tweak, 15),
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
        self.fig, self.ax = plt.subplots(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

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
        self.fig_dash, self.ax_dash = plt.subplots(figsize=(6, 4))
        self.canvas_dash = FigureCanvasTkAgg(self.fig_dash, master=frame)
        self.canvas_dash.get_tk_widget().pack(fill="both", expand=True)

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
        self.update_dashboard_plot()

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
        settings_window.geometry("400x400")
        ctk.CTkLabel(settings_window, text="Settings", font=("Segoe UI", 16, "bold")).pack(pady=10)

        # Theme Setting
        ctk.CTkLabel(settings_window, text="Theme", font=("Segoe UI", 14, "bold")).pack(pady=5)
        theme_options = ["Dark", "Light", "System"]
        self.theme_var = tk.StringVar(value=self.theme)
        ctk.CTkOptionMenu(settings_window, values=theme_options, variable=self.theme_var, command=self.change_theme).pack(pady=5)

        # Font Size Setting
        ctk.CTkLabel(settings_window, text="Font Size", font=("Segoe UI", 14, "bold")).pack(pady=5)
        self.font_size_var = tk.DoubleVar(value=11)
        font_slider = ctk.CTkSlider(settings_window, from_=8, to=16, variable=self.font_size_var, command=self.adjust_font_size)
        font_slider.pack(pady=5)
        ctk.CTkButton(settings_window, text="Apply Font", command=lambda: self.adjust_font_size(self.font_size_var.get())).pack(pady=5)

        # Update Check Interval
        ctk.CTkLabel(settings_window, text="Update Check Interval (seconds)", font=("Segoe UI", 14, "bold")).pack(pady=5)
        self.update_interval_var = tk.DoubleVar(value=self.update_check_interval / 3600)  # Convert to hours
        update_slider = ctk.CTkSlider(settings_window, from_=1, to=24, variable=self.update_interval_var)
        update_slider.pack(pady=5)
        ctk.CTkButton(settings_window, text="Apply Update Interval", command=lambda: self.set_update_interval(self.update_interval_var.get() * 3600)).pack(pady=5)

        # Log Level
        ctk.CTkLabel(settings_window, text="Log Level", font=("Segoe UI", 14, "bold")).pack(pady=5)
        log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        self.log_level_var = tk.StringVar(value=self.log_level)
        ctk.CTkOptionMenu(settings_window, values=log_levels, variable=self.log_level_var, command=self.set_log_level).pack(pady=5)

        # Language
        ctk.CTkLabel(settings_window, text="Language", font=("Segoe UI", 14, "bold")).pack(pady=5)
        languages = ["English", "Spanish", "French"]  # Add more as needed
        self.language_var = tk.StringVar(value=self.language)
        ctk.CTkOptionMenu(settings_window, values=languages, variable=self.language_var, command=self.set_language).pack(pady=5)

        ctk.CTkButton(settings_window, text="Save & Close", command=lambda: [self.save_config(), settings_window.destroy()]).pack(pady=10)

    def set_update_interval(self, value):
        self.update_check_interval = int(value)
        self.save_config()

    def set_log_level(self, value):
        self.log_level = value
        logging.getLogger('SlingShot').setLevel(getattr(logging, self.log_level))
        self.save_config()

    def set_language(self, value):
        self.language = value
        # Add language switching logic here if needed (e.g., update UI text)
        self.save_config()

    # Core Functionality
    def queue_task(self, func, timeout, name):
        task_id = secrets.token_hex(4)
        self.current_tasks[task_id] = {'name': name, 'timeout': timeout}
        self.task_queue.put((task_id, func))
        self.status_indicator.configure(text_color="yellow")
        self.status_label.configure(text=f"Running: {name}")
        self.progress_bar.set(0)
        threading.Thread(target=self.process_task_queue, daemon=True).start()

    def process_task_queue(self):
        while not self.task_queue.empty() and self.running:
            task_id, func = self.task_queue.get()
            if task_id in self.current_tasks:
                try:
                    self.progress_bar.set(0.1)
                    result = self.executor.submit(func).result(timeout=self.current_tasks[task_id]['timeout'])
                    self.progress_bar.set(1.0)
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
                elif isinstance(widget, ctk.CTkLabel):
                    widget.configure(font=("Segoe UI", font_size))
                elif isinstance(widget, ctk.CTkEntry):
                    widget.configure(font=("Segoe UI", font_size))

    def show_welcome_screen(self):
        welcome = Toplevel(self.root)
        welcome.title("Welcome to SlingShot")
        welcome.geometry("400x250")
        welcome.transient(self.root)
        welcome.configure(bg="#2b2b2b")
        ctk.CTkLabel(welcome, text="Welcome to SlingShot!", font=("Segoe UI", 18, "bold"), text_color="white").pack(pady=20)
        ctk.CTkLabel(welcome, text="Your IT Security Toolkit", font=("Segoe UI", 14), text_color="#d1d1d1").pack(pady=10)
        ctk.CTkLabel(welcome, text="Explore features like encryption, monitoring, and backups.", font=("Segoe UI", 12), text_color="#d1d1d1").pack(pady=5)
        ctk.CTkButton(welcome, text="Start", command=welcome.destroy, fg_color="#17a2b8", hover_color="#138496", width=100).pack(pady=20)

    def show_notification(self, message, error=False):
        notification = Toplevel(self.root)
        notification.title("Notification")
        x = self.root.winfo_screenwidth() - 300
        y = self.root.winfo_screenheight() - 100
        notification.geometry(f"250x80+{x}+{y}")
        notification.overrideredirect(True)
        notification.configure(bg="#2b2b2b" if ctk.get_appearance_mode() == "Dark" else "#ffffff")
        ctk.CTkLabel(notification, text=message, font=("Segoe UI", 12), text_color="red" if error else "white").pack(pady=10)
        ctk.CTkButton(notification, text="Close", command=notification.destroy, fg_color="#dc3545" if error else "#17a2b8", width=50).pack(pady=5)
        notification.after(5000, notification.destroy)

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
        return f"Generated key: {self.key.decode()}\nSave this key securely for decryption!"

    def encrypt_file(self):
        if not self.key:
            return "No key generated. Generate a key first."
        file = filedialog.askopenfilename()
        if file:
            with open(file, 'rb') as f:
                data = f.read()
            fernet = Fernet(self.key)
            encrypted = fernet.encrypt(data)
            encrypted_file = file + '.encrypted'
            with open(encrypted_file, 'wb') as f:
                f.write(encrypted)
            return f"Encrypted {file} to {encrypted_file}\nSize: {os.path.getsize(encrypted_file) / 1024:.2f} KB"

    def decrypt_file(self):
        if not self.key:
            return "No key generated. Generate a key first."
        file = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.encrypted")])
        if file:
            with open(file, 'rb') as f:
                data = f.read()
            fernet = Fernet(self.key)
            decrypted = fernet.decrypt(data)
            decrypted_file = file.replace('.encrypted', '_decrypted')
            with open(decrypted_file, 'wb') as f:
                f.write(decrypted)
            return f"Decrypted {file} to {decrypted_file}\nSize: {os.path.getsize(decrypted_file) / 1024:.2f} KB"

    def hash_file(self):
        file = filedialog.askopenfilename()
        if not file:
            return "No file selected."
        md5_hasher = hashlib.md5()
        sha1_hasher = hashlib.sha1()
        sha256_hasher = hashlib.sha256()
        file_size = os.path.getsize(file)
        with open(file, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hasher.update(chunk)
                sha1_hasher.update(chunk)
                sha256_hasher.update(chunk)
        hashes = [
            f"MD5: {md5_hasher.hexdigest()}",
            f"SHA-1: {sha1_hasher.hexdigest()}",
            f"SHA-256: {sha256_hasher.hexdigest()}"
        ]
        known_hash = self.ask_input("Enter a known hash to compare (or leave blank to skip):")
        if known_hash:
            known_hash = known_hash.lower().strip()
            for h in (md5_hasher.hexdigest(), sha1_hasher.hexdigest(), sha256_hasher.hexdigest()):
                if h == known_hash:
                    hashes.append("Hash Match: File integrity verified!")
                    break
            else:
                hashes.append("Hash Mismatch: File may be corrupted or tampered with.")
        return f"Hashes for {file} (Size: {file_size / 1024:.2f} KB):\n" + "\n".join(hashes)

    def check_antivirus_status(self):
        try:
            result = subprocess.run(['powershell', 'Get-MpComputerStatus'], capture_output=True, text=True, timeout=10)
            output = result.stdout.strip() or result.stderr.strip()
            lines = output.splitlines()
            status = {line.split(':')[0].strip(): line.split(':')[1].strip() for line in lines if ':' in line}
            return f"Antivirus Status:\nAMProductVersion: {status.get('AMProductVersion', 'N/A')}\nRealTimeProtectionEnabled: {status.get('RealTimeProtectionEnabled', 'N/A')}\nLastScan: {status.get('AntivirusSignatureLastUpdated', 'N/A')}"
        except Exception as e:
            return f"Error checking AV status: {e}"

    def check_firewall_status(self):
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True, timeout=10)
            output = result.stdout.strip() or result.stderr.strip()
            lines = [line for line in output.splitlines() if 'State' in line or 'Firewall Policy' in line]
            status = {line.split()[0]: line.split()[-1] for line in lines if len(line.split()) > 1}
            return f"Firewall Status:\nDomain: {status.get('Domain', 'N/A')}\nPrivate: {status.get('Private', 'N/A')}\nPublic: {status.get('Public', 'N/A')}\nPolicy: {status.get('Policy', 'N/A')}"
        except Exception as e:
            return f"Error checking firewall status: {e}"

    def list_startup_items(self):
        try:
            result = subprocess.run(['wmic', 'startup', 'get', 'caption,command,User'], capture_output=True, text=True, timeout=10)
            output = result.stdout.strip() or result.stderr.strip()
            lines = [line for line in output.splitlines() if line.strip() and not line.startswith('Caption')]
            items = [f"{line.split()[0]} (Command: {line.split()[1]}) - User: {line.split()[-1] if len(line.split()) > 2 else 'N/A'}" for line in lines]
            return "Startup Items:\n" + "\n".join(items[:10]) + "\n(Showing top 10, use Task Manager for more)"
        except Exception as e:
            return f"Error listing startup items: {e}"

    def check_suspicious_processes(self):
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'exe', 'create_time', 'connections']):
            try:
                cpu = proc.info['cpu_percent']
                mem = proc.info['memory_percent']
                exe = proc.info['exe']
                create_time = proc.info['create_time']
                age = (time.time() - create_time) / 60  # Age in minutes
                net_conns = len(proc.info['connections']) if proc.info['connections'] else 0
                reasons = []
                if cpu > 90:
                    reasons.append(f"High CPU: {cpu}%")
                if mem > 90:
                    reasons.append(f"High Memory: {mem}%")
                if age < 5:
                    reasons.append(f"Recently Started: {age:.1f} minutes ago")
                if net_conns > 5:
                    reasons.append(f"High Network Activity: {net_conns} connections")
                if exe and not exe.lower().startswith("c:\\windows") and not exe.lower().startswith("c:\\program files"):
                    reasons.append(f"Unusual Path: {exe}")
                if reasons:
                    remediation = "Action: Investigate further. Consider terminating with 'taskkill /PID {pid} /F' or quarantine if unrecognized."
                    suspicious.append(
                        f"PID: {proc.info['pid']}, Name: {proc.info['name']}, "
                        f"Reasons: {', '.join(reasons)}, {remediation}"
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return "Suspicious processes:\n" + "\n".join(suspicious) if suspicious else "No suspicious processes found."

    def generate_otp(self):
        otp = secrets.token_hex(4)
        return f"One-time password: {otp}\nValid for 5 minutes (use immediately!)"

    def log_security_events(self):
        try:
            security_event = f"Security Event Logged: System check initiated at {time.strftime('%Y-%m-%d %H:%M:%S')}"
            self.log_queue.put(security_event)
            logger.info(security_event)
            sample_events = [
                "Event 1: Successful login detected.",
                "Event 2: Firewall rule change attempted.",
                "Event 3: Antivirus scan completed."
            ]
            return "Logged security events:\n" + "\n".join(sample_events)
        except Exception as e:
            error_msg = f"Error logging security events: {e}"
            self.log_queue.put(error_msg)
            logger.error(error_msg, exc_info=True)
            return error_msg

    def vuln_scan(self):
        try:
            outdated = []
            if platform.release() < "10.0.19041":
                outdated.append("Operating System: Outdated version detected.")
            result = subprocess.run(['wmic', 'product', 'get', 'name,version'], capture_output=True, text=True, timeout=10)
            output = result.stdout.strip() or result.stderr.strip()
            lines = [line for line in output.splitlines() if line.strip() and not line.startswith('Name')]
            for line in lines[:10]:
                name, version = line.split()[:2] if len(line.split()) > 1 else (line.split()[0], "N/A")
                if float(version) < 1.0:
                    outdated.append(f"Software: {name} (Version {version} may be outdated)")
            return "Vulnerability Scan Results:\n" + "\n".join(outdated) if outdated else "No obvious vulnerabilities detected (basic scan)."
        except Exception as e:
            return f"Error during vulnerability scan: {e}"

    def pwd_strength(self):
        pwd = self.ask_input("Enter password to check:")
        if not pwd:
            return "No password entered."
        length = len(pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd)
        score = (length * 4) + (has_upper * 10) + (has_lower * 10) + (has_digit * 15) + (has_special * 20)
        strength = "Weak" if score < 50 else "Moderate" if score < 80 else "Strong"
        tips = [
            "Add uppercase letters" if not has_upper else "",
            "Add lowercase letters" if not has_lower else "",
            "Add numbers" if not has_digit else "",
            "Add special characters" if not has_special else "",
            "Increase length (>12)" if length < 12 else ""
        ]
        return f"Password Strength: {strength}\nScore: {score}/100\nLength: {length}\nTips: {', '.join(tip for tip in tips if tip)}"

    def fwall_rules(self):
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], capture_output=True, text=True, timeout=15)
            output = result.stdout.strip() or result.stderr.strip()
            lines = [line for line in output.splitlines() if line.strip() and not line.startswith('Rule')]
            rules = [f"{line.split()[0]}: {'Enabled' if 'Yes' in line else 'Disabled'}" for line in lines if len(line.split()) > 1]
            return "Firewall Rules:\n" + "\n".join(rules[:10]) + "\n(Showing top 10, use 'netsh advfirewall firewall show rule' for more)"
        except Exception as e:
            return f"Error retrieving firewall rules: {e}"

    def shred_file(self):
        file = filedialog.askopenfilename()
        if file:
            file_size = os.path.getsize(file)
            with open(file, 'ba+') as f:
                f.seek(0)
                f.write(os.urandom(file_size))
            os.remove(file)
            return f"File {file} securely shredded (Size: {file_size / 1024:.2f} KB)"

    def harden_sys(self):
        tips = [
            "Enable Windows Firewall: Run 'netsh advfirewall set allprofiles state on'",
            "Disable unused services: Use 'services.msc' to disable non-essential services",
            "Update OS: Check for updates in Settings > Windows Update",
            "Use strong passwords: Generate with 'Gen Pwd' feature",
            "Restrict user accounts: Remove unnecessary admin rights"
        ]
        return "System Hardening Tips:\n" + "\n".join(tips)

    # Monitoring Functions
    def show_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_times', 'username', 'exe']):
            try:
                mem = proc.info['memory_info'].rss / (1024 ** 2)
                cpu_time = proc.info['cpu_times'].user + proc.info['cpu_times'].system
                user = proc.info['username'].split('\\')[-1] if proc.info['username'] else "Unknown"
                exe_path = proc.info['exe'] if proc.info['exe'] else "N/A"
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'memory_mb': mem,
                    'cpu_time': cpu_time,
                    'user': user,
                    'exe': exe_path
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        processes.sort(key=lambda x: x['cpu_time'], reverse=True)
        output = ["Running Processes (Sorted by CPU Time):"]
        for proc in processes[:20]:
            output.append(
                f"PID: {proc['pid']}, Name: {proc['name']}, "
                f"Memory: {proc['memory_mb']:.2f} MB, CPU Time: {proc['cpu_time']:.2f}s, "
                f"User: {proc['user']}, Path: {proc['exe']}"
            )
        output.append("(Showing top 20 by CPU usage)")
        return "\n".join(output)

    def show_resource_usage(self):
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net = psutil.net_io_counters()
        return (
            f"Resource Usage:\n"
            f"CPU: {cpu:.1f}%\n"
            f"Memory: Total {mem.total / (1024**3):.2f} GB, Used {mem.used / (1024**3):.2f} GB, Free {mem.available / (1024**3):.2f} GB ({mem.percent}%)\n"
            f"Disk: Total {disk.total / (1024**3):.2f} GB, Used {disk.used / (1024**3):.2f} GB, Free {disk.free / (1024**3):.2f} GB ({disk.percent}%)\n"
            f"Network: Sent {net.bytes_sent / (1024**2):.2f} MB, Received {net.bytes_recv / (1024**2):.2f} MB"
        )

    def show_system_uptime(self):
        uptime = time.time() - psutil.boot_time()
        days, remainder = divmod(uptime, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"System Uptime: {int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds"

    def monitor_cpu_temp(self):
        return "CPU Temperature monitoring (placeholder, requires library like 'py-sensors' or 'openhardwaremonitor')."

    def list_running_threads(self):
        threads = []
        for thread in threading.enumerate():
            threads.append(f"Thread ID: {thread.ident}, Name: {thread.name}, Daemon: {thread.daemon}")
        return "Running Threads:\n" + "\n".join(threads)

    def check_system_health(self):
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        health_status = "Healthy" if cpu < 80 and mem < 80 and disk < 90 else "Unhealthy"
        recommendations = [
            "Reduce CPU load" if cpu > 80 else "",
            "Free up memory" if mem > 80 else "",
            "Clear disk space" if disk > 90 else ""
        ]
        return (
            f"System Health:\n"
            f"CPU: {cpu:.1f}%, Memory: {mem:.1f}%, Disk: {disk:.1f}%\n"
            f"Status: {health_status}\n"
            f"Recommendations: {', '.join(rec for rec in recommendations if rec)}"
        )

    def net_traffic(self):
        net_io = psutil.net_io_counters()
        net_io_prev = getattr(self, 'net_io_prev', net_io)
        delta_sent = (net_io.bytes_sent - net_io_prev.bytes_sent) / 1024
        delta_recv = (net_io.bytes_recv - net_io_prev.bytes_recv) / 1024
        self.net_io_prev = net_io
        return f"Network Traffic (Last 1s):\nSent: {delta_sent:.2f} KB/s, Received: {delta_recv:.2f} KB/s\nTotal Sent: {net_io.bytes_sent / (1024**2):.2f} MB, Total Received: {net_io.bytes_recv / (1024**2):.2f} MB"

    def proc_explorer(self):
        return "Process Explorer (placeholder, requires detailed process analysis library)."

    def disk_analyzer(self):
        disk = psutil.disk_usage('/')
        partitions = psutil.disk_partitions()
        analysis = [
            f"Disk Usage (Root): Total {disk.total / (1024**3):.2f} GB, Used {disk.used / (1024**3):.2f} GB, Free {disk.free / (1024**3):.2f} GB ({disk.percent}%)"
        ]
        for part in partitions:
            usage = psutil.disk_usage(part.mountpoint)
            analysis.append(f"Partition {part.device}: {part.fstype}, Used {usage.used / (1024**3):.2f} GB of {usage.total / (1024**3):.2f} GB ({usage.percent}%)")
        return "Disk Analysis:\n" + "\n".join(analysis)

    def event_viewer(self):
        return "Event Viewer (placeholder, requires win32evtlog for Windows Event Logs)."

    def benchmark(self):
        return "Benchmark completed (placeholder, requires performance testing library)."

    # Utilities Functions
    def get_system_info(self):
        info = []
        info.append(f"OS: {platform.system()} {platform.release()} (Build {platform.version()})")
        info.append(f"Architecture: {platform.machine()}")
        info.append(f"Hostname: {socket.gethostname()}")
        cpu_count = psutil.cpu_count(logical=True)
        cpu_physical = psutil.cpu_count(logical=False)
        cpu_freq = psutil.cpu_freq()
        cpu_info = f"CPU: {cpu_count} cores ({cpu_physical} physical), {cpu_freq.current if cpu_freq else 'N/A'} MHz"
        try:
            cpu_model = platform.processor()
            cpu_info += f", Model: {cpu_model}"
        except Exception:
            pass
        info.append(cpu_info)
        mem = psutil.virtual_memory()
        info.append(f"RAM: Total {mem.total / (1024**3):.2f} GB, Available {mem.available / (1024**3):.2f} GB, Used {mem.percent}%")
        disk = psutil.disk_usage('/')
        info.append(f"Disk: Total {disk.total / (1024**3):.2f} GB, Used {disk.used / (1024**3):.2f} GB, Free {disk.free / (1024**3):.2f} GB")
        try:
            ip = socket.gethostbyname(socket.gethostname())
            info.append(f"IP Address: {ip}")
        except Exception:
            info.append("IP Address: Unable to retrieve")
        try:
            mac = ':'.join(['{:02x}'.format((psutil.net_if_addrs()['Ethernet'][0].address[i:i+2])) for i in range(0, 12, 2)])
            info.append(f"MAC Address: {mac}")
        except Exception:
            info.append("MAC Address: Unable to retrieve (Ethernet adapter not found)")
        boot_time = psutil.boot_time()
        boot_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(boot_time))
        uptime = time.time() - boot_time
        info.append(f"Last Boot: {boot_time_str}, Uptime: {int(uptime // 3600)}h {int((uptime % 3600) // 60)}m")
        return "\n".join(info)

    def list_users(self):
        try:
            result = subprocess.run(['net', 'user'], capture_output=True, text=True, timeout=10)
            output = result.stdout.strip() or result.stderr.strip()
            users = [line for line in output.splitlines() if line.strip() and not line.startswith('The') and not line.startswith('---')]
            user_details = []
            for user in users[:10]:
                try:
                    detail = subprocess.run(['net', 'user', user], capture_output=True, text=True, timeout=5).stdout
                    full_name = re.search(r'Full Name\s+(.+)', detail, re.MULTILINE)
                    last_logon = re.search(r'Last logon\s+(.+)', detail, re.MULTILINE)
                    user_details.append(f"{user} (Full Name: {full_name.group(1) if full_name else 'N/A'}, Last Logon: {last_logon.group(1) if last_logon else 'N/A'})")
                except Exception:
                    user_details.append(f"{user} (Details unavailable)")
            return "User Accounts:\n" + "\n".join(user_details) + "\n(Showing top 10, use 'net user' for more)"
        except Exception as e:
            return f"Error listing users: {e}"

    def check_disk_health(self):
        try:
            result = subprocess.run(['wmic', 'diskdrive', 'get', 'status'], capture_output=True, text=True, timeout=15)
            output = result.stdout.strip() or result.stderr.strip()
            lines = [line for line in output.splitlines() if line.strip() and not line.startswith('Status')]
            health = "OK" if "OK" in output else "At Risk" if any("Warning" in line for line in lines) else "Failed"
            return f"Disk Health Check:\nStatus: {health}\nDetails: {'\n'.join(lines)}"
        except Exception as e:
            return f"Error checking disk health: {e}"

    def clear_temp_files(self):
        temp_dir = os.getenv('TEMP')
        if not temp_dir:
            return "No TEMP directory found."
        total_cleared = 0
        for root, _, files in os.walk(temp_dir):
            for file in files:
                path = os.path.join(root, file)
                try:
                    if os.path.isfile(path):
                        size = os.path.getsize(path)
                        os.unlink(path)
                        total_cleared += size
                except Exception as e:
                    self.log_queue.put(f"Failed to delete {path}: {e}")
        return f"Cleared {total_cleared / 1024:.2f} KB of temporary files in {temp_dir}"

    def list_environment_vars(self):
        env_vars = {k: v for k, v in os.environ.items() if k not in ['PATH', 'TEMP', 'TMP']}
        output = ["Environment Variables:"]
        for key, value in list(env_vars.items())[:20]:
            output.append(f"{key}: {value[:50]}{'...' if len(value) > 50 else ''}")
        output.append("(Showing top 20, use 'set' in CMD for full list)")
        return "\n".join(output)

    def file_convert(self):
        return "File conversion (placeholder, requires conversion library like 'PyPDF2' or 'pypandoc')."

    def batch_rename(self):
        return "Batch rename (placeholder, requires file renaming logic)."

    def dupe_finder(self):
        return "Duplicate finder (placeholder, requires file comparison logic)."

    def sys_cleaner(self):
        return "System cleaner (placeholder, requires advanced cleanup logic)."

    def clip_manager(self):
        return "Clipboard manager (placeholder, requires clipboard monitoring)."

    def ping_test(self):
        target = self.ask_input("Enter host to ping (e.g., google.com):", default="google.com")
        if not target:
            return "No target specified."
        try:
            result = subprocess.run(['ping', '-n', '4', target], capture_output=True, text=True, timeout=10)
            output = result.stdout.strip() or result.stderr.strip()
            lines = [line for line in output.splitlines() if line.strip()]
            return f"Ping Test to {target}:\n" + "\n".join(lines[-4:])  # Show last 4 lines (summary)
        except Exception as e:
            return f"Ping test failed: {e}"

    def check_network_connections(self):
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED:
                    local = f"{conn.laddr.ip}:{conn.laddr.port}"
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    pid = conn.pid if conn.pid else "Unknown"
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "Unknown"
                    connections.append(f"PID: {pid} ({proc_name}), Local: {local}, Remote: {remote}")
            return "Active Network Connections:\n" + "\n".join(connections[:10]) + "\n(Showing top 10, use 'netstat -ano' for more)"
        except Exception as e:
            return f"Error checking network connections: {e}"

    def scan_ports(self):
        target = self.ask_input("Enter host to scan (e.g., localhost):", default="localhost")
        if not target:
            return "No target specified."
        common_ports = [21, 22, 23, 80, 443, 445, 3389]
        open_ports = []
        try:
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(f"Port {port} is open")
                sock.close()
            return f"Port Scan on {target}:\n" + ("\n".join(open_ports) if open_ports else "No common ports open.")
        except Exception as e:
            return f"Port scan failed: {e}"

    def port_scan(self):
        return "Detailed port scan (placeholder, requires library like 'nmap' or 'scapy')."

    def speed_test(self):
        return "Network speed test (placeholder, requires library like 'speedtest-cli')."

    def dns_lookup(self):
        target = self.ask_input("Enter domain for DNS lookup (e.g., google.com):", default="google.com")
        if not target:
            return "No domain specified."
        try:
            ip = socket.gethostbyname(target)
            return f"DNS Lookup for {target}:\nIP Address: {ip}"
        except Exception as e:
            return f"DNS lookup failed: {e}"

    def traceroute(self):
        target = self.ask_input("Enter host for traceroute (e.g., google.com):", default="google.com")
        if not target:
            return "No target specified."
        try:
            result = subprocess.run(['tracert', '-d', target], capture_output=True, text=True, timeout=30)
            output = result.stdout.strip() or result.stderr.strip()
            lines = [line for line in output.splitlines() if line.strip()]
            return f"Traceroute to {target}:\n" + "\n".join(lines[:10]) + "\n(Showing first 10 hops)"
        except Exception as e:
            return f"Traceroute failed: {e}"

    def wifi_analyzer(self):
        return "WiFi Analyzer (placeholder, requires library like 'pywifi' or 'netsh wlan show networks')."

    # Backup Functions
    def backup_files(self):
        src_dir = filedialog.askdirectory(title="Select directory to backup")
        if not src_dir:
            return "No directory selected."
        dst_file = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("ZIP files", "*.zip")])
        if not dst_file:
            return "No backup file specified."
        total_size = 0
        for root, _, files in os.walk(src_dir):
            for file in files:
                total_size += os.path.getsize(os.path.join(root, file))
        with ZipFile(dst_file, 'w') as zipf:
            for root, _, files in os.walk(src_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, src_dir)
                    zipf.write(file_path, arcname)
        return f"Backup created: {dst_file}\nTotal size: {total_size / (1024**2):.2f} MB"

    def restore_files(self):
        zip_file = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        if not zip_file:
            return "No backup file selected."
        dst_dir = filedialog.askdirectory(title="Select directory to restore to")
        if not dst_dir:
            return "No restore directory specified."
        with ZipFile(zip_file, 'r') as zipf:
            zipf.extractall(dst_dir)
        return f"Restored backup to {dst_dir}"

    def inc_backup(self):
        return "Incremental backup (placeholder, requires backup library with delta tracking)."

    def cloud_backup(self):
        return "Cloud backup (placeholder, requires cloud service API like AWS S3 or Google Drive)."

    def backup_sched(self):
        return "Backup scheduled (placeholder, added to scheduler)."

    def backup_verify(self):
        zip_file = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        if not zip_file:
            return "No backup file selected."
        try:
            with ZipFile(zip_file, 'r') as zipf:
                result = zipf.testzip()
                if result is None:
                    return f"Backup verification: {zip_file} is intact."
                else:
                    return f"Backup verification failed: {result}"
        except Exception as e:
            return f"Backup verification failed: {e}"

    def restore_points(self):
        return "System Restore Points (placeholder, requires 'wmic' or 'pywin32' for system restore management)."

    # Advanced Functions
    def toggle_firewall(self):
        try:
            state = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True, timeout=5).stdout
            if "ON" in state:
                subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'off'], capture_output=True, timeout=5)
                return "Firewall disabled."
            else:
                subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'], capture_output=True, timeout=5)
                return "Firewall enabled."
        except Exception as e:
            return f"Error toggling firewall: {e}"

    def generate_random_password(self):
        length = int(self.ask_input("Enter password length (8-32):", default="12") or 12)
        length = max(8, min(length, 32))
        chars = string.ascii_letters + string.digits + string.punctuation
        pwd = ''.join(secrets.choice(chars) for _ in range(length))
        return f"Generated Password: {pwd}\nStrength: {self.pwd_strength_checker(pwd)}"

    def pwd_strength_checker(self, pwd):
        score = len(pwd) * 4
        if any(c.isupper() for c in pwd):
            score += 10
        if any(c.islower() for c in pwd):
            score += 10
        if any(c.isdigit() for c in pwd):
            score += 15
        if any(c in string.punctuation for c in pwd):
            score += 20
        return "Strong" if score >= 80 else "Moderate" if score >= 50 else "Weak"

    def restart_system(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to restart the system?"):
            subprocess.run(['shutdown', '/r', '/t', '0'])
            return "System restarting..."
        return "Restart cancelled."

    def shutdown_system(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to shutdown the system?"):
            subprocess.run(['shutdown', '/s', '/t', '0'])
            return "System shutting down..."
        return "Shutdown cancelled."

    def lock_workstation(self):
        subprocess.run(['rundll32.exe', 'user32.dll,LockWorkStation'])
        return "Workstation locked."

    def sys_tweak(self):
        return "System tweak (placeholder, requires specific tweak implementation)."

    def reg_editor(self):
        subprocess.run(['regedit'])
        return "Registry Editor opened."

    def driver_mgr(self):
        subprocess.run(['devmgmt.msc'])
        return "Device Manager opened."

    def boot_mgr(self):
        return "Boot Manager (placeholder, requires 'bcdedit' or boot management library)."

    def sys_info_export(self):
        info = self.get_system_info()
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file:
            with open(file, 'w') as f:
                f.write(info)
            return f"System info exported to {file}"
        return "Export cancelled."

    # Password Manager Functions
    def add_password(self):
        name = self.pwd_name.get()
        pwd = self.pwd_value.get()
        if name and pwd:
            encrypted_pwd = self.cipher.encrypt(pwd.encode()).decode()
            self.passwords[name] = encrypted_pwd
            self.save_config()
            self.update_password_list()
            self.pwd_name.delete(0, tk.END)
            self.pwd_value.delete(0, tk.END)
            return f"Password for {name} added."
        return "Please enter both service name and password."

    def view_password(self):
        selection = self.pwd_list.curselection()
        if not selection:
            return "No password selected."
        name = self.pwd_list.get(selection[0])
        encrypted_pwd = self.passwords.get(name)
        if encrypted_pwd:
            pwd = self.cipher.decrypt(encrypted_pwd.encode()).decode()
            return f"Password for {name}: {pwd}"
        return f"No password found for {name}."

    def delete_password(self):
        selection = self.pwd_list.curselection()
        if not selection:
            return "No password selected."
        name = self.pwd_list.get(selection[0])
        if name in self.passwords:
            del self.passwords[name]
            self.save_config()
            self.update_password_list()
            return f"Password for {name} deleted."
        return f"No password found for {name}."

    def update_password_list(self):
        self.pwd_list.delete(0, tk.END)
        for name in self.passwords.keys():
            self.pwd_list.insert(tk.END, name)

    # Scheduler Functions
    def add_scheduled_task(self):
        name = self.task_name.get()
        time_str = self.task_time.get()
        if name and time_str:
            try:
                task_time = time.strptime(time_str, "%H:%M")
                self.scheduled_tasks.append({"name": name, "time": time_str})
                self.save_config()
                self.update_task_list()
                self.task_name.delete(0, tk.END)
                self.task_time.delete(0, tk.END)
                return f"Scheduled task '{name}' at {time_str}."
            except ValueError:
                return "Invalid time format. Use HH:MM (24-hour)."
        return "Please enter both task name and time."

    def remove_scheduled_task(self):
        selection = self.task_list.curselection()
        if not selection:
            return "No task selected."
        task = self.scheduled_tasks.pop(selection[0])
        self.save_config()
        self.update_task_list()
        return f"Removed task: {task['name']}"

    def update_task_list(self):
        self.task_list.delete(0, tk.END)
        for task in self.scheduled_tasks:
            self.task_list.insert(tk.END, f"{task['name']} at {task['time']}")

    def check_scheduled_tasks(self):
        while self.running:
            current_time = time.strftime("%H:%M")
            for task in self.scheduled_tasks:
                if task["time"] == current_time:
                    self.log_queue.put(f"Running scheduled task: {task['name']}")
                    for tab_name in self.notebook._tab_dict:
                        tab = self.notebook._tab_dict[tab_name]
                        for widget in tab.winfo_children():
                            if isinstance(widget, ctk.CTkButton) and widget.cget("text") == task["name"]:
                                self.queue_task(widget.cget("command"), 60, task["name"])
                                break
            time.sleep(60)  # Check every minute

    # Analytics and Dashboard Functions
    def collect_analytics(self):
        while self.running:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            timestamp = time.time()
            with self.lock:
                self.analytics_data['cpu'].append(cpu)
                self.analytics_data['mem'].append(mem)
                self.analytics_data['disk'].append(disk)
                self.analytics_data['times'].append(timestamp)
                if len(self.analytics_data['cpu']) > 100:  # Limit to 100 data points
                    self.analytics_data['cpu'].pop(0)
                    self.analytics_data['mem'].pop(0)
                    self.analytics_data['disk'].pop(0)
                    self.analytics_data['times'].pop(0)
            # Signal main thread to update plot
            self.root.event_generate("<<UpdateAnalytics>>", when="tail")
            time.sleep(5)  # Update every 5 seconds

    def update_analytics_plot(self):
        if not self.analytics_data['times']:  # Avoid plotting with empty data
            return
        self.ax.clear()
        times = [time.strftime('%H:%M:%S', time.localtime(t)) for t in self.analytics_data['times']]
        self.ax.plot(times, self.analytics_data['cpu'], label='CPU %', color='red')
        self.ax.plot(times, self.analytics_data['mem'], label='Memory %', color='blue')
        self.ax.plot(times, self.analytics_data['disk'], label='Disk %', color='green')
        self.ax.set_title('System Resource Usage Over Time')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Percentage (%)')
        self.ax.legend()
        self.ax.grid(True)
        plt.xticks(rotation=45)
        self.canvas.draw()

    def update_dashboard(self):
        while self.running:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            self.cpu_label.configure(text=f"CPU: {cpu:.1f}%")
            self.ram_label.configure(text=f"RAM: {mem.percent}%")
            self.disk_label.configure(text=f"Disk: {disk.percent}%")
            self.update_dashboard_plot()
            time.sleep(5)

    def update_dashboard_plot(self):
        if not self.analytics_data['times']:
            return
        self.ax_dash.clear()
        times = [time.strftime('%H:%M:%S', time.localtime(t)) for t in self.analytics_data['times']]
        self.ax_dash.plot(times, self.analytics_data['cpu'], label='CPU %', color='red')
        self.ax_dash.plot(times, self.analytics_data['mem'], label='Memory %', color='blue')
        self.ax_dash.plot(times, self.analytics_data['disk'], label='Disk %', color='green')
        self.ax_dash.set_title('System Metrics')
        self.ax_dash.set_xlabel('Time')
        self.ax_dash.set_ylabel('Usage (%)')
        self.ax_dash.legend()
        self.ax_dash.grid(True)
        plt.xticks(rotation=45)
        self.canvas_dash.draw()

    # Plugin Functions
    def load_plugin(self):
        file = filedialog.askopenfilename(filetypes=[("Python files", "*.py")])
        if not file:
            return "No plugin file selected."
        plugin_name = os.path.splitext(os.path.basename(file))[0]
        spec = importlib.util.spec_from_file_location(plugin_name, file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, 'run'):
            self.plugins[plugin_name] = module
            self.update_plugin_list()
            return f"Plugin {plugin_name} loaded."
        return "Plugin does not have a 'run' function."

    def update_plugin_list(self):
        self.plugin_list.delete(0, tk.END)
        for name in self.plugins.keys():
            self.plugin_list.insert(tk.END, name)

    # Utility Methods
    def ask_input(self, prompt, default=None):
        return simpledialog.askstring("Input", prompt, initialvalue=default)

    def update_health_periodically(self):
        while self.running:
            health = self.check_system_health()
            if "Unhealthy" in health:
                self.status_indicator.configure(text_color="red")
                self.status_label.configure(text="System Unhealthy - Check Logs")
            else:
                self.status_indicator.configure(text_color="green")
                self.status_label.configure(text="Ready")
            time.sleep(300)  # Check every 5 minutes

    def check_for_updates(self):
        while self.running:
            try:
                response = requests.get('https://example.com/slingshot_version', timeout=5)
                latest_version = response.text.strip()
                current_version = "1.0"  # Placeholder for actual version
                if latest_version > current_version:
                    if messagebox.askyesno("Update Available", f"Version {latest_version} is available. Update now?"):
                        subprocess.run(['start', 'https://example.com/download'], shell=True)
                        return "Download started."
                time.sleep(self.update_check_interval)  # Check based on config interval
            except Exception:
                time.sleep(3600)  # Check hourly if network fails

    def run_favorite(self, index):
        if self.favorites[index]:
            for tab_name in self.notebook._tab_dict:
                tab = self.notebook._tab_dict[tab_name]
                for widget in tab.winfo_children():
                    if isinstance(widget, ctk.CTkButton) and widget.cget("text") == self.favorites[index]:
                        self.queue_task(widget.cget("command"), 60, self.favorites[index])
                        return
            self.log_queue.put(f"Favorite {self.favorites[index]} not found in current tabs.")

    def add_to_favorites(self, text):
        if text in self.favorites:
            return
        for i in range(8):
            if self.favorites[i] is None:
                self.favorites[i] = text
                btn = self.favorites_grid.grid_slaves(row=i // 4, column=i % 4)[0]
                btn.configure(text=text)
                self.save_config()
                self.show_notification(f"Added {text} to favorites")
                return
        self.show_notification("Favorites full! Remove one to add new.", error=True)

    def remove_from_favorites(self, index):
        if self.favorites[index]:
            self.favorites[index] = None
            btn = self.favorites_grid.grid_slaves(row=index // 4, column=index % 4)[0]  # Fixed: replaced 'i' with 'index'
            btn.configure(text="Empty")
            self.save_config()
            self.show_notification(f"Removed from favorites")

if __name__ == "__main__":
    root = ctk.CTk()
    app = SlingShot(root)
    root.protocol("WM_DELETE_WINDOW", app.kill_program)
    root.mainloop()