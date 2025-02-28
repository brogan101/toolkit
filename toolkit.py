import sys
import os
import json
import subprocess
import logging
import platform
import psutil
import time
from typing import Dict, List, Optional
from dataclasses import dataclass
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLineEdit, QPushButton, QTextEdit, QTabWidget, QStatusBar,
                             QMessageBox, QComboBox, QLabel, QScrollArea, QCheckBox, QFileDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QRect
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QClipboard
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import numpy as np
import asyncio

# Set up logging manually with file and console handlers
logger = logging.getLogger('ToolkitApp')
logger.setLevel(logging.DEBUG)

# File handler for toolkit.log
file_handler = logging.FileHandler('toolkit.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Console handler for stdout (for live log window)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

@dataclass
class Tool:
    command: str
    description: str

# Check and request admin privileges
def is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception as e:
        logging.error(f"Error checking admin status: {str(e)}")
        return False

def request_admin() -> None:
    if not is_admin():
        logging.info("Requesting admin privileges...")
        try:
            script_path = os.path.abspath(sys.argv[0])
            if platform.system() == "Windows":
                import ctypes
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}"', None, 1)
                logging.info(f"Windows elevation requested for {script_path}")
                sys.exit(0)
            else:
                subprocess.run(["sudo", sys.executable, script_path], check=False)
                logging.info(f"Unix elevation requested for {script_path}")
                sys.exit(0)
        except Exception as e:
            logging.error(f"Failed to request admin privileges: {str(e)}")
            QMessageBox.critical(None, "Error", f"Failed to elevate privileges: {str(e)}")
            sys.exit(1)

# Tool execution thread
class ToolThread(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()  # Signal for when the thread finishes
    def __init__(self, command: str):
        super().__init__()
        self.command = command
        self.is_running = True
    def run(self) -> None:
        try:
            # Check if tool is installed
            if not self._is_tool_installed(self.command.split()[0]):
                self.output_signal.emit(f"Error: Tool '{self.command.split()[0]}' is not installed. Install it manually or use 'pip'/'apt'/'yum'.")
                logging.warning(f"Tool not found: {self.command.split()[0]}")
                self.finished_signal.emit()
                return
            result = subprocess.run(self.command, shell=True, capture_output=True, text=True, timeout=30)
            if self.is_running:  # Only emit if not killed
                self.output_signal.emit(result.stdout + result.stderr)
            self.finished_signal.emit()
        except Exception as e:
            if self.is_running:  # Only emit if not killed
                self.output_signal.emit(f"Error executing command: {str(e)}")
            logging.error(f"Tool execution failed: {str(e)}")
            self.finished_signal.emit()

    def _is_tool_installed(self, tool: str) -> bool:
        try:
            subprocess.run(['which', tool] if platform.system() != "Windows" else ['where', tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    def kill(self) -> None:
        self.is_running = False
        self.terminate()

# Live monitoring thread
class MonitorThread(QThread):
    update_signal = pyqtSignal(dict)
    def run(self) -> None:
        try:
            while True:
                cpu = psutil.cpu_percent()
                memory = psutil.virtual_memory().percent
                disk = psutil.disk_usage('/').percent
                network_io = psutil.net_io_counters()
                network = (network_io.bytes_sent + network_io.bytes_recv) / 1024 / 1024  # Convert to MB
                self.update_signal.emit({"cpu": cpu, "memory": memory, "disk": disk, "network": network})
                time.sleep(1)
        except Exception as e:
            logging.error(f"Monitor thread failed: {str(e)}")

# Main application window
class ToolkitApp(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        logging.info("Initializing ToolkitApp (post-elevation)")
        self.setWindowTitle("Advanced Cybersecurity & IT Toolkit v1.0")
        self.setGeometry(100, 100, 1400, 900)
        self.setWindowIcon(QIcon('icon.png'))  # Add an icon file (optional)
        self.favorites: set = set()
        self.tools: Dict[str, Dict[str, Tool]] = {}
        self.load_tools()
        self.current_thread = None  # Track the current running tool thread
        self.init_ui()
        self.statusBar().showMessage(f"Toolkit Ready | Admin Mode: {'Yes' if is_admin() else 'No'}")

        # Start live monitoring
        self.monitor_thread = MonitorThread()
        self.monitor_thread.update_signal.connect(self.update_monitor_and_graph)
        self.monitor_thread.start()

        # Timer for graph updates
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_monitor_and_graph)
        self.timer.start(1000)  # Update every second

        # Initialize data for live graph
        self.cpu_data = []
        self.memory_data = []
        self.disk_data = []
        self.network_data = []  # New for network traffic

    def load_tools(self) -> None:
        try:
            if not os.path.exists('tools_config.json'):
                raise FileNotFoundError("tools_config.json not found")
            with open('tools_config.json', 'r') as f:
                self.tools = {cat: {name: Tool(**info) for name, info in tools.items()} for cat, tools in json.load(f).items()}
            logging.info("Tools configuration loaded successfully")
        except Exception as e:
            logging.error(f"Error loading tools: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to load tools: {str(e)}")
            sys.exit(1)

    def init_ui(self) -> None:
        # Define themes with distinct, modern colors
        self.themes = {
            "Dark": """
                QMainWindow { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1e1e2f, stop:1 #2c2c3f); color: #ffffff; }
                QLineEdit, QComboBox, QPushButton, QTextEdit, QLabel { background: #3c3c5c; color: #ffffff; border: 1px solid #5c5c7f; border-radius: 6px; padding: 4px; }
                QPushButton { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3c3c5c, stop:1 #5c5c7f); }
                QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #5c5c7f, stop:1 #7c7ca0); }
                QTabWidget::pane { border: 1px solid #5c5c7f; background: #2c2c3f; border-radius: 6px; }
                QTabBar::tab { background: #3c3c5c; color: #ffffff; padding: 8px; border-radius: 4px; margin-right: 2px; }
                QTabBar::tab:selected { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #5c5c7f, stop:1 #7c7ca0); }
                QStatusBar { background: #1e1e2f; color: #ffffff; border-top: 1px solid #5c5c7f; }
                QScrollArea { background: #2c2c3f; border: 1px solid #5c5c7f; border-radius: 6px; }
            """,
            "Light": """
                QMainWindow { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f5f5ff, stop:1 #e5e5f5); color: #000000; }
                QLineEdit, QComboBox, QPushButton, QTextEdit, QLabel { background: #ffffff; color: #000000; border: 1px solid #a0a0d0; border-radius: 6px; padding: 4px; }
                QPushButton { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #e5e5f5, stop:1 #d5d5e5); }
                QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #d5d5e5, stop:1 #c5c5d5); }
                QTabWidget::pane { border: 1px solid #a0a0d0; background: #e5e5f5; border-radius: 6px; }
                QTabBar::tab { background: #ffffff; color: #000000; padding: 8px; border-radius: 4px; margin-right: 2px; }
                QTabBar::tab:selected { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #d5d5e5, stop:1 #c5c5d5); }
                QStatusBar { background: #f5f5ff; color: #000000; border-top: 1px solid #a0a0d0; }
                QScrollArea { background: #e5e5f5; border: 1px solid #a0a0d0; border-radius: 6px; }
            """
        }
        self.current_theme = "Dark"
        self.setStyleSheet(self.themes[self.current_theme])

        # Main layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Top bar with search, dropdown, theme toggle, and info
        top_bar = QWidget()
        top_layout = QHBoxLayout(top_bar)
        
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search tools...")
        self.search_bar.textChanged.connect(self.update_search_dropdown)
        top_layout.addWidget(self.search_bar)

        self.search_dropdown = QComboBox()
        self.search_dropdown.setFixedWidth(250)
        self.search_dropdown.currentTextChanged.connect(self.select_from_dropdown)
        top_layout.addWidget(self.search_dropdown)

        self.theme_toggle = QCheckBox("Switch to Light Theme")
        self.theme_toggle.stateChanged.connect(self.toggle_theme)
        top_layout.addWidget(self.theme_toggle)

        self.info_button = QPushButton("About")
        self.info_button.clicked.connect(self.show_about)
        self.info_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3c3c5c, stop:1 #5c5c7f);" if self.current_theme == "Dark" else "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #e5e5f5, stop:1 #d5d5e5);")
        top_layout.addWidget(self.info_button)
        layout.addWidget(top_bar)

        # Split layout for tools, monitors/terminals, and logs
        split_layout = QHBoxLayout()
        
        # Left panel (tools with tabs)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Tool tabs for categories
        self.tool_tabs = QTabWidget()
        self.tool_buttons: Dict[str, List[QPushButton]] = {}  # Reinitialize tool_buttons
        for category in sorted(self.tools.keys()):
            tool_widget = QWidget()
            tool_layout = QVBoxLayout(tool_widget)
            
            scroll_area = QScrollArea()
            scroll_widget = QWidget()
            grid_layout = QGridLayout(scroll_widget)
            grid_layout.setSpacing(5)  # Reduce spacing between buttons
            
            tools = sorted(self.tools[category].keys())
            for i, tool_name in enumerate(tools):  # Define 'i' in the loop
                row = i // 5  # 5 buttons per row for better visibility
                col = i % 5   # Fit side by side, reduce cutoff
                button = QPushButton(tool_name)
                button.setFixedSize(180, 50)  # Larger buttons to prevent cutoff
                description = self.tools[category][tool_name].description
                button.setToolTip(description)  # Tooltip for description
                button.clicked.connect(lambda checked, c=category, t=tool_name: self.run_tool(c, t))
                grid_layout.addWidget(button, row, col)
                if category not in self.tool_buttons:
                    self.tool_buttons[category] = []
                self.tool_buttons[category].append(button)
                # Add description label (optional, hidden by default, show on hover if needed)
                desc_label = QLabel(f"<small>{description}</small>")
                desc_label.setStyleSheet("color: #a0c0ff; margin: 2px 0;" if self.current_theme == "Dark" else "color: #0000a0; margin: 2px 0;")
                desc_label.setVisible(False)  # Hidden by default
                grid_layout.addWidget(desc_label, row, col, 1, 1, Qt.AlignBottom)
            scroll_widget.setLayout(grid_layout)
            scroll_area.setWidget(scroll_widget)
            scroll_area.setWidgetResizable(True)
            tool_layout.addWidget(scroll_area)
            tool_layout.addStretch()
            tool_widget.setLayout(tool_layout)
            self.tool_tabs.addTab(tool_widget, category)
        
        left_layout.addWidget(self.tool_tabs)
        left_layout.addStretch()
        split_layout.addWidget(left_panel, 2)

        # Right panel (health, monitors, terminals, and logs)
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        # System Health Area
        self.health_label = QLabel("System Health")
        self.health_label.setStyleSheet("font-weight: bold; color: #a0c0ff; margin: 5px 0;" if self.current_theme == "Dark" else "font-weight: bold; color: #0000a0; margin: 5px 0;")
        right_layout.addWidget(self.health_label)

        self.health_output = QTextEdit()
        self.health_output.setReadOnly(True)
        self.health_output.setStyleSheet("background: #2c2c3f; color: #a0c0ff; border: 1px solid #5c5c7f; border-radius: 6px; margin: 5px 0;" if self.current_theme == "Dark" else "background: #e5e5f5; color: #000000; border: 1px solid #a0a0d0; border-radius: 6px; margin: 5px 0;")
        right_layout.addWidget(self.health_output)

        # Live Graph
        self.figure = plt.Figure(figsize=(5, 3), facecolor='#2c2c3f' if self.current_theme == "Dark" else '#e5e5f5')
        self.canvas = FigureCanvas(self.figure)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor('#2c2c3f' if self.current_theme == "Dark" else '#e5e5f5')
        self.ax.tick_params(colors='white' if self.current_theme == "Dark" else 'black')
        self.ax.set_title("System Metrics (Last 60s)", color='white' if self.current_theme == "Dark" else 'black')
        self.ax.set_xlabel("Time (s)", color='white' if self.current_theme == "Dark" else 'black')
        self.ax.set_ylabel("Usage (%) / Traffic (MB)", color='white' if self.current_theme == "Dark" else 'black')
        right_layout.addWidget(self.canvas)

        # Terminal Tabs (Command Prompt, PowerShell, Tool Output, Live Logs)
        self.terminal_tabs = QTabWidget()
        self.output_tab = QTextEdit()  # Output for tool results
        self.output_tab.setReadOnly(True)
        self.cmd_terminal = QTextEdit()
        self.cmd_terminal.setReadOnly(False)
        self.powershell_terminal = QTextEdit()
        self.powershell_terminal.setReadOnly(False)
        self.live_log = QTextEdit()  # Live log window
        self.live_log.setReadOnly(True)
        self.terminal_tabs.addTab(self.output_tab, "Tool Output")
        self.terminal_tabs.addTab(self.cmd_terminal, "Command Prompt")
        self.terminal_tabs.addTab(self.powershell_terminal, "PowerShell")
        self.terminal_tabs.addTab(self.live_log, "Live Logs")
        right_layout.addWidget(self.terminal_tabs)

        # Buttons for terminal interaction, kill task, kill program, and export logs
        button_layout = QHBoxLayout()
        self.cmd_run_button = QPushButton("Run CMD Command")
        self.cmd_run_button.clicked.connect(lambda: self.run_terminal_command(self.cmd_terminal, "cmd.exe /c " if platform.system() == "Windows" else "bash -c "))
        button_layout.addWidget(self.cmd_run_button)

        self.ps_run_button = QPushButton("Run PowerShell Command")
        self.ps_run_button.clicked.connect(lambda: self.run_terminal_command(self.powershell_terminal, "powershell -Command " if platform.system() == "Windows" else "bash -c "))
        button_layout.addWidget(self.ps_run_button)

        self.kill_task_button = QPushButton("Kill Running Task")
        self.kill_task_button.clicked.connect(self.kill_current_tool)
        button_layout.addWidget(self.kill_task_button)

        self.kill_program_button = QPushButton("Kill Program")
        self.kill_program_button.clicked.connect(self.close)
        button_layout.addWidget(self.kill_program_button)

        self.export_logs_button = QPushButton("Export Logs")
        self.export_logs_button.clicked.connect(self.export_logs)
        button_layout.addWidget(self.export_logs_button)

        right_layout.addLayout(button_layout)

        split_layout.addWidget(right_panel, 1)
        layout.addLayout(split_layout)

        # Status bar
        self.statusBar().showMessage(f"Toolkit Ready | Admin Mode: {'Yes' if is_admin() else 'No'}")

        # Animation for tool buttons
        self.animate_buttons()

        # Setup log handler for live log window
        self.log_handler = logging.StreamHandler()
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.log_handler.emit = lambda record: self.live_log.append(f"{self.log_handler.format(record)}")
        logger.addHandler(self.log_handler)

    def toggle_theme(self, state: int) -> None:
        self.current_theme = "Light" if state == Qt.Checked else "Dark"
        self.setStyleSheet(self.themes[self.current_theme])
        # Update styles for dynamic elements
        self.health_label.setStyleSheet("font-weight: bold; color: #a0c0ff; margin: 5px 0;" if self.current_theme == "Dark" else "font-weight: bold; color: #0000a0; margin: 5px 0;")
        self.health_output.setStyleSheet("background: #2c2c3f; color: #a0c0ff; border: 1px solid #5c5c7f; border-radius: 6px; margin: 5px 0;" if self.current_theme == "Dark" else "background: #e5e5f5; color: #000000; border: 1px solid #a0a0d0; border-radius: 6px; margin: 5px 0;")
        self.figure.set_facecolor('#2c2c3f' if self.current_theme == "Dark" else '#e5e5f5')
        self.ax.set_facecolor('#2c2c3f' if self.current_theme == "Dark" else '#e5e5f5')
        self.ax.tick_params(colors='white' if self.current_theme == "Dark" else 'black')
        self.ax.set_title("System Metrics (Last 60s)", color='white' if self.current_theme == "Dark" else 'black')
        self.ax.set_xlabel("Time (s)", color='white' if self.current_theme == "Dark" else 'black')
        self.ax.set_ylabel("Usage (%) / Traffic (MB)", color='white' if self.current_theme == "Dark" else 'black')
        self.canvas.draw()
        self.info_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3c3c5c, stop:1 #5c5c7f);" if self.current_theme == "Dark" else "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #e5e5f5, stop:1 #d5d5e5);")

    def animate_buttons(self) -> None:
        for category, buttons in self.tool_buttons.items():
            for button in buttons:
                anim = QPropertyAnimation(button, b"geometry")
                anim.setDuration(500)
                start_rect = QRect(button.x(), button.y(), button.width(), button.height())
                end_rect = QRect(button.x(), button.y() - 5, button.width(), button.height())  # Smaller bounce
                anim.setStartValue(start_rect)
                anim.setEndValue(end_rect)
                anim.setLoopCount(-1)
                anim.start()

    def update_search_dropdown(self, text: str) -> None:
        self.search_dropdown.clear()
        query = text.lower()
        matches = []
        for category, tools in self.tools.items():
            for tool_name in tools.keys():
                if query in tool_name.lower() or query in tools[tool_name].description.lower():
                    matches.append((tool_name, category))
        matches.sort(key=lambda x: x[0])  # Sort by tool name
        for i, (tool_name, category) in enumerate(matches):  # Define 'i' in the loop
            self.search_dropdown.addItem(tool_name)
            self.search_dropdown.setItemData(i, category)  # Store category as item data
        self.search_dropdown.setVisible(bool(text))

    def select_from_dropdown(self, text: str) -> None:
        if text:
            for i in range(self.search_dropdown.count()):  # Use 'i' here, properly scoped
                if self.search_dropdown.itemText(i) == text:
                    tool_name = text
                    category = self.search_dropdown.itemData(i)
                    if category:
                        self.run_tool(category, tool_name)
                        self.search_bar.clear()
                        self.search_dropdown.setVisible(False)
                        self.tool_tabs.setCurrentIndex(list(self.tools.keys()).index(category))  # Switch to the correct tab
                    break
            else:
                logging.warning(f"Tool '{text}' not found in any category")

    def run_tool(self, category: str, tool_name: str) -> None:
        if not is_admin():
            self.output_tab.append("Admin privileges required.")
            logging.warning("Tool execution attempted without admin privileges")
            return
        command = self.tools[category][tool_name].command
        self.output_tab.append(f"Running {tool_name}...")
        logging.info(f"Executing tool: {tool_name} with command: {command}")
        self.statusBar().showMessage(f"Running: {tool_name}")
        self.current_thread = ToolThread(command)
        self.current_thread.output_signal.connect(self.display_output)
        self.current_thread.finished_signal.connect(lambda: setattr(self, 'current_thread', None))
        self.current_thread.start()
        # Highlight the button
        for button in self.tool_buttons.get(category, []):
            if button.text() == tool_name:
                button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #5c5c7f, stop:1 #7c7ca0);" if self.current_theme == "Dark" else "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #d5d5e5, stop:1 #c5c5d5);")

    def update_monitor_and_graph(self) -> None:
        try:
            cpu = psutil.cpu_percent()
            memory = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            network_io = psutil.net_io_counters()
            network = (network_io.bytes_sent + network_io.bytes_recv) / 1024 / 1024  # Convert to MB

            # Update health output
            health_text = f"""
CPU Usage: {cpu:.1f}%
Memory Usage: {memory:.1f}%
Disk Usage: {disk:.1f}%
Network Traffic: {network:.2f} MB
OS: {platform.system()} {platform.release()}
Python Version: {platform.python_version()}
"""
            self.health_output.setText(health_text)

            # Update live graph
            self.cpu_data.append(cpu)
            self.memory_data.append(memory)
            self.disk_data.append(disk)
            self.network_data.append(network)
            if len(self.cpu_data) > 60:  # Keep last 60 seconds
                self.cpu_data.pop(0)
                self.memory_data.pop(0)
                self.disk_data.pop(0)
                self.network_data.pop(0)

            self.ax.clear()
            self.ax.set_facecolor('#2c2c3f' if self.current_theme == "Dark" else '#e5e5f5')
            self.ax.tick_params(colors='white' if self.current_theme == "Dark" else 'black')
            self.ax.set_title("System Metrics (Last 60s)", color='white' if self.current_theme == "Dark" else 'black')
            self.ax.set_xlabel("Time (s)", color='white' if self.current_theme == "Dark" else 'black')
            self.ax.set_ylabel("Usage (%) / Traffic (MB)", color='white' if self.current_theme == "Dark" else 'black')
            t = np.arange(len(self.cpu_data))
            self.ax.plot(t, self.cpu_data, label='CPU', color='red')
            self.ax.plot(t, self.memory_data, label='Memory', color='blue')
            self.ax.plot(t, self.disk_data, label='Disk', color='green')
            self.ax.plot(t, self.network_data, label='Network (MB)', color='purple', linestyle='--')
            self.ax.legend(loc='upper right', facecolor='#2c2c3f' if self.current_theme == "Dark" else '#e5e5f5', edgecolor='white' if self.current_theme == "Dark" else 'black', labelcolor='white' if self.current_theme == "Dark" else 'black')
            self.canvas.draw()

        except Exception as e:
            logging.error(f"Monitor/graph update failed: {str(e)}")
            self.health_output.setText(f"Error: {str(e)}")

    def run_terminal_command(self, terminal: QTextEdit, prefix: str) -> None:
        command = terminal.toPlainText().strip()
        if command:
            try:
                if platform.system() == "Windows":
                    if "powershell" in prefix.lower():
                        full_command = prefix + command
                    else:
                        full_command = prefix + command
                else:
                    full_command = prefix + command  # Use bash for Unix
                result = subprocess.run(full_command, shell=True, capture_output=True, text=True, timeout=30)
                terminal.append(f"\n> {command}\n{result.stdout}{result.stderr}")
                logging.info(f"Executed terminal command: {command}")
            except Exception as e:
                terminal.append(f"\nError: {str(e)}")
                logging.error(f"Terminal command failed: {str(e)}")

    def show_about(self) -> None:
        about_text = """
<h2>Advanced Cybersecurity & IT Toolkit</h2>
<p>Version: 1.0</p>
<p>Author: Grok 3 (xAI)</p>
<p>Description: A comprehensive toolkit for cybersecurity, IT support, and penetration testing, featuring live monitoring, advanced tools, and modern GUI.</p>
<p>Contact: support@xai.com</p>
        """
        QMessageBox.information(self, "About", about_text, QMessageBox.Ok)

    def display_output(self, text: str) -> None:
        self.output_tab.append(text)
        self.statusBar().showMessage(f"Toolkit Ready | Admin Mode: {'Yes' if is_admin() else 'No'}")

    def kill_current_tool(self) -> None:
        if self.current_thread and self.current_thread.isRunning():
            self.current_thread.kill()
            self.output_tab.append("Running task killed.")
            logging.info("Current tool thread terminated by user")
            self.statusBar().showMessage("Task Killed | Toolkit Ready | Admin Mode: {'Yes' if is_admin() else 'No'}")
            self.current_thread = None

    def export_logs(self) -> None:
        try:
            log_file = "toolkit.log"
            if not os.path.exists(log_file):
                logging.warning("Log file not found, creating new log file")
                with open(log_file, 'w') as f:
                    f.write("Initial log file created.\n")
            with open(log_file, 'r') as f:
                log_content = f.read()
            # Option to save to file or copy to clipboard
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Logs", "", "Text Files (*.txt);;All Files (*)")
            if save_path:
                with open(save_path, 'w') as f:
                    f.write(log_content)
                logging.info(f"Logs exported to {save_path}")
                QMessageBox.information(self, "Success", f"Logs exported to {save_path}")
            else:
                # Copy to clipboard as fallback
                clipboard = QApplication.clipboard()
                clipboard.setText(log_content)
                logging.info("Logs copied to clipboard")
                QMessageBox.information(self, "Success", "Logs copied to clipboard")
        except Exception as e:
            logging.error(f"Failed to export logs: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to export logs: {str(e)}")

# Run with admin privileges
if __name__ == "__main__":
    try:
        request_admin()  # Request admin privileges on startup
        app = QApplication(sys.argv)
        app.setFont(QFont("Arial", 11))
        logging.info("Creating application instance")
        window = ToolkitApp()
        logging.info("Showing window")
        window.show()
        logging.info("Application started successfully")
        sys.exit(app.exec_())
    except Exception as e:
        logging.critical(f"Application crashed: {str(e)}")
        QMessageBox.critical(None, "Critical Error", f"Application failed to start: {str(e)}")
        sys.exit(1)