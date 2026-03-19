import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
import logging
import time
from collections import defaultdict
import requests
import sys
import customtkinter as ctk  # pip install customtkinter
from datetime import datetime
import scapy.all as scapy
from rich.console import Console
from rich.text import Text
import subprocess

# Create queues for thread-safe communication
log_queue = queue.Queue()
detection_queue = queue.Queue()

# Custom logger that puts logs into our queue
class QueueHandler(logging.Handler):
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(record)

# Configure logging to use our custom handler
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
queue_handler = QueueHandler(log_queue)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
queue_handler.setFormatter(formatter)
logger.addHandler(queue_handler)
logger.propagate = False  # Don't propagate to parent loggers

# Rich console for formatted output
console = Console()

class AbuseIPDBDDoSDetector:
    def __init__(self, api_key, threshold=50, packet_threshold=100):
        self.api_url = "https://api.abuseipdb.com/api/v2/check"
        self.api_key = api_key
        self.threshold = threshold  # AbuseIPDB confidence score threshold
        self.packet_threshold = packet_threshold  # Number of packets before checking IP
        self.packet_rate = defaultdict(int)  # Track packet counts per source IP
        self.ip_cache = {}  # Cache IP reputation results
        self.blocked_ips = set()  # Keep track of blocked IPs
        self.running = False

    def check_ip(self, ip_address):
        # Check if IP is in cache to reduce API calls
        if ip_address in self.ip_cache:
            logger.info(f"Using cached result for {ip_address}")
            return self.ip_cache[ip_address]
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        
        params = {
            "ipAddress": ip_address
        }

        try:
            response = requests.get(self.api_url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                abuse_score = data["data"]["abuseConfidenceScore"]
                result = "suspicious" if abuse_score > self.threshold else "benign"
                
                # Cache the result for 5 minutes
                self.ip_cache[ip_address] = {
                    "result": result,
                    "score": abuse_score,
                    "timestamp": time.time()
                }
                
                logger.info(f"IP {ip_address} checked: score {abuse_score} ({result})")
                return {"result": result, "score": abuse_score}
            else:
                logger.error(f"Failed to check IP {ip_address}: {response.text}")
                return {"result": "unknown", "score": 0}
        except Exception as e:
            logger.error(f"Error checking IP {ip_address}: {e}")
            return {"result": "unknown", "score": 0}

    def mitigate_ddos(self, ip_address):
        # Check if this IP is already blocked
        if ip_address in self.blocked_ips:
            logger.info(f"IP {ip_address} is already blocked")
            return
        
        logger.warning(f"Mitigating DDoS attack by blocking IP {ip_address}...")
        
        # This is a cross-platform approach that doesn't actually execute the command
        # In a real implementation, you would execute the blocking command
        if sys.platform == "win32":
            command = f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}'
        else:
            command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        
        logger.info(f"Would execute: {command}")
        # In a real implementation with proper permissions:
        # subprocess.run(command, shell=True, check=True)
        
        # Mark IP as blocked
        self.blocked_ips.add(ip_address)
        logger.warning(f"IP {ip_address} has been virtually blocked")

    def packet_callback(self, packet):
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            self.packet_rate[ip_src] += 1
            
            # Clean up old cache entries every 100 packets
            if sum(self.packet_rate.values()) % 100 == 0:
                self._clean_cache()
            
            current_time = datetime.now().strftime("%H:%M:%S")
            
            # If packet count exceeds threshold, check if it's suspicious
            if self.packet_rate[ip_src] > self.packet_threshold:
                logger.info(f"Checking IP reputation for {ip_src} (packet count: {self.packet_rate[ip_src]})")
                ip_info = self.check_ip(ip_src)
                
                if ip_info["result"] == "suspicious":
                    logger.warning(f"Alert: DDoS detected from IP: {ip_src} (Score: {ip_info['score']})")
                    
                    # Send to UI queue
                    detection_queue.put({
                        'timestamp': current_time,
                        'src_ip': ip_src,
                        'dst_ip': ip_dst,
                        'label': "DDoS",
                        'score': ip_info['score']
                    })
                    
                    # Mitigate if score is high
                    if ip_info["score"] > 80:
                        self.mitigate_ddos(ip_src)
                else:
                    # For benign traffic that exceeded packet threshold
                    detection_queue.put({
                        'timestamp': current_time,
                        'src_ip': ip_src,
                        'dst_ip': ip_dst,
                        'label': "Benign",
                        'score': ip_info.get('score', 0)
                    })
            else:
                # For normal traffic
                if self.packet_rate[ip_src] % 10 == 0:  # Reduce UI updates
                    detection_queue.put({
                        'timestamp': current_time,
                        'src_ip': ip_src,
                        'dst_ip': ip_dst,
                        'label': "Benign",
                        'score': 0
                    })

    def _clean_cache(self):
        """Clean cached IP reputation results older than 5 minutes"""
        current_time = time.time()
        expired_keys = [
            ip for ip, data in self.ip_cache.items() 
            if current_time - data["timestamp"] > 300  # 5 minutes
        ]
        
        for key in expired_keys:
            del self.ip_cache[key]
            
        # Also reset packet rates for IPs not seen in a while
        for ip in list(self.packet_rate.keys()):
            if current_time - self.packet_rate.get(f"{ip}_last_seen", 0) > 300:
                del self.packet_rate[ip]

    def start_packet_capture(self, interface=None):
        self.running = True
        logger.info(f"Starting packet capture on interface: {interface or 'default'}")
        
        # Start actual packet capture
        try:
            filter_str = "ip"  # Capture all IP packets
            if interface:
                scapy.sniff(prn=self.packet_callback, store=0, iface=interface, 
                           filter=filter_str, stop_filter=lambda p: not self.running)
            else:
                scapy.sniff(prn=self.packet_callback, store=0, 
                           filter=filter_str, stop_filter=lambda p: not self.running)
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.running = False

    def stop_capture(self):
        logger.info("Stopping packet capture...")
        self.running = False


class AbuseIPDBDDoSDetectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Set appearance mode and default color theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.title("Aegis")
        self.geometry("1200x800")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Create main container
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=10)
        self.grid_rowconfigure(1, weight=3)
        
        # Create frames
        self.create_detection_frame()
        self.create_log_frame()
        self.create_control_frame()
        
        # Initialize variables
        self.detector = None
        self.detector_thread = None
        self.running = False
        
        # Start UI update threads
        self.after(100, self.update_ui)
        
    def create_detection_frame(self):
        # Create frame for detection table
        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(0, weight=0)  # Header
        main_frame.grid_rowconfigure(1, weight=1)  # Tree
        
        # Title
        header = ctk.CTkLabel(main_frame, text="Network Traffic Analysis", font=ctk.CTkFont(size=18, weight="bold"))
        header.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="nw")
        
        # Stats frame
        stats_frame = ctk.CTkFrame(main_frame, fg_color="#1a1a1a")
        stats_frame.grid(row=0, column=0, padx=(200, 10), pady=(10, 5), sticky="ne")
        
        self.blocked_label = ctk.CTkLabel(stats_frame, text="Blocked IPs: 0", 
                                        font=ctk.CTkFont(size=14))
        self.blocked_label.grid(row=0, column=0, padx=10, pady=5)
        
        self.packets_label = ctk.CTkLabel(stats_frame, text="Packets: 0", 
                                        font=ctk.CTkFont(size=14))
        self.packets_label.grid(row=0, column=1, padx=10, pady=5)
        
        # Create Treeview with columns
        columns = ("timestamp", "src_ip", "dst_ip", "traffic_type", "score")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings")
        
        # Configure column headings
        self.tree.heading("timestamp", text="Time")
        self.tree.heading("src_ip", text="Source IP")
        self.tree.heading("dst_ip", text="Destination IP")
        self.tree.heading("traffic_type", text="Traffic Type")
        self.tree.heading("score", text="Abuse Score")
        
        # Configure column widths
        self.tree.column("timestamp", width=100)
        self.tree.column("src_ip", width=150)
        self.tree.column("dst_ip", width=150)
        self.tree.column("traffic_type", width=100)
        self.tree.column("score", width=100)
        
        # Create custom ttk style for the treeview
        style = ttk.Style()
        style.configure("Treeview", background="#2a2d2e", foreground="white", fieldbackground="#2a2d2e", rowheight=25)
        style.configure("Treeview.Heading", background="#1f6aa5", foreground="black", relief="flat")
        style.map("Treeview", background=[("selected", "#1f6aa5")])
        
        # Create a Scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Place the treeview and scrollbar
        self.tree.grid(row=1, column=0, padx=(10, 0), pady=5, sticky="nsew")
        scrollbar.grid(row=1, column=1, padx=(0, 10), pady=5, sticky="ns")
        
        # Configure tag colors for different traffic types
        self.tree.tag_configure("DDoS", background="#ff5252", foreground="white")
        self.tree.tag_configure("Benign", background="#2a2d2e", foreground="white")
        
    def create_log_frame(self):
        # Create frame for logs
        log_frame = ctk.CTkFrame(self)
        log_frame.grid(row=1, column=0, padx=10, pady=(5, 10), sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=0)  # Header
        log_frame.grid_rowconfigure(1, weight=1)  # Text
        
        # Log title
        log_header = ctk.CTkLabel(log_frame, text="System Logs", font=ctk.CTkFont(size=16, weight="bold"))
        log_header.grid(row=0, column=0, padx=10, pady=5, sticky="nw")
        
        # Create log text area with custom colors
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=("Consolas", 10),
                                                 bg="#2a2d2e", fg="#ffffff", insertbackground="white")
        self.log_text.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.log_text.config(state=tk.DISABLED)
        
        # Configure tag colors for different log levels
        self.log_text.tag_configure("INFO", foreground="#8bc34a")
        self.log_text.tag_configure("WARNING", foreground="#ffc107")
        self.log_text.tag_configure("ERROR", foreground="#ff5252")
        self.log_text.tag_configure("CRITICAL", foreground="red", underline=1)
        
    def create_control_frame(self):
        # Create a horizontal frame at the bottom for controls
        control_frame = ctk.CTkFrame(self)
        control_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        
        # Configure the grid
        for i in range(6):
            control_frame.grid_columnconfigure(i, weight=1)
            
        # Interface selection
        self.interface_var = tk.StringVar(value="Wi-Fi")
        interface_label = ctk.CTkLabel(control_frame, text="Network Interface:")
        interface_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
        
        interface_combo = ctk.CTkComboBox(control_frame, values=["Wi-Fi", "Ethernet", "en0", "eth0"], 
                                          variable=self.interface_var, width=120)
        interface_combo.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        
        # AbuseIPDB Threshold slider
        threshold_label = ctk.CTkLabel(control_frame, text="Abuse Score Threshold:")
        threshold_label.grid(row=0, column=2, padx=10, pady=10, sticky="e")
        
        self.threshold_var = tk.IntVar(value=50)
        threshold_slider = ctk.CTkSlider(control_frame, from_=10, to=90, number_of_steps=8,
                                        variable=self.threshold_var, width=120)
        threshold_slider.grid(row=0, column=3, padx=10, pady=10, sticky="w")
        
        self.threshold_value_label = ctk.CTkLabel(control_frame, text="50")
        self.threshold_value_label.grid(row=0, column=3, padx=(140, 0), pady=10, sticky="w")
        
        # Update threshold label when slider changes
        def update_threshold_label(event=None):
            self.threshold_value_label.configure(text=f"{self.threshold_var.get()}")
        
        threshold_slider.bind("<ButtonRelease-1>", update_threshold_label)
        
        # Packet threshold slider
        packet_label = ctk.CTkLabel(control_frame, text="Packet Threshold:")
        packet_label.grid(row=0, column=4, padx=10, pady=10, sticky="e")
        
        self.packet_var = tk.IntVar(value=100)
        packet_slider = ctk.CTkSlider(control_frame, from_=20, to=200, number_of_steps=9,
                                     variable=self.packet_var, width=120)
        packet_slider.grid(row=0, column=5, padx=10, pady=10, sticky="w")
        
        self.packet_value_label = ctk.CTkLabel(control_frame, text="100")
        self.packet_value_label.grid(row=0, column=5, padx=(140, 0), pady=10, sticky="w")
        
        # Update packet threshold label when slider changes
        def update_packet_label(event=None):
            self.packet_value_label.configure(text=f"{self.packet_var.get()}")
        
        packet_slider.bind("<ButtonRelease-1>", update_packet_label)
        
        # API Key entry
        #api_label = ctk.CTkLabel(control_frame, text="AbuseIPDB API Key:")
        #api_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
        
        self.api_key_var = tk.StringVar(value="4a27af00b3b7d1cddb2e8e5c91af8a5c583123e12fba42957c011fcb692fc341e544eb7219e8c77d")
        #api_entry = ctk.CTkEntry(control_frame, textvariable=self.api_key_var, width=300)
        #api_entry.grid(row=1, column=1, columnspan=3, padx=10, pady=10, sticky="w")
        
        # Start/Stop button
        self.start_button = ctk.CTkButton(control_frame, text="Start Monitoring", 
                                        command=self.toggle_monitoring,
                                        fg_color="#2196f3", hover_color="#1976d2")
        self.start_button.grid(row=1, column=4, columnspan=2, padx=10, pady=10)
        
        # Status indicator
        self.status_label = ctk.CTkLabel(control_frame, text="● Stopped", text_color="#ff5252")
        self.status_label.grid(row=1, column=5, padx=(0, 50), pady=10, sticky="e")
    
    def toggle_monitoring(self):
        if not self.running:
            # Start monitoring
            self.start_monitoring()
            self.start_button.configure(text="Stop Monitoring", fg_color="#f44336", hover_color="#d32f2f")
            self.status_label.configure(text="● Running", text_color="#8bc34a")
        else:
            # Stop monitoring
            self.stop_monitoring()
            self.start_button.configure(text="Start Monitoring", fg_color="#2196f3", hover_color="#1976d2")
            self.status_label.configure(text="● Stopped", text_color="#ff5252")
    
    def start_monitoring(self):
        interface = self.interface_var.get()
        api_key = self.api_key_var.get()
        threshold = self.threshold_var.get()
        packet_threshold = self.packet_var.get()
        
        try:
            self.detector = AbuseIPDBDDoSDetector(
                api_key=api_key,
                threshold=threshold,
                packet_threshold=packet_threshold
            )
            self.detector_thread = threading.Thread(
                target=self.detector.start_packet_capture, 
                kwargs={"interface": interface}
            )
            self.detector_thread.daemon = True
            self.detector_thread.start()
            self.running = True
            logger.info(f"Started monitoring on {interface} with abuse score threshold {threshold}")
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            self.status_label.configure(text="● Error", text_color="#ff5252")
            
    def stop_monitoring(self):
        if self.detector:
            self.detector.stop_capture()
            self.running = False
            logger.info("Stopped monitoring")
            
    def update_ui(self):
        self.process_log_queue()
        self.process_detection_queue()
        
        # Update stats if detector is running
        if self.detector and self.running:
            blocked_count = len(self.detector.blocked_ips)
            self.blocked_label.configure(text=f"Blocked IPs: {blocked_count}")
            
            packet_count = sum(self.detector.packet_rate.values())
            self.packets_label.configure(text=f"Packets: {packet_count}")
        
        self.after(100, self.update_ui)
        
    def process_log_queue(self):
        while not log_queue.empty():
            record = log_queue.get()
            self.display_log(record)
            
    def display_log(self, record):
        level_tag = record.levelname
        log_time = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        log_message = f"[{log_time}] {record.levelname}: {record.getMessage()}\n"
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_message, level_tag)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
    def process_detection_queue(self):
        while not detection_queue.empty():
            detection = detection_queue.get()
            self.add_detection_to_tree(detection)
            
    def add_detection_to_tree(self, detection):
        # Insert new item at the top of the tree
        item_id = self.tree.insert("", 0, values=(
            detection['timestamp'],
            detection['src_ip'],
            detection['dst_ip'],
            detection['label'],
            f"{detection['score']}"
        ))
        
        # Apply tag based on label
        self.tree.item(item_id, tags=(detection['label'],))
        
        # Keep only the last 100 items to avoid performance issues
        if len(self.tree.get_children()) > 100:
            last_item = self.tree.get_children()[-1]
            self.tree.delete(last_item)
        
    def on_closing(self):
        self.stop_monitoring()
        self.destroy()
        sys.exit(0)


if __name__ == "__main__":
    app = AbuseIPDBDDoSDetectorApp()
    app.mainloop()