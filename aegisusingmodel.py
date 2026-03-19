import tkinter as tk
from tkinter import ttk, scrolledtext, font
import threading
import queue
import logging
import numpy as np
import joblib
import time
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
from tensorflow.keras.models import load_model
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from datetime import datetime
import sys
import customtkinter as ctk  # You'll need to pip install customtkinter

# Create a queue for thread-safe communication
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


class DDoSDetector:
    def __init__(self, threshold=0.7, detection_window=10):
        self.threshold = threshold
        self.detection_window = detection_window
        self.running = False
        self.packet_stats = {}
        self.last_cleanup = time.time()

        try:
            self.xgb_model = joblib.load("xgb_model.pkl")
            self.meta_model = joblib.load("meta_model.pkl")
            self.mlp_model = load_model("mlp_model.h5")
            self.preprocessor = joblib.load("preprocessor.pkl")
            logger.info("All models and preprocessor loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading models or preprocessor: {e}")
            raise RuntimeError("Failed to load models or preprocessor.")

    def _extract_features(self, packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_size = len(packet)
                protocol = packet[IP].proto

                if src_ip not in self.packet_stats:
                    self.packet_stats[src_ip] = {"count": 0, "last_seen": time.time(), "sizes": []}

                self.packet_stats[src_ip]["count"] += 1
                self.packet_stats[src_ip]["last_seen"] = time.time()
                self.packet_stats[src_ip]["sizes"].append(packet_size)

                ttl = packet[IP].ttl if hasattr(packet[IP], "ttl") else 0
                flags = packet.sprintf("%TCP.flags%") if TCP in packet else "None"
                src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
                dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)

                flag_values = {"S": 1, "A": 2, "F": 3, "R": 4, "P": 5, "U": 6, "E": 7, "C": 8, "None": 0}
                flag_numeric = flag_values.get(flags, 0)

                ip_stats = self.packet_stats[src_ip]
                current_time = time.time()
                time_window = current_time - ip_stats["last_seen"] + 0.001
                packets_per_second = ip_stats["count"] / time_window if time_window > 0 else 0

                avg_packet_size = sum(ip_stats["sizes"]) / len(ip_stats["sizes"])
                std_packet_size = np.std(ip_stats["sizes"]) if len(ip_stats["sizes"]) > 1 else 0

                features = {
                    'ip.src': src_ip,
                    'ip.dst': dst_ip,
                    'ip.len': float(packet_size),
                    'ip.ttl': float(ttl),
                    'tcp.srcport': float(src_port),
                    'tcp.dstport': float(dst_port),
                    'protocol': float(protocol),
                    'tcp_flags': float(flag_numeric),
                    'packets_per_second': float(packets_per_second),
                    'avg_packet_size': float(avg_packet_size),
                    'std_packet_size': float(std_packet_size),
                    'Rx Bytes': float(packet[IP].len) if IP in packet else 0.0,
                    'Tx Bytes': float(packet[IP].len) if IP in packet else 0.0,
                    'Rx Packets': 1.0,
                    'Tx Packets': 1.0,
                    'frame.len': float(len(packet)),
                    'Packets': float(ip_stats["count"]),
                    'Bytes': float(len(packet)),
                    'tcp.flags.push': float(packet[TCP].flags.P) if TCP in packet else 0.0,
                    'ip.flags.df': float(packet[IP].flags.DF) if IP in packet else 0.0
                }

                return features, src_ip, dst_ip
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
        return None, None, None

    def _predict_ddos(self, features):
        try:
            df = pd.DataFrame([features])
            expected = set(self.preprocessor.feature_names_in_)
            actual = set(df.columns)
            missing_cols = expected - actual

            if missing_cols:
                logger.error(f"Missing columns: {missing_cols}")
                raise ValueError("Missing expected columns")

            X = self.preprocessor.transform(df)
            xgb_pred = self.xgb_model.predict_proba(X)
            mlp_pred = self.mlp_model.predict(X)
            stacked_input = np.hstack((xgb_pred, mlp_pred))
            final_pred_proba = self.meta_model.predict_proba(stacked_input)[:, 1]

            logger.info(f"Hybrid Model Probability: {final_pred_proba[0]:.4f}")
            return ("DDoS" if final_pred_proba[0] >= self.threshold else "Benign", float(final_pred_proba[0]))

        except Exception as e:
            logger.warning(f"Fallback prediction used: {e}")
            fallback_features = {
                'ip.len': features.get('ip.len', 0.0),
                'packets_per_second': features.get('packets_per_second', 0.0),
                'avg_packet_size': features.get('avg_packet_size', 0.0),
                'tcp_flags': features.get('tcp_flags', 0.0),
                'protocol': features.get('protocol', 0.0)
            }
            return "Benign", 0.1

    def _cleanup_old_stats(self):
        current_time = time.time()
        if current_time - self.last_cleanup > 60:
            self.packet_stats = {
                ip: stats for ip, stats in self.packet_stats.items()
                if current_time - stats["last_seen"] < 300
            }
            self.last_cleanup = current_time

    def _process_packet(self, packet):
        try:
            features, src_ip, dst_ip = self._extract_features(packet)
            if features:
                self._cleanup_old_stats()
                current_time = time.time()

                if (self.packet_stats[src_ip]["count"] % 10 == 0) or \
                   (current_time - self.packet_stats[src_ip].get("last_analyzed", 0) > 5):
                    self.packet_stats[src_ip]["last_analyzed"] = current_time
                    label, probability = self._predict_ddos(features)

                    # Add to detection queue for UI
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    detection_queue.put({
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'label': label,
                        'probability': probability
                    })

                    if label == "DDoS" and probability > self.threshold:
                        logger.warning(f"DDoS Detected! Probability: {probability:.2f} | Src IP: {src_ip} | Dst IP: {dst_ip}")
                    else:
                        logger.info(f"Packet from {src_ip} to {dst_ip}: {label} | Probability: {probability:.2f}")
        except Exception as e:
            logger.error(f"Error in packet processing: {e}")

    def _stop_filter(self, packet):
        return not self.running

    def start_monitoring(self, interface="Wi-Fi"):
        self.running = True
        logger.info(f"Starting real-time DDoS detection on {interface}...")
        try:
            sniff(iface=interface, prn=self._process_packet, store=False, stop_filter=self._stop_filter)
        except Exception as e:
            logger.error(f"Packet sniffing error: {e}")
            self.running = False

    def stop_monitoring(self):
        self.running = False
        logger.info("Stopping DDoS detection.")


class DDoSDetectorApp(ctk.CTk):
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
        
        # Create Treeview with columns
        columns = ("timestamp", "src_ip", "dst_ip", "traffic_type", "probability")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings")
        
        # Configure column headings
        self.tree.heading("timestamp", text="Time")
        self.tree.heading("src_ip", text="Source IP")
        self.tree.heading("dst_ip", text="Destination IP")
        self.tree.heading("traffic_type", text="Traffic Type")
        self.tree.heading("probability", text="Confidence")
        
        # Configure column widths
        self.tree.column("timestamp", width=100)
        self.tree.column("src_ip", width=150)
        self.tree.column("dst_ip", width=150)
        self.tree.column("traffic_type", width=100)
        self.tree.column("probability", width=100)
        
        # Create custom ttk style for the treeview
        style = ttk.Style()
        style.configure("Treeview", background="#2a2d2e", foreground="white", fieldbackground="#2a2d2e", rowheight=25)
        style.configure("Treeview.Heading", background="000000", foreground="black", relief="flat")
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
        
        # Threshold slider
        threshold_label = ctk.CTkLabel(control_frame, text="Detection Threshold:")
        threshold_label.grid(row=0, column=2, padx=10, pady=10, sticky="e")
        
        self.threshold_var = tk.DoubleVar(value=0.7)
        threshold_slider = ctk.CTkSlider(control_frame, from_=0.1, to=0.9, number_of_steps=8,
                                        variable=self.threshold_var, width=120)
        threshold_slider.grid(row=0, column=3, padx=10, pady=10, sticky="w")
        
        self.threshold_value_label = ctk.CTkLabel(control_frame, text="0.7")
        self.threshold_value_label.grid(row=0, column=3, padx=(140, 0), pady=10, sticky="w")
        
        # Update threshold label when slider changes
        def update_threshold_label(event=None):
            self.threshold_value_label.configure(text=f"{self.threshold_var.get():.1f}")
        
        threshold_slider.bind("<ButtonRelease-1>", update_threshold_label)
        
        # Start/Stop button
        self.start_button = ctk.CTkButton(control_frame, text="Start Monitoring", 
                                        command=self.toggle_monitoring,
                                        fg_color="#2196f3", hover_color="#1976d2")
        self.start_button.grid(row=1, column=4,columnspan=2, padx=10, pady=10)
        
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
        threshold = self.threshold_var.get()
        
        try:
            self.detector = DDoSDetector(threshold=threshold, detection_window=10)
            self.detector_thread = threading.Thread(target=self.detector.start_monitoring, 
                                                   kwargs={"interface": interface})
            self.detector_thread.daemon = True
            self.detector_thread.start()
            self.running = True
            logger.info(f"Started monitoring on {interface} with threshold {threshold}")
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            self.status_label.configure(text="● Error", text_color="#ff5252")
            
    def stop_monitoring(self):
        if self.detector:
            self.detector.stop_monitoring()
            self.running = False
            logger.info("Stopped monitoring")
            
    def update_ui(self):
        self.process_log_queue()
        self.process_detection_queue()
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
        # Format probability as percentage
        prob_str = f"{detection['probability']*100:.1f}%"
        
        # Insert new item at the top of the tree
        item_id = self.tree.insert("", 0, values=(
            detection['timestamp'],
            detection['src_ip'],
            detection['dst_ip'],
            detection['label'],
            prob_str
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
    app = DDoSDetectorApp()
    app.mainloop()