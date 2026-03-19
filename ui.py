import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
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
from datetime import datetime
import sys
import customtkinter as ctk
import socket  # Missing import added
import ipaddress


# Create a queue for thread-safe communication
log_queue = queue.Queue()
detection_queue = queue.Queue()

# Custom logger that puts logs into our queue
class QueueHandler(logging.Handler):
    def _init_(self, log_queue):
        super()._init_()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(record)

# Configure logging to use our custom handler
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(_name_)
queue_handler = QueueHandler(log_queue)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
queue_handler.setFormatter(formatter)
logger.addHandler(queue_handler)
logger.propagate = False  # Don't propagate to parent loggers

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.0.108"  # Fallback IP

class DDoSDetector:
    def _init_(self, threshold=0.7, detection_window=10):
        self.TRUSTED_IPS = {
            '8.8.8.8', '8.8.4.4',          # Google DNS
            '142.250.0.0/16',              # Google services
            '104.16.0.0/13',               # Cloudflare
            '192.168.0.108',                # Local device
            '142.251.42.99'
        }
        self.threshold = threshold
        self.detection_window = detection_window
        self.running = False
        self.packet_stats = {}
        self.last_cleanup = time.time()
        self.local_ip = get_local_ip()

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
                current_time = time.time()

                if src_ip not in self.packet_stats:
                    self.packet_stats[src_ip] = {
                        "count": 0,
                        "bwd_count": 0,
                        "sizes": [],
                        "bwd_sizes": [],
                        "iat": [],
                        "fwd_iat": [],
                        "first_seen": current_time,
                        "last_seen": current_time
                    }

                ip_stats = self.packet_stats[src_ip]
                
                if dst_ip == self.local_ip:
                    ip_stats["bwd_count"] += 1
                    ip_stats["bwd_sizes"].append(packet_size)
                else:
                    ip_stats["count"] += 1
                    ip_stats["sizes"].append(packet_size)

                if ip_stats["last_seen"]:
                    iat = current_time - ip_stats["last_seen"]
                    ip_stats["iat"].append(iat)
                    if dst_ip != self.local_ip:
                        ip_stats["fwd_iat"].append(iat)
                ip_stats["last_seen"] = current_time

                features = {
                    'Flow Duration': max(0.0, float(current_time - ip_stats["first_seen"])),
                    'Tot Fwd Pkts': float(ip_stats["count"]),
                    'Tot Bwd Pkts': float(ip_stats["bwd_count"]),
                    'Fwd Pkt Len Max': float(max(ip_stats["sizes"])) if ip_stats["sizes"] else 0.0,
                    'Bwd Pkt Len Max': float(max(ip_stats["bwd_sizes"])) if ip_stats["bwd_sizes"] else 0.0,
                    'Flow IAT Mean': float(np.mean(ip_stats["iat"])) if ip_stats["iat"] else 0.0,
                    'Fwd IAT Mean': float(np.mean(ip_stats["fwd_iat"])) if ip_stats["fwd_iat"] else 0.0,
                    'Pkt Size Avg': float(np.mean(ip_stats["sizes"] + ip_stats["bwd_sizes"])) if (ip_stats["sizes"] or ip_stats["bwd_sizes"]) else 0.0,
                    'Init Fwd Win Byts': float(packet[TCP].window) if TCP in packet else -1.0,
                    'Init Bwd Win Byts': -1.0
                }
                return features, src_ip, dst_ip
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
        return None, None, None

    def _predict_ddos(self, features):
        try:
            if features['Init Fwd Win Byts'] < -1 or features['Init Bwd Win Byts'] < -1:
                logger.warning("Invalid window bytes detected, using fallback")
                return "Benign", 0.1
                
            df = pd.DataFrame([features])
            X = self.preprocessor.transform(df)
            
            xgb_pred = self.xgb_model.predict_proba(X)[:, 1]
            mlp_pred = self.mlp_model.predict(X).flatten()
            stacked_input = np.column_stack((xgb_pred, mlp_pred))
            
            final_pred_proba = self.meta_model.predict_proba(stacked_input)[:, 1]
            return ("DDoS" if final_pred_proba[0] >= self.threshold else "Benign", float(final_pred_proba[0]))

        except Exception as e:
            logger.warning(f"Fallback prediction used: {str(e)}")
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
        def is_valid_ip(ip):
            try:
                ipaddress.ip_address(ip)
                return True
            except ValueError:
                return False
        try:
            features, src_ip, dst_ip = self._extract_features(packet)
            
            # Add these validation checks
            if src_ip is None or dst_ip is None:
                return
            if src_ip in self.packet_stats and self.packet_stats[src_ip]["count"] > 1000:
                logger.warning(f"Rate limit exceeded for {src_ip}")
                return
            if not (is_valid_ip(src_ip) and is_valid_ip(dst_ip)):
                return
                
            if any(ipaddress.ip_address(src_ip) in ipaddress.ip_network(cidr) 
                for cidr in self.TRUSTED_IPS):
                return
                
            if features:
                self._cleanup_old_stats()
                current_time = time.time()

                if (src_ip not in self.packet_stats or 
                    self.packet_stats[src_ip]["count"] % 10 == 0 or 
                    (current_time - self.packet_stats[src_ip].get("last_analyzed", 0) > 5)):
                    
                    if src_ip in self.packet_stats:
                        self.packet_stats[src_ip]["last_analyzed"] = current_time
                        
                    label, probability = self._predict_ddos(features)

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
            logger.error(f"Error in packet processing: {str(e)}")
    def _stop_filter(self, packet):
        return not self.running

    def start_monitoring(self, interface="Wi-Fi"):
        self.running = True
        logger.info(f"Starting real-time DDoS detection on {interface}...")
        try:
            sniff(iface=interface, prn=self._process_packet, store=False, stop_filter=self._stop_filter,filter="ip or ip6")
        except Exception as e:
            logger.error(f"Packet sniffing error: {e}")
            self.running = False

    def stop_monitoring(self):
        self.running = False
        logger.info("Stopping DDoS detection.")

class DDoSDetectorApp(ctk.CTk):
    def _init_(self):
        super()._init_()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title("Aegis")
        self.geometry("1200x800")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=10)
        self.grid_rowconfigure(1, weight=3)
        
        self.create_detection_frame()
        self.create_log_frame()
        self.create_control_frame()
        
        self.detector = None
        self.detector_thread = None
        self.running = False
        
        self.after(100, self.update_ui)
        
    def create_detection_frame(self):
        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(0, weight=0)
        main_frame.grid_rowconfigure(1, weight=1)
        
        header = ctk.CTkLabel(main_frame, text="Network Traffic Analysis", font=ctk.CTkFont(size=18, weight="bold"))
        header.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="nw")
        
        columns = ("timestamp", "src_ip", "dst_ip", "traffic_type", "probability")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings")
        
        self.tree.heading("timestamp", text="Time")
        self.tree.heading("src_ip", text="Source IP")
        self.tree.heading("dst_ip", text="Destination IP")
        self.tree.heading("traffic_type", text="Traffic Type")
        self.tree.heading("probability", text="Confidence")
        
        self.tree.column("timestamp", width=100)
        self.tree.column("src_ip", width=150)
        self.tree.column("dst_ip", width=150)
        self.tree.column("traffic_type", width=100)
        self.tree.column("probability", width=100)
        
        style = ttk.Style()
        style.configure("Treeview", background="#2a2d2e", foreground="white", fieldbackground="#2a2d2e", rowheight=25)
        style.configure("Treeview.Heading", background="000000", foreground="black", relief="flat")
        style.map("Treeview", background=[("selected", "#1f6aa5")])
        
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=1, column=0, padx=(10, 0), pady=5, sticky="nsew")
        scrollbar.grid(row=1, column=1, padx=(0, 10), pady=5, sticky="ns")
        
        self.tree.tag_configure("DDoS", background="#ff5252", foreground="white")
        self.tree.tag_configure("Benign", background="#2a2d2e", foreground="white")
        
    def create_log_frame(self):
        log_frame = ctk.CTkFrame(self)
        log_frame.grid(row=1, column=0, padx=10, pady=(5, 10), sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=0)
        log_frame.grid_rowconfigure(1, weight=1)
        
        log_header = ctk.CTkLabel(log_frame, text="System Logs", font=ctk.CTkFont(size=16, weight="bold"))
        log_header.grid(row=0, column=0, padx=10, pady=5, sticky="nw")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=("Consolas", 10),
                                                 bg="#2a2d2e", fg="#ffffff", insertbackground="white")
        self.log_text.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.log_text.config(state=tk.DISABLED)
        
        self.log_text.tag_configure("INFO", foreground="#8bc34a")
        self.log_text.tag_configure("WARNING", foreground="#ffc107")
        self.log_text.tag_configure("ERROR", foreground="#ff5252")
        self.log_text.tag_configure("CRITICAL", foreground="red", underline=1)
        
    def create_control_frame(self):
        control_frame = ctk.CTkFrame(self)
        control_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        
        for i in range(5):
            control_frame.grid_columnconfigure(i, weight=1)
            
        self.interface_var = tk.StringVar(value="Wi-Fi")
        interface_label = ctk.CTkLabel(control_frame, text="Network Interface:")
        interface_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
        
        interface_combo = ctk.CTkComboBox(control_frame, values=["Wi-Fi", "Ethernet", "en0", "eth0"], 
                                          variable=self.interface_var, width=120)
        interface_combo.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        
        threshold_label = ctk.CTkLabel(control_frame, text="Detection Threshold:")
        threshold_label.grid(row=0, column=2, padx=10, pady=10, sticky="e")
        
        self.threshold_var = tk.DoubleVar(value=0.85)
        threshold_slider = ctk.CTkSlider(control_frame, from_=0.1, to=0.9, number_of_steps=8,
                                        variable=self.threshold_var, width=120)
        threshold_slider.grid(row=0, column=3, padx=10, pady=10, sticky="w")
        
        self.threshold_value_label = ctk.CTkLabel(control_frame, text="0.85")
        self.threshold_value_label.grid(row=0, column=3, padx=(140, 0), pady=10, sticky="w")
        
        def update_threshold_label(event=None):
            self.threshold_value_label.configure(text=f"{self.threshold_var.get():.1f}")
        
        threshold_slider.bind("<ButtonRelease-1>", update_threshold_label)
        
        self.start_button = ctk.CTkButton(control_frame, text="Start Monitoring", 
                                        command=self.toggle_monitoring,
                                        fg_color="#2196f3", hover_color="#1976d2")
        self.start_button.grid(row=0, column=4, padx=10, pady=10)
        
        self.status_label = ctk.CTkLabel(control_frame, text="● Stopped", text_color="#ff5252")
        self.status_label.grid(row=0, column=4, padx=(0, 100), pady=10, sticky="e")
    
    def toggle_monitoring(self):
        if not self.running:
            self.start_monitoring()
            self.start_button.configure(text="Stop Monitoring", fg_color="#f44336", hover_color="#d32f2f")
            self.status_label.configure(text="● Running", text_color="#8bc34a")
        else:
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
        prob_str = f"{detection['probability']*100:.1f}%"
        item_id = self.tree.insert("", 0, values=(
            detection['timestamp'],
            detection['src_ip'],
            detection['dst_ip'],
            detection['label'],
            prob_str
        ))
        self.tree.item(item_id, tags=(detection['label'],))
        
        if len(self.tree.get_children()) > 100:
            last_item = self.tree.get_children()[-1]
            self.tree.delete(last_item)
        
    def on_closing(self):
        self.stop_monitoring()
        self.destroy()
        sys.exit(0)

if _name_ == "_main_":
    app = DDoSDetectorApp()
    app.mainloop()