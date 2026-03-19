# Aegis - Realtime DDoS Detection Dashboard

Aegis is a hybrid machine learning and reputation-based system for **real-time detection of DDoS (Distributed Denial of Service) attacks** in network traffic. It provides a modern desktop dashboard using Tkinter and CustomTkinter, visualizing detections and system logs as network traffic flows through your machine.

---

## Features

- 🧠 **Hybrid Detection**: Combines a stacked ML ensemble (XGBoost, Neural Network, Random Forest, Decision Tree, Meta-Logistic Regression) with AbuseIPDB reputation checks.
- ⚡ **Real-time Network Traffic Analysis** – Monitors packets live using [Scapy](https://scapy.net/) and displays per-packet results.
- 📊 **Detection Dashboard** – Interactive GUI (Tkinter + CustomTkinter) shows timestamped sources, traffic types, confidence scores, and detection logs.
- 🛡️ **Automatic Mitigation** – (Reputation mode) Blocks highly suspicious IPs with system firewall rules.
- 🌒 **Dark Modern UI** – Smooth, dark-themed interface with real-time stats.
- 🛠️ **Highly Configurable** – Adjustable detection thresholds, packet count triggers, and interface selection.
- 💡 **Live Logging**: Color-coded logs for info, warnings, and errors.

---

## Requirements

- Python 3.8+
- Windows, Linux, or macOS
- **Admin/root access required for packet capture and firewall modifications**

### Python Package Dependencies

```
scapy>=2.4.5
customtkinter>=5.0
joblib>=1.0
tensorflow>=2.10
numpy>=1.21
pandas>=1.3
xgboost>=1.5
scikit-learn>=1.0
rich>=10.0
requests>=2.28
```

Install dependencies with:

```bash
pip install scapy customtkinter joblib tensorflow numpy pandas xgboost scikit-learn rich requests
```

---

## Model & Data Files

**Trained model files required** in the same directory:

- `xgb_model.pkl` – XGBoost classifier
- `mlp_model.h5` – TensorFlow/Keras Neural Network
- `meta_model.pkl` – Meta-classifier for stacking
- `preprocessor.pkl` – StandardScaler or preprocessing pipeline
- `rf_model.pkl` (optional) – Random Forest classifier
- `dt_model.pkl` (optional) – Decision Tree classifier

### Training Models

Use the provided training scripts to generate these files:

```bash
python newhybrid.py  # Modern training pipeline (recommended)
# OR
python hybrid.py     # Legacy training pipeline
```

These scripts expect a labeled CSV dataset with DDoS/benign labels. Update the file path in the script to match your dataset.

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Prepare Models

Train or obtain pre-trained models (see section above).

### 3. Run the Application

Choose one of the main interfaces:

```bash
# Hybrid ML-based detection
python bi.py
# or
python h.py
# or
python aegisusingmodel.py

# ML + AbuseIPDB reputation-based detection with auto-blocking
python aegismitigate.py
```

### 4. Configure Settings

- **Network Interface**: Select from dropdown (Wi-Fi, Ethernet, en0, eth0, etc.)
- **Detection Threshold**: Adjust confidence level for DDoS classification (0.1–0.9)
- **Packet Threshold** *(aegismitigate.py)*: Number of packets before checking IP reputation
- **AbuseIPDB API Key** *(aegismitigate.py)*: Add your free key from https://www.abuseipdb.com/

### 5. Start Monitoring

Click **"Start Monitoring"** to begin real-time analysis.

- Detections appear in the table with timestamps, source/destination IPs, traffic type, and confidence scores.
- System logs display operational messages and alerts.
- Status indicator shows "Running" or "Stopped".

---

## Application Modes

### Mode 1: Pure ML Detection (`bi.py`, `h.py`, `aegisusingmodel.py`)

Uses trained ensemble model to classify traffic:
- Extracts flow features from live packets
- Passes through XGBoost + MLP + meta-classifier
- Labels as "DDoS" or "Benign" with confidence score
- **No external API calls** – fully offline

### Mode 2: ML + Reputation-Based (`aegismitigate.py`)

Combines ML with AbuseIPDB lookups:
- Monitors packet rate from source IPs
- When threshold exceeded, queries AbuseIPDB
- Blocks IPs with high abuse scores via firewall
- **Requires API key and internet connection**

---

## File Descriptions

| File | Purpose |
|------|---------|
| `bi.py` | Main ML detection GUI (best stability) |
| `h.py` | ML detection GUI (alternative) |
| `aegisusingmodel.py` | Hybrid ML GUI (classic version) |
| `aegismitigate.py` | ML + AbuseIPDB with auto-blocking |
| `newhybrid.py` | **Recommended** model training script |
| `hybrid.py` | Legacy model training script |
| `ui.py` | Reference UI logic |

---

## Feature Extraction

Live packets are analyzed for the following features:

- `Flow Duration` – Time since flow started (ms)
- `Tot Fwd Pkts` – Forward packets count
- `Tot Bwd Pkts` – Backward packets count
- `Fwd Pkt Len Max` – Max forward packet size
- `Bwd Pkt Len Max` – Max backward packet size
- `Flow IAT Mean` – Mean inter-arrival time
- `Fwd IAT Mean` – Mean forward inter-arrival time
- `Pkt Size Avg` – Average packet size
- `Init Fwd Win Byts` – TCP window size (forward)
- `Init Bwd Win Byts` – TCP window size (backward)

---

## Architecture

### Detection Pipeline

```
Live Packets → Scapy Capture
   ↓
Feature Extraction (per source IP)
   ↓
Preprocessing (StandardScaler)
   ↓
Base Models: XGBoost + MLP + RF + DT
   ↓
Meta-Classifier (Logistic Regression)
   ↓
Classification: "DDoS" or "Benign"
   ↓
UI Update + Optional Firewall Block
```

### UI Architecture

- **Detection Frame** – Treeview table of detections
- **Log Frame** – ScrolledText with color-coded logs
- **Control Frame** – Interface, threshold, and button controls
- **Background Thread** – Scapy packet capture loop
- **Queue-based Communication** – Thread-safe log/detection updates

---

## Configuration & Customization

### Change Detection Threshold

In the GUI, use the **"Detection Threshold"** slider (0.1–0.9).
- Lower = more sensitive, higher false positive rate
- Higher = stricter, may miss attacks

### Change Network Interface

Update the dropdown in the control panel or hardcode:

```python
interface_combo = ctk.CTkComboBox(
    control_frame, 
    values=["Your-Interface-Here", "eth0", "Wi-Fi"]
)
```

### Use Your Own Models

Replace `.pkl` and `.h5` files with your own. Ensure:
1. Same input feature names and order
2. Same output format (probabilities for binary classification)
3. Compatible sklearn/TensorFlow versions

### Adjust Trusted IPs

In the detector class, modify:

```python
self.TRUSTED_IPS = {
    '8.8.8.8',          # Google DNS
    '142.250.0.0/16',   # Google services
    # Add yours here
}
```

---

## Usage Examples

### Example 1: Monitor Wi-Fi for Attacks

```bash
python bi.py
# Select "Wi-Fi" → Set threshold to 0.8 → Click "Start Monitoring"
```

### Example 2: Auto-block with AbuseIPDB

```bash
python aegismitigate.py
# Enter API key → Select interface → Adjust packet threshold → Start
```

### Example 3: Train on Custom Dataset

Edit `newhybrid.py`:
```python
df = load_data(r"path/to/your/dataset.csv")
# Modify feature names if needed
python newhybrid.py
```

---

## Performance Notes

- **Latency**: ~100ms per detection update (UI refresh rate)
- **CPU Usage**: Moderate; scales with packet rate
- **Memory**: ~200–500MB typical (depends on flow tracking window)
- **Accuracy**: Depends on training dataset balance and diversity

For high-volume traffic (>10k packets/sec), consider:
- Packet sampling
- Longer detection windows
- Distributed processing

---

## Troubleshooting

### "Permission Denied" Error

You need **admin/root privileges**:

```bash
# Windows
python bi.py  # Run as Administrator

# Linux/macOS
sudo python bi.py
```

### "Models Not Found" Error

Ensure `.pkl` and `.h5` files are in the same directory. Train them using `newhybrid.py` if missing.

### "Failed to Load Preprocessor" Error

Check that `preprocessor.pkl` matches the features in your live extraction code.

### GUI Not Responding

If detections flood the UI, reduce packet sampling or increase detection window in code.

### No Packets Captured

Verify the network interface name is correct (e.g., "Wi-Fi" vs "wifi").

---

## Security & Ethical Use

⚠️ **Important**: This tool is for **authorized network monitoring only**.

- **Obtain permission** before monitoring any network
- **Comply with privacy laws** (GDPR, CCPA, etc.)
- Use in **research, educational, or defensive security contexts**
- Do not use for unauthorized access or interference

---

## Contributing

Contributions welcome! Areas for improvement:

- [ ] GPU acceleration for model inference
- [ ] Multi-threaded packet processing
- [ ] Enhanced firewall integration for other OSs
- [ ] Web-based dashboard (Flask/React)
- [ ] Federated learning for distributed detection

Submit issues and PRs to the repository.

---

## License

**MIT License**

See LICENSE file for details.

---

## Citation

If you use Aegis in research, please cite:

```
@software{aegis2024,
  author = {zeelpatel1},
  title = {Aegis: Realtime DDoS Detection Dashboard},
  year = {2024},
  url = {https://github.com/zeelpatel1/aegis}
}
```

---

## Changelog

### v1.0 (2024)
- Initial release
- Hybrid ML + AbuseIPDB modes
- Full feature extraction and real-time dashboard

---

## Acknowledgments

- Built with [Scapy](https://scapy.net/) for packet capture
- UI powered by [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)
- Models trained with [XGBoost](https://xgboost.readthedocs.io/) and [TensorFlow](https://www.tensorflow.org/)
- Reputation data from [AbuseIPDB](https://www.abuseipdb.com/)

---

**Happy monitoring! Stay secure. 🛡️**
