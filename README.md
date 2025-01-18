# AlertNet
### A Lightweight Intrusion Detection System (IDS) for Real-Time Network Monitoring

AlertNet is a Python-based Intrusion Detection System (IDS) designed to monitor network traffic, detect potential attacks, and log malicious activity. It uses a combination of rule-based detection and machine learning to classify traffic as normal or anomalous.

## Features
- Real-time packet sniffing using Scapy.
- Detects:
  - SYN scans
  - Suspicious Telnet, SSH, and FTP activity.
- Logs alerts to a file for post-event analysis.
- Machine Learning model for anomaly detection (using Random Forest).
- Lightweight and easy to set up.

## How It Works
1. **Packet Sniffing**: Captures live TCP packets on specified ports.
2. **Anomaly Detection**: Identifies unusual behavior using both rule-based logic and a trained ML model.
3. **Alerting**: Generates alerts for suspicious activity and logs them for further analysis.

## Installation
### Prerequisites
- Python 3.10 or higher
- Pip and virtualenv
- Admin/root privileges for sniffing packets

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/nabhan-mohy/AlertNet.git
   cd AlertNet
python -m venv env
source env/bin/activate  # For Linux/Mac
env\Scripts\activate     # For Windows
nmap -sS -p 21,22 <target_IP>
File Structure
IDS.py: Main script.

requirements.txt: Python dependencies.
data/: Folder for datasets used for training/testing the ML model.
logs/: Contains detection logs.
Contributing
Contributions are welcome! Feel free to open issues or submit pull requests.
![Screenshot_2025-01-18_02_46_35](https://github.com/user-attachments/assets/ca688240-78b1-402e-875a-c40df6c156ec)
