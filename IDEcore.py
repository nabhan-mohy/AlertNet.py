import os
import logging
from scapy.all import sniff, IP, TCP
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from datetime import datetime

logging.basicConfig(
    filename="ids.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def alert(message):
    print(f"[ALERT] {message}")
    logging.info(message)

def detect_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        if tcp_layer.dport == 23:
            alert(f"Telnet traffic detected: {ip_layer.src} -> {ip_layer.dst}")
        if tcp_layer.dport in [21, 22]:
            alert(f"Sensitive service traffic detected (FTP/SSH): {ip_layer.src} -> {ip_layer.dst}")

def prepare_dataset():
    data = {
        "src_ip": ["192.168.0.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"],
        "dst_ip": ["192.168.0.2", "10.0.0.2", "172.16.0.2", "8.8.4.4"],
        "src_port": [12345, 12346, 12347, 5000],
        "dst_port": [80, 443, 23, 53],
        "protocol": [6, 6, 6, 17],
        "is_attack": [0, 0, 1, 1],
    }
    df = pd.DataFrame(data)
    return df

def train_model():
    dataset = prepare_dataset()
    X = dataset.drop(columns=["is_attack"])
    X = pd.get_dummies(X, columns=["src_ip", "dst_ip"], drop_first=True)
    y = dataset["is_attack"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    model = RandomForestClassifier()
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))
    return model

def log_detection_to_file(packet, detection_type):
    with open("detection_log.txt", "a") as file:
        file.write(f"{datetime.now()} - {detection_type} - Packet: {packet.summary()}\n")

def enhanced_detect_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        if tcp_layer.dport == 23:
            alert(f"Telnet traffic detected: {ip_layer.src} -> {ip_layer.dst}")
            log_detection_to_file(packet, "Telnet Traffic")
        if tcp_layer.dport in [21, 22]:
            alert(f"Sensitive service traffic detected (FTP/SSH): {ip_layer.src} -> {ip_layer.dst}")
            log_detection_to_file(packet, "Sensitive Service Traffic")
        if tcp_layer.flags == 2:
            alert(f"Possible SYN scan detected: {ip_layer.src} -> {ip_layer.dst}")
            log_detection_to_file(packet, "SYN Scan")

def start_ids():
    print("Starting IDS...")
    sniff(filter="tcp", prn=enhanced_detect_packet, store=False)

if __name__ == "__main__":
    try:
        print("Training anomaly detection model...")
        model = train_model()
        start_ids()
    except KeyboardInterrupt:
        print("Exiting IDS...")
        os._exit(0)
