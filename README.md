# 🛡️ Network Traffic Analysis Tool

A Python-based **Packet Sniffing and Visualization GUI** application built using `Scapy`, `Tkinter`, and `Seaborn`. It captures live network packets, displays protocol statistics, and allows saving data to a CSV file with timestamps.

---

## 🚀 Features

* 🖥️ **Graphical User Interface** for ease of use (Tkinter)
* 📡 **Live Packet Capture** using Scapy
* 📁 **CSV Export** with detailed data including:

  * Source IP
  * Destination IP
  * Protocol Name (e.g., TCP, UDP)
  * Packet Length
  * Timestamp
* 📊 **Traffic Visualization** with protocol distribution charts (Seaborn + Matplotlib)
* 🔒 Graceful handling of permission and interface errors
* 🧵 Non-blocking capture using multithreading

---

## 📦 Requirements

Install the required Python packages using pip:

```bash
pip install scapy pandas seaborn matplotlib
```

> ⚠️ **Note**: Scapy requires root/administrator privileges to sniff packets.

---

## 📷 Visualization Example

The tool creates a bar plot showing the number of packets per protocol (TCP, UDP, etc.).

---


## ⚠️ Permissions

Packet sniffing requires administrative/root privileges:

* **Linux/macOS**: Run with `sudo`
* **Windows**: Run as administrator

---
