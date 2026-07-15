# ⚡ Valence | Web Network Scanner

Valence is a modern, lightweight, and ultra-fast web-based local network discovery and port auditing tool. Powered by a **Python Flask** backend and a sleek, dark-themed **Tailwind CSS** frontend dashboard, Valence lets you analyze your local area network (LAN) directly from your web browser at `localhost:3000`.

Unlike other basic scripts, Valence executes **real, non-simulated** multi-threaded network sweeps and socket handshakes to find active devices and open ports.

---

## ✨ Features

- **Auto-Subnet Detection:** Instantly identifies your local IP address and gateway range.
- **High-Speed Network Discovery:** Uses a optimized python thread-pool to sweep your network in seconds.
- **Physical Address Resolution:** Pulls MAC addresses using raw Layer 2 ARP requests (via Scapy).
- **Targeted Port Auditing:** Checks custom port ranges (e.g. `21-25, 80, 443, 8080`) using direct TCP connections.
- **Interactive Console Log:** Streamlined real-time progress logging in a built-in terminal mock container.
- **Data Export:** Export your network mapping reports directly to a `.csv` spreadsheet.

---

## 🛠️ Architecture

Valence is designed with lightweight simplicity in mind:

* **Backend:** Python 3, Flask, Socket, Scapy (Optional)
* **Frontend:** HTML5, Tailwind CSS, Vanilla JavaScript (Fetch API)

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/rishabhks651-byte/Valence.git
cd Valence
```

### 2. Install requirements
```bash
pip install -r requirements.txt
```

### 3. Run Valence
```bash
python app.py
```

### 4. Open your browser and go to
```bash
localhost:3000
```
