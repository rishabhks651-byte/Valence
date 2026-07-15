import sys
import socket
import subprocess
import threading
import ipaddress
from flask import Flask, jsonify, request, send_from_directory
import os

# Try importing scapy
try:
    from scapy.all import srp, Ether, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

app = Flask(__name__, static_folder='.')

# --- Network Helper Functions ---

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def ping_check(ip: str) -> bool:
    if sys.platform.startswith('win'):
        command = ['ping', '-n', '1', '-w', '400', ip]
    else:
        command = ['ping', '-c', '1', '-W', '1', ip]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=1.0)
        return result.returncode == 0
    except Exception:
        return False

def resolve_mac(ip: str) -> str:
    if not SCAPY_AVAILABLE:
        return "N/A"
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, verbose=False)
        for snd, rcv in ans:
            return rcv.src
    except Exception:
        pass
    return "N/A"

# --- Web Routes ---

@app.route('/')
def home():
    # Serves the index.html frontend file
    return send_from_directory('.', 'index.html')

@app.route('/api/info', methods=['GET'])
def get_info():
    local_ip = get_local_ip()
    octets = local_ip.split('.')
    subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24" if len(octets) == 4 else "192.168.1.0/24"
    return jsonify({
        "local_ip": local_ip,
        "subnet": subnet,
        "hostname": socket.gethostname(),
        "platform": sys.platform
    })

@app.route('/api/scan', methods=['POST'])
def scan_network():
    data = request.json or {}
    subnet = data.get('subnet')
    if not subnet:
        return jsonify({"error": "Subnet is required"}), 400

    try:
        network = ipaddress.ip_network(subnet, strict=False)
        ips = [str(ip) for ip in network.hosts()]
    except ValueError:
        return jsonify({"error": "Invalid CIDR format"}), 400

    active_devices = []
    lock = threading.Lock()
    threads = []

    def scan_host(ip):
        if ping_check(ip):
            mac = resolve_mac(ip)
            try:
                hostname = socket.getfqdn(ip)
                if hostname == ip:
                    hostname = "Unknown"
            except Exception:
                hostname = "Unknown"
            
            with lock:
                active_devices.append({
                    "status": "🟢 UP",
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname
                })

    # Speed up scanning using standard threads
    for ip in ips:
        t = threading.Thread(target=scan_host, args=(ip,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Sort results by IP
    active_devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return jsonify({"devices": active_devices})

@app.route('/api/scan-ports', methods=['POST'])
def scan_ports():
    data = request.json or {}
    ip = data.get('ip')
    ports_str = data.get('ports', '21,22,80,443,8080')

    if not ip:
        return jsonify({"error": "IP target is required"}), 400

    # Parse ports string
    ports = set()
    for item in [p.strip() for p in ports_str.split(',')]:
        if not item:
            continue
        if '-' in item:
            try:
                start, end = map(int, item.split('-'))
                ports.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(item))
            except ValueError:
                continue
    
    sorted_ports = sorted(list(ports))
    open_ports = []

    # Quick sequential scan of target ports
    for port in sorted_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            sock.close()

    return jsonify({
        "ip": ip,
        "scanned_ports": sorted_ports,
        "open_ports": open_ports
    })

if __name__ == '__main__':
    # Host on port 3000
    app.run(host='0.0.0.0', port=3000, debug=True)
