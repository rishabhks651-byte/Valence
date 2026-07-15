import sys
import datetime
import socket
import subprocess
import threading
import ipaddress
import csv
import json
from typing import List, Dict, Optional
import customtkinter as ctk
from tkinter import ttk, messagebox

# Try importing scapy; if it fails, fallback is handled gracefully.
try:
    from scapy.all import srp, Ether, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: scapy not found. Falling back to basic ping sweeps for MAC/Hostname.")
    srp = None
    Ether = ARP = None
    SCAPY_AVAILABLE = False


class ValenceScannerApp:
    """
    The main application class implementing the UI and scanning logic for Valence.
    Implements local IP detection, Ping Sweep, MAC/Hostname resolution, and Port Scanning.
    """
    def __init__(self, master):
        self.master = master
        self.master.title("Valence | Network Scanner")
        ctk.set_appearance_mode("Dark")  # Dark mode theme
        ctk.set_default_color_theme("blue")

        # --- Configuration & State ---
        self.local_ip: str = "Fetching..."
        self.subnet_cidr: str = ""
        self.discovered_devices: List[Dict] = []
        self.selected_device_ip: Optional[str] = None

        # --- UI Setup ---
        self._setup_ui()
        self._detect_network_info()

    def _setup_ui(self):
        """Sets up the entire layout using a grid system."""

        # Configure main window padding and geometry
        self.master.geometry("1200x750")
        self.master.resizable(False, False)

        # Main container uses a pack system: Sidebar (Left) | Main Content (Right)
        self.main_container = ctk.CTkFrame(self.master)
        self.main_container.pack(padx=20, pady=20, fill="both", expand=True)

        # 1. Side Panel (Sidebar) - For Controls and Status
        self.sidebar_frame = ctk.CTkFrame(self.main_container, width=250)
        self.sidebar_frame.pack(side="left", padx=(0, 20), pady=0, fill="y")

        # Branding/Header
        self.logo = ctk.CTkLabel(self.sidebar_frame, text="VALENCE", 
                                 font=ctk.CTkFont(size=28, weight="bold"))
        self.logo.pack(pady=(20, 15))

        # Subnet Status Display
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Detecting Network...", 
                                         font=ctk.CTkFont(size=12), wraplength=220)
        self.status_label.pack(pady=(0, 15))

        # Scan Button
        self.scan_button = ctk.CTkButton(self.sidebar_frame, text="⚡ Scan Network", command=self.start_discovery_thread, 
                                         fg_color="#8a2be2", hover_color="#6b1e9c") # Neon Purple Accent
        self.scan_button.pack(pady=15, fill="x", padx=10)

        # Export Button
        self.export_button = ctk.CTkButton(self.sidebar_frame, text="💾 Export Results (CSV)", command=self.export_results, 
                                           fg_color="#2ecc71", hover_color="#27ae60", state="disabled") # Green Accent
        self.export_button.pack(pady=15, fill="x", padx=10)

        # Separator and Footer (optional status info)
        ctk.CTkLabel(self.sidebar_frame, text="System Info:", font=ctk.CTkFont(size=12, weight="bold")).pack(pady=(20, 5))
        self.info_label = ctk.CTkLabel(self.sidebar_frame, text="Gathering details...", wraplength=220)
        self.info_label.pack(pady=5)

        # 2. Main Content Area (Device Table & Port Scanner Drawer)
        self.main_frame = ctk.CTkFrame(self.main_container)
        self.main_frame.pack(side="right", fill="both", expand=True)

        # --- Tabbed Layout for Organization ---
        self.tabview = ctk.CTkTabview(self.main_frame, width=1000)
        self.tabview.pack(fill="both", expand=True)

        # Tab 1: Device List (The primary view)
        self.tab_devices = self.tabview.add("Device Overview")
        self._setup_device_table(self.tab_devices)

        # Tab 2: Port Scanner Details (Initially hidden/secondary focus)
        self.tab_port_scanner = self.tabview.add("Port Scanner")
        self._setup_port_scanner_ui(self.tab_port_scanner)

    def _setup_device_table(self, tab):
        """Sets up the Treeview/Table widget within the Device Overview tab."""

        # Frame for holding the table
        table_frame = ctk.CTkFrame(tab)
        table_frame.pack(padx=20, pady=10, fill="both", expand=True)

        # Custom styling for standard ttk Treeview to fit the dark theme
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background="#2a2a2a",
                        foreground="white",
                        rowheight=25,
                        fieldbackground="#2a2a2a")
        style.map('Treeview', background=[('selected', '#8a2be2')])
        style.configure("Treeview.Heading",
                        background="#1e1e1e",
                        foreground="white",
                        relief="flat")

        # Styling the Treeview/Table appearance
        self.device_tree = ttk.Treeview(table_frame, 
                                        columns=("Status", "IP Address", "MAC Address", "Hostname"), 
                                        show='headings', height=15)

        # Define headings and column widths
        self.device_tree.heading("Status", text="Status", anchor="center")
        self.device_tree.heading("IP Address", text="IP Address", anchor="w")
        self.device_tree.heading("MAC Address", text="MAC Address", anchor="w")
        self.device_tree.heading("Hostname", text="Hostname", anchor="w")

        self.device_tree.column("Status", width=100, anchor="center")
        self.device_tree.column("IP Address", width=200, anchor="w")
        self.device_tree.column("MAC Address", width=220, anchor="w")
        self.device_tree.column("Hostname", width=250, anchor="w")

        # Layout Setup inside Frame
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # Scrollbar integration
        scrollbar = ctk.CTkScrollbar(table_frame, orientation="vertical", command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)

        self.device_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Bind selection event to populate port scanner view
        self.device_tree.bind("<<TreeviewSelect>>", self._on_device_select)

    def _setup_port_scanner_ui(self, tab):
        """Sets up the Port Scanner controls within the dedicated tab."""

        # Layout: Controls (Top) | Results/Output (Bottom)
        control_frame = ctk.CTkFrame(tab, height=150)
        control_frame.pack(pady=15, padx=20, fill="x")

        # Target IP Input
        ctk.CTkLabel(control_frame, text="Target IP:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.port_target_ip = ctk.CTkEntry(control_frame, width=200)
        self.port_target_ip.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        # Target Port Range Input
        ctk.CTkLabel(control_frame, text="Ports (e.g., 21-25, 80, 443):").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.port_range_entry = ctk.CTkEntry(control_frame, width=250)
        self.port_range_entry.insert(0, "21, 22, 80, 443, 8080")
        self.port_range_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

        # Scan button for ports
        self.scan_port_button = ctk.CTkButton(control_frame, text="🔬 Start Port Scan", command=self.start_port_scan, 
                                              fg_color="#3498db", hover_color="#2980b9")
        self.scan_port_button.grid(row=0, column=2, rowspan=2, padx=20, pady=5, sticky="ns")

        # --- Results Area (Progress Bar and Output Log) ---
        output_frame = ctk.CTkFrame(tab, fg_color="transparent")
        output_frame.pack(pady=10, padx=20, fill="both", expand=True)

        ctk.CTkLabel(output_frame, text="Scan Log / Results:", font=ctk.CTkFont(size=14)).pack(anchor="w")

        self.port_progress = ctk.CTkProgressBar(output_frame, mode="determinate")
        self.port_progress.pack(fill="x", pady=5)
        self.port_progress.set(0)

        # Text widget for detailed output logs (Port open/closed status)
        self.port_log = ctk.CTkTextbox(output_frame, wrap="word")
        self.port_log.pack(fill="both", expand=True, pady=10)
        self.port_log.insert("0.0", "--- Port Scan Log Initialized ---\nReady to scan.\n")

    # =====================================================================
    # 1. INITIALIZATION & DISCOVERY (IP Detection & Host Discovery)
    # =====================================================================

    def _detect_network_info(self):
        """Automatically detects local IP and attempts to guess subnet range."""
        try:
            local_ip = self._get_local_ip()
            self.local_ip = local_ip

            # Standard assumption for home subnets (/24 class C)
            octets = local_ip.split('.')
            if len(octets) == 4:
                self.subnet_cidr = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
            else:
                self.subnet_cidr = "192.168.1.0/24"

            self.status_label.configure(
                text=f"Local IP: {local_ip}\nScanning Subnet: {self.subnet_cidr}", 
                text_color="#00ffff"
            )
            
            # Formulate System Label
            uname_sys = sys.platform
            self.info_label.configure(text=f"Host: {socket.gethostname()}\nPlatform: {uname_sys}")

        except Exception as e:
            self.status_label.configure(text=f"Error detecting network: {e}", text_color="#ff4500")
            self.info_label.configure(text="Could not determine system details.")
            self.subnet_cidr = "192.168.1.0/24"

    def _get_local_ip(self) -> str:
        """Attempts to get the primary local IP address of the machine."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to public IP (doesn't send actual packet, just maps local routing interface)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

    def start_discovery_thread(self):
        """Starts the background thread for network discovery."""
        if not self.subnet_cidr:
            messagebox.showerror("Error", "Subnet information is unavailable.")
            return

        self.scan_button.configure(text="Scanning...", state="disabled")
        self.export_button.configure(state="disabled")
        
        # Spawn thread for non-blocking scanner execution
        threading.Thread(target=self._run_discovery, daemon=True).start()

    def _run_discovery(self):
        """Performs the actual synchronous scan and updates results."""
        print("Starting discovery process...")
        active_hosts = self.scan_subnet_sweep()
        self.discovered_devices = active_hosts

        # Safely schedule GUI updates onto the Main Thread
        self.master.after(0, self._update_device_table, active_hosts)
        self.master.after(0, self._finalize_scan_ui, len(active_hosts))

    def scan_subnet_sweep(self) -> List[Dict]:
        """Performs active host discovery using a fast multithreaded ping system."""
        network_range = self._expand_cidr(self.subnet_cidr)
        active_devices: List[Dict] = []
        threads = []
        lock = threading.Lock()

        def scan_host(ip):
            if self._ping_check(ip):
                mac = self._resolve_mac(ip)
                try:
                    hostname = socket.getfqdn(ip)
                    if hostname == ip:
                        hostname = "Unknown"
                except Exception:
                    hostname = "Unknown"

                device = {
                    "Status": "🟢 UP",
                    "IP": ip,
                    "MAC": mac if mac else "N/A",
                    "Hostname": hostname
                }
                with lock:
                    active_devices.append(device)

        # Spawn a localized thread pool for high-speed scanning
        for ip in network_range:
            thread = threading.Thread(target=scan_host, args=(ip,), daemon=True)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Sort IP addresses in ascending order
        active_devices.sort(key=lambda d: ipaddress.ip_address(d["IP"]))
        return active_devices

    def _ping_check(self, ip: str) -> bool:
        """Uses subprocess to ping the host."""
        if sys.platform.startswith('win'):
            command = ['ping', '-n', '1', '-w', '500', ip]  # -w 500 sets timeout to 500ms
        else:
            command = ['ping', '-c', '1', '-W', '1', ip]  # -W 1 sets timeout to 1s

        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=1.5)
            return result.returncode == 0
        except Exception:
            return False

    def _resolve_mac(self, ip: str) -> Optional[str]:
        """Uses Scapy (ARP scan) if available to get MAC address."""
        if not SCAPY_AVAILABLE:
            return "N/A (Scapy missing)"

        try:
            # Send standard ARP request Layer 2 Packet
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, verbose=False)
            for snd, rcv in ans:
                return rcv.src
        except Exception as e:
            print(f"Scapy error resolving {ip}: {e}")
        return None

    def _expand_cidr(self, cidr: str) -> List[str]:
        """Converts CIDR notation to a list of usable IPs."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            self.master.after(0, lambda: messagebox.showerror("Error", f"Invalid CIDR format: {cidr}"))
            return []

    # =====================================================================
    # 2. UI UPDATES AND EVENT HANDLERS
    # =====================================================================

    def _update_device_table(self, devices: List[Dict]):
        """Clears and repopulates the Treeview with the scanned device data."""
        # Clear existing items
        for i in self.device_tree.get_children():
            self.device_tree.delete(i)

        for device in devices:
            data = (
                device["Status"], 
                device["IP"], 
                device["MAC"], 
                device["Hostname"]
            )
            self.device_tree.insert("", "end", values=data)

    def _finalize_scan_ui(self, count: int):
        """Called after scanning to reset buttons and update status."""
        self.scan_button.configure(text="⚡ Scan Network", state="normal")
        self.export_button.configure(state="normal")
        self.status_label.configure(
            text=f"Scan Complete! Found {count} active devices.", 
            text_color="#2ecc71"
        )

    def _on_device_select(self, event):
        """Handles selecting an active row in the table, setting up the Port Scanner."""
        selected_items = self.device_tree.selection()
        if selected_items:
            item_values = self.device_tree.item(selected_items[0])['values']
            ip = item_values[1] 
            self.selected_device_ip = ip
            self.port_target_ip.delete(0, "end")
            self.port_target_ip.insert(0, ip)

    def export_results(self):
        """Saves current discovery dataset cleanly to a CSV file."""
        if not self.discovered_devices:
            messagebox.showwarning("Export Warning", "No devices found to export.")
            return

        filename = f"valence_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Status', 'IP Address', 'MAC Address', 'Hostname']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for device in self.discovered_devices:
                    writer.writerow({
                        'Status': device['Status'],
                        'IP Address': device['IP'],
                        'MAC Address': device['MAC'],
                        'Hostname': device['Hostname']
                    })

            messagebox.showinfo("Success", f"Scan results successfully exported to:\n{filename}")
        except IOError:
            messagebox.showerror("Error", "I/O error while saving the file.")

    # =====================================================================
    # 3. PORT SCANNER LOGIC
    # =====================================================================

    def start_port_scan(self):
        """Initiates the port scanning process, running on a background thread."""
        target_ip = self.port_target_ip.get().strip()
        ports_range_str = self.port_range_entry.get().strip()

        if not target_ip:
            messagebox.showwarning("Input Error", "Please select a device or enter a Target IP Address.")
            return

        try:
            port_list = self._parse_ports(ports_range_str)
        except Exception:
            messagebox.showerror("Input Error", "Invalid port range format.")
            return

        if not port_list:
            messagebox.showwarning("Input Error", "No valid ports resolved to scan.")
            return

        self.scan_port_button.configure(text="Scanning...", state="disabled")
        self.port_log.delete("1.0", "end")
        self.port_log.insert("1.0", f"Initiating Scan against {target_ip}...\n")
        self.port_progress.set(0)

        # Run socket ports checking asynchronously
        threading.Thread(target=self._run_port_scan_worker, args=(target_ip, port_list), daemon=True).start()

    def _run_port_scan_worker(self, ip: str, ports: List[int]):
        """The background worker function for scanning ports."""
        open_ports = []
        total_ports = len(ports)

        for i, port in enumerate(ports):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Set aggressive half-second timeout

            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
            except Exception:
                pass
            finally:
                sock.close()

            # Safely report progress back to the UI thread
            progress = (i + 1) / total_ports
            self.master.after(0, self._update_progress, progress, port, open_ports)

        # Final UI results update
        self.master.after(0, self._display_port_results, open_ports)

    def _parse_ports(self, ports_range_str: str) -> List[int]:
        """Parses complex combinations of lists and ranges (e.g., '21-25, 80, 443')."""
        ports = set()
        for item in [p.strip() for p in ports_range_str.split(',')]:
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
        return sorted(list(ports))

    def _update_progress(self, progress_ratio: float, current_port: int, open_ports: List[int]):
        """Runs on main thread. Updates progress bar and appends logs."""
        self.port_progress.set(progress_ratio)
        self.port_log.delete("1.0", "end")
        
        status_text = (
            f"--- Port Scan in Progress ---\n"
            f"Scanning Port: {current_port}\n"
            f"Open Ports Found: {', '.join(map(str, open_ports)) if open_ports else 'None yet'}"
        )
        self.port_log.insert("1.0", status_text)

    def _display_port_results(self, open_ports: List[int]):
        """Updates the textbox with the final list of open ports."""
        self.port_log.delete("1.0", "end")

        output = f"--- Port Scan Complete for {self.port_target_ip.get()} ---\n\n"
        if open_ports:
            output += f"🟢 FOUND OPEN PORTS: {', '.join(map(str, open_ports))}\n"
        else:
            output += "🔴 No scanned ports were identified as open.\n"
        output += "\n--- End of Scan ---"
        
        self.port_log.insert("1.0", output)
        self.scan_port_button.configure(text="🔬 Start Port Scan", state="normal")


# =====================================================================
# MAIN EXECUTION BLOCK
# =====================================================================

if __name__ == "__main__":
    app_root = ctk.CTk()
    app = ValenceScannerApp(app_root)
    app_root.mainloop()
