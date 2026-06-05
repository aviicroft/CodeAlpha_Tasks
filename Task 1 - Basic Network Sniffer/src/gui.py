"""
GUI Module
Modern graphical user interface for the Advanced Network Traffic Analyzer.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Thread
import sys

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False

from packet_capture import PacketCapture
from protocol_parser import ProtocolParser
from threat_detector import ThreatDetector
from traffic_analyzer import TrafficAnalyzer
from data_exporter import DataExporter


class AnalyzerGUI:
    """Main GUI application for network traffic analyzer."""

    def __init__(self, root):
        """Initialize GUI."""
        self.root = root
        self.root.title("Advanced Network Traffic Analyzer")
        self.root.geometry("1200x700")

        # Initialize components
        self.capture = PacketCapture()
        self.parser = ProtocolParser()
        self.detector = ThreatDetector()
        self.analyzer = TrafficAnalyzer()
        self.exporter = DataExporter()

        # State variables
        self.is_capturing = False
        self.filter_protocol = tk.StringVar(value="All")
        self.search_ip = tk.StringVar()

        # Configure style
        self._configure_style()

        # Build GUI
        self._build_gui()

        # Start auto-update thread
        self._start_update_thread()

    def _configure_style(self):
        """Configure GUI style."""
        style = ttk.Style()
        style.theme_use('clam')

    def _build_gui(self):
        """Build main GUI layout."""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        # Create tabs
        self.capture_tab = ttk.Frame(self.notebook)
        self.stats_tab = ttk.Frame(self.notebook)
        self.threats_tab = ttk.Frame(self.notebook)
        self.export_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.capture_tab, text="Packet Capture")
        self.notebook.add(self.stats_tab, text="Statistics")
        self.notebook.add(self.threats_tab, text="Threats")
        self.notebook.add(self.export_tab, text="Export")

        # Build each tab
        self._build_capture_tab()
        self._build_stats_tab()
        self._build_threats_tab()
        self._build_export_tab()

    def _build_capture_tab(self):
        """Build packet capture tab."""
        # Control panel
        control_frame = ttk.LabelFrame(self.capture_tab, text="Capture Controls")
        control_frame.pack(fill="x", padx=5, pady=5)

        # Button frame
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill="x", padx=5, pady=5)

        self.start_btn = ttk.Button(button_frame, text="Start Capture", command=self._start_capture)
        self.start_btn.pack(side="left", padx=2)

        self.stop_btn = ttk.Button(button_frame, text="Stop Capture", command=self._stop_capture, state="disabled")
        self.stop_btn.pack(side="left", padx=2)

        ttk.Button(button_frame, text="Clear Packets", command=self._clear_packets).pack(side="left", padx=2)

        # Status label
        self.status_label = ttk.Label(control_frame, text="Status: Idle", foreground="blue")
        self.status_label.pack(fill="x", padx=5, pady=5)

        # Filter panel
        filter_frame = ttk.LabelFrame(self.capture_tab, text="Filters")
        filter_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(filter_frame, text="Protocol:").pack(side="left", padx=5)
        protocol_combo = ttk.Combobox(
            filter_frame, textvariable=self.filter_protocol,
            values=["All", "TCP", "UDP", "DNS", "HTTP", "ARP", "ICMP"],
            state="readonly", width=10
        )
        protocol_combo.pack(side="left", padx=5)
        protocol_combo.bind("<<ComboboxSelected>>", lambda e: self._refresh_packets_display())

        ttk.Label(filter_frame, text="Search IP:").pack(side="left", padx=5)
        ttk.Entry(filter_frame, textvariable=self.search_ip, width=15).pack(side="left", padx=5)
        ttk.Button(filter_frame, text="Search", command=self._search_packets).pack(side="left", padx=5)

        # Packets table
        table_frame = ttk.LabelFrame(self.capture_tab, text="Captured Packets")
        table_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Create Treeview
        columns = ("Timestamp", "Source", "Destination", "Protocol", "Length", "Info")
        self.packets_tree = ttk.Treeview(table_frame, columns=columns, height=15)

        # Define column headings
        self.packets_tree.column("#0", width=0, stretch="no")
        self.packets_tree.column("Timestamp", anchor="w", width=150)
        self.packets_tree.column("Source", anchor="w", width=150)
        self.packets_tree.column("Destination", anchor="w", width=150)
        self.packets_tree.column("Protocol", anchor="center", width=80)
        self.packets_tree.column("Length", anchor="center", width=80)
        self.packets_tree.column("Info", anchor="w", width=200)

        self.packets_tree.heading("#0", text="", anchor="w")
        self.packets_tree.heading("Timestamp", text="Timestamp", anchor="w")
        self.packets_tree.heading("Source", text="Source", anchor="w")
        self.packets_tree.heading("Destination", text="Destination", anchor="w")
        self.packets_tree.heading("Protocol", text="Protocol", anchor="center")
        self.packets_tree.heading("Length", text="Length", anchor="center")
        self.packets_tree.heading("Info", text="Info", anchor="w")

        # Add scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.packets_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.packets_tree.xview)
        self.packets_tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.packets_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

    def _build_stats_tab(self):
        """Build statistics tab."""
        stats_frame = ttk.LabelFrame(self.stats_tab, text="Traffic Statistics")
        stats_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.stats_text = tk.Text(stats_frame, height=30, width=100, state="disabled")
        self.stats_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Scrollbar
        scrollbar = ttk.Scrollbar(stats_frame, orient="vertical", command=self.stats_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.stats_text.configure(yscrollcommand=scrollbar.set)

    def _build_threats_tab(self):
        """Build threats detection tab."""
        threats_frame = ttk.LabelFrame(self.threats_tab, text="Detected Threats")
        threats_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.threats_text = tk.Text(threats_frame, height=30, width=100, state="disabled")
        self.threats_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Scrollbar
        scrollbar = ttk.Scrollbar(threats_frame, orient="vertical", command=self.threats_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.threats_text.configure(yscrollcommand=scrollbar.set)

    def _build_export_tab(self):
        """Build export tab."""
        button_frame = ttk.LabelFrame(self.export_tab, text="Export Options")
        button_frame.pack(fill="x", padx=5, pady=5)

        ttk.Button(button_frame, text="Export to CSV", command=self._export_csv).pack(side="left", padx=5, pady=5)
        ttk.Button(button_frame, text="Export to PCAP", command=self._export_pcap).pack(side="left", padx=5, pady=5)
        ttk.Button(button_frame, text="Generate Report", command=self._generate_report).pack(side="left", padx=5, pady=5)
        ttk.Button(button_frame, text="Export Threats", command=self._export_threats).pack(side="left", padx=5, pady=5)

        # Exports list
        exports_frame = ttk.LabelFrame(self.export_tab, text="Exported Files")
        exports_frame.pack(fill="both", expand=True, padx=5, pady=5)

        columns = ("Filename", "Size", "Modified")
        self.exports_tree = ttk.Treeview(exports_frame, columns=columns, height=15)

        self.exports_tree.column("#0", width=0, stretch="no")
        self.exports_tree.column("Filename", anchor="w", width=300)
        self.exports_tree.column("Size", anchor="center", width=100)
        self.exports_tree.column("Modified", anchor="w", width=200)

        self.exports_tree.heading("Filename", text="Filename", anchor="w")
        self.exports_tree.heading("Size", text="Size", anchor="center")
        self.exports_tree.heading("Modified", text="Modified", anchor="w")

        vsb = ttk.Scrollbar(exports_frame, orient="vertical", command=self.exports_tree.yview)
        self.exports_tree.configure(yscroll=vsb.set)

        self.exports_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        exports_frame.grid_rowconfigure(0, weight=1)
        exports_frame.grid_columnconfigure(0, weight=1)

    def _start_capture(self):
        """Start packet capture."""
        if self.capture.start():
            self.is_capturing = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.status_label.config(text="Status: Capturing...", foreground="green")
            messagebox.showinfo("Success", "Packet capture started")
        else:
            messagebox.showerror("Error", "Failed to start capture")

    def _stop_capture(self):
        """Stop packet capture."""
        if self.capture.stop():
            self.is_capturing = False
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.status_label.config(text="Status: Stopped", foreground="red")
            messagebox.showinfo("Success", "Packet capture stopped")

    def _clear_packets(self):
        """Clear captured packets."""
        self.capture.clear_packets()
        self.analyzer.clear_statistics()
        self.detector.clear_threats()
        for item in self.packets_tree.get_children():
            self.packets_tree.delete(item)
        messagebox.showinfo("Success", "Packets cleared")

    def _refresh_packets_display(self):
        """Refresh the packets display."""
        for item in self.packets_tree.delete(item) for item in self.packets_tree.get_children():
            pass

        packets = self.capture.get_packets()
        protocol_filter = self.filter_protocol.get()

        for packet_data in packets:
            parsed = self.parser.parse(packet_data)
            protocols = parsed.get("protocols", [])

            if protocol_filter != "All" and protocol_filter not in protocols:
                continue

            src = parsed.get("src_ip", "Unknown")
            dst = parsed.get("dst_ip", "Unknown")
            protocol = " / ".join(protocols) if protocols else "Unknown"
            length = parsed.get("size", 0)
            info = self.parser.get_summary(parsed)
            timestamp = parsed.get("timestamp", "")

            self.packets_tree.insert(
                "", "end",
                values=(timestamp, src, dst, protocol, length, info)
            )

            # Analyze for threats
            threats = self.detector.analyze(parsed)
            for threat in threats:
                self.detector.threats.append(threat)

            # Update statistics
            self.analyzer.analyze_packet(parsed)

    def _search_packets(self):
        """Search packets by IP."""
        ip = self.search_ip.get()
        if not ip:
            self._refresh_packets_display()
            return

        for item in self.packets_tree.get_children():
            self.packets_tree.delete(item)

        packets = self.capture.get_packets()

        for packet_data in packets:
            parsed = self.parser.parse(packet_data)
            src = parsed.get("src_ip", "")
            dst = parsed.get("dst_ip", "")

            if ip not in (src, dst):
                continue

            src_display = f"{src}:{parsed.get('src_port', '')}" if src else src
            dst_display = f"{dst}:{parsed.get('dst_port', '')}" if dst else dst
            protocol = " / ".join(parsed.get("protocols", ["Unknown"]))
            length = parsed.get("size", 0)
            info = self.parser.get_summary(parsed)
            timestamp = parsed.get("timestamp", "")

            self.packets_tree.insert(
                "", "end",
                values=(timestamp, src_display, dst_display, protocol, length, info)
            )

    def _update_statistics_display(self):
        """Update statistics display."""
        stats = self.analyzer.get_statistics()

        self.stats_text.config(state="normal")
        self.stats_text.delete("1.0", "end")

        text_content = "=" * 100 + "\n"
        text_content += "TRAFFIC STATISTICS\n"
        text_content += "=" * 100 + "\n\n"

        text_content += f"Total Packets: {stats.get('total_packets', 0)}\n"
        text_content += f"Total Bytes: {stats.get('total_bytes', 0):,}\n"
        text_content += f"Average Packet Size: {stats.get('average_packet_size', 0):.2f} bytes\n\n"

        text_content += "PROTOCOL BREAKDOWN\n"
        text_content += "-" * 100 + "\n"
        for protocol, info in stats.get("protocols", {}).items():
            text_content += f"{protocol:20} {info.get('count', 0):10} packets ({info.get('percentage', 0):6.2f}%)\n"

        text_content += "\nTOP IP ADDRESSES\n"
        text_content += "-" * 100 + "\n"
        for ip_info in stats.get("top_ips", []):
            text_content += f"{ip_info['ip']:20} {ip_info['total_bytes']:15,} bytes ({ip_info['packets']:5} packets)\n"

        text_content += "\nTOP PORTS\n"
        text_content += "-" * 100 + "\n"
        for port_info in stats.get("top_ports", [])[:10]:
            text_content += f"Port {port_info['port']:5} ({port_info['service']:15}) {port_info['traffic_count']:10} connections\n"

        self.stats_text.insert("1.0", text_content)
        self.stats_text.config(state="disabled")

    def _update_threats_display(self):
        """Update threats display."""
        self.threats_text.config(state="normal")
        self.threats_text.delete("1.0", "end")

        threats = self.detector.threats

        text_content = "=" * 100 + "\n"
        text_content += "DETECTED THREATS\n"
        text_content += "=" * 100 + "\n\n"

        if threats:
            for threat in threats[-50:]:  # Show last 50 threats
                text_content += f"[{threat.get('severity', 'UNKNOWN')}] {threat.get('type', 'Unknown').upper()}\n"
                text_content += f"  Message: {threat.get('message', 'N/A')}\n"
                text_content += f"  Time: {threat.get('timestamp', 'N/A')}\n"
                if threat.get('source_ip'):
                    text_content += f"  Source: {threat.get('source_ip')}\n"
                text_content += "\n"
        else:
            text_content += "No threats detected.\n"

        self.threats_text.insert("1.0", text_content)
        self.threats_text.config(state="disabled")

    def _export_csv(self):
        """Export packets to CSV."""
        try:
            packets = self.capture.get_packets()
            parsed_packets = [self.parser.parse(p) for p in packets]
            filepath = self.exporter.export_csv(parsed_packets)
            messagebox.showinfo("Success", f"Exported to: {filepath}")
            self._refresh_exports_display()
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    def _export_pcap(self):
        """Export packets to PCAP."""
        try:
            packets = self.capture.get_packets()
            filepath = self.exporter.export_pcap(packets)
            messagebox.showinfo("Success", f"Exported to: {filepath}")
            self._refresh_exports_display()
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    def _generate_report(self):
        """Generate analysis report."""
        try:
            stats = self.analyzer.get_statistics()
            threats = self.detector.threats
            filepath = self.exporter.export_report(stats, threats)
            messagebox.showinfo("Success", f"Report generated: {filepath}")
            self._refresh_exports_display()
        except Exception as e:
            messagebox.showerror("Error", f"Report generation failed: {e}")

    def _export_threats(self):
        """Export detected threats."""
        try:
            threats = self.detector.threats
            filepath = self.exporter.export_threat_report(threats)
            messagebox.showinfo("Success", f"Threats exported to: {filepath}")
            self._refresh_exports_display()
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    def _refresh_exports_display(self):
        """Refresh exports list."""
        for item in self.exports_tree.get_children():
            self.exports_tree.delete(item)

        exports = self.exporter.list_exports()
        for export in exports:
            self.exports_tree.insert(
                "", "end",
                values=(export["name"], export["size"], export["modified"])
            )

    def _start_update_thread(self):
        """Start background update thread."""
        def update_loop():
            while True:
                self._refresh_packets_display()
                self._update_statistics_display()
                self._update_threats_display()
                self._refresh_exports_display()
                self.root.after(2000)

        Thread(target=update_loop, daemon=True).start()

    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    """Main entry point for GUI."""
    root = tk.Tk()
    app = AnalyzerGUI(root)
    app.run()


if __name__ == "__main__":
    main()
