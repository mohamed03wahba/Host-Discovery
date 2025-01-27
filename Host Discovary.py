import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel,
    QLineEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QProgressBar
)
from PyQt6.QtCore import QThread, pyqtSignal , Qt
from scapy.all import ARP, Ether, srp, IP, TCP, UDP, sr1, conf
import socket
import ipaddress
from datetime import datetime
from fpdf import FPDF
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

# Scanning worker class to run ARP and port scans 
class ScanWorker(QThread):
    scan_results = pyqtSignal(list)  # Signal to send data back to the GUI
    update_progress = pyqtSignal(int)  # Signal to update progress

    def __init__(self, ip_range):
        super().__init__()
        self.ip_range = ip_range
        self.ports_to_scan = [22, 80, 443, 53, 445]  # Predefined list of ports to scan
        self.mac_vendor_dict = self.load_mac_vendors()
    

    def load_mac_vendors(self):
        """Load MAC vendor information from a text file."""
        vendor_dict = {}
        try:
            # Open the text file
            with open('mac_vendors.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    # Strip any surrounding whitespace and split the line using " - "
                    line_parts = line.strip().split(' - ')
                    if len(line_parts) == 3:  # Ensure there are 3 parts in the line
                        mac_prefix = line_parts[1].strip().lower()  # Extract the prefix from the example
                        vendor_name = line_parts[2].strip()
                        vendor_dict[mac_prefix] = vendor_name

        except FileNotFoundError:
            print("MAC vendor text file not found. Please ensure 'mac_vendors.txt' is in the same directory.")
        except Exception as e:
            print(f"Error reading text file: {e}")
        
        return vendor_dict


    def get_mac_vendor(self, mac_address):
        """Fetch the vendor name from the preloaded dictionary."""
        mac_prefix = mac_address.lower()[:8]  # Get the first 8 characters (including colons)
        return self.mac_vendor_dict.get(mac_prefix, "Unknown Vendor")

    def run(self):
        devices_list = self.arp_scan(self.ip_range)
        total_devices = len(devices_list)
        for index, device in enumerate(devices_list):
            device["ports"] = self.scan_ports(device["ip"], self.ports_to_scan)
            # Update progress
            self.update_progress.emit(int(((index + 1) / total_devices) * 100))
        self.scan_results.emit(devices_list)  # Emit results when scan is done

    def arp_scan(self, ip_range):
        """Perform an ARP scan on the specified IP range."""
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=.05, verbose=False)[0]
        devices_list = []

        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc

            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = "Unknown"

            vendor = self.get_mac_vendor(mac)
            devices_list.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})

        return devices_list

    def scan_ports(self, ip, ports):
        """Scan the specified ports using TCP SYN, TCP ACK, and UDP."""
        port_results = []
        for port in ports:
            syn_result = self.tcp_syn_scan(ip, port)
            ack_result = self.tcp_ack_scan(ip, port)
            udp_result = self.udp_scan(ip, port)
            most_accurate = self.compare_results(syn_result, ack_result, udp_result)
            port_results.append(f"Port {port}: {most_accurate}")
        return port_results

    def compare_results(self, syn_result, ack_result, udp_result):
        """Compare TCP SYN, TCP ACK, and UDP results and determine the most accurate."""
        if "open" in syn_result:
            return syn_result  # TCP SYN is most reliable for detecting open ports
        elif "closed" in ack_result:
            return ack_result  # TCP ACK is reliable for confirming closed ports
        elif "open" in udp_result:
            return udp_result  # UDP can help identify open UDP ports
        return syn_result  # Fallback to SYN scan result if unsure

    def tcp_syn_scan(self, ip, port):
        """Send a TCP SYN packet and check the response."""
        conf.verb = 0
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=False)

        if resp is None:
            return f"{port}: filtered or no response"
        elif resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            return f"{port}: open"
        else:
            return f"{port}: closed"

    def tcp_ack_scan(self, ip, port):
        """Send a TCP ACK packet and check the response."""
        conf.verb = 0
        pkt = IP(dst=ip) / TCP(dport=port, flags="A")
        resp = sr1(pkt, timeout=1, verbose=False)

        if resp is None:
            return f"{port}: filtered or no response"
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x14:
                return f"{port}: closed"
            else:
                return f"{port}: open or filtered"
        else:
            return f"{port}: filtered or no response"

    def udp_scan(self, ip, port):
        """Send a UDP packet and check the response."""
        conf.verb = 0
        pkt = IP(dst=ip) / UDP(dport=port)
        resp = sr1(pkt, timeout=1, verbose=False)

        if resp is None:
            return f"{port}: open or filtered (no response)"
        elif resp.haslayer(UDP):
            return f"{port}: open (UDP response received)"
        else:
            return f"{port}: closed (ICMP response received)"

# Main Window class
class NetworkScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Network Discovery')
        self.setGeometry(100, 100, 800, 600)

        # Main layout: Vertical layout for the whole UI
        main_layout = QVBoxLayout()

        # Input field for IP range
        self.ip_range_label = QLabel('Enter IP Range:')
        main_layout.addWidget(self.ip_range_label)
        self.ip_range_input = QLineEdit(self)
        main_layout.addWidget(self.ip_range_input)

        # Button to start scan
        self.scan_button = QPushButton('Start Scan')
        self.scan_button.clicked.connect(self.start_scan)
        main_layout.addWidget(self.scan_button)

        # Progress bar for scan progress
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)

        # Table to show scan results
        self.table = QTableWidget(self)
        self.table.setColumnCount(4)  # Only 4 columns now
        self.table.setHorizontalHeaderLabels(['IP Address', 'MAC Address', 'Vendor', 'Hostname'])

        # Set all columns to equal size
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        # Add the table to the layout
        main_layout.addWidget(self.table)

        # Status labels for total hosts, up hosts, down hosts
        self.total_hosts_label = QLabel('Total Hosts: 0')
        self.up_hosts_label = QLabel('Up Hosts: 0')
        self.down_hosts_label = QLabel('Down Hosts: 0')

        main_layout.addWidget(self.total_hosts_label)
        main_layout.addWidget(self.up_hosts_label)
        main_layout.addWidget(self.down_hosts_label)

        # Matplotlib figure for the pie chart
        self.figure = plt.Figure()
        self.canvas = FigureCanvas(self.figure)
        main_layout.addWidget(self.canvas)

        self.download_pdf_button = QPushButton('Download PDF Report')
        self.download_pdf_button.setEnabled(False)
        self.download_pdf_button.clicked.connect(self.generate_pdf_report)
        main_layout.addWidget(self.download_pdf_button)

        # Set the main layout
        self.setLayout(main_layout)

        self.total_hosts = 0
        self.up_hosts = 0

    def show_message(self, title, message):
        """Show a message box with the given title and message."""
        message_box = QMessageBox()
        message_box.setWindowTitle(title)
        message_box.setText(message)
        message_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        message_box.exec()

    def start_scan(self):
        ip_range = self.ip_range_input.text()

        if not ip_range:
            self.show_message("Input Error", "Enter an IP range first.")
            return

        try:
            # Validate IP range using ipaddress module
            ip_network = ipaddress.IPv4Network(ip_range, strict=False)
        except ValueError:
            if '/' in ip_range:
                # Invalid subnet mask
                self.show_message("Invalid Mask", "Enter a valid subnet mask.")
            else:
                # Invalid IP range
                self.show_message("Invalid IP Range", "Enter a valid IP range.")
            return

        # Disable the scan button and input field while scanning
        self.scan_button.setEnabled(False)
        self.ip_range_input.setEnabled(False)
        self.progress_bar.setValue(0)  # Reset progress bar
        self.download_pdf_button.setEnabled(False)

        # If both IP range is valid, proceed with the scan
        self.scan_worker = ScanWorker(ip_range)
        self.scan_worker.scan_results.connect(self.display_results)
        self.scan_worker.update_progress.connect(self.update_progress)  # Connect the progress update
        self.scan_worker.finished.connect(self.scan_finished)  # Connect the finished signal to a slot
        self.scan_worker.start()

    def display_results(self, devices):
        # Clear existing rows
        self.table.setRowCount(0)

        # Populate the table with new results
        for i, device in enumerate(devices):
            self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(device['ip']))
            self.table.setItem(i, 1, QTableWidgetItem(device['mac']))
            self.table.setItem(i, 2, QTableWidgetItem(device['vendor']))
            self.table.setItem(i, 3, QTableWidgetItem(device['hostname']))

            for j in range(4):  # 4 columns in total
                item = self.table.item(i, j)
                item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
        
        # Update host statistics
        self.total_hosts = len(list(ipaddress.IPv4Network(self.ip_range_input.text()).hosts()))
        self.up_hosts = len(devices)
        down_hosts = self.total_hosts - self.up_hosts

        self.total_hosts_label.setText(f"Total Hosts: {self.total_hosts}")
        self.up_hosts_label.setText(f"Up Hosts: {self.up_hosts}")
        self.down_hosts_label.setText(f"Down Hosts: {down_hosts}")

        # Update the pie chart
        self.update_graph()

    def update_progress(self, value):
        """Update the progress bar with the current value."""
        self.progress_bar.setValue(value)

    def update_graph(self):
        """Update the graph with total hosts, up hosts, and down hosts."""
        down_hosts = self.total_hosts - self.up_hosts
        sizes = [self.up_hosts, down_hosts]
        labels = ['Up Hosts', 'Down Hosts']
        colors = ['#1E90FF', '#FF6347']  # Blue for up hosts, red for down hosts

        # Clear the previous plot
        self.figure.clear()

        # Create a pie chart with improved aesthetics
        ax = self.figure.add_subplot(111)
        
        # Adding shadow and better design to the pie chart
        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90,
            shadow=True, explode=(0.1, 0), wedgeprops={'edgecolor': 'black', 'linewidth': 1}
        )

        # Customize the appearance of the text in the pie chart
        for text in texts:
            text.set_color('black')
            text.set_fontsize(10)
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontsize(8)

        # Add a legend to the side of the chart
        ax.legend(wedges, labels, title="Host Status", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
        
        # Set the title with improved styling
        ax.set_title('Host Status on the Network', color='k', fontsize=14, fontweight='bold')

        # Equal aspect ratio ensures that pie chart is a circle
        ax.axis('equal')

        # Refresh the canvas
        self.canvas.draw()
    def scan_finished(self):
        """Handle tasks to be performed when the scan finishes."""
        # Re-enable the scan button and input field
        self.scan_button.setEnabled(True)
        self.ip_range_input.setEnabled(True)
        self.download_pdf_button.setEnabled(True)
        self.show_message("Scan Completed", "Host scan completed successfully.")

    def generate_pdf_report(self):
        """Generate a PDF report with company details, scan results, date/time, and graph."""
        pdf = FPDF()
        pdf.add_page()
        
        # Title and company details
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Host Discovery Report", ln=True, align="C")
        pdf.set_font("Arial", "I", 10)
        pdf.cell(0, 10, f"Date and Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")

        # Date and time of scan
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Spiders", ln=True, align="R")

        # Select and add company logo in the top right corner
        logo_path = r'D:\\Project wahba\\poto.png'  # Predefined path for the logo
        if logo_path and os.path.exists(logo_path):
            pdf.image(logo_path, x=160, y=5, w=30)  # Adjust x, y, and width (w) as needed for your logo's size

        # Scan summary
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Scan Summary", ln=True, align="L")
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 10, f"Total Hosts: {self.total_hosts}", ln=True)
        pdf.cell(0, 10, f"Up Hosts: {self.up_hosts}", ln=True)
        pdf.cell(0, 10, f"Down Hosts: {self.total_hosts - self.up_hosts}", ln=True)

        # Table of results
        pdf.set_font("Arial", "B", 10)
        pdf.cell(40, 10, "IP Address", border=1)
        pdf.cell(40, 10, "MAC Address", border=1)
        pdf.cell(40, 10, "Vendor", border=1)
        pdf.cell(40, 10, "Hostname", border=1)
        pdf.ln()
        pdf.set_font("Arial", "", 8)
        
        for row in range(self.table.rowCount()):
            pdf.cell(40, 10, self.table.item(row, 0).text(), border=1)
            pdf.cell(40, 10, self.table.item(row, 1).text(), border=1)
            pdf.cell(40, 10, self.table.item(row, 2).text(), border=1)
            pdf.cell(40, 10, self.table.item(row, 3).text(), border=1)
            pdf.ln()

        # Insert graph into PDF
        graph_filename = "host_status_graph.png"
        self.figure.savefig(graph_filename)  # Save current figure to file
        pdf.image(graph_filename, x=10, y=None, w=190)  # Insert graph image

        # Save PDF
        pdf_file_name = f"host_discovery_report.pdf"
        pdf.output(pdf_file_name)
        QMessageBox.information(self, "PDF Saved", f"Report saved as {pdf_file_name}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NetworkScannerApp()
    window.show()
    sys.exit(app.exec())
