from scapy.all import sniff, wrpcap, get_if_list
import schedule
import time
from datetime import datetime

def capture_packets(interface):
    print(f"Starting packet capture on interface {interface}...")
    packets = sniff(iface=interface, timeout=180)
    filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    wrpcap(filename, packets)
    print(f"Packet capture complete. Saved to {filename}")

# Specify the network interface you want to capture packets on
network_interface = "Wi-Fi"  # Replace with your desired interface

# Schedule the packet capture to run every 24 hours starting at 08:00 AM
schedule.every().day.at("08:00").do(capture_packets, interface=network_interface)

print("Scheduler started. Waiting for the next scheduled task...")
while True:
    schedule.run_pending()
    time.sleep(1)
