from scapy.all import sniff, wrpcap
import schedule
import time
from datetime import datetime

def capture_packets():
    print("Starting packet capture...")
    packets = sniff(timeout=180)
    filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    wrpcap(filename, packets)
    print(f"Packet capture complete. Saved to {filename}")

# Schedule the packet capture to run every 24 hours starting at 08:00 AM
schedule.every().day.at("08:00").do(capture_packets)

print("Scheduler started. Waiting for the next scheduled task...")
while True:
    schedule.run_pending()
    time.sleep(1)