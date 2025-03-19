from scapy.all import sniff
import threading
import schedule
import time

def packet_callback(packet):
    print(packet.show())

def stop_sniffing():
    global sniffing
    sniffing = False

def start_sniffing():
    global sniffing
    # Define and set the timeout duration in seconds
    timeout_duration = 180

    # Start a timer to stop sniffing after the timeout duration
    sniffing = True
    timer = threading.Timer(timeout_duration, stop_sniffing)
    timer.start()

    # Capture packets on the default network interface
    sniff(prn=packet_callback, stop_filter=lambda x: not sniffing)

# Schedule the packet capture to run at the same time every day (e.g., 14:00)
schedule.every().day.at("08:00").do(start_sniffing)

while True:
    schedule.run_pending()
    time.sleep(1)




