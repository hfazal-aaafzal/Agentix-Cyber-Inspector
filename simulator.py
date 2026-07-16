import time
import csv
import datetime
import random

# File that our Streamlit app is reading
LOG_FILE = "live_network_logs.csv"

# Write the CSV header first
with open(LOG_FILE, mode='w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["Timestamp", "IP Address", "Protocol", "Packet Size (KB)", "Requests/sec"])

print("🟢 Live Web Traffic Simulator Started...")

# Keep generating live traffic endlessly until stopped
while True:
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Simulate a user IP
    ip_address = f"192.168.1.{random.randint(1, 254)}"
    
    # Occasionally trigger an attack from your blocklist to show off the system!
    if random.random() < 0.05:
        ip_address = "192.168.1.99"  # Blocked IP
        
    protocol = random.choice(["HTTPS", "HTTP", "TCP", "UDP"])
    packet_size = round(random.normalvariate(400, 100), 2)
    requests_sec = random.randint(10, 50)
    
    # Occasionally trigger a massive payload size violation
    if random.random() < 0.05:
        packet_size = 4500  # Exceeds max payload threshold
        
    with open(LOG_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, ip_address, protocol, packet_size, requests_sec])
        
    print(f"[{timestamp}] Sent packet from {ip_address} | {packet_size} KB | {protocol}")
    time.sleep(2) # Sends a new "live" packet every 2 seconds