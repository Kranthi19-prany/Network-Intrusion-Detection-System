import json
from collections import Counter
import matplotlib.pyplot as plt

mock_logs = [
    '{"event_type":"alert","src_ip":"192.168.1.10","dest_ip":"192.168.1.1","alert":{"signature":"Suspicious HTTP Login Attempt"}}',
    '{"event_type":"alert","src_ip":"192.168.1.11","dest_ip":"192.168.1.1","alert":{"signature":"Suspicious HTTP Login Attempt"}}',
    '{"event_type":"alert","src_ip":"192.168.1.12","dest_ip":"192.168.1.1","alert":{"signature":"ICMP Ping Sweep Detected"}}',
    '{"event_type":"alert","src_ip":"192.168.1.13","dest_ip":"192.168.1.1","alert":{"signature":"ICMP Ping Sweep Detected"}}',
    '{"event_type":"alert","src_ip":"192.168.1.14","dest_ip":"192.168.1.1","alert":{"signature":"Malicious FTP Login Attempt"}}',
    '{"event_type":"alert","src_ip":"192.168.1.15","dest_ip":"192.168.1.1","alert":{"signature":"Suspicious HTTP Login Attempt"}}'
]
import json
from collections import Counter

# Step 2: Parse alert signatures
signatures = []

for line in mock_logs:
    try:
        event = json.loads(line)
        if event.get("event_type") == "alert":
            sig = event["alert"]["signature"]
            signatures.append(sig)
    except json.JSONDecodeError:
        continue
# Step 4: Simple response mechanism (block IPs with repeated alerts)
blocked_ips = {}
for line in mock_logs:
    event = json.loads(line)
    ip = event.get("src_ip")
    if ip in blocked_ips:
        blocked_ips[ip] += 1
    else:
        blocked_ips[ip] = 1

# Block IPs that triggered more than 1 alert
for ip, count in blocked_ips.items():
    if count > 1:
        print(f"[RESPONSE] Blocking IP: {ip} (Triggered {count} alerts)")
import matplotlib.pyplot as plt

# Step 5: Visualization
count = Counter(signatures)
labels, values = zip(*count.items())

plt.figure(figsize=(10, 6))
plt.barh(labels, values, color='darkorange')
plt.xlabel("Number of Alerts")
plt.title("Detected Intrusions (Suricata Log Simulation)")
plt.tight_layout()
plt.show()
