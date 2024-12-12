## traffic-analyzer-qos
Kernel module uses Netfilter framework to capture network packets. Extracts and logs info: source/destination ips, ports, and packet sizes. Will be added support for filtering traffic by protocol TCP, UDP. 

+QT app to:
- Display live traffic statistics (charts (bar/line) for bandwidth usage).
- Tweaks for user to set QoS rules like prioritizing certain traffic types.