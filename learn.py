import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
# Assuming we have a dataset containing network traffic characteristics and labels
# The dataset contains the following characteristics: traffic size, protocol type, source IP, destination IP, port number, etc
# Tag: 0 represents normal traffic, 1 represents attack traffic
# Read the dataset
data = pd.read_csv('network_traffic.csv')
# Features and labels
X = data.drop('label', axis=1)
y = data['label']
# Divide the training set and testing set
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
# Create model pipeline
pipeline = Pipeline([
          ('scaler', StandardScaler()),  # data standardization
          ('classifier', RandomForestClassifier(n_estimators=100, random_state=42)) # random forest classifier
            ])
# training model
pipeline.fit(X_train, y_train)
# Predictive testing set
y_pred = pipeline.predict(X_test)
# evaluation model
print(classification_report(y_test, y_pred))
# Example: Predicting new data
new_data = pd.DataFrame([[1500, 6, 192, 168, 1, 100, 80]],  # sample data
           columns=['bytes', 'protocol', 'src_ip1', 'src_ip2', 'dst_ip1', 'dst_ip2', 'port'])
prediction = pipeline.predict(new_data)
print("Predicted label:", prediction)
def detect_attacks(packet):
   # Check whether it is a TCP packet
    if packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        # Detect SYN Flood Attack
        if packet[TCP].flags == 'S':  # SYNFlag setting
            current_time = time.time()
            syn_counter[ip_src] += 1

           # Check once per second
            if int(current_time) > int(last_alert_time.get('syn_flood', 0)):
                if syn_counter[ip_src] > THRESHOLD_SYN_FLOOD:
                   alert_msg = f"[!] Potential SYN Flood attack detected! Source ip: {ip_src} (SYN package: {syn_counter[ip_src]}/s)"
                   print(alert_msg)
                   log_attack("SYN_FLOOD", ip_src, ip_dst, alert_msg)
               # Reset counter
                syn_counter.clear()
                last_alert_time['syn_flood'] = current_time
        # Detect port scan
        if packet[TCP].flags == 'S':  # Detect port scan
            port_scan_key = (ip_src, ip_dst)
            port_scan_stats[port_scan_key].add(dst_port)
            # If multiple ports are scanned
            if len(port_scan_stats[port_scan_key]) > THRESHOLD_PORT_SCAN:
                alert_msg = f"[!] Potential port scan detected! Source ip: {ip\u src} destination ip: {ip\u dst} (number of scan ports: {len(port_scan_stats[port_scan_key])})"
                print(alert_msg)
                log_attack("PORT_SCAN", ip_src, ip_dst, alert_msg)
                # Reset statistics
                del port_scan_stats[port_scan_key]
if __name__ == "__main__":
    main()

