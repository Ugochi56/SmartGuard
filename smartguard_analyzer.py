import pandas as pd
import matplotlib.pyplot as plt
import os
import uuid

def analyze_network_capture(file_path):
    try:
        df = pd.read_csv(file_path)
        total_packets = len(df)

        suspicious_ips = {}
        vulnerabilities = {}

        for _, row in df.iterrows():
            src = row.get('Source')
            protocol = row.get('Protocol')
            info = row.get('Info', '')

            if protocol in ['ICMP', 'TCP', 'UDP'] and 'malformed' in info.lower():
                suspicious_ips[src] = suspicious_ips.get(src, 0) + 1
                vulnerabilities[src] = vulnerabilities.get(src, []) + [f"Suspicious {protocol} packet"]

            elif 'dns' in protocol.lower() and 'query' in info.lower():
                if 'ANY' in info:
                    suspicious_ips[src] = suspicious_ips.get(src, 0) + 1
                    vulnerabilities[src] = vulnerabilities.get(src, []) + ['Potential DNS amplification']

        return {
            'total_packets': total_packets,
            'suspicious_ips': suspicious_ips,
            'vulnerabilities': vulnerabilities
        }
    except Exception as e:
        return {
            'total_packets': 0,
            'suspicious_ips': {},
            'vulnerabilities': {},
            'error': str(e)
        }

def generate_graph(vulnerabilities, output_dir):
    if not vulnerabilities:
        return ""

    ip_list = list(vulnerabilities.keys())
    vuln_counts = [len(vulnerabilities[ip]) for ip in ip_list]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(ip_list, vuln_counts, color='coral', edgecolor='black')

    ax.set_xlabel('IP Addresses')
    ax.set_ylabel('Number of Vulnerabilities')
    ax.set_title('Vulnerabilities Detected Per IP')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    # Label bars with count
    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, yval + 0.1, int(yval), ha='center', va='bottom')

    filename = f"vuln_graph_{uuid.uuid4().hex}.png"
    path = os.path.join(output_dir, filename)
    plt.savefig(path)
    plt.close()
    return path
