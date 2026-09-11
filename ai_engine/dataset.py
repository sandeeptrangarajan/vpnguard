import os
import numpy as np
import pandas as pd
from .features import FEATURE_NAMES

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DATASET_PATH = os.path.join(DATA_DIR, "vpn_traffic_dataset.csv")

TRAFFIC_CLASSES = [
    "Web browsing",
    "VoIP",
    "Video streaming",
    "Messaging",
    "File transfer",
    "ICMP/ping",
    "Tunnel keep-alive"
]

def generate_synthetic_testbed_dataset(n_samples_per_class=200, random_state=42):
    """
    Generates a realistic, labeled training dataset derived from controlled IPsec VPN testbed behavior profiles.
    Ground-truth labels correspond to known protocol and traffic generator profiles.
    """
    np.random.seed(random_state)
    records = []

    for _ in range(n_samples_per_class):
        # 1. VoIP Profile (G.711 / Opus over ESP/UDP)
        # Small fixed packets, steady 20ms IAT (~50 pps), symmetric 1:1
        pkt_cnt = np.random.randint(200, 2000)
        dur = pkt_cnt / 50.0 + np.random.uniform(-0.5, 0.5)
        avg_sz = np.random.normal(200, 15)
        min_sz = max(60, avg_sz - np.random.uniform(20, 40))
        max_sz = avg_sz + np.random.uniform(20, 40)
        std_sz = np.random.uniform(5, 20)
        avg_iat = 0.02 + np.random.normal(0, 0.003)
        std_iat = np.random.uniform(0.001, 0.005)
        pps = pkt_cnt / max(1.0, dur)
        bps = (pkt_cnt * avg_sz) / max(1.0, dur)
        fwd_cnt = pkt_cnt // 2 + np.random.randint(-5, 5)
        rev_cnt = max(1, pkt_cnt - fwd_cnt)
        fwd_ratio = fwd_cnt / rev_cnt
        bursts = np.random.randint(1, 10)
        avg_burst = pkt_cnt / max(1, bursts)
        records.append({
            "packet_count": pkt_cnt, "total_bytes": pkt_cnt * avg_sz, "duration_seconds": dur,
            "avg_packet_size": avg_sz, "min_packet_size": min_sz, "max_packet_size": max_sz,
            "packet_size_std": std_sz, "avg_inter_arrival_time": avg_iat, "inter_arrival_time_std": std_iat,
            "packets_per_second": pps, "bytes_per_second": bps, "forward_packet_count": fwd_cnt,
            "reverse_packet_count": rev_cnt, "forward_reverse_ratio": fwd_ratio, "burst_count": bursts,
            "avg_burst_size": avg_burst, "esp_packet_count": pkt_cnt, "ike_packet_count": 0,
            "ah_packet_count": 0, "tcp_packet_count": 0, "udp_packet_count": pkt_cnt,
            "unique_endpoints_count": 1, "unique_spi_count": 2, "label": "VoIP", "is_anomaly": 0
        })

        # 2. Video Streaming Profile (High throughput, near-MTU packets ~1350-1420B, bursty downloads)
        pkt_cnt = np.random.randint(1000, 15000)
        dur = np.random.uniform(10.0, 120.0)
        avg_sz = np.random.normal(1280, 80)
        min_sz = 80
        max_sz = 1420
        std_sz = np.random.uniform(200, 350)
        avg_iat = dur / pkt_cnt
        std_iat = np.random.uniform(0.01, 0.08)
        pps = pkt_cnt / max(1.0, dur)
        bps = (pkt_cnt * avg_sz) / max(1.0, dur)
        fwd_cnt = int(pkt_cnt * np.random.uniform(0.1, 0.2)) # ACKs upstream
        rev_cnt = pkt_cnt - fwd_cnt                          # Video downstream
        fwd_ratio = fwd_cnt / max(1, rev_cnt)
        bursts = np.random.randint(15, 60)
        avg_burst = pkt_cnt / max(1, bursts)
        records.append({
            "packet_count": pkt_cnt, "total_bytes": pkt_cnt * avg_sz, "duration_seconds": dur,
            "avg_packet_size": avg_sz, "min_packet_size": min_sz, "max_packet_size": max_sz,
            "packet_size_std": std_sz, "avg_inter_arrival_time": avg_iat, "inter_arrival_time_std": std_iat,
            "packets_per_second": pps, "bytes_per_second": bps, "forward_packet_count": fwd_cnt,
            "reverse_packet_count": rev_cnt, "forward_reverse_ratio": fwd_ratio, "burst_count": bursts,
            "avg_burst_size": avg_burst, "esp_packet_count": pkt_cnt, "ike_packet_count": 0,
            "ah_packet_count": 0, "tcp_packet_count": pkt_cnt, "udp_packet_count": 0,
            "unique_endpoints_count": 2, "unique_spi_count": 2, "label": "Video streaming", "is_anomaly": 0
        })

        # 3. Web Browsing Profile (HTTPS/TCP interactive bursts, asymmetric, moderate sizes)
        pkt_cnt = np.random.randint(100, 3000)
        dur = np.random.uniform(5.0, 60.0)
        avg_sz = np.random.normal(820, 120)
        min_sz = 60
        max_sz = 1420
        std_sz = np.random.uniform(350, 500)
        avg_iat = dur / pkt_cnt
        std_iat = np.random.uniform(0.05, 0.3)
        pps = pkt_cnt / max(1.0, dur)
        bps = (pkt_cnt * avg_sz) / max(1.0, dur)
        fwd_cnt = int(pkt_cnt * np.random.uniform(0.3, 0.45))
        rev_cnt = pkt_cnt - fwd_cnt
        fwd_ratio = fwd_cnt / max(1, rev_cnt)
        bursts = np.random.randint(8, 40)
        avg_burst = pkt_cnt / max(1, bursts)
        records.append({
            "packet_count": pkt_cnt, "total_bytes": pkt_cnt * avg_sz, "duration_seconds": dur,
            "avg_packet_size": avg_sz, "min_packet_size": min_sz, "max_packet_size": max_sz,
            "packet_size_std": std_sz, "avg_inter_arrival_time": avg_iat, "inter_arrival_time_std": std_iat,
            "packets_per_second": pps, "bytes_per_second": bps, "forward_packet_count": fwd_cnt,
            "reverse_packet_count": rev_cnt, "forward_reverse_ratio": fwd_ratio, "burst_count": bursts,
            "avg_burst_size": avg_burst, "esp_packet_count": pkt_cnt, "ike_packet_count": 0,
            "ah_packet_count": 0, "tcp_packet_count": pkt_cnt, "udp_packet_count": 0,
            "unique_endpoints_count": 4, "unique_spi_count": 2, "label": "Web browsing", "is_anomaly": 0
        })

        # 4. File Transfer Profile (FTP/SFTP/SMB: continuous max MTU frames, very high bps)
        pkt_cnt = np.random.randint(2000, 25000)
        dur = np.random.uniform(10.0, 100.0)
        avg_sz = np.random.normal(1390, 30)
        min_sz = 70
        max_sz = 1420
        std_sz = np.random.uniform(100, 200)
        avg_iat = dur / pkt_cnt
        std_iat = np.random.uniform(0.001, 0.01)
        pps = pkt_cnt / max(1.0, dur)
        bps = (pkt_cnt * avg_sz) / max(1.0, dur)
        fwd_cnt = int(pkt_cnt * np.random.uniform(0.85, 0.95)) # Heavy upload
        rev_cnt = pkt_cnt - fwd_cnt
        fwd_ratio = fwd_cnt / max(1, rev_cnt)
        bursts = np.random.randint(5, 20)
        avg_burst = pkt_cnt / max(1, bursts)
        records.append({
            "packet_count": pkt_cnt, "total_bytes": pkt_cnt * avg_sz, "duration_seconds": dur,
            "avg_packet_size": avg_sz, "min_packet_size": min_sz, "max_packet_size": max_sz,
            "packet_size_std": std_sz, "avg_inter_arrival_time": avg_iat, "inter_arrival_time_std": std_iat,
            "packets_per_second": pps, "bytes_per_second": bps, "forward_packet_count": fwd_cnt,
            "reverse_packet_count": rev_cnt, "forward_reverse_ratio": fwd_ratio, "burst_count": bursts,
            "avg_burst_size": avg_burst, "esp_packet_count": pkt_cnt, "ike_packet_count": 0,
            "ah_packet_count": 0, "tcp_packet_count": pkt_cnt, "udp_packet_count": 0,
            "unique_endpoints_count": 1, "unique_spi_count": 2, "label": "File transfer", "is_anomaly": 0
        })

        # 5. Messaging Profile (Low volume, small packets ~100B, sporadic bursts)
        pkt_cnt = np.random.randint(20, 300)
        dur = np.random.uniform(10.0, 180.0)
        avg_sz = np.random.normal(140, 25)
        min_sz = 70
        max_sz = 350
        std_sz = np.random.uniform(20, 60)
        avg_iat = dur / pkt_cnt
        std_iat = np.random.uniform(0.5, 3.0)
        pps = pkt_cnt / max(1.0, dur)
        bps = (pkt_cnt * avg_sz) / max(1.0, dur)
        fwd_cnt = int(pkt_cnt * np.random.uniform(0.4, 0.6))
        rev_cnt = pkt_cnt - fwd_cnt
        fwd_ratio = fwd_cnt / max(1, rev_cnt)
        bursts = np.random.randint(3, 15)
        avg_burst = pkt_cnt / max(1, bursts)
        records.append({
            "packet_count": pkt_cnt, "total_bytes": pkt_cnt * avg_sz, "duration_seconds": dur,
            "avg_packet_size": avg_sz, "min_packet_size": min_sz, "max_packet_size": max_sz,
            "packet_size_std": std_sz, "avg_inter_arrival_time": avg_iat, "inter_arrival_time_std": std_iat,
            "packets_per_second": pps, "bytes_per_second": bps, "forward_packet_count": fwd_cnt,
            "reverse_packet_count": rev_cnt, "forward_reverse_ratio": fwd_ratio, "burst_count": bursts,
            "avg_burst_size": avg_burst, "esp_packet_count": pkt_cnt, "ike_packet_count": 0,
            "ah_packet_count": 0, "tcp_packet_count": 0, "udp_packet_count": pkt_cnt,
            "unique_endpoints_count": 2, "unique_spi_count": 2, "label": "Messaging", "is_anomaly": 0
        })

        # 6. ICMP/Ping Profile (Small fixed 74-98B, periodic 1s, exact 1:1)
        pkt_cnt = np.random.randint(10, 200)
        dur = float(pkt_cnt // 2)
        avg_sz = 84.0 + np.random.choice([0, 14])
        min_sz = avg_sz
        max_sz = avg_sz
        std_sz = 0.0
        avg_iat = 0.5 + np.random.normal(0, 0.01)
        std_iat = 0.005
        pps = pkt_cnt / max(1.0, dur)
        bps = (pkt_cnt * avg_sz) / max(1.0, dur)
        fwd_cnt = pkt_cnt // 2
        rev_cnt = pkt_cnt // 2
        fwd_ratio = 1.0
        bursts = pkt_cnt
        avg_burst = 1.0
        records.append({
            "packet_count": pkt_cnt, "total_bytes": pkt_cnt * avg_sz, "duration_seconds": dur,
            "avg_packet_size": avg_sz, "min_packet_size": min_sz, "max_packet_size": max_sz,
            "packet_size_std": std_sz, "avg_inter_arrival_time": avg_iat, "inter_arrival_time_std": std_iat,
            "packets_per_second": pps, "bytes_per_second": bps, "forward_packet_count": fwd_cnt,
            "reverse_packet_count": rev_cnt, "forward_reverse_ratio": fwd_ratio, "burst_count": bursts,
            "avg_burst_size": avg_burst, "esp_packet_count": 0, "ike_packet_count": 0,
            "ah_packet_count": 0, "tcp_packet_count": 0, "udp_packet_count": 0,
            "unique_endpoints_count": 1, "unique_spi_count": 0, "label": "ICMP/ping", "is_anomaly": 0
        })

        # 7. Tunnel Keep-alive / DPD Profile (Small periodic NAT-T/ISAKMP keep-alives)
        pkt_cnt = np.random.randint(6, 60)
        dur = np.random.uniform(60.0, 600.0)
        avg_sz = np.random.normal(92, 10)
        min_sz = 78
        max_sz = 120
        std_sz = 8.0
        avg_iat = dur / pkt_cnt
        std_iat = 0.2
        pps = pkt_cnt / max(1.0, dur)
        bps = (pkt_cnt * avg_sz) / max(1.0, dur)
        fwd_cnt = pkt_cnt // 2
        rev_cnt = pkt_cnt - fwd_cnt
        fwd_ratio = 1.0
        bursts = pkt_cnt // 2
        avg_burst = 2.0
        records.append({
            "packet_count": pkt_cnt, "total_bytes": pkt_cnt * avg_sz, "duration_seconds": dur,
            "avg_packet_size": avg_sz, "min_packet_size": min_sz, "max_packet_size": max_sz,
            "packet_size_std": std_sz, "avg_inter_arrival_time": avg_iat, "inter_arrival_time_std": std_iat,
            "packets_per_second": pps, "bytes_per_second": bps, "forward_packet_count": fwd_cnt,
            "reverse_packet_count": rev_cnt, "forward_reverse_ratio": fwd_ratio, "burst_count": bursts,
            "avg_burst_size": avg_burst, "esp_packet_count": 0, "ike_packet_count": pkt_cnt,
            "ah_packet_count": 0, "tcp_packet_count": 0, "udp_packet_count": pkt_cnt,
            "unique_endpoints_count": 1, "unique_spi_count": 1, "label": "Tunnel keep-alive", "is_anomaly": 0
        })

    # Add Anomalous Samples (High rate flood, excessive entropy, random bursts)
    for _ in range(n_samples_per_class // 4):
        pkt_cnt = np.random.randint(5000, 50000)
        dur = np.random.uniform(1.0, 10.0)
        avg_sz = np.random.uniform(100, 1400)
        min_sz = 40
        max_sz = 1500
        std_sz = np.random.uniform(400, 700)
        avg_iat = 0.0001
        std_iat = 0.0005
        pps = pkt_cnt / max(0.1, dur)
        bps = (pkt_cnt * avg_sz) / max(0.1, dur)
        fwd_cnt = int(pkt_cnt * 0.99)
        rev_cnt = max(1, pkt_cnt - fwd_cnt)
        fwd_ratio = fwd_cnt / rev_cnt
        bursts = 1
        avg_burst = float(pkt_cnt)
        records.append({
            "packet_count": pkt_cnt, "total_bytes": pkt_cnt * avg_sz, "duration_seconds": dur,
            "avg_packet_size": avg_sz, "min_packet_size": min_sz, "max_packet_size": max_sz,
            "packet_size_std": std_sz, "avg_inter_arrival_time": avg_iat, "inter_arrival_time_std": std_iat,
            "packets_per_second": pps, "bytes_per_second": bps, "forward_packet_count": fwd_cnt,
            "reverse_packet_count": rev_cnt, "forward_reverse_ratio": fwd_ratio, "burst_count": bursts,
            "avg_burst_size": avg_burst, "esp_packet_count": pkt_cnt, "ike_packet_count": 0,
            "ah_packet_count": 0, "tcp_packet_count": 0, "udp_packet_count": 0,
            "unique_endpoints_count": 15, "unique_spi_count": 12, "label": "Web browsing", "is_anomaly": 1
        })

    df = pd.DataFrame(records)
    return df

def save_dataset(df, path=DATASET_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)
    print(f"Dataset saved to {path} ({len(df)} samples).")

def load_dataset(path=DATASET_PATH):
    if not os.path.exists(path):
        df = generate_synthetic_testbed_dataset()
        save_dataset(df, path)
        return df
    return pd.read_csv(path)

if __name__ == "__main__":
    df = generate_synthetic_testbed_dataset()
    save_dataset(df)
