import numpy as np

FEATURE_NAMES = [
    "packet_count",
    "total_bytes",
    "duration_seconds",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "packet_size_std",
    "avg_inter_arrival_time",
    "inter_arrival_time_std",
    "packets_per_second",
    "bytes_per_second",
    "forward_packet_count",
    "reverse_packet_count",
    "forward_reverse_ratio",
    "burst_count",
    "avg_burst_size",
    "esp_packet_count",
    "ike_packet_count",
    "ah_packet_count",
    "tcp_packet_count",
    "udp_packet_count",
    "unique_endpoints_count",
    "unique_spi_count"
]

def extract_features_from_packets(packets, duration_seconds=None):
    """
    Extracts statistical traffic metadata features from a list of packet dictionaries.
    Each packet dictionary expected to have:
      - 'length': int (frame bytes)
      - 'timestamp': float or int (epoch timestamp in seconds)
      - 'source': str
      - 'destination': str
      - 'protocol': str (e.g. 'ESP', 'IKE', 'TCP', 'UDP')
      - 'spi': str (optional)
    """
    if not packets or len(packets) == 0:
        return {k: 0.0 for k in FEATURE_NAMES}

    def _get_val(p, *keys, default=0):
        for k in keys:
            if isinstance(p, dict) and k in p and p[k] is not None:
                return p[k]
        return default

    lengths = np.array([float(_get_val(p, "length", "Length", default=0)) for p in packets], dtype=float)

    def _timestamp_to_epoch(p):
        value = _get_val(p, "epoch", "Epoch", "timestamp_epoch", "TimestampEpoch", default=None)
        if value is not None and value != "":
            try:
                return float(value)
            except (TypeError, ValueError):
                pass

        value = _get_val(p, "timestamp", "Timestamp", default=0.0)
        try:
            return float(value)
        except (TypeError, ValueError):
            # PacketInfo.Timestamp is a display string (yyyy-MM-dd HH:mm:ss.fff).
            # Accept ISO-like timestamps so the AI engine also works with older clients.
            try:
                import datetime as _dt
                parsed = _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=_dt.timezone.utc)
                return parsed.timestamp()
            except (TypeError, ValueError, OverflowError):
                return 0.0

    timestamps = np.array([_timestamp_to_epoch(p) for p in packets], dtype=float)
    
    packet_count = float(len(packets))
    total_bytes = float(np.sum(lengths))
    
    # Calculate duration
    if duration_seconds is not None and duration_seconds > 0:
        duration = float(duration_seconds)
    elif len(timestamps) > 1 and np.max(timestamps) > np.min(timestamps):
        duration = float(np.max(timestamps) - np.min(timestamps))
    else:
        duration = 1.0  # default minimum baseline for rate calculations

    avg_packet_size = float(np.mean(lengths)) if len(lengths) > 0 else 0.0
    min_packet_size = float(np.min(lengths)) if len(lengths) > 0 else 0.0
    max_packet_size = float(np.max(lengths)) if len(lengths) > 0 else 0.0
    packet_size_std = float(np.std(lengths)) if len(lengths) > 0 else 0.0

    # Inter-arrival times
    if len(timestamps) > 1:
        sorted_times = np.sort(timestamps)
        deltas = np.diff(sorted_times)
        avg_iat = float(np.mean(deltas))
        std_iat = float(np.std(deltas))
    else:
        avg_iat = 0.0
        std_iat = 0.0

    pps = packet_count / duration if duration > 0 else 0.0
    bps = total_bytes / duration if duration > 0 else 0.0

    # Direction metrics
    first_src = str(_get_val(packets[0], "source", "Source", default=""))
    fwd_count = sum(1 for p in packets if str(_get_val(p, "source", "Source", default="")) == first_src)
    rev_count = packet_count - fwd_count
    fwd_rev_ratio = float(fwd_count) / (float(rev_count) + 1e-5)

    # Burst calculation (burst threshold = 50ms)
    burst_count = 0
    burst_sizes = []
    current_burst_size = 1
    if len(timestamps) > 1:
        sorted_times = np.sort(timestamps)
        for i in range(1, len(sorted_times)):
            if sorted_times[i] - sorted_times[i - 1] < 0.05:
                current_burst_size += 1
            else:
                burst_count += 1
                burst_sizes.append(current_burst_size)
                current_burst_size = 1
        burst_count += 1
        burst_sizes.append(current_burst_size)
    else:
        burst_count = 1
        burst_sizes.append(1)

    avg_burst_size = float(np.mean(burst_sizes)) if len(burst_sizes) > 0 else 1.0

    # Protocol counts
    esp_count = sum(1 for p in packets if "ESP" in str(_get_val(p, "protocol", "Protocol", default="")).upper())
    ike_count = sum(1 for p in packets if any(k in str(_get_val(p, "protocol", "Protocol", default="")).upper() for k in ["IKE", "ISAKMP"]))
    ah_count = sum(1 for p in packets if "AH" in str(_get_val(p, "protocol", "Protocol", default="")).upper())
    tcp_count = sum(1 for p in packets if "TCP" in str(_get_val(p, "protocol", "Protocol", default="")).upper())
    udp_count = sum(1 for p in packets if "UDP" in str(_get_val(p, "protocol", "Protocol", default="")).upper())

    # Endpoints & SPIs
    endpoints = set()
    spis = set()
    for p in packets:
        src = str(_get_val(p, "source", "Source", default=""))
        dst = str(_get_val(p, "destination", "Destination", default=""))
        if src or dst:
            endpoints.add(f"{src}->{dst}")
        spi = str(_get_val(p, "spi", "Spi", default=""))
        if spi and spi != "Unknown" and spi != "0x00000000" and spi != "None":
            spis.add(spi)

    return {
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "duration_seconds": duration,
        "avg_packet_size": avg_packet_size,
        "min_packet_size": min_packet_size,
        "max_packet_size": max_packet_size,
        "packet_size_std": packet_size_std,
        "avg_inter_arrival_time": avg_iat,
        "inter_arrival_time_std": std_iat,
        "packets_per_second": pps,
        "bytes_per_second": bps,
        "forward_packet_count": float(fwd_count),
        "reverse_packet_count": float(rev_count),
        "forward_reverse_ratio": fwd_rev_ratio,
        "burst_count": float(burst_count),
        "avg_burst_size": avg_burst_size,
        "esp_packet_count": float(esp_count),
        "ike_packet_count": float(ike_count),
        "ah_packet_count": float(ah_count),
        "tcp_packet_count": float(tcp_count),
        "udp_packet_count": float(udp_count),
        "unique_endpoints_count": float(len(endpoints)),
        "unique_spi_count": float(len(spis))
    }

def dict_to_feature_vector(feature_dict):
    """Converts a feature dictionary to a numpy array ordered by FEATURE_NAMES."""
    return np.array([feature_dict.get(k, 0.0) for k in FEATURE_NAMES], dtype=float)
