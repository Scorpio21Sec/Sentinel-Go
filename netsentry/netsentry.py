"""
============================================================
netsentry/netsentry.py
TOPIC 8 — NetSentry-AI
Network-level anomaly detection using Scapy + Isolation Forest.

Captures live packets, extracts behavioural features per 10-second
window, and scores them with Isolation Forest.

Run (requires root for raw socket):
  sudo pip install scapy scikit-learn numpy
  sudo python netsentry/netsentry.py --iface eth0
  sudo python netsentry/netsentry.py --stub   # no capture needed
============================================================
"""
from __future__ import annotations

import argparse
import logging
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import List

import numpy as np
from sklearn.ensemble import IsolationForest

log = logging.getLogger("netsentry")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)


# ─────────────────────────────────────────────────────────────
# Feature Accumulator (one per time window)
# ─────────────────────────────────────────────────────────────
@dataclass
class WindowAccumulator:
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    unique_src_ips: set = field(default_factory=set)
    unique_dst_ips: set = field(default_factory=set)
    unique_dst_ports: set = field(default_factory=set)
    dns_queries: int = 0
    icmp_count: int = 0
    payload_sizes: List[int] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)

    def to_feature_vector(self) -> List[float]:
        duration = max(time.time() - self.start_time, 1.0)
        avg_payload = (
            sum(self.payload_sizes) / len(self.payload_sizes)
            if self.payload_sizes else 0.0
        )
        syn_ratio = self.syn_count / max(self.packet_count, 1)
        return [
            self.packet_count / duration,       # packet_rate
            self.byte_count / duration,         # byte_rate (bps)
            syn_ratio,                          # syn_ratio
            len(self.unique_src_ips),           # unique_src_ips
            len(self.unique_dst_ips),           # unique_dst_ips
            len(self.unique_dst_ports),         # unique_dst_ports
            self.dns_queries / duration,        # dns_query_rate
            self.icmp_count / duration,         # icmp_rate
            avg_payload,                        # avg_payload_bytes
        ]


FEATURE_NAMES = [
    "packet_rate", "byte_rate", "syn_ratio",
    "unique_src_ips", "unique_dst_ips", "unique_dst_ports",
    "dns_query_rate", "icmp_rate", "avg_payload_bytes",
]


# ─────────────────────────────────────────────────────────────
# Packet Processor
# ─────────────────────────────────────────────────────────────
class PacketProcessor:
    def __init__(self, window_seconds: int = 10):
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._acc = WindowAccumulator()
        self._features_history: List[List[float]] = []
        self._model: IsolationForest | None = None
        self._total = 0
        self._anomalies = 0

    def process_packet(self, pkt) -> None:
        """Called by Scapy's sniff() for each captured packet."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.dns import DNS

            with self._lock:
                self._acc.packet_count += 1
                raw_len = len(pkt)
                self._acc.byte_count += raw_len
                self._acc.payload_sizes.append(raw_len)

                if IP in pkt:
                    self._acc.unique_src_ips.add(pkt[IP].src)
                    self._acc.unique_dst_ips.add(pkt[IP].dst)

                if TCP in pkt:
                    self._acc.unique_dst_ports.add(pkt[TCP].dport)
                    # SYN flag = 0x02
                    if pkt[TCP].flags & 0x02:
                        self._acc.syn_count += 1

                if UDP in pkt:
                    self._acc.unique_dst_ports.add(pkt[UDP].dport)

                if DNS in pkt and pkt[DNS].qr == 0:   # DNS query (not response)
                    self._acc.dns_queries += 1

                if ICMP in pkt:
                    self._acc.icmp_count += 1

        except Exception as e:
            log.debug("Packet decode error: %s", e)

    def flush_window(self) -> None:
        """Extract features from the current window and score them."""
        with self._lock:
            fv = self._acc.to_feature_vector()
            self._acc = WindowAccumulator()

        self._features_history.append(fv)
        self._total += 1

        # Auto-train after 20 windows of warm-up
        if len(self._features_history) == 20:
            log.info("Auto-training IsolationForest on %d warm-up windows…",
                     len(self._features_history))
            self._train(self._features_history)

        if self._model is not None:
            self._score(fv)
        else:
            names_vals = ", ".join(
                f"{n}={v:.1f}" for n, v in zip(FEATURE_NAMES, fv)
            )
            log.info("[warmup %2d/20] %s", self._total, names_vals)

    def _train(self, data: List[List[float]]) -> None:
        X = np.array(data, dtype=float)
        self._model = IsolationForest(
            n_estimators=100, contamination=0.05, random_state=42
        )
        self._model.fit(X)
        log.info("✅ NetSentry model trained.")

    def _score(self, fv: List[float]) -> None:
        X = np.array([fv], dtype=float)
        score = float(self._model.decision_function(X)[0])
        label = int(self._model.predict(X)[0])
        is_anomaly = label == -1

        if is_anomaly:
            self._anomalies += 1
            log.warning(
                "🚨 NETWORK ANOMALY  score=%.4f  pkt_rate=%.1f  syn_ratio=%.2f  "
                "unique_ports=%d  dns_rate=%.1f",
                score, fv[0], fv[2], int(fv[5]), fv[6],
            )
        else:
            log.info(
                "✅ normal  score=%.4f  pkt_rate=%.1f  dns_rate=%.1f",
                score, fv[0], fv[6],
            )


# ─────────────────────────────────────────────────────────────
# Stub packet generator (no live capture needed)
# ─────────────────────────────────────────────────────────────
def run_stub(processor: PacketProcessor, window_sec: int) -> None:
    """Generates synthetic packet-stream data without Scapy."""
    log.info("🧪 Stub mode — generating synthetic packet data")
    rng = np.random.default_rng(0)
    tick = 0
    while True:
        time.sleep(0.1)
        # Every ~100 calls simulate one 'packet'
        is_attack = tick > 150 and tick < 200   # simulate attack burst

        class FakePkt:
            pass

        # Inject counters directly
        with processor._lock:
            if is_attack:
                processor._acc.packet_count += rng.integers(50, 100)
                processor._acc.syn_count += rng.integers(40, 80)
                processor._acc.byte_count += rng.integers(50_000, 200_000)
                processor._acc.unique_dst_ports.update(
                    set(rng.integers(1, 65535, size=50).tolist())
                )
                processor._acc.dns_queries += rng.integers(20, 60)
            else:
                processor._acc.packet_count += rng.integers(1, 15)
                processor._acc.syn_count += rng.integers(0, 3)
                processor._acc.byte_count += rng.integers(500, 5_000)
                processor._acc.unique_dst_ports.update(
                    set(rng.integers(80, 9000, size=3).tolist())
                )
                processor._acc.dns_queries += rng.integers(0, 3)
            processor._acc.unique_src_ips.add(f"192.168.1.{rng.integers(1, 10)}")
            processor._acc.unique_dst_ips.add(f"10.0.0.{rng.integers(1, 20)}")

        tick += 1
        if tick % (window_sec * 10) == 0:
            processor.flush_window()


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="NetSentry-AI — Network Anomaly Detector")
    parser.add_argument("--iface", default="eth0", help="Network interface to capture on")
    parser.add_argument("--window", type=int, default=10, help="Feature window in seconds")
    parser.add_argument("--stub", action="store_true", help="Use synthetic data (no capture)")
    args = parser.parse_args()

    processor = PacketProcessor(window_seconds=args.window)

    if args.stub:
        run_stub(processor, args.window)
        return

    try:
        from scapy.all import sniff
    except ImportError:
        log.error("Scapy not installed. Run: pip install scapy")
        return

    # Window flush thread
    def flush_loop():
        while True:
            time.sleep(args.window)
            processor.flush_window()

    threading.Thread(target=flush_loop, daemon=True).start()

    log.info("Capturing on %s — window=%ds", args.iface, args.window)
    sniff(iface=args.iface, prn=processor.process_packet, store=False)


if __name__ == "__main__":
    main()
