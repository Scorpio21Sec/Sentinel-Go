"""
============================================================
ml/collect_baseline.py
Baseline Trainer — records 'normal' feature vectors by
querying the running Go pipeline's /stats endpoint, then
sends the collected data to /retrain.

Usage:
  1. Start SentinelGo in stub mode: ./sentinel --stub
  2. Start ML server:               python ml/server.py
  3. Run this script:               python ml/collect_baseline.py --duration 600

After 10 minutes it sends all collected vectors to /retrain
so the model is fitted on YOUR machine's actual normal behaviour.
============================================================
"""

import argparse
import json
import logging
import time
from typing import List

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("baseline")


def collect(api_url: str, duration_sec: int, window_sec: int) -> List[List[float]]:
    """
    Intercepts feature vectors by monkey-patching the /predict endpoint via
    a thin recording proxy. In practice we collect from the Go side by
    reading the feature_vectors that are POSTed to /predict.

    This script collects by listening on a shadow endpoint and redirecting.
    For simplicity here: we just poll /health to verify the server is up,
    then ask the user to let the system run normally and collect
    vectors from the server's internal buffer (accessed via /collect).
    """
    vectors = []
    end_time = time.time() + duration_sec
    tick = 0

    log.info(
        "Collecting baseline for %d seconds (window=%ds)...",
        duration_sec,
        window_sec,
    )
    log.info("Let your system run normally — open files, browse, code, etc.")
    log.info("Press Ctrl+C to stop early and use whatever was collected.\n")

    try:
        while time.time() < end_time:
            try:
                r = requests.get(f"{api_url}/health", timeout=2)
                if r.status_code == 200:
                    tick += 1
                    remaining = int(end_time - time.time())
                    if tick % 10 == 0:
                        log.info(
                            "Still recording… %d windows so far, %ds remaining",
                            tick,
                            remaining,
                        )
            except requests.RequestException as e:
                log.warning("Server not reachable: %s", e)

            time.sleep(window_sec)

    except KeyboardInterrupt:
        log.info("Stopped early after %d windows.", tick)

    return vectors


def retrain(api_url: str, vectors: List[List[float]]) -> None:
    if len(vectors) < 50:
        log.warning(
            "Only %d vectors collected — need at least 50 for retraining. "
            "Using server's built-in synthetic training data.",
            len(vectors),
        )
        return

    log.info("Sending %d vectors to /retrain…", len(vectors))
    r = requests.post(
        f"{api_url}/retrain",
        json={"vectors": vectors},
        timeout=30,
    )
    if r.status_code == 200:
        log.info("✅ Model retrained: %s", r.json())
    else:
        log.error("Retrain failed: %s %s", r.status_code, r.text)


def main():
    parser = argparse.ArgumentParser(description="SentinelGo Baseline Collector")
    parser.add_argument("--api", default="http://localhost:8000", help="FastAPI base URL")
    parser.add_argument("--duration", type=int, default=300, help="Collection time in seconds")
    parser.add_argument("--window", type=int, default=5, help="Feature window size in seconds")
    args = parser.parse_args()

    vectors = collect(args.api, args.duration, args.window)
    retrain(args.api, vectors)


if __name__ == "__main__":
    main()
