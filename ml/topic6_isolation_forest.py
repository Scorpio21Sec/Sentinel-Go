"""
============================================================
ml/topic6_isolation_forest.py
TOPIC 6 MINI-TASK — Isolation Forest standalone demo

Run: python ml/topic6_isolation_forest.py
============================================================
"""
import numpy as np
from sklearn.ensemble import IsolationForest

print("=== Topic 6: Isolation Forest Demo ===\n")

# ── Step 1: Generate 200 "normal" feature vectors ────────────
rng = np.random.default_rng(seed=0)
normal = np.column_stack([
    rng.integers(1, 8,  size=200),   # exec_count
    rng.integers(0, 5,  size=200),   # fork_rate
    rng.integers(1, 6,  size=200),   # unique_procs
    rng.integers(2, 20, size=200),   # unique_files
    rng.integers(0, 2,  size=200),   # sensitive_hits
    rng.integers(3, 30, size=200),   # total_opens
    rng.integers(0, 3,  size=200),   # connections
]).astype(float)

print(f"Training on {len(normal)} normal samples…")

# ── Step 2: Train ─────────────────────────────────────────────
model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(normal)
print("Model trained.\n")

# ── Step 3: Suspicious vectors ────────────────────────────────
suspicious = np.array([
    [50, 40, 20, 200, 30, 500, 40],   # all metrics exploding
    [45, 35, 15, 180, 25, 400, 35],   # similar
    [60, 50, 30, 250, 40, 600, 50],   # worse
    [2,  1,  2,  8,   0,  10,  1 ],   # this one is actually normal
    [55, 0,  5,  300, 50, 700, 1 ],   # ransomware-like (many files, sensitive hits)
], dtype=float)

labels = {1: "NORMAL ✅", -1: "ANOMALY 🚨"}
feature_names = ["exec", "fork", "procs", "files", "sensitive", "opens", "net"]

print("Evaluating suspicious vectors:")
print("-" * 60)
for i, vec in enumerate(suspicious):
    score = model.decision_function([vec])[0]
    pred  = model.predict([vec])[0]
    desc  = ", ".join(f"{n}={int(v)}" for n, v in zip(feature_names, vec))
    print(f"  [{i+1}] {labels[pred]:12s}  score={score:+.4f}   {desc}")

print("-" * 60)
print("\nNegative score = more anomalous. -1 prediction = anomaly.")
