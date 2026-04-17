"""
============================================================
ml/server.py
TOPIC 6 + TOPIC 7 — Isolation Forest + FastAPI Bridge

Starts an HTTP server that:
  1. Trains an Isolation Forest on synthetic "normal" data at startup
  2. Exposes POST /predict — receives a FeatureVector, returns anomaly score
  3. Exposes GET  /health  — liveness probe
  4. Exposes GET  /stats   — running counts of predictions
  5. Exposes POST /retrain — accepts new training data and retrains the model

Run:
  pip install fastapi uvicorn scikit-learn numpy
  python ml/server.py
  # or via uvicorn:
  # uvicorn ml.server:app --host 0.0.0.0 --port 8000 --reload
============================================================
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import List

import numpy as np
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sentinel-ml")

# ── Feature order (MUST match Go's FeatureVector.ToSlice()) ──
FEATURE_NAMES = [
    "exec_count",
    "fork_rate",
    "unique_procs",
    "unique_files_opened",
    "sensitive_file_hits",
    "total_open_calls",
    "new_connections",
]


# ─────────────────────────────────────────────────────────────
# Model state (module-level — shared across requests)
# ─────────────────────────────────────────────────────────────
class ModelState:
    def __init__(self):
        self.model: IsolationForest | None = None
        self.trained_at: float = 0.0
        self.train_samples: int = 0
        self.total_predictions: int = 0
        self.total_anomalies: int = 0


state = ModelState()


def generate_normal_training_data(n: int = 500) -> np.ndarray:
    """
    Generates synthetic 'normal behaviour' feature vectors.
    In production you'd replace this with 10–30 minutes of
    real system activity recorded during a quiet baseline period.

    Normal ranges (per 5-second window on a quiet workstation):
      exec_count         : 1–8   processes started
      fork_rate          : 0–5   clone/fork calls
      unique_procs       : 1–6   distinct process names
      unique_files_opened: 2–20  distinct files opened
      sensitive_file_hits: 0–2   /etc/ or /root/ accesses
      total_open_calls   : 3–30  raw openat count
      new_connections    : 0–3   outbound connections
    """
    rng = np.random.default_rng(seed=42)
    data = np.column_stack([
        rng.integers(1, 9,   size=n),   # exec_count
        rng.integers(0, 6,   size=n),   # fork_rate
        rng.integers(1, 7,   size=n),   # unique_procs
        rng.integers(2, 21,  size=n),   # unique_files_opened
        rng.integers(0, 3,   size=n),   # sensitive_file_hits
        rng.integers(3, 31,  size=n),   # total_open_calls
        rng.integers(0, 4,   size=n),   # new_connections
    ]).astype(float)
    return data


def train_model(X: np.ndarray) -> IsolationForest:
    """Fits and returns a new IsolationForest."""
    model = IsolationForest(
        n_estimators=200,       # number of isolation trees
        contamination=0.05,     # expected fraction of anomalies
        max_samples="auto",     # samples per tree
        random_state=42,
        n_jobs=-1,              # use all CPU cores
    )
    model.fit(X)
    return model


# ─────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup: train on synthetic normal data ───────────────
    log.info("Training Isolation Forest on synthetic normal-behaviour data…")
    X_train = generate_normal_training_data(n=500)
    state.model = train_model(X_train)
    state.trained_at = time.time()
    state.train_samples = len(X_train)
    log.info(
        "✅ Model ready — %d training samples, contamination=0.05",
        state.train_samples,
    )
    yield
    # ── Shutdown (nothing to clean up) ───────────────────────


app = FastAPI(
    title="SentinelGo ML Server",
    description="Isolation Forest anomaly detection for OS-level behavioural features.",
    version="1.0.0",
    lifespan=lifespan,
)


# ─────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────
class FeatureVector(BaseModel):
    exec_count: int
    fork_rate: int
    unique_procs: int
    unique_files_opened: int
    sensitive_file_hits: int
    total_open_calls: int
    new_connections: int

    def to_numpy(self) -> np.ndarray:
        return np.array([[
            self.exec_count,
            self.fork_rate,
            self.unique_procs,
            self.unique_files_opened,
            self.sensitive_file_hits,
            self.total_open_calls,
            self.new_connections,
        ]], dtype=float)


class PredictResponse(BaseModel):
    anomaly_score: float
    is_anomaly: bool
    confidence: float   # |anomaly_score| normalised 0–1, just for display
    model: str = "IsolationForest"
    features_received: dict


class RetrainRequest(BaseModel):
    """Accepts a list of feature vectors as the new training set."""
    vectors: List[List[float]]


# ─────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_trained": state.model is not None,
        "train_samples": state.train_samples,
        "trained_at": state.trained_at,
    }


@app.get("/stats")
def stats():
    return {
        "total_predictions": state.total_predictions,
        "total_anomalies": state.total_anomalies,
        "anomaly_rate": (
            state.total_anomalies / state.total_predictions
            if state.total_predictions > 0
            else 0.0
        ),
    }


@app.post("/predict", response_model=PredictResponse)
def predict(features: FeatureVector):
    if state.model is None:
        raise HTTPException(status_code=503, detail="Model not trained yet")

    X = features.to_numpy()

    # decision_function: more negative = more anomalous
    raw_score = float(state.model.decision_function(X)[0])
    label = int(state.model.predict(X)[0])  # -1 = anomaly, 1 = normal
    is_anomaly = label == -1

    # Confidence: |score| clamped to 0–1 for a human-readable percentage
    confidence = min(abs(raw_score) * 2, 1.0)

    state.total_predictions += 1
    if is_anomaly:
        state.total_anomalies += 1
        log.warning(
            "🚨 ANOMALY  score=%.4f  exec=%d  fork=%d  files=%d  sensitive=%d  net=%d",
            raw_score,
            features.exec_count,
            features.fork_rate,
            features.unique_files_opened,
            features.sensitive_file_hits,
            features.new_connections,
        )
    else:
        log.info(
            "✅ normal   score=%.4f  exec=%d  fork=%d  net=%d",
            raw_score, features.exec_count, features.fork_rate, features.new_connections,
        )

    return PredictResponse(
        anomaly_score=raw_score,
        is_anomaly=is_anomaly,
        confidence=confidence,
        features_received=features.model_dump(),
    )


@app.post("/retrain")
def retrain(req: RetrainRequest):
    """Accepts new training data and retrains the model in-place."""
    if len(req.vectors) < 50:
        raise HTTPException(
            status_code=400,
            detail="Need at least 50 samples to retrain",
        )

    X = np.array(req.vectors, dtype=float)
    if X.shape[1] != len(FEATURE_NAMES):
        raise HTTPException(
            status_code=400,
            detail=f"Expected {len(FEATURE_NAMES)} features per vector, got {X.shape[1]}",
        )

    state.model = train_model(X)
    state.trained_at = time.time()
    state.train_samples = len(X)
    log.info("Model retrained on %d samples", state.train_samples)

    return {"status": "retrained", "samples": state.train_samples}


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=False,
    )
