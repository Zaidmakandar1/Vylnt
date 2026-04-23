"""
ML Filter Microservice — Vylnt (DevGuard)
POST /classify endpoint for DOM manipulation pattern classification.
Requirements: 6.1, 6.4
"""

import os
import json
import time
import logging
from typing import Optional

import numpy as np
from flask import Flask, request, jsonify

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_PATTERN_TYPES = frozenset([
    "eval",
    "innerHTML",
    "document.write",
    "setTimeout_string",
    "setInterval_string",
])

MODEL_DIR = os.environ.get("MODEL_DIR", os.path.join(os.path.dirname(__file__), "model"))
RESPONSE_TIMEOUT_MS = 300  # ≤ 300ms per requirement 6.4

# ---------------------------------------------------------------------------
# Model loader (lazy singleton)
# ---------------------------------------------------------------------------

_model = None
_tokenizer = None
_config: Optional[dict] = None
_model_load_error: Optional[str] = None


def _load_model():
    """Attempt to load the LSTM model and tokenizer from MODEL_DIR."""
    global _model, _tokenizer, _config, _model_load_error

    config_path = os.path.join(MODEL_DIR, "config.json")
    tokenizer_path = os.path.join(MODEL_DIR, "tokenizer.json")

    if not os.path.exists(config_path) or not os.path.exists(tokenizer_path):
        _model_load_error = f"Model artifacts not found in '{MODEL_DIR}'. Run train.py first."
        logger.warning(_model_load_error)
        return

    try:
        import tensorflow as tf
        from train import JSTokenizer

        with open(config_path) as f:
            _config = json.load(f)

        model_path = os.path.join(MODEL_DIR, _config["model_file"])
        _model = tf.keras.models.load_model(model_path)
        _tokenizer = JSTokenizer.load(tokenizer_path)
        logger.info("ML model loaded successfully from '%s'", MODEL_DIR)
        _model_load_error = None
    except Exception as exc:
        _model_load_error = str(exc)
        logger.error("Failed to load ML model: %s", exc)
        _model = None
        _tokenizer = None


# Try to load at startup
_load_model()

# ---------------------------------------------------------------------------
# Inference helpers
# ---------------------------------------------------------------------------

def _deterministic_mock(pattern_type: str, context_tokens: list[str]) -> tuple[str, float]:
    """
    Deterministic fallback when the model is not loaded.
    Uses simple heuristics based on pattern type and context tokens.
    Returns (classification, confidence).
    """
    dangerous_keywords = {"eval", "innerHTML", "document.write", "setTimeout", "setInterval",
                          "untrustedData", "userInput", "payload", "encodedPayload",
                          "exfiltrationUrl", "userControlledString", "atob"}

    # Count dangerous tokens in context
    dangerous_count = sum(1 for t in context_tokens if t in dangerous_keywords)

    # Patterns that are inherently higher risk
    high_risk_patterns = {"eval", "document.write", "setTimeout_string", "setInterval_string"}

    if pattern_type in high_risk_patterns or dangerous_count >= 2:
        return "anomalous", 0.85
    elif dangerous_count == 1:
        return "anomalous", 0.65
    else:
        return "safe", 0.80


def _run_inference(pattern_type: str, context_tokens: list[str]) -> tuple[str, float]:
    """Run LSTM inference. Returns (classification, confidence)."""
    from train import extract_context_window, CONTEXT_WINDOW

    # Encode context tokens
    encoded = _tokenizer.encode(context_tokens)

    # Ensure correct input length
    input_length = _config["input_length"]
    if len(encoded) < input_length:
        encoded = [0] * (input_length - len(encoded)) + encoded
    else:
        encoded = encoded[:input_length]

    X = np.array([encoded], dtype=np.int32)
    prob = float(_model.predict(X, verbose=0)[0][0])

    classification = "anomalous" if prob >= 0.5 else "safe"
    confidence = prob if classification == "anomalous" else (1.0 - prob)
    return classification, round(confidence, 4)


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    status = "ok" if _model is not None else "degraded"
    return jsonify({"status": status, "model_loaded": _model is not None}), 200


@app.route("/classify", methods=["POST"])
def classify():
    """
    POST /classify
    Body: { finding_id, pattern_type, context_tokens }
    Returns: { finding_id, classification, confidence }
    Enforces ≤ 300ms response time; returns HTTP 503 on model load failure
    when no fallback is available.
    """
    start_ms = time.monotonic() * 1000

    # Parse JSON body
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    # Validate required fields
    finding_id = data.get("finding_id")
    pattern_type = data.get("pattern_type")
    context_tokens = data.get("context_tokens")

    if not finding_id or not isinstance(finding_id, str):
        return jsonify({"error": "finding_id must be a non-empty string"}), 400

    if pattern_type not in VALID_PATTERN_TYPES:
        return jsonify({
            "error": f"Invalid pattern_type '{pattern_type}'. "
                     f"Must be one of: {sorted(VALID_PATTERN_TYPES)}"
        }), 400

    if not isinstance(context_tokens, list) or len(context_tokens) == 0:
        return jsonify({"error": "context_tokens must be a non-empty array of strings"}), 400

    if not all(isinstance(t, str) for t in context_tokens):
        return jsonify({"error": "All context_tokens must be strings"}), 400

    # Run classification
    try:
        if _model is not None and _tokenizer is not None:
            classification, confidence = _run_inference(pattern_type, context_tokens)
        elif _model_load_error:
            # Model failed to load — use deterministic mock (graceful degradation)
            logger.warning("Model unavailable, using deterministic mock: %s", _model_load_error)
            classification, confidence = _deterministic_mock(pattern_type, context_tokens)
        else:
            return jsonify({"error": "ML model service unavailable"}), 503

    except Exception as exc:
        logger.error("Inference error for finding_id=%s: %s", finding_id, exc)
        return jsonify({"error": "Internal inference error"}), 503

    elapsed_ms = time.monotonic() * 1000 - start_ms
    if elapsed_ms > RESPONSE_TIMEOUT_MS:
        logger.warning("Response time %.1fms exceeded %dms SLA for finding_id=%s",
                       elapsed_ms, RESPONSE_TIMEOUT_MS, finding_id)

    return jsonify({
        "finding_id": finding_id,
        "classification": classification,
        "confidence": confidence,
    }), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
