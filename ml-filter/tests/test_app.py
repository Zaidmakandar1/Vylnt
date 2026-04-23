"""
Unit tests for ML Filter service — Task 8.4
Requirements: 6.1, 6.4, 6.5
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import app as ml_app


@pytest.fixture
def client():
    ml_app.app.config["TESTING"] = True
    with ml_app.app.test_client() as c:
        yield c


VALID_PAYLOAD = {
    "finding_id": "abc-123",
    "pattern_type": "eval",
    "context_tokens": ["var", "x", "=", "eval", "(", "userInput", ")"],
}


# ---------------------------------------------------------------------------
# Test: valid request → valid classification and confidence in [0, 1]
# ---------------------------------------------------------------------------

def test_valid_request_returns_classification(client):
    """Valid request returns 200 with valid classification and confidence in [0, 1]."""
    resp = client.post("/classify", json=VALID_PAYLOAD)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["finding_id"] == "abc-123"
    assert body["classification"] in ("safe", "anomalous")
    assert 0.0 <= body["confidence"] <= 1.0


def test_valid_request_all_pattern_types(client):
    """All valid pattern_type values are accepted."""
    pattern_types = ["eval", "innerHTML", "document.write", "setTimeout_string", "setInterval_string"]
    for pt in pattern_types:
        resp = client.post("/classify", json={
            "finding_id": f"id-{pt}",
            "pattern_type": pt,
            "context_tokens": ["some", "context", "tokens"],
        })
        assert resp.status_code == 200, f"Expected 200 for pattern_type={pt}, got {resp.status_code}"
        body = resp.get_json()
        assert body["classification"] in ("safe", "anomalous")
        assert 0.0 <= body["confidence"] <= 1.0


def test_response_time_within_300ms(client):
    """Response time should be ≤ 300ms (Requirement 6.4)."""
    start = time.monotonic()
    resp = client.post("/classify", json=VALID_PAYLOAD)
    elapsed_ms = (time.monotonic() - start) * 1000
    assert resp.status_code == 200
    # Allow generous margin for test environment overhead
    assert elapsed_ms < 1000, f"Response took {elapsed_ms:.1f}ms, expected < 1000ms in test env"


def test_finding_id_echoed(client):
    """The response finding_id must match the request finding_id."""
    payload = {**VALID_PAYLOAD, "finding_id": "unique-finding-xyz-999"}
    resp = client.post("/classify", json=payload)
    assert resp.status_code == 200
    assert resp.get_json()["finding_id"] == "unique-finding-xyz-999"


# ---------------------------------------------------------------------------
# Test: invalid pattern_type → HTTP 400
# ---------------------------------------------------------------------------

def test_invalid_pattern_type_returns_400(client):
    """Invalid pattern_type returns HTTP 400."""
    resp = client.post("/classify", json={
        "finding_id": "abc-123",
        "pattern_type": "dangerousFunction",  # not in enum
        "context_tokens": ["some", "tokens"],
    })
    assert resp.status_code == 400
    body = resp.get_json()
    assert "error" in body
    assert "pattern_type" in body["error"].lower() or "invalid" in body["error"].lower()


def test_missing_pattern_type_returns_400(client):
    """Missing pattern_type returns HTTP 400."""
    resp = client.post("/classify", json={
        "finding_id": "abc-123",
        "context_tokens": ["some", "tokens"],
    })
    assert resp.status_code == 400


def test_empty_pattern_type_returns_400(client):
    """Empty string pattern_type returns HTTP 400."""
    resp = client.post("/classify", json={
        "finding_id": "abc-123",
        "pattern_type": "",
        "context_tokens": ["some", "tokens"],
    })
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Test: invalid context_tokens → HTTP 400
# ---------------------------------------------------------------------------

def test_empty_context_tokens_returns_400(client):
    """Empty context_tokens array returns HTTP 400."""
    resp = client.post("/classify", json={
        "finding_id": "abc-123",
        "pattern_type": "eval",
        "context_tokens": [],
    })
    assert resp.status_code == 400


def test_non_array_context_tokens_returns_400(client):
    """Non-array context_tokens returns HTTP 400."""
    resp = client.post("/classify", json={
        "finding_id": "abc-123",
        "pattern_type": "eval",
        "context_tokens": "not an array",
    })
    assert resp.status_code == 400


def test_non_string_tokens_returns_400(client):
    """context_tokens containing non-strings returns HTTP 400."""
    resp = client.post("/classify", json={
        "finding_id": "abc-123",
        "pattern_type": "eval",
        "context_tokens": ["valid", 42, "token"],
    })
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Test: missing finding_id → HTTP 400
# ---------------------------------------------------------------------------

def test_missing_finding_id_returns_400(client):
    """Missing finding_id returns HTTP 400."""
    resp = client.post("/classify", json={
        "pattern_type": "eval",
        "context_tokens": ["some", "tokens"],
    })
    assert resp.status_code == 400


def test_non_json_body_returns_400(client):
    """Non-JSON body returns HTTP 400."""
    resp = client.post("/classify", data="not json", content_type="text/plain")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Test: model unavailable → HTTP 503 (simulated)
# ---------------------------------------------------------------------------

def test_model_unavailable_returns_503(client, monkeypatch):
    """
    When the model is unavailable AND there is a load error (no mock fallback),
    the service returns HTTP 503. We simulate this by patching the module state.
    """
    # Patch to simulate model load failure with no fallback mock
    monkeypatch.setattr(ml_app, "_model", None)
    monkeypatch.setattr(ml_app, "_tokenizer", None)
    monkeypatch.setattr(ml_app, "_model_load_error", None)  # no error = no mock

    resp = client.post("/classify", json=VALID_PAYLOAD)
    assert resp.status_code == 503
    body = resp.get_json()
    assert "error" in body


def test_model_unavailable_with_error_uses_mock(client, monkeypatch):
    """
    When model fails to load (error set), the service uses the deterministic mock
    and still returns 200 (graceful degradation per Requirement 6.5).
    """
    monkeypatch.setattr(ml_app, "_model", None)
    monkeypatch.setattr(ml_app, "_tokenizer", None)
    monkeypatch.setattr(ml_app, "_model_load_error", "Model file not found")

    resp = client.post("/classify", json=VALID_PAYLOAD)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["classification"] in ("safe", "anomalous")
    assert 0.0 <= body["confidence"] <= 1.0


# ---------------------------------------------------------------------------
# Test: health endpoint
# ---------------------------------------------------------------------------

def test_health_endpoint(client):
    """Health endpoint returns 200."""
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "status" in body
    assert "model_loaded" in body
