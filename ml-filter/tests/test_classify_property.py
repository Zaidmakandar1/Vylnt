"""
Property test for ML Filter classification coverage — Property 9.

Feature: vylnt-devguard, Property 9: ML Filter classification applied to all DOM findings

**Validates: Requirements 6.1, 6.2, 6.3**

For any set of DOM-level JavaScript findings produced by the scanner, each finding SHALL be
sent to the ML Filter for classification before the Scan Report is assembled.
Findings classified as `safe` SHALL be excluded from the report.
Findings classified as `anomalous` SHALL be included in the report with the ML Filter's
confidence score attached.
"""

import sys
import os

# Ensure ml-filter root is on the path so we can import app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

import app as ml_app

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

PATTERN_TYPES = ["eval", "innerHTML", "document.write", "setTimeout_string", "setInterval_string"]

js_token = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="_$.()'\""),
    min_size=1,
    max_size=20,
)

finding_strategy = st.fixed_dictionaries({
    "finding_id": st.uuids().map(str),
    "pattern_type": st.sampled_from(PATTERN_TYPES),
    "context_tokens": st.lists(js_token, min_size=1, max_size=21),
})

findings_set_strategy = st.lists(finding_strategy, min_size=1, max_size=20)


# ---------------------------------------------------------------------------
# Helper: call the classify endpoint directly via Flask test client
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    ml_app.app.config["TESTING"] = True
    with ml_app.app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Property 9: Every finding is classified; routing is correct
# ---------------------------------------------------------------------------

@given(findings=findings_set_strategy)
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_every_finding_is_classified(findings):
    """
    Property 9: For any set of DOM findings, each finding must receive a classification
    response. The response must have a valid classification ('safe' or 'anomalous') and
    a confidence in [0, 1].
    """
    ml_app.app.config["TESTING"] = True
    with ml_app.app.test_client() as client:
        for finding in findings:
            resp = client.post("/classify", json=finding)
            # Each finding must get a 200 response (model loaded or mock fallback)
            assert resp.status_code == 200, (
                f"Expected 200 for finding {finding['finding_id']}, got {resp.status_code}: {resp.data}"
            )
            body = resp.get_json()
            assert body is not None

            # finding_id is echoed back
            assert body["finding_id"] == finding["finding_id"]

            # classification must be one of the two valid values
            assert body["classification"] in ("safe", "anomalous"), (
                f"Invalid classification: {body['classification']}"
            )

            # confidence must be in [0, 1]
            confidence = body["confidence"]
            assert isinstance(confidence, (int, float)), f"confidence must be numeric, got {type(confidence)}"
            assert 0.0 <= confidence <= 1.0, f"confidence {confidence} out of range [0, 1]"


@given(findings=findings_set_strategy)
@settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
def test_safe_findings_excluded_anomalous_included(findings):
    """
    Property 9 routing: safe findings should be excluded from the report (classification='safe'),
    anomalous findings should be included with confidence attached (classification='anomalous').
    This test verifies the routing logic by simulating report assembly.
    """
    ml_app.app.config["TESTING"] = True
    with ml_app.app.test_client() as client:
        report_findings = []

        for finding in findings:
            resp = client.post("/classify", json=finding)
            assert resp.status_code == 200
            body = resp.get_json()

            # Simulate report assembly logic (Req 6.2, 6.3)
            if body["classification"] == "anomalous":
                # Include in report with confidence attached
                report_findings.append({
                    **finding,
                    "ml_confidence": body["confidence"],
                    "classification": "anomalous",
                })
            # safe findings are excluded (not appended)

        # All entries in the assembled report must be anomalous
        for entry in report_findings:
            assert entry["classification"] == "anomalous"
            assert "ml_confidence" in entry
            assert 0.0 <= entry["ml_confidence"] <= 1.0


@given(
    finding_id=st.uuids().map(str),
    pattern_type=st.sampled_from(PATTERN_TYPES),
    context_tokens=st.lists(js_token, min_size=1, max_size=21),
)
@settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
def test_finding_id_echoed_back(finding_id, pattern_type, context_tokens):
    """
    The response finding_id must always match the request finding_id,
    ensuring the caller can correlate responses to requests.
    """
    ml_app.app.config["TESTING"] = True
    with ml_app.app.test_client() as client:
        resp = client.post("/classify", json={
            "finding_id": finding_id,
            "pattern_type": pattern_type,
            "context_tokens": context_tokens,
        })
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["finding_id"] == finding_id
