"""Tests for log redaction: credentials must not reach public build logs.

Only the type, ``server:port``, result and a safe reason may remain.
"""

import logging

from src.checker.pipeline import LOG, _RedactFilter, redact


def _emit(message: str) -> str:
    """Emit a log record through the pipeline logger and return its text."""
    captured: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda record: captured.append(record.getMessage())
    LOG.addHandler(handler)
    try:
        LOG.warning("%s", message)
    finally:
        LOG.removeHandler(handler)
    assert captured
    return captured[0]


def test_redact_masks_uuid_in_query_string():
    text = "candidate node (192.0.2.1:443) type=vless result=dead reason=uuid=550e8400-e29b-41d4-a716-446655440000 invalid"
    redacted = redact(text)
    assert "550e8400-e29b-41d4-a716-446655440000" not in redacted
    assert "192.0.2.1:443" in redacted  # host:port stays

    emitted = _emit(text)
    assert "550e8400-e29b-41d4-a716-446655440000" not in emitted


def test_redact_masks_password_token():
    text = "failed for ss://... password=secretpassword123"
    redacted = redact(text)
    assert "secretpassword123" not in redacted


def test_redact_masks_reality_key_and_short_id():
    text = "reality check pbk=PbGxvxxQ1ytAqN7eg2doH3BmNGaLnIJBKnslrhxg5cY sid=ab12"
    redacted = redact(text)
    assert "PbGxvxxQ1ytAqN7eg2doH3BmNGaLnIJBKnslrhxg5cY" not in redacted
    assert "ab12" not in redacted


def test_redact_masks_bearer_secret():
    text = "401 from Clash API (Bearer a1b2c3d4e5f6) — stale secret?"
    redacted = redact(text)
    assert "a1b2c3d4e5f6" not in redacted
    assert redacted == "401 from Clash API (…) — stale secret?"


def test_redact_masks_full_proxy_uri_but_keeps_scheme():
    text = "dropping vless://550e8400-e29b-41d4-a716-446655440000@192.0.2.5:443?security=tls#name"
    redacted = redact(text)
    assert "550e8400-e29b-41d4-a716-446655440000" not in redacted
    assert redacted.startswith("dropping vless://")


def test_redact_keeps_safe_metadata():
    text = "candidate node-1 (203.0.113.7:8443) type=trojan result=verified delay_kbps=1234.5 reason=OK"
    redacted = redact(text)
    assert redacted == text  # nothing sensitive to strip

    emitted = _emit(text)
    assert "203.0.113.7:8443" in emitted
    assert "verified" in emitted


def test_redact_filter_cleans_slipped_arguments():
    """Even when the call site forgets redact(), the filter on the logger
    strips credentials before the record is written anywhere."""
    record = LOG.makeRecord(
        "src.checker.pipeline", logging.WARNING, "test", 1,
        "error uuid=550e8400-e29b-41d4-a716-446655440000 for 192.0.2.9:443",
        (), None,
    )
    _RedactFilter().filter(record)
    assert "550e8400-e29b-41d4-a716-446655440000" not in record.getMessage()
    assert "192.0.2.9:443" in record.getMessage()
