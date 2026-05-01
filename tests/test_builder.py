"""Tests for the wire-format builder. These run offline — no Burp required."""

from __future__ import annotations

import pytest

from burp_mcp_plus.builder import (
    BuildError,
    apply_overrides,
    build_wire,
    from_url,
    host_port_https,
    lint,
    parse_raw_request,
)


def test_from_url_get_minimal():
    req = from_url("GET", "https://api.example.com/users")
    wire = build_wire(req)
    assert wire.startswith("GET /users HTTP/1.1\r\n")
    assert "Host: api.example.com\r\n" in wire
    assert "User-Agent:" in wire  # auto-injected default
    assert "Content-Length" not in wire  # GET has no body
    assert wire.endswith("\r\n\r\n")


def test_from_url_post_computes_content_length():
    body = '{"a":1}'
    req = from_url("POST", "https://x.test/p", headers={"Content-Type": "application/json"}, body=body)
    wire = build_wire(req)
    assert f"Content-Length: {len(body)}\r\n" in wire
    assert wire.endswith("\r\n\r\n" + body)


def test_url_with_query_preserved():
    req = from_url("GET", "https://x.test/p?a=1&b=2")
    wire = build_wire(req)
    assert wire.startswith("GET /p?a=1&b=2 HTTP/1.1\r\n")


def test_non_default_port_in_host():
    req = from_url("GET", "https://x.test:8443/p")
    wire = build_wire(req)
    assert "Host: x.test:8443\r\n" in wire


def test_parse_raw_request_roundtrip():
    raw = (
        "POST /api/login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Cookie: a=b; c=d\r\n"
        "User-Agent: TestUA/1.0\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        '{"u":"alice"}'
    )
    parsed = parse_raw_request(raw)
    assert parsed.method == "POST"
    assert parsed.path == "/api/login"
    assert parsed.host == "example.com"
    assert parsed.body == '{"u":"alice"}'
    rebuilt = build_wire(parsed)
    # Content-Length recomputed and equal to body length
    assert "Content-Length: 13\r\n" in rebuilt
    assert rebuilt.endswith('{"u":"alice"}')


def test_apply_overrides_recomputes_content_length():
    raw = (
        "POST /old HTTP/1.1\r\n"
        "Host: x.test\r\n"
        "Cookie: s=abc\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 99\r\n"
        "\r\n"
        '{"old":true}'
    )
    base = parse_raw_request(raw)
    new = apply_overrides(
        base,
        method="PUT",
        path="/new",
        set_headers={"X-Test": "1"},
        body='{"new":1,"more":2}',
    )
    wire = build_wire(new)
    assert wire.startswith("PUT /new HTTP/1.1\r\n")
    assert "Cookie: s=abc\r\n" in wire  # inherited from baseline
    assert "X-Test: 1\r\n" in wire
    assert f"Content-Length: {len('{\"new\":1,\"more\":2}')}\r\n" in wire


def test_get_drops_body_silently():
    raw = (
        "POST /p HTTP/1.1\r\n"
        "Host: x.test\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello"
    )
    base = parse_raw_request(raw)
    new = apply_overrides(base, method="GET")
    wire = build_wire(new)
    assert wire.startswith("GET /p HTTP/1.1\r\n")
    assert "Content-Length" not in wire
    assert wire.endswith("\r\n\r\n")


def test_remove_headers():
    raw = (
        "GET /p HTTP/1.1\r\n"
        "Host: x.test\r\n"
        "Cookie: a=b\r\n"
        "User-Agent: keep\r\n"
        "\r\n"
    )
    base = parse_raw_request(raw)
    new = apply_overrides(base, remove_headers=["cookie"])  # case-insensitive
    wire = build_wire(new)
    assert "Cookie" not in wire
    assert "User-Agent: keep\r\n" in wire


def test_path_must_be_absolute():
    req = from_url("GET", "https://x.test/p")
    req.path = "relative/path"
    with pytest.raises(BuildError):
        build_wire(req)


def test_host_port_https_default_https():
    req = from_url("GET", "https://x.test/p")
    name, port, https = host_port_https(req)
    assert (name, port, https) == ("x.test", 443, True)


def test_host_port_https_explicit_http():
    req = from_url("GET", "http://x.test/p")
    name, port, https = host_port_https(req, scheme_hint="http")
    assert (name, port, https) == ("x.test", 80, False)


def test_lint_warns_on_body_without_content_type():
    req = from_url("POST", "https://x.test/p", body="hello")
    warnings = lint(req)
    assert "body present but Content-Type missing" in warnings


def test_invalid_url_raises():
    with pytest.raises(BuildError):
        from_url("GET", "not-a-url")


# --- empty / malformed input handling ----------------------------------


def test_parse_raw_request_none():
    with pytest.raises(BuildError, match="None"):
        parse_raw_request(None)  # type: ignore[arg-type]


def test_parse_raw_request_empty_string():
    with pytest.raises(BuildError, match="nothing to parse"):
        parse_raw_request("")


def test_parse_raw_request_whitespace_only():
    with pytest.raises(BuildError, match="nothing to parse"):
        parse_raw_request("   \n\t  \r\n")


def test_parse_raw_request_burp_status_marker():
    # If a "Reached end of items" string ever leaks into the parser, it
    # should raise a specific error pointing at the upstream MCP, not a
    # generic "malformed request line".
    with pytest.raises(BuildError, match="Burp status message"):
        parse_raw_request("Reached end of items")


def test_parse_raw_request_no_request_line():
    # Headers without a request line shouldn't pretend the first header is
    # a request line.
    with pytest.raises(BuildError, match="malformed request line"):
        parse_raw_request("Host: x.test\r\nUser-Agent: foo\r\n\r\n")


def test_parse_raw_request_missing_host():
    with pytest.raises(BuildError, match="Host"):
        parse_raw_request("GET / HTTP/1.1\r\nUser-Agent: foo\r\n\r\n")


def test_parse_raw_request_lf_only_line_endings():
    # Burp sometimes hands us LF-only text. Should still parse.
    raw = "GET /p HTTP/1.1\nHost: x.test\nUser-Agent: foo\n\nbody"
    parsed = parse_raw_request(raw)
    assert parsed.method == "GET"
    assert parsed.host == "x.test"
