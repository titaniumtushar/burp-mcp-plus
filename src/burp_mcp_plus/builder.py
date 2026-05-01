"""HTTP/1.1 wire-format builder with strict completeness checks.

The whole reason this package exists: the model frequently emits Burp
Repeater/Intruder/send_http1 payloads that are missing Host, Cookie, UA,
Content-Length, or have wrong line endings. This module guarantees a
fully-formed request, or refuses to build one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlsplit

CRLF = "\r\n"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

METHODS_WITHOUT_BODY = {"GET", "HEAD", "DELETE", "OPTIONS", "TRACE"}


class BuildError(ValueError):
    """Raised when a request cannot be built into a complete wire format."""


@dataclass
class Header:
    name: str
    value: str

    def line(self) -> str:
        return f"{self.name}: {self.value}"


@dataclass
class HttpRequest:
    method: str
    path: str  # request-target, e.g. "/api/users?id=1"
    host: str  # value of the Host header (host[:port] if non-default)
    headers: list[Header] = field(default_factory=list)
    body: str = ""
    version: str = "HTTP/1.1"

    def header_names_lower(self) -> set[str]:
        return {h.name.lower() for h in self.headers}

    def get(self, name: str) -> str | None:
        nl = name.lower()
        for h in self.headers:
            if h.name.lower() == nl:
                return h.value
        return None

    def set(self, name: str, value: str) -> None:
        nl = name.lower()
        for h in self.headers:
            if h.name.lower() == nl:
                h.value = value
                return
        self.headers.append(Header(name, value))

    def remove(self, name: str) -> None:
        nl = name.lower()
        self.headers = [h for h in self.headers if h.name.lower() != nl]


# Strings Burp's MCP returns instead of actual entries when there's nothing
# to show. If we ever try to parse one of these as a raw request, give a
# specific error rather than failing with a confusing "malformed request line".
_BURP_STATUS_MARKERS = (
    "reached end of items",
    "no items",
    "no entries",
    "no matches",
    "empty",
)


def parse_raw_request(raw: str) -> HttpRequest:
    """Parse a raw HTTP/1.1 request (e.g. from Burp history) into HttpRequest.

    Tolerant of LF-only line endings; emits CRLF on rebuild.

    Raises BuildError with a specific message for the common empty-input
    failure modes (None, empty string, whitespace-only, Burp status markers).
    """
    if raw is None:
        raise BuildError("empty raw request: input is None")
    if not raw.strip():
        raise BuildError(
            "empty raw request: nothing to parse "
            "(check that the source entry actually has request bytes)"
        )
    low = raw.strip().lower()
    if low.startswith(_BURP_STATUS_MARKERS):
        raise BuildError(
            f"refusing to parse Burp status message as a request: {raw.strip()[:80]!r}. "
            "This usually means the upstream tool returned no entries — "
            "try widening your regex or page size."
        )
    text = raw.replace("\r\n", "\n")
    # Split on first blank line.
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""
    lines = [ln for ln in head.split("\n") if ln.strip()]
    if not lines:
        raise BuildError("empty raw request: no header lines after stripping whitespace")
    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) < 3:
        raise BuildError(
            f"malformed request line: {request_line!r}. "
            "Expected: 'METHOD path HTTP/version'."
        )
    method, path, version = parts[0], parts[1], parts[2]
    headers: list[Header] = []
    host = ""
    for ln in lines[1:]:
        if ":" not in ln:
            raise BuildError(f"malformed header line: {ln!r}")
        name, value = ln.split(":", 1)
        name = name.strip()
        value = value.strip()
        headers.append(Header(name, value))
        if name.lower() == "host":
            host = value
    if not host:
        raise BuildError("baseline request is missing Host header")
    return HttpRequest(
        method=method.upper(),
        path=path,
        host=host,
        headers=headers,
        body=body,
        version=version,
    )


def from_url(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
) -> HttpRequest:
    """Build a fresh request from a URL + structured fields."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise BuildError(f"invalid url: {url!r}")
    default_port = 443 if parts.scheme == "https" else 80
    port = parts.port or default_port
    host_header = parts.hostname if port == default_port else f"{parts.hostname}:{port}"
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    req = HttpRequest(
        method=method.upper(),
        path=path,
        host=host_header,
        headers=[],
        body=body or "",
    )
    req.set("Host", host_header)
    if headers:
        for k, v in headers.items():
            if k.lower() == "host":
                req.set("Host", v)
                req.host = v
            else:
                req.set(k, v)
    return req


def apply_overrides(
    base: HttpRequest,
    *,
    method: str | None = None,
    path: str | None = None,
    set_headers: dict[str, str] | None = None,
    remove_headers: Iterable[str] | None = None,
    body: str | None = None,
) -> HttpRequest:
    """Return a new HttpRequest with the given overrides applied to a baseline."""
    new = HttpRequest(
        method=base.method,
        path=base.path,
        host=base.host,
        headers=[Header(h.name, h.value) for h in base.headers],
        body=base.body,
        version=base.version,
    )
    if method:
        new.method = method.upper()
    if path is not None:
        new.path = path
    if remove_headers:
        for name in remove_headers:
            new.remove(name)
    if set_headers:
        for k, v in set_headers.items():
            new.set(k, v)
            if k.lower() == "host":
                new.host = v
    if body is not None:
        new.body = body
    return new


def build_wire(
    req: HttpRequest,
    *,
    default_user_agent: str = DEFAULT_USER_AGENT,
    require_user_agent: bool = True,
    require_accept: bool = False,
) -> str:
    """Render the request into a complete HTTP/1.1 wire-format string.

    Auto-fixes:
    - Sets Host if absent (from req.host).
    - Sets Content-Length for body-bearing methods.
    - Drops body for body-less methods (and removes Content-Length).
    - Adds default User-Agent if missing and require_user_agent is True.

    Raises BuildError if a critical field cannot be filled (e.g. no Host
    available at all).
    """
    if not req.method:
        raise BuildError("method required")
    if not req.path:
        raise BuildError("path required (e.g. '/')")
    if not req.path.startswith("/") and not req.path.startswith("http"):
        # request-target should be absolute-path or absolute-form
        raise BuildError(f"path must start with '/': {req.path!r}")
    if not req.host and not req.get("Host"):
        raise BuildError("Host required (set req.host or a Host header)")

    # Ensure Host header is present and matches req.host.
    if req.get("Host") is None:
        req.set("Host", req.host)

    body_allowed = req.method.upper() not in METHODS_WITHOUT_BODY
    if body_allowed:
        # Always reflect actual body byte length.
        body_bytes = req.body.encode("utf-8")
        req.set("Content-Length", str(len(body_bytes)))
    else:
        if req.body:
            # Body-less methods: drop body silently rather than error — caller
            # may have inherited it from baseline.
            req.body = ""
        req.remove("Content-Length")

    if require_user_agent and req.get("User-Agent") is None:
        req.set("User-Agent", default_user_agent)
    if require_accept and req.get("Accept") is None:
        req.set("Accept", "*/*")

    request_line = f"{req.method} {req.path} {req.version}"
    header_lines = [h.line() for h in req.headers]
    head = CRLF.join([request_line, *header_lines])
    return head + CRLF + CRLF + (req.body if body_allowed else "")


def host_port_https(req: HttpRequest, scheme_hint: str | None = None) -> tuple[str, int, bool]:
    """Derive (hostname, port, usesHttps) from req.host + an optional hint.

    scheme_hint can be 'http' or 'https'. If absent, defaults to https on 443
    or when no port is given (most modern targets are TLS).
    """
    host = req.host or req.get("Host") or ""
    if not host:
        raise BuildError("cannot derive target: no Host")
    if ":" in host:
        name, _, port_s = host.partition(":")
        try:
            port = int(port_s)
        except ValueError as e:
            raise BuildError(f"bad port in Host: {host!r}") from e
    else:
        name = host
        port = 443 if (scheme_hint or "https") == "https" else 80
    if scheme_hint == "http":
        uses_https = False
    elif scheme_hint == "https":
        uses_https = True
    else:
        uses_https = port != 80
    return name, port, uses_https


def lint(req: HttpRequest) -> list[str]:
    """Return a list of soft warnings about a request (missing recommended headers)."""
    warnings: list[str] = []
    if req.get("Host") is None:
        warnings.append("missing Host")
    if req.get("User-Agent") is None:
        warnings.append("missing User-Agent")
    if req.method.upper() not in METHODS_WITHOUT_BODY and req.body and req.get("Content-Type") is None:
        warnings.append("body present but Content-Type missing")
    return warnings
