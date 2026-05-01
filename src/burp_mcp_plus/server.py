"""burp-mcp-plus: MCP server that builds *complete* HTTP requests and forwards
to Burp's MCP server.

Why: the upstream burp MCP accepts a free-form `content` string for
Repeater/Intruder/send_http1, and the model frequently emits a request
missing Host, Cookie, UA, or Content-Length. This wrapper enforces a
structured input + auto-fixes the wire format before forwarding.
"""

from __future__ import annotations

import json
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from .builder import (
    BuildError,
    apply_overrides,
    build_wire,
    from_url,
    host_port_https,
    lint,
    parse_raw_request,
)
from . import burp_client, dedup, jsfiles

mcp = FastMCP("burp-mcp-plus")


# --- helpers --------------------------------------------------------------


_EMPTY_MARKERS = (
    "reached end of items",
    "no items",
    "no entries",
    "no matches",
)


def _normalize_history(history_payload: Any) -> list[dict[str, Any]]:
    """Normalize whatever Burp's history tool returned into a flat list of entries.

    Burp's MCP returns one JSON object per entry (across multiple text content
    blocks), each shaped like {"request": "...", "response": "...", "notes": ""}.
    There is no `id` field and no target metadata — host/port/scheme must be
    derived from the parsed request itself.

    Burp also sometimes returns plain text status messages like
    "Reached end of items" instead of any entries — treat those as empty.
    """
    if isinstance(history_payload, list):
        return [e for e in history_payload if isinstance(e, dict)]
    if isinstance(history_payload, dict):
        for key in ("history", "items", "entries", "results"):
            v = history_payload.get(key)
            if isinstance(v, list):
                return [e for e in v if isinstance(e, dict)]
        if "request" in history_payload:
            return [history_payload]
    if isinstance(history_payload, str):
        if history_payload.strip().lower().startswith(_EMPTY_MARKERS):
            return []
    raise RuntimeError(
        f"could not parse Burp history payload (type={type(history_payload).__name__})"
    )


def _extract_baseline(history_payload: Any, history_index: int | None) -> dict[str, Any]:
    """Return the entry at `history_index` (0-based) within the returned page.

    If history_index is None, return the last entry (most recent in most layouts).
    """
    entries = _normalize_history(history_payload)
    if not entries:
        raise RuntimeError(
            "Burp returned no history entries. The page is empty or all entries "
            "were filtered out. Try `list_history(count=200)` to confirm there's "
            "any traffic, or `search_history(<broader_regex>)` to widen the filter."
        )
    if history_index is None:
        return entries[-1]
    if history_index < 0 or history_index >= len(entries):
        raise RuntimeError(
            f"history_index {history_index} out of range; page has {len(entries)} entries. "
            "Indices are 0-based positions within the most recent page returned by Burp; "
            "they shift when new traffic arrives. Re-run `list_history()` or "
            "`search_history()` to see current indices."
        )
    return entries[history_index]


def _validate_baseline(req, *, source: str) -> None:
    """Sanity-check a parsed baseline before mutating + sending. Raises RuntimeError
    with a specific, actionable message if the baseline is unusable.
    """
    if not req.method or not req.path:
        raise RuntimeError(
            f"baseline from {source} is missing method or path — cannot build a request from it"
        )
    if not (req.host or req.get("Host")):
        raise RuntimeError(
            f"baseline from {source} has no Host header — cannot derive a target. "
            "The source entry may be malformed or only contain a response."
        )


def _entry_raw_request(entry: dict[str, Any]) -> str:
    """Pull the raw HTTP/1.1 request bytes/string out of a history entry."""
    for key in ("request", "rawRequest", "requestBytes", "requestString"):
        v = entry.get(key)
        if isinstance(v, str) and v:
            return v
    raise RuntimeError(
        "history entry has no request field (looked for: request, rawRequest, requestBytes, requestString)"
    )


def _derive_target(parsed_request, entry: dict[str, Any] | None = None) -> tuple[str, int, bool]:
    """Derive (host, port, usesHttps) from a parsed request (and optionally
    metadata on the history entry, if Burp provides any).

    The Host header in the parsed request is the source of truth for hostname
    and (when present) port. Scheme is inferred:
      - explicit port 80 → http
      - explicit port 443 → https
      - no port → look at entry metadata if any, else default to https
        (most modern targets are TLS; safer default than http)
    """
    if entry:
        for k in ("usesHttps", "useHttps", "secure", "tls"):
            if k in entry:
                uses_https = bool(entry[k])
                host_hdr = parsed_request.get("Host") or parsed_request.host
                name, _, port_s = host_hdr.partition(":")
                if port_s:
                    return name, int(port_s), uses_https
                return name, (443 if uses_https else 80), uses_https
        proto = (entry.get("protocol") or entry.get("scheme") or "").lower()
        if proto:
            uses_https = proto in ("https", "h2", "tls")
            host_hdr = parsed_request.get("Host") or parsed_request.host
            name, _, port_s = host_hdr.partition(":")
            if port_s:
                return name, int(port_s), uses_https
            return name, (443 if uses_https else 80), uses_https
    # Pure derivation from the request line.
    host_hdr = parsed_request.get("Host") or parsed_request.host
    if not host_hdr:
        raise RuntimeError("cannot derive target: Host header missing")
    if ":" in host_hdr:
        name, _, port_s = host_hdr.partition(":")
        port = int(port_s)
        if port == 443:
            return name, 443, True
        if port == 80:
            return name, 80, False
        # Non-standard port: assume https (Burp users typically intercept TLS).
        return name, port, True
    return host_hdr, 443, True


def _format_response(burp_response: Any) -> str:
    """Render Burp's response payload for return to the model."""
    if isinstance(burp_response, str):
        return burp_response
    try:
        return json.dumps(burp_response, indent=2)
    except (TypeError, ValueError):
        return str(burp_response)


# --- tools ----------------------------------------------------------------


@mcp.tool()
async def inspect_history_entry(history_id: int, page_size: int = 200) -> str:
    """Fetch and pretty-print a Burp proxy history entry by index.

    `history_id` is the 0-based index into the most recent `page_size` entries
    (Burp's MCP doesn't expose stable IDs; addressing is positional).

    Use this to inspect cookies/headers before crafting a mutated request.
    """
    payload = await burp_client.call(
        "get_proxy_http_history",
        {"count": page_size, "offset": 0},
    )
    entry = _extract_baseline(payload, history_id)
    raw = _entry_raw_request(entry)
    parsed = parse_raw_request(raw)
    host, port, https = _derive_target(parsed, entry)
    summary = {
        "history_index": history_id,
        "target": {"host": host, "port": port, "usesHttps": https},
        "method": parsed.method,
        "path": parsed.path,
        "headers": [{"name": h.name, "value": h.value} for h in parsed.headers],
        "body_length": len(parsed.body),
        "body_preview": parsed.body[:512],
    }
    return json.dumps(summary, indent=2)


@mcp.tool()
async def repeater_from_history(
    history_id: int,
    tab_name: str | None = None,
    method: str | None = None,
    path: str | None = None,
    set_headers: dict[str, str] | None = None,
    remove_headers: list[str] | None = None,
    body: str | None = None,
    page_size: int = 200,
) -> str:
    """Send a request to Burp Repeater, built from a history baseline plus
    optional structured overrides.

    The baseline contributes Host, cookies, auth, UA, etc. so the resulting
    request is always complete. Overrides modify only what you specify.

    Args:
      history_id: id of the proxy history entry to clone
      tab_name: optional Repeater tab label
      method/path/body: override the corresponding field
      set_headers: replace or add these headers (case-insensitive)
      remove_headers: header names to delete
      page_size: how many recent history entries to scan to find the id
    """
    payload = await burp_client.call(
        "get_proxy_http_history",
        {"count": page_size, "offset": 0},
    )
    entry = _extract_baseline(payload, history_id)
    raw = _entry_raw_request(entry)
    base = parse_raw_request(raw)
    new = apply_overrides(
        base,
        method=method,
        path=path,
        set_headers=set_headers,
        remove_headers=remove_headers,
        body=body,
    )
    host, port, https = _derive_target(new, entry)
    try:
        wire = build_wire(new)
    except BuildError as e:
        raise RuntimeError(f"failed to build complete request: {e}") from e
    args: dict[str, Any] = {
        "content": wire,
        "targetHostname": host,
        "targetPort": port,
        "usesHttps": https,
    }
    if tab_name:
        args["tabName"] = tab_name
    result = await burp_client.call("create_repeater_tab", args)
    warnings = lint(new)
    out = {
        "ok": True,
        "burp_result": result,
        "warnings": warnings,
        "wire_preview": wire[:1024],
    }
    return _format_response(out)


@mcp.tool()
async def repeater_from_template(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    tab_name: str | None = None,
    inherit_from_history_id: int | None = None,
    page_size: int = 200,
) -> str:
    """Send a request to Burp Repeater, built from scratch (URL + structured
    fields). Optionally inherit cookies/auth/UA from a history baseline.

    Args:
      url: full URL, e.g. https://api.example.com/v1/users?id=1
      method: HTTP method (default GET)
      headers: additional headers (overrides any inherited values)
      body: request body
      tab_name: Repeater tab label
      inherit_from_history_id: copy headers from this baseline first; the
        `headers` arg then overrides them. Host/Content-Length always
        re-derived from the new url+body.
    """
    base_headers: dict[str, str] = {}
    if inherit_from_history_id is not None:
        payload = await burp_client.call(
            "get_proxy_http_history",
            {"count": page_size, "offset": 0},
        )
        entry = _extract_baseline(payload, inherit_from_history_id)
        baseline = parse_raw_request(_entry_raw_request(entry))
        for h in baseline.headers:
            if h.name.lower() in {"host", "content-length"}:
                continue
            base_headers[h.name] = h.value
    if headers:
        for k, v in headers.items():
            base_headers[k] = v
    req = from_url(method, url, headers=base_headers, body=body)
    try:
        wire = build_wire(req)
    except BuildError as e:
        raise RuntimeError(f"failed to build complete request: {e}") from e
    host, port, https = host_port_https(req, scheme_hint="https" if url.startswith("https") else "http")
    args: dict[str, Any] = {
        "content": wire,
        "targetHostname": host,
        "targetPort": port,
        "usesHttps": https,
    }
    if tab_name:
        args["tabName"] = tab_name
    result = await burp_client.call("create_repeater_tab", args)
    return _format_response({
        "ok": True,
        "burp_result": result,
        "warnings": lint(req),
        "wire_preview": wire[:1024],
    })


@mcp.tool()
async def send_request(
    history_id: int | None = None,
    url: str | None = None,
    method: str | None = None,
    path: str | None = None,
    set_headers: dict[str, str] | None = None,
    remove_headers: list[str] | None = None,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    inherit_from_history_id: int | None = None,
    page_size: int = 200,
) -> str:
    """Issue an HTTP/1.1 request via Burp (no Repeater tab) and return the
    response. Two usage modes:

    1. Mutate a history entry: pass `history_id` plus any of method/path/
       set_headers/remove_headers/body.
    2. Build from scratch: pass `url` + method + headers + body. Optionally
       `inherit_from_history_id` to copy cookies/auth from a baseline.
    """
    if history_id is not None and url is not None:
        raise ValueError("pass either history_id or url, not both")
    if history_id is None and url is None:
        raise ValueError("must pass history_id or url")

    if history_id is not None:
        payload = await burp_client.call(
            "get_proxy_http_history",
            {"count": page_size, "offset": 0},
        )
        entry = _extract_baseline(payload, history_id)
        base = parse_raw_request(_entry_raw_request(entry))
        new = apply_overrides(
            base,
            method=method,
            path=path,
            set_headers=set_headers,
            remove_headers=remove_headers,
            body=body,
        )
        host, port, https = _derive_target(new, entry)
    else:
        base_headers: dict[str, str] = {}
        if inherit_from_history_id is not None:
            payload = await burp_client.call(
                "get_proxy_http_history",
                {"count": page_size, "offset": 0},
            )
            entry = _extract_baseline(payload, inherit_from_history_id)
            baseline = parse_raw_request(_entry_raw_request(entry))
            for h in baseline.headers:
                if h.name.lower() in {"host", "content-length"}:
                    continue
                base_headers[h.name] = h.value
        if headers:
            for k, v in headers.items():
                base_headers[k] = v
        new = from_url(method or "GET", url, headers=base_headers, body=body or "")
        host, port, https = host_port_https(new, scheme_hint="https" if url.startswith("https") else "http")

    wire = build_wire(new)
    response = await burp_client.call(
        "send_http1_request",
        {
            "content": wire,
            "targetHostname": host,
            "targetPort": port,
            "usesHttps": https,
        },
    )
    return _format_response({
        "ok": True,
        "warnings": lint(new),
        "wire_preview": wire[:1024],
        "response": response,
    })


@mcp.tool()
async def intruder_from_history(
    history_id: int,
    tab_name: str | None = None,
    method: str | None = None,
    path: str | None = None,
    set_headers: dict[str, str] | None = None,
    remove_headers: list[str] | None = None,
    body: str | None = None,
    payload_markers: list[str] | None = None,
    page_size: int = 200,
) -> str:
    """Send a request to Burp Intruder, built from a history baseline.

    `payload_markers`: list of substrings in the final request to wrap with
    Burp's '§' insertion markers. The substring must appear verbatim in the
    final wire format (after overrides are applied). Markers are added in
    order; duplicate substrings are wrapped only once each.
    """
    payload = await burp_client.call(
        "get_proxy_http_history",
        {"count": page_size, "offset": 0},
    )
    entry = _extract_baseline(payload, history_id)
    base = parse_raw_request(_entry_raw_request(entry))
    new = apply_overrides(
        base,
        method=method,
        path=path,
        set_headers=set_headers,
        remove_headers=remove_headers,
        body=body,
    )
    host, port, https = _derive_target(new, entry)
    wire = build_wire(new)
    if payload_markers:
        missing = []
        for marker in payload_markers:
            if marker not in wire:
                missing.append(marker)
                continue
            wire = wire.replace(marker, f"§{marker}§", 1)
        if missing:
            raise RuntimeError(
                f"payload_markers not found verbatim in built request: {missing!r}"
            )
    args: dict[str, Any] = {
        "content": wire,
        "targetHostname": host,
        "targetPort": port,
        "usesHttps": https,
    }
    if tab_name:
        args["tabName"] = tab_name
    result = await burp_client.call("send_to_intruder", args)
    return _format_response({
        "ok": True,
        "burp_result": result,
        "warnings": lint(new),
        "wire_preview": wire[:1024],
    })


_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.MULTILINE)


def _summarize_entry(entry: dict[str, Any], index: int) -> dict[str, Any]:
    raw = _entry_raw_request(entry)
    parsed = parse_raw_request(raw)
    host, port, https = _derive_target(parsed, entry)
    scheme = "https" if https else "http"
    status: int | None = None
    resp = entry.get("response") or entry.get("rawResponse") or ""
    if isinstance(resp, str):
        m = _STATUS_RE.search(resp)
        if m:
            status = int(m.group(1))
    return {
        "history_index": index,
        "method": parsed.method,
        "url": f"{scheme}://{host}:{port}{parsed.path}",
        "status": status,
    }


@mcp.tool()
async def search_history(regex: str, count: int = 50, offset: int = 0) -> str:
    """Search Burp proxy history with a regex; returns a compact list of
    matching entries with their `history_index` (0-based position in the
    returned page). Feed `history_index` into the other tools as `history_id`.
    """
    payload = await burp_client.call(
        "get_proxy_http_history_regex",
        {"regex": regex, "count": count, "offset": offset},
    )
    entries = _normalize_history(payload)
    summary: list[dict[str, Any]] = []
    for i, e in enumerate(entries):
        try:
            summary.append(_summarize_entry(e, i))
        except Exception as exc:
            summary.append({"history_index": i, "error": str(exc)})
    return json.dumps(summary, indent=2)


@mcp.tool()
async def list_history(count: int = 20, offset: int = 0) -> str:
    """List recent Burp proxy history entries with their `history_index`.

    Use this to browse and find an entry to feed into the repeater/intruder
    tools when a regex search isn't precise enough.
    """
    payload = await burp_client.call(
        "get_proxy_http_history",
        {"count": count, "offset": offset},
    )
    entries = _normalize_history(payload)
    summary: list[dict[str, Any]] = []
    for i, e in enumerate(entries):
        try:
            summary.append(_summarize_entry(e, i))
        except Exception as exc:
            summary.append({"history_index": i, "error": str(exc)})
    return json.dumps(summary, indent=2)


# --- collaborator -------------------------------------------------------


@mcp.tool()
async def collaborator_generate(count: int = 1) -> str:
    """Generate one or more Burp Collaborator payloads.

    Use these as out-of-band injection canaries (SSRF, blind XSS, OOB SQLi,
    etc.). Save the returned payloads, plant them, then poll
    `collaborator_check` to see who phoned home.
    """
    if count < 1:
        raise ValueError("count must be >= 1")
    payloads: list[Any] = []
    for _ in range(count):
        p = await burp_client.call("generate_collaborator_payload", {})
        payloads.append(p)
    return json.dumps({"payloads": payloads}, indent=2)


@mcp.tool()
async def collaborator_check(payload: str | None = None) -> str:
    """Poll Burp Collaborator for received interactions.

    Returns whatever Burp's `get_collaborator_interactions` returns. If
    `payload` is given, the result is filtered to interactions referencing
    that payload string (best-effort substring match).
    """
    args: dict[str, Any] = {}
    if payload:
        # Some Burp MCP versions accept a payload filter; pass it if so.
        # If not, we'll filter client-side after the call.
        args["payload"] = payload
    try:
        result = await burp_client.call("get_collaborator_interactions", args)
    except RuntimeError:
        # Retry without the filter — older versions reject unknown args.
        result = await burp_client.call("get_collaborator_interactions", {})
    if payload and isinstance(result, (list, str)):
        text = json.dumps(result) if not isinstance(result, str) else result
        if payload not in text:
            return json.dumps({"matches": [], "note": f"no interactions referenced {payload!r}"}, indent=2)
    return _format_response(result)


# --- sitemap (synthesized from proxy history) --------------------------


@mcp.tool()
async def sitemap(host_filter: str | None = None, page_size: int = 500) -> str:
    """Build a sitemap from Burp proxy history (no upstream Target tool exists).

    Groups entries by (host, path, method) and counts occurrences. Returns
    a tree-style JSON: { host: { method: [{path, count, last_status}] } }.
    Use `host_filter` (regex) to scope to a specific target.
    """
    payload = await burp_client.call(
        "get_proxy_http_history",
        {"count": page_size, "offset": 0},
    )
    entries = _normalize_history(payload)
    host_rx = re.compile(host_filter, re.IGNORECASE) if host_filter else None
    tree: dict[str, dict[str, dict[str, dict[str, Any]]]] = {}
    for e in entries:
        try:
            parsed = parse_raw_request(_entry_raw_request(e))
        except Exception:
            continue
        host_hdr = parsed.get("Host") or ""
        host = host_hdr.split(":", 1)[0]
        if host_rx and not host_rx.search(host):
            continue
        # Strip query string for grouping; keep path
        path = parsed.path.split("?", 1)[0]
        method = parsed.method
        # Pull status from response if any
        status = None
        resp = e.get("response") or ""
        if isinstance(resp, str):
            m = _STATUS_RE.search(resp)
            if m:
                status = int(m.group(1))
        tree.setdefault(host, {}).setdefault(method, {}).setdefault(path, {"count": 0, "last_status": None})
        tree[host][method][path]["count"] += 1
        if status is not None:
            tree[host][method][path]["last_status"] = status
    # Flatten paths dict → list, sorted by path.
    out: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for host, methods in sorted(tree.items()):
        out[host] = {}
        for method, paths in sorted(methods.items()):
            out[host][method] = [
                {"path": p, **info} for p, info in sorted(paths.items())
            ]
    return json.dumps(out, indent=2)


# --- dedup file ingestion ----------------------------------------------


@mcp.tool()
def dedup_load(path: str, name: str | None = None) -> str:
    """Load a `deduped_requests.txt` file produced by the user's Burp
    `Deduped HTTP History + JS Exporter` extension.

    `path`: filesystem path (absolute or ~-expandable).
    `name`: identifier to address this source by in later calls. Default:
        parent directory name.
    """
    src = dedup.register(path, name)
    return json.dumps({"name": src.name, "path": src.path, "entries": len(src.entries)}, indent=2)


@mcp.tool()
def dedup_list() -> str:
    """List all registered dedup sources."""
    return json.dumps(dedup.list_sources(), indent=2)


@mcp.tool()
def dedup_search(
    name: str,
    pattern: str,
    field: str = "url",
    limit: int = 20,
) -> str:
    """Regex-search a registered dedup source.

    `field`: one of `url`, `request`, `response`, `params`, or `all`.
    Returns matches with index + url + status + a short snippet (token-thrifty).
    Use `dedup_get` to fetch the full request/response.
    """
    return json.dumps(dedup.search(name, pattern, field=field, limit=limit), indent=2)


@mcp.tool()
def dedup_get(name: str, index: int, full: bool = False) -> str:
    """Fetch a dedup entry by its 1-based index.

    By default returns metadata + truncated request/response previews. Set
    `full=True` to get the complete raw request and response.
    """
    src = dedup.get(name)
    target = next((e for e in src.entries if e.index == index), None)
    if target is None:
        raise KeyError(f"no entry index={index} in source {name!r}")
    out: dict[str, Any] = {
        "index": target.index,
        "method": target.method,
        "url": target.url,
        "status": target.status,
        "length": target.length,
        "parameters": target.parameters,
    }
    if full:
        out["request"] = target.request
        out["response"] = target.response
    else:
        out["request_preview"] = target.request[:1024]
        out["response_preview"] = target.response[:1024]
        out["request_bytes"] = len(target.request)
        out["response_bytes"] = len(target.response)
    return json.dumps(out, indent=2)


@mcp.tool()
async def dedup_to_repeater(
    name: str,
    index: int,
    tab_name: str | None = None,
    method: str | None = None,
    path: str | None = None,
    set_headers: dict[str, str] | None = None,
    remove_headers: list[str] | None = None,
    body: str | None = None,
) -> str:
    """Send a dedup entry to Burp Repeater, with optional structured overrides.

    The dedup entry is the baseline (cookies, UA, etc. inherited). The
    wrapper rebuilds the wire format and pushes it via Burp's
    `create_repeater_tab`.
    """
    src = dedup.get(name)
    target = next((e for e in src.entries if e.index == index), None)
    if target is None:
        raise KeyError(f"no entry index={index} in source {name!r}")
    raw = target.request
    if not raw or not raw.strip():
        raise RuntimeError(
            f"dedup entry {name!r}#{index} has an empty request — the source file may be "
            "truncated or malformed. Try `dedup_get(name, index, full=True)` to inspect it."
        )
    # The dedup file may store HTTP/2 requests with "HTTP/2" version. Coerce
    # to HTTP/1.1 for the Burp send_http1 / Repeater path. The Repeater can
    # still upgrade to HTTP/2 on send if the target supports it.
    raw = re.sub(r"(\S+\s+\S+)\s+HTTP/2(?:\.0)?\s*$", r"\1 HTTP/1.1", raw, count=1, flags=re.MULTILINE)
    try:
        base = parse_raw_request(raw)
    except BuildError as e:
        raise RuntimeError(
            f"dedup entry {name!r}#{index} could not be parsed: {e}"
        ) from e
    _validate_baseline(base, source=f"dedup {name!r}#{index}")
    new = apply_overrides(
        base,
        method=method,
        path=path,
        set_headers=set_headers,
        remove_headers=remove_headers,
        body=body,
    )
    host, port, https = _derive_target(new)
    try:
        wire = build_wire(new)
    except BuildError as e:
        raise RuntimeError(f"failed to build complete request: {e}") from e
    args: dict[str, Any] = {
        "content": wire,
        "targetHostname": host,
        "targetPort": port,
        "usesHttps": https,
    }
    if tab_name:
        args["tabName"] = tab_name
    result = await burp_client.call("create_repeater_tab", args)
    return _format_response({
        "ok": True,
        "burp_result": result,
        "warnings": lint(new),
        "wire_preview": wire[:1024],
        "source": {"name": name, "index": index, "url": target.url},
    })


# --- JS export ingestion -----------------------------------------------


@mcp.tool()
def js_load(manifest_path: str, name: str | None = None) -> str:
    """Load a `_manifest.csv` produced by the JS Exporter side of the user's
    Burp extension.
    """
    src = jsfiles.register(manifest_path, name)
    missing = sum(1 for r in src.records if not r.abs_path)
    return json.dumps({
        "name": src.name,
        "manifest": src.manifest_path,
        "files": len(src.records),
        "missing_on_disk": missing,
    }, indent=2)


@mcp.tool()
def js_list() -> str:
    """List all registered JS sources."""
    return json.dumps(jsfiles.list_sources(), indent=2)


@mcp.tool()
def js_files(name: str, host_filter: str | None = None, limit: int = 200) -> str:
    """List JS files in a source, optionally filtered by host regex."""
    return json.dumps(jsfiles.list_files(name, host_filter=host_filter, limit=limit), indent=2)


@mcp.tool()
def js_search(
    name: str,
    pattern: str,
    limit: int = 20,
    max_matches_per_file: int = 3,
    context: int = 60,
    host_filter: str | None = None,
) -> str:
    """Grep across all on-disk JS files in a source.

    Returns file:line + small context snippets (token-thrifty). Use `js_read`
    to fetch full content for files of interest.
    """
    return json.dumps(
        jsfiles.search(
            name,
            pattern,
            limit=limit,
            max_matches_per_file=max_matches_per_file,
            context=context,
            host_filter=host_filter,
        ),
        indent=2,
    )


@mcp.tool()
def js_read(name: str, ref: str, max_bytes: int = 50000) -> str:
    """Read one JS file from a source.

    `ref`: either the integer index (as string), the full URL, the path, the
    saved_as path, or the basename. The first matching record wins.
    """
    # Allow integer-looking refs.
    target: int | str
    try:
        target = int(ref)
    except ValueError:
        target = ref
    return json.dumps(jsfiles.read_file(name, target, max_bytes=max_bytes), indent=2)


def main() -> None:
    """stdio entrypoint for Claude Code / MCP host."""
    mcp.run()


if __name__ == "__main__":
    main()
