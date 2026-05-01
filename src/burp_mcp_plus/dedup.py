"""Parser for the user's `Deduped HTTP History + JS Exporter` Burp extension
output (deduped_requests.txt).

File format (from the extension source):

    # Deduped HTTP History Export
    # Total unique requests: N
    ...
    ========================================================================
    # [0001]  GET https://host/path
    #  Parameters : ...
    #  Status     : 200   Length: 12345
    ========================================================================
    -- REQUEST --
    <raw HTTP request, HTTP/1.1 or HTTP/2>
    ------------------------------------------------------------------------
    -- RESPONSE --
    <raw HTTP response>

    ========================================================================
    # [0002] ...

The point of ingesting it locally: lets the model search/replay endpoints
discovered in past sessions without round-tripping the full proxy history
through Burp's MCP.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

_HEADER_RE = re.compile(
    r"^# \[(\d+)\]\s+([A-Z]+)\s+(\S+)\s*$",
    re.MULTILINE,
)
_STATUS_RE = re.compile(r"^#\s+Status\s*:\s*(\d+)", re.MULTILINE)
_LENGTH_RE = re.compile(r"Length:\s*(\d+)", re.MULTILINE)
_PARAMS_RE = re.compile(r"^#\s+Parameters\s*:\s*(.*)$", re.MULTILINE)


@dataclass
class DedupEntry:
    index: int  # 1-based as in the file
    method: str
    url: str
    status: int | None
    length: int | None
    parameters: str
    request: str
    response: str

    def host_path(self) -> tuple[str, str]:
        # url is full https://host[:port]/path
        m = re.match(r"https?://([^/]+)(/.*)?$", self.url)
        if not m:
            return "", self.url
        host = m.group(1)
        path = m.group(2) or "/"
        return host, path


@dataclass
class DedupSource:
    name: str
    path: str
    entries: list[DedupEntry]


def parse_dedup_file(path: str | Path) -> list[DedupEntry]:
    text = Path(path).read_text(errors="replace")
    # Split on the long === line that delimits each entry header.
    # The format puts === lines around the metadata header. Easiest robust
    # parse: split by "-- REQUEST --" and walk back/forward.
    parts = text.split("-- REQUEST --")
    entries: list[DedupEntry] = []
    # parts[0] is the file preamble; parts[1..] each begin with the request
    # body, then "-- RESPONSE --", then response, then the next entry's
    # metadata header.
    # The metadata for entry i lives at the END of parts[i] (preceded by ===).
    for i in range(1, len(parts)):
        # Metadata for THIS entry sits at the end of the PREVIOUS chunk.
        prev = parts[i - 1]
        meta_match = _HEADER_RE.findall(prev)
        if not meta_match:
            continue
        idx_s, method, url = meta_match[-1]
        try:
            idx = int(idx_s)
        except ValueError:
            continue
        # Status/Length/Parameters from the trailing portion of prev.
        # Find the last header block in prev.
        last_eq = prev.rfind("======")
        meta_block = prev[max(0, prev.rfind("====", 0, last_eq) - 200):]
        status_m = _STATUS_RE.search(meta_block)
        length_m = _LENGTH_RE.search(meta_block)
        params_m = _PARAMS_RE.search(meta_block)
        status = int(status_m.group(1)) if status_m else None
        length = int(length_m.group(1)) if length_m else None
        parameters = params_m.group(1).strip() if params_m else ""
        # Body is parts[i] up to "-- RESPONSE --"; response is after.
        body = parts[i]
        if "-- RESPONSE --" in body:
            req_block, resp_block = body.split("-- RESPONSE --", 1)
        else:
            req_block, resp_block = body, ""
        # Trim the dashed separator line "-----..." from end of req_block.
        req_clean = re.sub(r"\n-{40,}\s*$", "", req_block.strip("\r\n"), count=1)
        # Trim the next entry's "===..." from start of resp_block.
        resp_clean = resp_block
        next_eq = resp_clean.find("\n========================================")
        if next_eq != -1:
            resp_clean = resp_clean[:next_eq]
        resp_clean = resp_clean.strip("\r\n")
        entries.append(
            DedupEntry(
                index=idx,
                method=method,
                url=url,
                status=status,
                length=length,
                parameters=parameters,
                request=req_clean,
                response=resp_clean,
            )
        )
    return entries


# In-process registry of loaded dedup sources.
_REGISTRY: dict[str, DedupSource] = {}


def register(path: str, name: str | None = None) -> DedupSource:
    p = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(p):
        raise FileNotFoundError(p)
    if name is None:
        # Default name: parent dir basename, fall back to file stem.
        parent = os.path.basename(os.path.dirname(p)) or os.path.splitext(
            os.path.basename(p)
        )[0]
        name = parent
    entries = parse_dedup_file(p)
    src = DedupSource(name=name, path=p, entries=entries)
    _REGISTRY[name] = src
    return src


def get(name: str) -> DedupSource:
    if name not in _REGISTRY:
        raise KeyError(f"dedup source {name!r} not loaded; call dedup_load first")
    return _REGISTRY[name]


def list_sources() -> list[dict[str, object]]:
    return [
        {"name": s.name, "path": s.path, "entries": len(s.entries)}
        for s in _REGISTRY.values()
    ]


def search(
    name: str,
    pattern: str,
    field: str = "url",
    limit: int = 20,
    flags: int = re.IGNORECASE,
) -> list[dict[str, object]]:
    src = get(name)
    rx = re.compile(pattern, flags)
    field = field.lower()
    out: list[dict[str, object]] = []
    for e in src.entries:
        haystacks: list[str] = []
        if field in ("url", "all"):
            haystacks.append(e.url)
        if field in ("request", "all"):
            haystacks.append(e.request)
        if field in ("response", "all"):
            haystacks.append(e.response)
        if field in ("params", "parameters", "all"):
            haystacks.append(e.parameters)
        for h in haystacks:
            m = rx.search(h)
            if m:
                # Snippet around the match for context.
                start = max(0, m.start() - 60)
                end = min(len(h), m.end() + 60)
                snippet = h[start:end].replace("\n", " ")
                out.append({
                    "index": e.index,
                    "method": e.method,
                    "url": e.url,
                    "status": e.status,
                    "match_field": field if field != "all" else _which_field(e, h),
                    "snippet": snippet,
                })
                break
        if len(out) >= limit:
            break
    return out


def _which_field(e: DedupEntry, h: str) -> str:
    if h is e.url:
        return "url"
    if h is e.request:
        return "request"
    if h is e.response:
        return "response"
    return "params"
