"""Indexer for the JS Exporter side of the user's Burp extension.

Layout:
    <root>/_manifest.csv
    <root>/<host>/<path-flattened>/<filename>.js

Manifest columns:
    index, timestamp, host, path, version, size_bytes, full_url, saved_as

`saved_as` is relative to the manifest's parent directory (or to <root>
two levels up — varies). We resolve it robustly by trying both.
"""

from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


_ARRAY_PREFIX_RE = re.compile(rb"^\s*array\s*\(\s*'b'\s*,\s*\[")
_ARRAY_BODY_RE = re.compile(rb"-?\d+")


def _maybe_decode_array_b(raw: bytes) -> bytes:
    """The user's JS Exporter (a Jython Burp extension) sometimes saves files
    as a Python `array('b', [10, 10, ...])` literal — the repr of the bytes,
    not the bytes themselves. Detect and decode that.
    """
    if not _ARRAY_PREFIX_RE.match(raw):
        return raw
    nums = _ARRAY_BODY_RE.findall(raw)
    try:
        out = bytes((int(n) & 0xFF) for n in nums)
    except (ValueError, OverflowError):
        return raw
    return out


@dataclass
class JsRecord:
    index: int
    timestamp: str
    host: str
    path: str
    version: str
    size_bytes: int
    full_url: str
    saved_as: str  # path as recorded in manifest
    abs_path: str  # absolute path on disk if found


@dataclass
class JsSource:
    name: str
    manifest_path: str
    records: list[JsRecord] = field(default_factory=list)


_REGISTRY: dict[str, JsSource] = {}


def _resolve_abs(manifest_path: str, saved_as: str) -> str:
    manifest_dir = os.path.dirname(os.path.abspath(manifest_path))
    # 1. Relative to manifest dir
    cand = os.path.join(manifest_dir, saved_as)
    if os.path.isfile(cand):
        return cand
    # 2. Relative to manifest's parent (extension sometimes nests)
    cand = os.path.join(os.path.dirname(manifest_dir), saved_as)
    if os.path.isfile(cand):
        return cand
    # 3. saved_as may already be absolute
    if os.path.isabs(saved_as) and os.path.isfile(saved_as):
        return saved_as
    return ""


def parse_manifest(manifest_path: str | Path) -> list[JsRecord]:
    path = str(manifest_path)
    records: list[JsRecord] = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                idx = int(row.get("index", "0"))
            except ValueError:
                continue
            try:
                size = int(row.get("size_bytes", "0"))
            except ValueError:
                size = 0
            saved_as = row.get("saved_as", "")
            abs_p = _resolve_abs(path, saved_as)
            records.append(
                JsRecord(
                    index=idx,
                    timestamp=row.get("timestamp", ""),
                    host=row.get("host", ""),
                    path=row.get("path", ""),
                    version=row.get("version", ""),
                    size_bytes=size,
                    full_url=row.get("full_url", ""),
                    saved_as=saved_as,
                    abs_path=abs_p,
                )
            )
    return records


def register(manifest_path: str, name: str | None = None) -> JsSource:
    p = os.path.abspath(os.path.expanduser(manifest_path))
    if not os.path.isfile(p):
        raise FileNotFoundError(p)
    if name is None:
        name = os.path.basename(os.path.dirname(p)) or "js"
    src = JsSource(name=name, manifest_path=p, records=parse_manifest(p))
    _REGISTRY[name] = src
    return src


def get(name: str) -> JsSource:
    if name not in _REGISTRY:
        raise KeyError(f"js source {name!r} not loaded; call js_load first")
    return _REGISTRY[name]


def list_sources() -> list[dict[str, object]]:
    return [
        {
            "name": s.name,
            "manifest": s.manifest_path,
            "files": len(s.records),
            "missing_on_disk": sum(1 for r in s.records if not r.abs_path),
        }
        for s in _REGISTRY.values()
    ]


def list_files(name: str, host_filter: str | None = None, limit: int = 200) -> list[dict[str, object]]:
    src = get(name)
    records = src.records
    if host_filter:
        rx = re.compile(host_filter, re.IGNORECASE)
        records = [r for r in records if rx.search(r.host)]
    return [
        {
            "index": r.index,
            "host": r.host,
            "path": r.path,
            "version": r.version,
            "size_bytes": r.size_bytes,
            "url": r.full_url,
            "on_disk": bool(r.abs_path),
        }
        for r in records[:limit]
    ]


def search(
    name: str,
    pattern: str,
    *,
    limit: int = 20,
    max_matches_per_file: int = 3,
    context: int = 60,
    host_filter: str | None = None,
) -> list[dict[str, object]]:
    """Grep across all on-disk JS files in this source.

    Returns a list of match descriptors with file:line + a small context
    snippet — keeps token usage low. Use `js_read` to fetch full file content.
    """
    src = get(name)
    rx = re.compile(pattern, re.IGNORECASE)
    host_rx = re.compile(host_filter, re.IGNORECASE) if host_filter else None
    out: list[dict[str, object]] = []
    for r in src.records:
        if not r.abs_path:
            continue
        if host_rx and not host_rx.search(r.host):
            continue
        try:
            raw_bytes = Path(r.abs_path).read_bytes()
        except OSError:
            continue
        decoded = _maybe_decode_array_b(raw_bytes)
        try:
            content = decoded.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            continue
        matches: list[dict[str, object]] = []
        for m in rx.finditer(content):
            # Compute line number
            line_no = content.count("\n", 0, m.start()) + 1
            start = max(0, m.start() - context)
            end = min(len(content), m.end() + context)
            snippet = content[start:end].replace("\n", " ")
            matches.append({
                "line": line_no,
                "snippet": snippet,
            })
            if len(matches) >= max_matches_per_file:
                break
        if matches:
            out.append({
                "index": r.index,
                "host": r.host,
                "path": r.path,
                "version": r.version,
                "size_bytes": r.size_bytes,
                "matches": matches,
            })
        if len(out) >= limit:
            break
    return out


def read_file(name: str, ref: int | str, *, max_bytes: int = 50000) -> dict[str, object]:
    """Read one file from the source by index, host+path, or basename."""
    src = get(name)
    target: JsRecord | None = None
    if isinstance(ref, int):
        for r in src.records:
            if r.index == ref:
                target = r
                break
    else:
        for r in src.records:
            if r.full_url == ref or r.path == ref or r.saved_as == ref or os.path.basename(r.saved_as) == ref:
                target = r
                break
    if target is None:
        raise KeyError(f"no JS record matching {ref!r} in source {name!r}")
    if not target.abs_path:
        return {"error": "file not on disk", "record": _record_to_dict(target)}
    raw = Path(target.abs_path).read_bytes()
    raw = _maybe_decode_array_b(raw)
    truncated = len(raw) > max_bytes
    body = raw[:max_bytes].decode("utf-8", errors="replace")
    return {
        "record": _record_to_dict(target),
        "size_bytes": len(raw),
        "truncated": truncated,
        "content": body,
    }


def _record_to_dict(r: JsRecord) -> dict[str, object]:
    return {
        "index": r.index,
        "host": r.host,
        "path": r.path,
        "version": r.version,
        "size_bytes": r.size_bytes,
        "url": r.full_url,
        "saved_as": r.saved_as,
        "abs_path": r.abs_path,
    }
