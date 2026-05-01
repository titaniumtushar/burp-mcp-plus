"""Thin MCP client to PortSwigger's Burp MCP server (default localhost:9876, SSE)."""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from typing import Any

from mcp import ClientSession
from mcp.client.sse import sse_client

DEFAULT_BURP_MCP_URL = os.environ.get("BURP_MCP_URL", "http://localhost:9876/")


@asynccontextmanager
async def open_session(url: str = DEFAULT_BURP_MCP_URL):
    """Open an MCP SSE session to Burp's mcp-proxy. Yields a ClientSession."""
    async with sse_client(url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


def _decode_concatenated(text: str) -> list[Any] | None:
    """Decode a string of concatenated JSON values (NDJSON or back-to-back).

    Resilient to Burp's quirks:
    - strict=False allows raw control bytes inside strings (Burp emits them)
    - When a value fails to parse mid-stream (e.g. Burp truncated a response
      with a literal "... (truncated)" marker, leaving an unclosed string),
      we skip ahead to the next likely object boundary (`\\n\\n{"request":`)
      and continue. Already-decoded objects are kept.
    - If even the first object fails, returns None so the caller can fall
      back to raw text.
    """
    decoder = json.JSONDecoder(strict=False)
    out: list[Any] = []
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i] in " \r\n\t":
            i += 1
        if i >= n:
            break
        try:
            obj, end = decoder.raw_decode(text, i)
            out.append(obj)
            i = end
        except (json.JSONDecodeError, ValueError):
            # Try to recover: scan forward to the next object boundary.
            # Burp separates entries with two newlines.
            nxt = text.find('\n\n{"', i + 1)
            if nxt == -1:
                # No more objects we can recover. Bail with what we have.
                if out:
                    return out
                return None
            i = nxt + 2  # skip the '\n\n', leave the '{' for next iteration
    return out if out else None


async def call(
    tool: str,
    arguments: dict[str, Any],
    *,
    url: str = DEFAULT_BURP_MCP_URL,
) -> Any:
    """Call a single Burp MCP tool and return the parsed result.

    Burp's MCP frequently returns multiple JSON objects concatenated inside a
    single TextContent block (NDJSON-ish). We stream-decode them. Behavior:
      - Multiple JSON values decoded → return as a list
      - Single JSON value decoded → return that value
      - No clean decode → return the raw text

    Raises RuntimeError on tool error.
    """
    async with open_session(url) as session:
        result = await session.call_tool(tool, arguments=arguments)
        if result.isError:
            text_parts = [
                getattr(c, "text", "") for c in result.content if hasattr(c, "text")
            ]
            raise RuntimeError(
                f"burp MCP tool {tool!r} returned error: {' | '.join(text_parts) or result}"
            )
        chunks: list[str] = []
        for c in result.content:
            t = getattr(c, "text", None)
            if t:
                chunks.append(t)
        if not chunks:
            return None

        # First try: each TextContent block is itself one or more JSON values.
        all_decoded: list[Any] = []
        any_failed = False
        for ch in chunks:
            decoded = _decode_concatenated(ch)
            if decoded is None:
                any_failed = True
                break
            all_decoded.extend(decoded)
        if not any_failed:
            if len(all_decoded) == 1:
                return all_decoded[0]
            return all_decoded

        # Fallback: treat the joined text as one stream of JSON values.
        joined = "\n".join(chunks)
        decoded = _decode_concatenated(joined)
        if decoded is not None:
            return decoded[0] if len(decoded) == 1 else decoded
        return joined
