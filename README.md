<div align="center">
  <img src="assets/logo.svg" alt="burp-mcp-plus" width="640">

  <p>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
    <img src="https://img.shields.io/badge/python-3.11%2B-3776ab?logo=python&logoColor=white" alt="Python 3.11+">
    <img src="https://img.shields.io/badge/MCP-1.2%2B-5e60ce" alt="MCP 1.2+">
    <img src="https://img.shields.io/badge/Burp%20Suite-Pro-ff6633?logo=burpsuite&logoColor=white" alt="Burp Pro">
    <img src="https://img.shields.io/badge/status-beta-orange" alt="beta">
    <img src="https://img.shields.io/badge/tests-20%20passing-2ea44f" alt="tests">
  </p>

  <p><b>The MCP for Burp Suite that doesn't make your LLM hallucinate broken HTTP requests.</b></p>
</div>

---

## The problem

You hook up an LLM to Burp's official MCP server and ask it to "replay this request with a tampered cookie." It dutifully crafts a Repeater payload — and silently drops the `Cookie` header, gets a 401, and confidently tells you the endpoint requires no auth.

Or it forgets `Content-Length`. Or `Host`. Or uses LF instead of CRLF. Or pastes a JSON body with no headers at all.

This happens because the upstream Burp MCP takes a free-form `content` string. Whatever the model emits goes straight to the wire. There's no schema, no validation, no help.

The other thing that breaks long pentest sessions: **token cost**. Each `get_proxy_http_history` call ships kilobytes of repeated headers back to the model. Triage a target for an hour and you've burned a fortune re-paginating the same proxy history.

---

## What this fixes

**`burp-mcp-plus`** is a Python MCP wrapper that sits between your LLM and Burp's official MCP server. Two big ideas:

### 1. Structured input, not free-form strings

Every tool that touches HTTP takes typed fields — `method`, `path`, `set_headers`, `body` — and a *baseline* (a real entry from Burp's history, or a URL). The wrapper builds the wire format itself. Correct CRLF, auto-`Host`, auto-`Content-Length`, default `User-Agent`, inherited cookies. The LLM literally cannot produce a malformed request because there's no `content` parameter to put a malformed request in.

### 2. Local file ingestion for the boring stuff

If you've already triaged a target with the bundled `Deduped HTTP History + JS Exporter` Burp extension, the wrapper indexes the exports on disk. `dedup_search` and `js_search` return file:line + 60-char snippets — meaningfully cheaper than re-hitting Burp every time the model wants to look at past traffic. Full content is only fetched on demand.

---

## Architecture

<div align="center">
  <img src="assets/architecture.svg" alt="architecture" width="720">
</div>

Plain Python stdio MCP server. Talks SSE to Burp's `mcp-proxy-all` extension on `localhost:9876`. Reads dedup/JS exports off disk. Works with any MCP host: Claude Desktop, Claude Code, Cursor, Continue, anything that speaks the protocol.

---

## Features

### Live Burp interaction

- **`list_history`** / **`search_history`** — paginate or regex over proxy history. Returns compact summaries (id + method + url + status), not raw bytes.
- **`inspect_history_entry`** — pretty-print one entry's headers, body, target.
- **`repeater_from_history`** — clone a baseline, mutate any subset of (method, path, headers, body), push to Repeater. **All other headers preserved verbatim from the baseline.** Cookies, auth tokens, Sec-Fetch-*, custom Anthropic-* / X-* headers — all carry through.
- **`repeater_from_template`** — build from scratch with a URL. Optionally inherit auth from a history baseline.
- **`send_request`** — same shape, but actually sends and returns the response. Skip the Repeater dance when you just want to test.
- **`intruder_from_history`** — push to Intruder with `§…§` payload markers wrapped automatically around substrings you specify.
- **`sitemap`** — host → method → paths tree, synthesized from history. Burp's MCP doesn't expose Target; we synthesize one.
- **`collaborator_generate`** / **`collaborator_check`** — OOB canary payloads + interaction polling.

### Local dedup file ingestion

Point at a `deduped_requests.txt` produced by the bundled extension and the model can search/replay endpoints from past sessions without round-tripping through Burp.

- **`dedup_load`** / **`dedup_list`** — register file(s) under a name.
- **`dedup_search`** — regex over `url` / `request` / `response` / `params` / `all`. Returns 60-char snippets.
- **`dedup_get`** — preview by default, full request/response on demand.
- **`dedup_to_repeater`** — replay a stored entry into a fresh Repeater tab with optional mutations. HTTP/2 lines auto-coerced to HTTP/1.1.

### Local JS-export ingestion

Point at a `_manifest.csv` produced by the bundled extension's JS Exporter and the model can grep across all the JavaScript captured for a target.

- **`js_load`** / **`js_list`** — register an export.
- **`js_files`** — browse the manifest, filter by host regex.
- **`js_search`** — grep across all on-disk JS. Returns file:line + snippet, max N matches per file (default 3). Transparently decodes the legacy `array('b', [...])` byte-list format that older versions of the extension produced.
- **`js_read`** — fetch full content for files of interest.

### Hardened against the real world

- Tolerates Burp's NDJSON-with-no-separators history format.
- Recovers parse-mid-stream when Burp truncates a long response with `... (truncated)`.
- `strict=False` JSON decoding for raw control bytes inside body strings.
- Specific error messages for empty inputs, status markers, malformed entries — pointing the model at the next tool to call.
- 20 tests covering wire-format building and edge cases (no Burp required to run them).

---

## Install

### 1. Burp side

Install **MCP Server** from Burp's BApp Store. Confirm it's listening on `http://127.0.0.1:9876` (Output tab).

If you want the dedup/JS ingestion features, install the bundled extension:

1. Set up Jython 2.7 in Burp → Settings → Extensions → Python environment.
2. Burp → Extensions → Installed → Add → Python → `burp-extension/deduped_history.py` from this repo.
3. Two new tabs appear: **Deduped History** and **JS Exporter**. Browse a target, then export.

### 2. Wrapper side

Requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/titaniumtushar/burp-mcp-plus.git
cd burp-mcp-plus
uv sync
uv run pytest                  # offline tests; no Burp required
```

### 3. Wire it into your MCP host

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "burp": {
      "command": "/path/to/burp-suite-jdk/bin/java",
      "args": [
        "-jar", "/path/to/.BurpSuite/mcp-proxy/mcp-proxy-all.jar",
        "--sse-url", "http://127.0.0.1:9876"
      ]
    },
    "burp-plus": {
      "command": "/opt/homebrew/bin/uv",
      "args": [
        "run", "--directory", "/path/to/burp-mcp-plus", "burp-mcp-plus"
      ]
    }
  }
}
```

(Sample at [`examples/claude_desktop_config.json`](examples/claude_desktop_config.json).)

Restart the host. Tools appear as `mcp__burp-plus__*`.

For **Claude Code CLI**, **Cursor**, **Continue** — same config shape, different config file. The MCP server itself doesn't care.

---

## What it looks like in practice

### Replay an authenticated POST with a single mutation

Model says:
> "Replay history entry 47 with `X-Forwarded-For: 127.0.0.1` and send it to a Repeater tab."

Tool call:
```python
repeater_from_history(
    history_id=47,
    set_headers={"X-Forwarded-For": "127.0.0.1"},
    tab_name="acme idor probe"
)
```

What lands in Burp:
- Original method, path, HTTP version
- All 18 baseline headers preserved (Cookie chain, `Anthropic-*`, `Sec-Fetch-*`, custom auth)
- One header injected
- Body unchanged
- `Content-Length` recomputed to match the actual body bytes
- 0 lint warnings — the request is structurally complete

If you'd asked the model to craft this as a free-form string, it would have lost at least one of those headers and the request would 401.

### Find an endpoint in old triage data without re-pulling history

```python
dedup_load("/Users/me/targets/acme/deduped_requests.txt")     # 412 entries
dedup_search("acme", r"/api/v\d+/admin", field="url", limit=5)
# [
#   { index: 47, method: "GET", url: "https://app.acme.com/api/v1/admin/users", status: 200 },
#   ...
# ]
dedup_to_repeater("acme", 47, set_headers={"X-Forwarded-For": "127.0.0.1"})
```

Total bytes shipped to the model: ~600 for the search, ~1000 for the replay confirmation. Same flow through Burp's MCP would be tens of KB just for the history page.

### Grep every captured JS file for an auth pattern

```python
js_load("/Users/me/targets/acme/_manifest.csv")
js_search("acme", r"Bearer\s+[A-Za-z0-9._-]{20,}", host_filter=r"app\.acme")
# returns file:line + 60 chars of context, max 3 hits per file
js_read("acme", 42)   # fetch one specific file in full
```

### Plant an OOB canary

```python
collaborator_generate(count=2)
# { payloads: ["o8xx....oastify.com", "oskx....oastify.com"] }

# (use them in injection points...)

collaborator_check()
# returns interactions, if any
```

---

## Tools at a glance

| Group | Tool | Returns |
| ----- | ---- | ------- |
| **History** | `list_history` | compact list w/ `history_index` |
| | `search_history` | regex-filtered compact list |
| | `inspect_history_entry` | one entry pretty-printed |
| **Replay** | `repeater_from_history` | Repeater tab (mutated) |
| | `repeater_from_template` | Repeater tab (built from URL) |
| | `send_request` | response from a built request |
| | `intruder_from_history` | Intruder tab w/ `§…§` markers |
| **Sitemap** | `sitemap` | host → method → paths tree |
| **OOB** | `collaborator_generate` | N Burp Collaborator payloads |
| | `collaborator_check` | interactions, optionally filtered |
| **Dedup** | `dedup_load` / `dedup_list` | source registration |
| | `dedup_search` | regex hits w/ snippets |
| | `dedup_get` | one entry, preview or full |
| | `dedup_to_repeater` | Repeater tab from stored entry |
| **JS** | `js_load` / `js_list` / `js_files` | source mgmt + browse |
| | `js_search` | grep w/ file:line + snippet |
| | `js_read` | one file's content |

20 tools total. All structured input. All return either compact JSON or short text.

---

## What it doesn't do (yet)

- **HTTP/2 wire format** — the wrapper sends HTTP/1.1; Burp Repeater/Intruder upgrades to HTTP/2 on send if the target supports it. If you need raw HTTP/2 frame control, fall back to upstream `mcp__burp__send_http2_request`.
- **Scanner / Active Scan triggering** — exposed by the upstream MCP but not yet wrapped here.
- **Project options / session rules / scope edits** — same.
- **WebSocket history** — only HTTP for now.

PRs welcome for any of the above.

---

## The bundled Burp extension

`burp-extension/deduped_history.py` is a Jython extension I wrote (and fixed — see `CHANGELOG`-equivalent notes below) that produces the dedup/JS exports the wrapper indexes.

**Tab 1: Deduped History.** Watches proxy traffic. Adds a row only when a new (method, host, path, parameters) tuple appears. Re-fires when new query/body parameter names show up on an endpoint. Export the whole thing to `deduped_requests.txt`.

**Tab 2: JS Exporter.** Watches for JavaScript responses, saves each unique JS file to `<output>/<project>/<host>/<flattened-path>/<name>.js`, writes a `_manifest.csv`. Detects version strings from filenames and content hashes.

**Bug fix included:** Older versions wrote JS files as Python `array('b', [10, 10, ...])` literals instead of raw bytes (Jython slice-of-byte-array gotcha). The version in this repo writes proper bytes. The wrapper transparently decodes the old format too, so legacy exports keep working.

---

## Token economics

Rough numbers from a typical pentest session:

| Action | Upstream Burp MCP | burp-mcp-plus | Reduction |
| ------ | ---------------- | -------------- | --------- |
| List 50 history entries | ~60 KB | ~3 KB | 95% |
| Search history (regex, 30 hits) | ~90 KB | ~4 KB | 95% |
| Replay one auth'd request | ~5 KB request + ~5 KB confirmation | ~1 KB | 80% |
| Find an endpoint in past triage | re-paginate proxy (~60 KB) | dedup_search (~600 B) | 99% |
| Grep all JS for a pattern | not feasible | ~2 KB w/ snippets | — |

The wrapper's job is to keep the model focused on the smallest bytes that answer the question.

---

## Tested with

- Burp Suite Pro 2025.x
- Anthropic MCP Server BApp 1.x
- Claude Desktop on macOS
- Python 3.11, 3.12, 3.13
- macOS arm64, Linux x86_64

Should work on Windows but I haven't tested it. Reports welcome.

---

## Security notes

This is a **defensive tool for authorized testing.** It's no more dangerous than Burp itself — but:

- The MCP exposes your Burp's full power to whatever model you connect. Don't connect untrusted models.
- File ingestion (`dedup_*`, `js_*`) reads paths you provide. There's no sandbox; treat the wrapper's host as trusted.
- The wrapper doesn't authenticate to Burp's MCP — it relies on Burp's `localhost`-only binding. Don't expose Burp's MCP port externally.
- Pentest scope discipline applies. The wrapper makes it easier to fire requests; it doesn't validate that you should.

---

## Contributing

Issues and PRs welcome. A few ground rules:

- **Tests stay green.** `uv run pytest` before opening a PR. The builder in `src/burp_mcp_plus/builder.py` is pure logic and easy to test offline.
- **No new free-form `content` parameters.** That's the whole anti-pattern this tool exists to prevent. Add structured fields instead.
- **Compact returns.** If a new tool would return more than a few KB by default, add a `limit` / `field` / `preview` knob.
- **No hidden network calls.** Tool side effects should be obvious from the name.

---

## License

[MIT](LICENSE).

## Thanks

- **PortSwigger** — Burp Suite and the official MCP server.
- **Anthropic** — the MCP spec and Python SDK.
- Everyone running long pentest sessions who got tired of debugging "why did my LLM drop the Cookie header again."
