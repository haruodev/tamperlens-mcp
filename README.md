# tamperlens-mcp

MCP server for [Tamperlens](https://tamperlens.com) — ask whether a document was
edited, whether its redactions held, and whether it is safe for a model to read,
**before** it reaches your agent's context.

```jsonc
// Claude Desktop / Claude Code — claude_desktop_config.json or .mcp.json
{
  "mcpServers": {
    "tamperlens": {
      "command": "npx",
      "args": ["-y", "tamperlens-mcp"],
      "env": { "TAMPERLENS_API_KEY": "tl_..." }
    }
  }
}
```

No key is required to try it — without one you get the anonymous allowance of
**10 documents an hour**. A free key at
[tamperlens.com/account](https://tamperlens.com/account) raises that to 50 a
month with no card.

## Tools

| Tool | Answers |
|---|---|
| `inspect_document` | Was this edited after it was written? Revisions appended after the original save, metadata that disagrees with itself, editor fingerprints, signature coverage and integrity, hidden text, macros, AI-generator traces in images — **and** whether the file carries text addressed to a language model rather than to a reader. |
| `triage_document` | Is this worth ingesting, and what does it cost to open? The cheap pre-flight: structure, metadata, signatures and presence flags only — no per-page content walk — at a fraction of the I/O. Returns the risk band, the measured cost (bytes read, bytes expanded, expansion ratio) and a `triage` block naming the page-content families it did **not** check. A quiet triage is not a clean document — use it to route, then `inspect_document` for the full check. |
| `check_redaction` | Did the redaction actually remove anything? Covering text with a black box hides it from a person and removes nothing from the file. |
| `compare_documents` | Is this the same file as the original I already hold, unchanged? |

Accepts PDF; Word, Excel and PowerPoint (`.docx`, `.xlsx`, `.pptx` and the
macro-enabled twins); and JPEG, PNG, WebP, HEIC/HEIF and AVIF.

### A local path or a URL

`inspect_document`, `check_redaction` and `compare_documents` (as
`originalUrl`/`candidateUrl`) take **either** a local `path` **or** an http/https
`url` — not both. A `url` is fetched **by this server, on your own machine, over
your own network**, and only the bytes are sent on to Tamperlens. That is why the
option lives here and not on the REST API: a server-side fetch of a
caller-supplied URL is an SSRF risk on the API host, whereas fetching from your
machine reaches only what you can already reach. It is still guarded: http/https
only (re-checked at every redirect), a redirect cap, a 30s timeout
(`TAMPERLENS_FETCH_TIMEOUT_MS` to tune), and the same 10 MB cap, enforced on the
bytes received rather than a `Content-Length` that can lie.

It also **checks the destination IP, not just the scheme**: a `url` that points
at — or redirects to, or resolves by DNS to — a loopback, link-local/metadata
(`169.254.169.254`), private or otherwise non-routable address is refused, and
the address it connects to is pinned to the one it validated, so DNS rebinding
cannot slip an internal address past the check. The check re-runs at every
redirect hop. If you genuinely need to fetch from an internal host, allow-list
specific addresses with `TAMPERLENS_FETCH_ALLOW_IPS` (comma-separated; empty by
default, and the default reaches nothing internal).

> **The `path` argument reads any local file and sends its bytes to the API.**
> `inspect_document`, `triage_document`, `check_redaction` and
> `compare_documents` read whatever local path they are given — there is no
> directory sandbox and no extension filter, because reading a document off disk
> is the whole job and an intake path is not knowable in advance. The bytes of
> that file are then transmitted to the configured Tamperlens deployment. A model
> an attacker is steering could therefore name a private file (`~/.ssh/id_rsa`,
> `~/.aws/credentials`) and cause its bytes to leave the machine. **Run this
> server only with agents and inputs you trust**, the same rule you would apply
> to any tool that can read the local filesystem. For a hard boundary, front the
> intake with a directory you control and pass only paths inside it.

## Why you would put this in front of an agent

A document is read by two audiences and only one of them sees the page. An
extraction pipeline reads the title, the keywords, the XMP packet, the
comments, the names of attachments — fields that exist to be read by software.
Text placed there can be written to be *obeyed* rather than *read*.

`inspect_document` reports that before your agent ingests the file, and **the
recovered payload is elided unconditionally in this server**. That is not a
convenience: the most likely next reader of a Tamperlens report is the same
model that was about to read the document, so an MCP server that echoed the
attacker's sentence back into the context would be completing the attack it
just detected. You get the field, the location and the cue categories. You do
not get the sentence.

## What it does not do

- **No local analysis.** Every tool is a thin wrapper over the Tamperlens REST
  API on a running deployment. There is no second engine here to drift from the
  first.
- **No verdicts.** Tamperlens reports *risk signals with the evidence behind
  them*, never "this document is fraudulent". Combine them with your own
  decision logic.
- **The document never enters the model's context.** Tools take a path on the
  caller's filesystem (or a URL fetched here) and read the bytes on this side.
  Base64 in a tool call would put megabytes of document into the context window
  to reach a service that needs the bytes, not the model.
- **Nothing is stored.** Files are parsed in memory by the API and discarded
  with the response.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TAMPERLENS_API_KEY` | none | Optional. Without it the anonymous allowance applies (10 documents/hour). |
| `TAMPERLENS_BASE_URL` | `https://tamperlens.com` | Point at your own deployment. |
| `TAMPERLENS_FETCH_TIMEOUT_MS` | `30000` | Total budget for a `url` fetch, body and all redirects included. |
| `TAMPERLENS_FETCH_ALLOW_IPS` | none | Comma-separated exact IPs a `url` fetch may reach despite the non-routable-address guard. For a deliberate internal document store. Empty means nothing internal is reachable. |
| `TAMPERLENS_ALLOWED_DIRS` | none | Colon- or comma-separated absolute directories to confine local file reads to. Unset means any absolute path the process can read. Set it to an intake directory so a `path` argument cannot reach secrets like `~/.ssh` or a stray `.env`; a symlink pointing out of a root is resolved and refused. |

## Links

[Field guide to every signal](https://tamperlens.com/pdf-fraud-signals) ·
[Is this file safe for your model to read?](https://tamperlens.com/injection-check) ·
[API reference](https://tamperlens.com/api-reference) ·
[Security and privacy posture](https://tamperlens.com/security)

MIT licensed. Issues and source:
[github.com/haruodev/tamperlens-mcp](https://github.com/haruodev/tamperlens-mcp).
