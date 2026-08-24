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
| `check_redaction` | Did the redaction actually remove anything? Covering text with a black box hides it from a person and removes nothing from the file. |
| `compare_documents` | Is this the same file as the original I already hold, unchanged? |

Accepts PDF; Word, Excel and PowerPoint (`.docx`, `.xlsx`, `.pptx` and the
macro-enabled twins); and JPEG, PNG, WebP, HEIC/HEIF and AVIF.

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
  caller's filesystem and read the bytes here. Base64 in a tool call would put
  megabytes of document into the context window to reach a service that needs
  the bytes, not the model.
- **Nothing is stored.** Files are parsed in memory by the API and discarded
  with the response.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TAMPERLENS_API_KEY` | none | Optional. Without it the anonymous allowance applies (10 documents/hour). |
| `TAMPERLENS_BASE_URL` | `https://tamperlens.com` | Point at your own deployment. |

## Links

[Field guide to every signal](https://tamperlens.com/pdf-fraud-signals) ·
[Is this file safe for your model to read?](https://tamperlens.com/injection-check) ·
[API reference](https://tamperlens.com/api-reference) ·
[Security and privacy posture](https://tamperlens.com/security)

MIT licensed. Issues and source:
[github.com/haruodev/tamperlens-mcp](https://github.com/haruodev/tamperlens-mcp).
The engine it talks to is [tamperlens.com](https://tamperlens.com); this
repository is the MCP client alone.
