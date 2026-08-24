/**
 * Drop attacker-authored bytes from a report, keeping the finding.
 *
 * WHY THIS IS A MODULE AND NOT A FLAG ON THE SIGNAL. `document-injection-markers`
 * and `office-injection-markers` recover text somebody wrote **in order to be
 * read by a language model**. The buyer for that finding is, by construction,
 * running an ingestion pipeline — so the obvious integration is to hand the
 * report straight to the model, and a report carrying the payload has then
 * delivered the injection with Tamperlens's name on it. Plan 7 §6.4 makes that
 * concrete rather than hypothetical: `src/mcp/server.ts` returns the report body
 * as tool-result text, directly into a model's context.
 *
 * Two callers need the same elision and must not implement it twice:
 *
 *   - **the MCP server, unconditionally.** This is the one place where the safe
 *     default differs from the REST API's, and it differs because the consumer
 *     is definitionally a model.
 *   - **`GET`-style opt-in on `/inspect?redact=payload`,** for integrators who
 *     want the finding and never the bytes.
 *
 * WHAT IS AND IS NOT REMOVED. Only signals that declare
 * `evidence.payloadIsUntrusted === true` are touched, and within those only the
 * keys in `PAYLOAD_KEYS`. Cue categories, counts, confidence, which kind of
 * field carried it, which obfuscation techniques were used and how long the
 * payload was all survive — that is the whole finding, minus the words. Prose
 * (`title`, `detail`, `message`, `notes`) is untouched because no family in
 * this repo is allowed to put a payload there in the first place; the test
 * `test/engine/injection.test.ts` pins that separately, so this function is the
 * second lock and not the first.
 *
 * DEFENCE IN DEPTH, NOT A PARSER. The walk is structural and key-based rather
 * than a scan of the report for suspicious strings, because a scan would have to
 * decide what "suspicious" means and would be wrong about a document that
 * legitimately contains the word `<system>`. A family that adds a new
 * attacker-derived evidence key must add its name here; the alternative — a
 * whitelist of safe keys — was considered and rejected because it fails CLOSED
 * on evidence a future family adds, silently dropping facts a caller paid for.
 */
import type { InspectionReport, Signal } from "./types.js";

/**
 * Evidence keys whose values are written by whoever wrote the document.
 *
 * `payload` is the recovered text. `name` is the field's own name — a custom
 * Info key, an XMP property in an invented namespace, an attachment filename —
 * and it is every bit as attacker-chosen as the value beside it, which is the
 * detail that makes a whitelist of "safe" keys the wrong shape here.
 *
 * `recovered` (engine 1.30.0) is the Office families' sample array — comment
 * text on `office-hidden-content`, deleted `w:delText` on
 * `office-tracked-changes`. Both carried document-authored prose past
 * `?redact=payload` because neither key was registered and neither signal
 * declared itself untrusted; the fail-open guard in `injection.test.ts` only
 * walked signals that had. It is an ARRAY of strings, which is why the walk
 * below redacts string arrays under a payload key as well as bare strings.
 * `authors` rides with it: a comment or revision author is a string the
 * document chose, exactly like a custom Info key's name.
 */
const PAYLOAD_KEYS: ReadonlySet<string> = new Set(["payload", "name", "recovered", "authors"]);

/** Replaces the value at a payload key. Kept as a constant so a consumer can
 * recognise an elided field rather than guess from an empty string. */
export const REDACTED = "[redacted]";

/** Depth bound: evidence is a hand-built literal in every family, but a bound
 * costs nothing and this function must never be the thing that throws. */
const MAX_DEPTH = 12;

function redactValue(value: unknown, depth: number): unknown {
  if (depth > MAX_DEPTH) return value;
  if (Array.isArray(value)) return value.map((item) => redactValue(item, depth + 1));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      out[key] = PAYLOAD_KEYS.has(key) && typeof inner === "string"
        ? REDACTED
        : PAYLOAD_KEYS.has(key) && Array.isArray(inner)
          ? inner.map((item) => (typeof item === "string" ? REDACTED : redactValue(item, depth + 1)))
          : redactValue(inner, depth + 1);
    }
    return out;
  }
  return value;
}

/** True when this signal's evidence is attacker-derived. */
export function carriesUntrustedPayload(signal: Signal): boolean {
  return (signal.evidence as { payloadIsUntrusted?: unknown }).payloadIsUntrusted === true;
}

/**
 * A copy of the report with every untrusted payload elided.
 *
 * Returns the SAME OBJECT when nothing needed redacting, so the default REST
 * response stays byte-identical to what it has always been and the cost on the
 * overwhelming majority of documents is one array scan.
 */
export function redactUntrustedPayloads<T extends InspectionReport>(report: T): T {
  if (!report.signals.some(carriesUntrustedPayload)) return report;
  return {
    ...report,
    signals: report.signals.map((signal) =>
      carriesUntrustedPayload(signal)
        ? {
            ...signal,
            evidence: {
              ...(redactValue(signal.evidence, 0) as Record<string, unknown>),
              /** So a caller can tell "no payload was found" from "the payload
               * was not returned to you". Silence would conflate them. */
              payloadRedacted: true,
            },
          }
        : signal,
    ),
  };
}

/**
 * The same elision over a report this process did not produce — the MCP server
 * receives one as JSON over HTTP and never holds an `InspectionReport`.
 *
 * Written against the wire shape rather than the type on purpose: the MCP
 * server must keep working against a deployment running a different engine
 * version, including one whose report carries a family this build has never
 * heard of.
 */
export function redactUntrustedPayloadsInBody(
  body: Record<string, unknown>,
): Record<string, unknown> {
  const signals = body.signals;
  if (!Array.isArray(signals)) return body;
  let touched = false;
  const next = signals.map((signal) => {
    const evidence = (signal as { evidence?: unknown }).evidence;
    if (
      evidence === null ||
      typeof evidence !== "object" ||
      (evidence as { payloadIsUntrusted?: unknown }).payloadIsUntrusted !== true
    ) {
      return signal;
    }
    touched = true;
    return {
      ...(signal as Record<string, unknown>),
      evidence: {
        ...(redactValue(evidence, 0) as Record<string, unknown>),
        payloadRedacted: true,
      },
    };
  });
  return touched ? { ...body, signals: next } : body;
}
