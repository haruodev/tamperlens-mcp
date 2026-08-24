/**
 * Tamperlens as an MCP server.
 *
 * WHY. An agent doing document intake — reading an email attachment, checking a
 * filing before it goes out, triaging an onboarding queue — has no way to ask
 * "was this edited?" without a human pasting the file into a web page. The REST
 * API already answers it; this is the same API with a tool description an agent
 * can discover and a file path instead of a multipart body.
 *
 * WHAT IT IS NOT. There is no second engine here and no local analysis: every
 * tool below is a thin, honest wrapper over `POST /api/v1/inspect` and
 * `POST /api/v1/compare` on a running deployment. Keeping it thin is the point
 * — an MCP server that reimplemented any of the parsing would be a second
 * implementation to keep in step with the first, and it would drift.
 *
 * CONFIGURATION, all environment:
 *   TAMPERLENS_API_KEY   optional. Without it the anonymous allowance applies
 *                        (10/hour), which is enough to try but not to work.
 *   TAMPERLENS_BASE_URL  optional, defaults to the public deployment.
 *
 * THE FILE PATH ARGUMENT. Tools take a path on the caller's own filesystem and
 * read it here, rather than taking base64 in the tool call. Base64 would put
 * the whole document into the model's context — megabytes of it — which is slow,
 * expensive and completely unnecessary: the bytes need to reach Tamperlens, not
 * the model. The agent never sees the document, only the report.
 *
 * TRUST BOUNDARY OF THE `path` ARGUMENT — READ THIS BEFORE WIRING IT TO AN
 * UNTRUSTED AGENT. `readDocument` will read ANY local file the process can read
 * — there is no directory confinement and no extension filter, by design: reading
 * a local document off disk is the tool's whole purpose, and an intake path is not
 * knowable in advance. The bytes of whatever path it is given are then sent to the
 * configured Tamperlens deployment. So a model an attacker is steering can name
 * `~/.ssh/id_rsa`, `~/.aws/credentials` or any private document and have its bytes
 * leave the machine (non-document content comes back only as a fixed 422, but it
 * has still been transmitted; a document-shaped file comes back analysed in full).
 * MITIGATION IS OPERATIONAL, NOT CODE: run this server only with agents and inputs
 * you trust, exactly as you would any tool that can read the local filesystem. If
 * you need a hard confinement, front the intake with a directory you control and
 * pass only paths inside it.
 *
 * THE URL ARGUMENT. As an alternative to `path`, the single-file tools take a
 * `url` and fetch the document themselves (`fetchDocument`). The fetch happens
 * HERE, on the caller's machine and over the caller's network — which is the
 * whole reason it exists on the MCP server and NOT on the REST API: a
 * server-side fetch of a caller-supplied URL is an SSRF primitive, and the
 * production deployment sits on a box with internal services. Running the fetch
 * client-side moves that risk onto the caller's own network instead of ours. It
 * still carries guards, because an agent an attacker is steering could point it
 * at the caller's own localhost or metadata endpoint:
 *   - a scheme allow-list (http/https only), re-checked at every redirect hop;
 *   - a DESTINATION-IP guard (`./ssrf-guard.ts`): the resolved address is checked
 *     against the non-routable ranges (loopback, link-local/metadata, private,
 *     reserved) and PINNED at connect time so DNS rebinding cannot slip a private
 *     address past the check — re-applied per hop like the scheme check;
 *   - a redirect cap, a total timeout, and a size cap enforced on the bytes
 *     received rather than a Content-Length that can lie.
 * The fetched bytes take the exact same path as a file read off disk, payload
 * elision included. An operator who genuinely fetches from an internal host can
 * allow specific addresses through with TAMPERLENS_FETCH_ALLOW_IPS (off by
 * default; the secure default reaches nothing internal).
 */
import fs from "node:fs/promises";
import path from "node:path";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import { randomBytes } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { McpServer } from "@modelcontextprotocol/server";
import { ENGINE_VERSION } from "../engine/version.js";
import {
  redactUntrustedPayloadsInBody,
  redactUntrustedPayloadsInCompareBody,
  redactInjectionShapedRecovery,
} from "../engine/redact-payload.js";
import {
  guardedLookup,
  isBlockedAddress,
  blockedUrlError,
  SSRF_BLOCKED_CODE,
} from "./ssrf-guard.js";
import * as z from "zod/v4";

/** Matches the API's own cap (config.maxUploadMb). Checked before the upload so
 * an oversized file costs a stat rather than a round trip. */
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

/** How long a `url` fetch may take end to end, body included. An agent driving
 * this tool should not be able to make it hang on a slow or hostile host.
 * Overridable with TAMPERLENS_FETCH_TIMEOUT_MS — a self-hoster on a slow link
 * can raise it, and the tests lower it to exercise the timeout path. */
const FETCH_TIMEOUT_MS = 30_000;

function fetchTimeoutMs(): number {
  const raw = Number(process.env.TAMPERLENS_FETCH_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : FETCH_TIMEOUT_MS;
}

/** Redirect hops a `url` fetch will follow. Handled by hand (redirect:"manual")
 * so the scheme is re-checked at every hop, not just on the URL the caller
 * typed — an `https://` link that 302s to `file://` or `http://169.254.169.254`
 * must not slip through because the first hop looked fine. */
const MAX_REDIRECTS = 5;

const DEFAULT_BASE_URL = "https://tamperlens.com";

export interface McpConfig {
  baseUrl: string;
  apiKey: string | null;
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): McpConfig {
  const raw = (env.TAMPERLENS_BASE_URL || DEFAULT_BASE_URL).trim();
  return {
    baseUrl: raw.replace(/\/+$/, ""),
    apiKey: env.TAMPERLENS_API_KEY?.trim() || null,
  };
}

/**
 * Optional read allowlist. `readDocument` accepts any absolute path by design —
 * the header comment spells that out — because the MCP host already gates each
 * tool call behind user approval. `TAMPERLENS_ALLOWED_DIRS` lets an operator who
 * wants belt-and-suspenders confine reads to an intake directory, turning "any
 * file this process can read" into "files under these roots" so a prompt-injected
 * agent cannot coax the tool into reading `~/.ssh/id_ed25519` or a stray `.env`.
 *
 * Empty/unset ⇒ unchanged behaviour (any absolute path). Roots are colon- or
 * comma-separated absolute paths; each is realpath-resolved once so the
 * containment check compares canonical paths and a symlink cannot be configured
 * to widen the allowlist. A configured root that does not exist is dropped.
 */
let allowedDirsCache: string[] | undefined;
async function allowedReadDirs(): Promise<string[]> {
  if (allowedDirsCache !== undefined) return allowedDirsCache;
  const raw = process.env.TAMPERLENS_ALLOWED_DIRS?.trim();
  if (!raw) return (allowedDirsCache = []);
  const candidates = raw
    .split(/[:,]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && path.isAbsolute(s));
  const resolved: string[] = [];
  for (const dir of candidates) {
    try {
      resolved.push(await fs.realpath(dir));
    } catch {
      // A root that does not exist right now cannot contain anything; skip it
      // rather than fail every read.
    }
  }
  return (allowedDirsCache = resolved);
}

/** True when `realPath` is inside `root` (or is `root` itself). Both must be
 * canonical (realpath-resolved) for this to be sound against `..` and symlinks. */
function isWithin(root: string, realPath: string): boolean {
  const rel = path.relative(root, realPath);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** A tool result the model can read and, where it makes sense, recover from. */
type ToolResult = {
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};

function fail(message: string): ToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

function ok(payload: Record<string, unknown>, summary: string): ToolResult {
  return {
    content: [{ type: "text", text: `${summary}\n\n${JSON.stringify(payload, null, 2)}` }],
    structuredContent: payload,
  };
}

/**
 * Reads a document off the caller's disk, with the failures an agent will
 * actually hit spelled out.
 *
 * Every branch returns a message the model can act on rather than a stack
 * trace: a relative path is a mistake it can correct, an oversized file is a
 * fact it should report to the user, and a missing file usually means it
 * guessed at a name.
 */
async function readDocument(
  filePath: string,
): Promise<{ bytes: Buffer; name: string } | { error: string }> {
  if (!path.isAbsolute(filePath)) {
    return { error: `path must be absolute, got "${filePath}"` };
  }
  let stat;
  try {
    stat = await fs.stat(filePath);
  } catch {
    return { error: `no file at ${filePath}` };
  }
  if (!stat.isFile()) return { error: `${filePath} is not a file` };
  if (stat.size === 0) return { error: `${filePath} is empty` };

  // Confine to the intake allowlist when one is configured. Compare CANONICAL
  // paths (realpath both sides) so neither a `..` segment nor a symlink pointing
  // out of an allowed root can escape it. Unset ⇒ no restriction.
  const roots = await allowedReadDirs();
  if (roots.length > 0) {
    let real: string;
    try {
      real = await fs.realpath(filePath);
    } catch {
      return { error: `no file at ${filePath}` };
    }
    if (!roots.some((root) => isWithin(root, real))) {
      return {
        error:
          `${filePath} is outside the directories this server is allowed to read ` +
          "(TAMPERLENS_ALLOWED_DIRS). Move the file into an allowed directory or send it by url.",
      };
    }
  }

  if (stat.size > MAX_UPLOAD_BYTES) {
    return {
      error:
        `${filePath} is ${(stat.size / 1024 / 1024).toFixed(1)} MB, over the 10 MB limit. ` +
        "Tamperlens reads document structure, so splitting the file changes what it can see " +
        "— send the original from a plan with a higher cap instead.",
    };
  }
  return { bytes: await fs.readFile(filePath), name: path.basename(filePath) };
}

/** http:/https: only. Everything else — file:, data:, ftp:, gopher: — is a way
 * to make this tool read something that is not a document off the network, and
 * is refused by name. */
function schemeAllowed(u: URL): boolean {
  return u.protocol === "http:" || u.protocol === "https:";
}

/** A filename for a fetched document, from the URL's own path. Only cosmetic —
 * it names the file in the multipart part and in the summary line; the engine
 * sniffs the bytes and ignores it. */
function nameFromUrl(u: URL): string {
  let base = "";
  try {
    base = decodeURIComponent(path.basename(u.pathname));
  } catch {
    base = path.basename(u.pathname);
  }
  return base && base !== "/" ? base : "document";
}

/** An abort whose reason is a timeout, so a caught error can be told apart from
 * a real connection failure without matching on message text. */
function isAbort(err: unknown): boolean {
  const e = err as { name?: string; code?: string };
  return e?.name === "AbortError" || e?.code === "ABORT_ERR";
}

/** True when this error is the SSRF guard's refusal — surfaced up through
 * `net.connect` as a socket error carrying our sentinel code. */
function isBlockedError(err: unknown): boolean {
  const e = err as { code?: string; cause?: { code?: string } };
  return e?.code === SSRF_BLOCKED_CODE || e?.cause?.code === SSRF_BLOCKED_CODE;
}

/** One GET, resolved to its response headers (body still unread), or rejected.
 * The `lookup` pins the connection to a guard-validated address; `agent:false`
 * keeps each hop a fresh socket so nothing is reused across hosts. */
/** A URL's host with the IPv6 brackets removed — `[::1]` → `::1` — so `net.isIP`
 * recognises it and Node's request gets a bare hostname. */
function bareHost(u: URL): string {
  return u.hostname.replace(/^\[|\]$/g, "");
}

function requestOnce(current: URL, signal: AbortSignal): Promise<IncomingMessage> {
  const isHttps = current.protocol === "https:";
  const options: https.RequestOptions = {
    protocol: current.protocol,
    hostname: bareHost(current),
    port: current.port || (isHttps ? "443" : "80"),
    path: `${current.pathname}${current.search}`,
    method: "GET",
    headers: { "user-agent": `tamperlens-mcp/${ENGINE_VERSION}`, accept: "*/*" },
    signal,
    lookup: guardedLookup,
    agent: false,
  };
  return new Promise<IncomingMessage>((resolve, reject) => {
    const req = (isHttps ? https : http).request(options, resolve);
    req.on("error", reject);
    req.end();
  });
}

/**
 * Fetches a document from an http/https URL over the CALLER'S OWN NETWORK — this
 * server runs on the caller's machine, so the request leaves from there, not
 * from the Tamperlens deployment. That is the whole reason `url` exists on the
 * MCP tools and deliberately NOT on the REST API: a server-side fetch of a
 * caller-supplied URL is an SSRF primitive against whatever the server can
 * reach, and the production box hosts internal services. Here the blast radius
 * is the caller's own network instead of ours.
 *
 * It is still not unguarded — an agent an attacker is steering could aim this at
 * `http://169.254.169.254/…` or a `file://` on the user's own box — so:
 *   - only http:/https: is allowed, re-checked at every redirect hop;
 *   - the DESTINATION IP is checked against the non-routable ranges and the
 *     connection is PINNED to the validated address (`./ssrf-guard.ts`), so
 *     neither a literal internal IP nor a rebinding hostname reaches an internal
 *     service — re-applied per hop exactly like the scheme check;
 *   - redirects are followed by hand, capped at MAX_REDIRECTS;
 *   - the whole fetch, body included, is bounded by FETCH_TIMEOUT_MS;
 *   - bytes are counted AS THEY ARRIVE against MAX_UPLOAD_BYTES — Content-Length
 *     is only an early reject, never the thing trusted, because it can lie.
 *
 * It uses node:http/https rather than `fetch` for ONE reason: pinning needs a
 * custom `lookup` at connect time, which those request options take and `fetch`
 * does not (undici's dispatcher would, but undici is not a dependency of this
 * two-dep package). Every failure comes back as a plain `{ error }` message the
 * model can act on, never a thrown stack trace. The bytes it returns go through
 * exactly the same postDocument path — and the same unconditional payload
 * elision — as a file read off disk.
 */
async function fetchDocument(
  rawUrl: string,
): Promise<{ bytes: Buffer; name: string } | { error: string }> {
  let target: URL;
  try {
    target = new URL(rawUrl);
  } catch {
    return { error: `not a valid URL: "${rawUrl}"` };
  }
  if (!schemeAllowed(target)) {
    return {
      error:
        `url must be http: or https: — refusing ${target.protocol} ("${rawUrl}"). ` +
        "This tool fetches over your own network; other schemes would read local " +
        "files or non-document endpoints.",
    };
  }

  const timeoutMs = fetchTimeoutMs();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let current = target;
    let response: IncomingMessage | null = null;

    for (let hop = 0; ; hop++) {
      if (!schemeAllowed(current)) {
        return {
          error: `${rawUrl} redirected to a ${current.protocol} URL, which is not allowed — only http:/https:`,
        };
      }
      // A URL whose host is already a literal IP never reaches `guardedLookup`
      // (Node skips DNS for it), so check it here — same predicate, every hop.
      const host = bareHost(current);
      if (net.isIP(host) && isBlockedAddress(host)) {
        return { error: blockedUrlError(rawUrl) };
      }

      let res: IncomingMessage;
      try {
        res = await requestOnce(current, controller.signal);
      } catch (err) {
        if (isAbort(err)) {
          return { error: `fetching ${rawUrl} timed out after ${timeoutMs / 1000}s` };
        }
        if (isBlockedError(err)) return { error: blockedUrlError(rawUrl) };
        return { error: `could not fetch ${rawUrl}: ${(err as Error).message}` };
      }

      const status = res.statusCode ?? 0;
      // A redirect: revalidate, count the hop, and follow it ourselves.
      if (status >= 300 && status < 400 && res.headers.location) {
        res.resume(); // drain and free the socket
        if (hop >= MAX_REDIRECTS) {
          return { error: `${rawUrl} exceeded the redirect limit (${MAX_REDIRECTS})` };
        }
        try {
          current = new URL(res.headers.location, current);
        } catch {
          return { error: `${rawUrl} redirected to an invalid location "${res.headers.location}"` };
        }
        continue;
      }

      response = res;
      break;
    }

    if ((response.statusCode ?? 0) < 200 || (response.statusCode ?? 0) >= 300) {
      response.resume();
      return { error: `fetching ${rawUrl} failed with HTTP ${response.statusCode}` };
    }

    // Content-Length is an early reject only — a lying or absent header must not
    // be the thing that lets an oversized body through, so the real cap is the
    // byte count below.
    const declared = Number(response.headers["content-length"]);
    if (Number.isFinite(declared) && declared > MAX_UPLOAD_BYTES) {
      response.resume();
      return {
        error:
          `${rawUrl} is ${(declared / 1024 / 1024).toFixed(1)} MB by its Content-Length, ` +
          "over the 10 MB limit.",
      };
    }

    const chunks: Buffer[] = [];
    let total = 0;
    try {
      for await (const chunk of response) {
        const buf = chunk as Buffer;
        total += buf.byteLength;
        if (total > MAX_UPLOAD_BYTES) {
          response.destroy();
          return {
            error:
              `${rawUrl} is over the 10 MB limit — stopped after ` +
              `${(total / 1024 / 1024).toFixed(1)} MB. Content-Length cannot be trusted, so ` +
              "the size is enforced on the bytes actually received.",
          };
        }
        chunks.push(buf);
      }
    } catch (err) {
      if (isAbort(err)) {
        return { error: `fetching ${rawUrl} timed out after ${timeoutMs / 1000}s` };
      }
      return { error: `could not read ${rawUrl}: ${(err as Error).message}` };
    }

    const bytes = Buffer.concat(chunks);
    if (bytes.length === 0) return { error: `${rawUrl} returned an empty body` };
    return { bytes, name: nameFromUrl(target) };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Resolves one document argument to bytes, from a local `path` OR a remote
 * `url`, with the two held mutually exclusive: giving both is ambiguous and
 * giving neither is nothing to do, and either mistake earns a message the model
 * can correct rather than a silent pick.
 */
async function loadDocument(args: {
  path?: string;
  url?: string;
}): Promise<{ bytes: Buffer; name: string } | { error: string }> {
  const hasPath = typeof args.path === "string" && args.path.trim() !== "";
  const hasUrl = typeof args.url === "string" && args.url.trim() !== "";
  if (hasPath && hasUrl) {
    return { error: "give either path or url, not both" };
  }
  if (!hasPath && !hasUrl) {
    return { error: "give a document: either path (a file on this machine) or url (http/https)" };
  }
  return hasUrl ? fetchDocument(args.url!.trim()) : readDocument(args.path!);
}

/** The HTTP errors this API actually returns, translated once. */
async function describeHttpFailure(response: Response): Promise<string> {
  let body: Record<string, unknown> = {};
  try {
    body = (await response.json()) as Record<string, unknown>;
  } catch {
    /* a non-JSON error body is still worth reporting by status alone */
  }
  const code = typeof body.error === "string" ? body.error : `http_${response.status}`;
  const detail = typeof body.message === "string" ? ` — ${body.message}` : "";

  switch (response.status) {
    case 401:
      return `Tamperlens rejected the API key (${code}). Check TAMPERLENS_API_KEY.`;
    case 402:
      return `The account is over its monthly quota (${code})${detail}`;
    case 422:
      return `Tamperlens could not analyse that file (${code})${detail}`;
    case 429:
      return (
        `Rate limited (${code})${detail}. Without TAMPERLENS_API_KEY the anonymous ` +
        "allowance is 10 documents an hour; a free key raises it."
      );
    case 503:
      return `Tamperlens is busy (${code}). Retry in a few seconds.`;
    default:
      return `Tamperlens returned HTTP ${response.status} (${code})${detail}`;
  }
}

function authHeaders(config: McpConfig): Record<string, string> {
  return config.apiKey ? { authorization: `Bearer ${config.apiKey}` } : {};
}

/** POSTs one document as a raw body — the simpler of the API's two request
 * forms, and the only one needed when there is no multipart field to send. */
async function postDocument(
  config: McpConfig,
  bytes: Buffer,
  extraHeaders: Record<string, string> = {},
  opts: { triage?: boolean } = {},
): Promise<{ report: Record<string, unknown> } | { error: string }> {
  // `redact=payload` is unconditional — an MCP tool result IS a model's context,
  // and the injection families recover text written to be read by one. `triage`
  // is added when the caller asked for the cheap tier.
  const query = opts.triage ? "?redact=payload&mode=triage" : "?redact=payload";
  let response: Response;
  try {
    response = await fetch(`${config.baseUrl}/api/v1/inspect${query}`, {
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        ...authHeaders(config),
        ...extraHeaders,
      },
      body: new Uint8Array(bytes),
    });
  } catch (err) {
    return { error: `could not reach ${config.baseUrl}: ${(err as Error).message}` };
  }
  if (!response.ok) return { error: await describeHttpFailure(response) };
  /**
   * THE ONE PLACE WHERE THE SAFE DEFAULT DIFFERS FROM THE REST API'S.
   *
   * `ok()` below puts the whole report into the tool result, which lands
   * verbatim in a model's context — that is what an MCP tool result IS. The
   * injection families recover text somebody wrote *in order to be read by a
   * model*, so returning it here would use Tamperlens's own tool to deliver the
   * injection, with a trusted label on it. Plan 7 §6.4 makes this a requirement
   * rather than advice.
   *
   * Applied at the transport boundary, unconditionally, rather than at each
   * call site: a fourth tool added later inherits the guarantee instead of
   * having to remember it. The request also asks the API to redact server-side
   * (below), and this is the second lock — the MCP server must be safe against
   * a deployment too old to know the parameter, which is precisely the
   * configuration a self-hosting customer will have.
   */
  // Two locks, both client-side because the MCP result IS a model's context.
  // The first elides payloads from signals that flagged themselves untrusted
  // (the injection-marker families). The second catches recovered text that its
  // signal did NOT flag — redaction-exposure's hidden-under-a-rectangle text —
  // and removes only the instruction-shaped part of it, so a hostile PDF cannot
  // smuggle a prompt injection out through a redaction finding while a benign
  // redaction failure still returns its words. See redact-payload.ts.
  const body = (await response.json()) as Record<string, unknown>;
  return { report: redactInjectionShapedRecovery(redactUntrustedPayloadsInBody(body)) };
}

/** One-line human summary, so an agent that reads only `content` still gets the
 * answer without parsing the report. */
function summarise(report: Record<string, unknown>, name: string): string {
  const summary = (report.summary ?? {}) as { riskScore?: number; riskBand?: string };
  const signals = Array.isArray(report.signals) ? report.signals : [];
  const named = signals
    .filter((s) => (s as { severity?: string }).severity !== "info")
    .map((s) => (s as { id?: string }).id)
    .join(", ");
  const verdict = (report.policy as { verdict?: string } | undefined)?.verdict;

  /**
   * The injection families get a sentence of their own, and it is built from
   * CUE CATEGORIES AND COUNTS — never from the recovered text.
   *
   * A model reading this summary is the exact reader the payload was written
   * for, so the one thing this line must not do is repeat it. Cue categories
   * (`override`, `role-address`, …) are a closed enum the engine chose; counts
   * are numbers. Both are safe to say out loud, and together they are the
   * finding. Plan 7 §6.4.
   */
  //
  // Selected by the cue-category evidence the injection families alone carry,
  // not by `payloadIsUntrusted`: since engine 1.30.0 the Office comment and
  // tracked-change families declare that flag too (their recovered text is
  // document-authored), and a docx with one comment must not be announced as
  // "0 document field(s) carry text addressed to a machine reader".
  const injection = signals.filter((s) => {
    const evidence = (s as { evidence?: unknown }).evidence;
    return (
      evidence !== null &&
      typeof evidence === "object" &&
      (evidence as { payloadIsUntrusted?: unknown }).payloadIsUntrusted === true &&
      Array.isArray((evidence as { cueCategories?: unknown }).cueCategories)
    );
  });
  let injectionNote = "";
  if (injection.length > 0) {
    const categories = new Set<string>();
    let fields = 0;
    for (const signal of injection) {
      const evidence = (signal as { evidence: Record<string, unknown> }).evidence;
      const cues = evidence.cueCategories;
      if (Array.isArray(cues)) for (const cue of cues) categories.add(String(cue));
      const matched = evidence.fieldsMatched;
      if (typeof matched === "number") fields += matched;
    }
    injectionNote =
      ` PROMPT-INJECTION MARKERS: ${fields} document field(s) carry text addressed to a machine` +
      ` reader, matching cue categories [${[...categories].sort().join(", ")}].` +
      " The text itself is deliberately NOT returned through this tool — it is attacker-authored" +
      " and reading it is the attack. Fetch the report over the REST API without" +
      " `?redact=payload` if a human needs to see the words.";
  }

  return (
    `${name}: risk ${summary.riskScore ?? "?"}/100 (${summary.riskBand ?? "?"})` +
    (verdict ? `, your policy says ${verdict}` : "") +
    (named ? `. Signals: ${named}` : ". No signals above info severity.") +
    injectionNote +
    " Risk signals are not a verdict — benign causes are documented per signal."
  );
}

/**
 * One-line summary for a triage result. Leads with the routing answer and the
 * measured cost, and states plainly what triage did NOT check — because a model
 * reading a short "no signals" line is exactly the reader that would mistake a
 * cheap pass for a clean document.
 */
function triageSummary(report: Record<string, unknown>, name: string): string {
  const summary = (report.summary ?? {}) as {
    riskScore?: number;
    riskBand?: string;
    cost?: { physicalBytes?: number; expandedBytes?: number; expansionRatio?: number };
  };
  const signals = Array.isArray(report.signals) ? report.signals : [];
  const named = signals
    .filter((s) => (s as { severity?: string }).severity !== "info")
    .map((s) => (s as { id?: string }).id)
    .join(", ");
  const cost = summary.cost;
  const costNote = cost
    ? ` Cost: ${cost.physicalBytes ?? "?"} bytes read, ${cost.expandedBytes ?? "?"} expanded ` +
      `(ratio ${cost.expansionRatio ?? "?"}).`
    : "";
  const triage = report.triage as { suppressedFamilies?: unknown } | undefined;
  const suppressed =
    triage && Array.isArray(triage.suppressedFamilies) ? triage.suppressedFamilies.length : 0;
  const caveat = triage
    ? ` TRIAGE ONLY — the page-content walk did NOT run, so ${suppressed} page-content families ` +
      "(hidden text, redaction failure, altered arithmetic, glyph tampering, embedded-image " +
      "anomalies, certification breaks) were not checked. A quiet result is not a clean document: " +
      "run inspect_document for a full check."
    : " (Full report — this medium has no separate cheap tier.)";

  return (
    `${name}: risk ${summary.riskScore ?? "?"}/100 (${summary.riskBand ?? "?"}).` +
    costNote +
    (named ? ` Signals: ${named}.` : " No structural signals above info severity.") +
    caveat
  );
}

export function createMcpServer(config: McpConfig = configFromEnv()): McpServer {
  // The engine version, not a number of this file's own. What a client actually
  // wants to know from a version here is which analysis it is talking to, and a
  // second hand-maintained constant would drift from the first — which is
  // exactly what happened: this said 1.5.0 in the release that shipped 1.6.0.
  const server = new McpServer({ name: "tamperlens", version: ENGINE_VERSION });

  server.registerTool(
    "inspect_document",
    {
      description:
        "Inspect a document or image for fraud and tamper signals: revisions appended after " +
        "the original save, metadata that disagrees with itself, editor fingerprints, " +
        "signature coverage gaps, text still readable under a redaction box, unaccepted " +
        "tracked changes whose deleted text is still recoverable, hidden text, hidden " +
        "spreadsheet sheets, macros, and AI-generator or editor traces in images. Returns " +
        "risk signals with the raw evidence behind each one — never a verdict on " +
        "authenticity. Accepts PDF; Word, Excel and PowerPoint documents (.docx, .xlsx, " +
        ".pptx and macro-enabled twins); and JPEG, PNG, WebP, HEIC/HEIF and AVIF images.\n\n" +
        "ALSO ANSWERS: is this file safe for a model to read? Document properties, XMP, " +
        "annotations, attachment names, docProps, comments and hidden Word runs are checked " +
        "for text written to be read by a language model rather than by a person — the " +
        "prompt-injection carriers an extraction pipeline surfaces and a human reader never " +
        "sees. Call this BEFORE the document reaches your own context. The recovered text " +
        "itself is never returned through this tool: you get the cue categories, the counts " +
        "and which kind of field carried it, because reading the payload is the attack.",
      inputSchema: z.object({
        path: z
          .string()
          .optional()
          .describe(
            "Absolute path to the document on this machine — PDF, Office document or " +
              "image. Max 10 MB. Give this OR url, not both.",
          ),
        url: z
          .string()
          .optional()
          .describe(
            "http:/https: URL to fetch the document from. The fetch runs LOCALLY, over " +
              "this machine's own network (not from the Tamperlens server), and only the " +
              "bytes are sent on. Only http/https is accepted; redirects are followed but " +
              "re-checked; max 10 MB, enforced on the bytes received. Give this OR path, not both.",
          ),
        issuer: z
          .string()
          .optional()
          .describe(
            "Optional issuer slug (e.g. 'chase') to additionally compare the document " +
              "against a structural baseline of genuine documents from that institution. " +
              "PDFs only — ignored for Office documents and images.",
          ),
        policy: z
          .object({
            review: z.number().min(0).max(100).optional(),
            reject: z.number().min(0).max(100).optional(),
            rejectOn: z.array(z.string()).optional(),
            reviewOn: z.array(z.string()).optional(),
          })
          .optional()
          .describe(
            "Optional. Your own risk thresholds and signal rules; the response gains a " +
              "verdict of accept/review/reject computed from them. Nothing about the " +
              "report changes.",
          ),
      }),
    },
    async ({ path: filePath, url, issuer, policy }) => {
      const file = await loadDocument({ path: filePath, url });
      if ("error" in file) return fail(file.error);

      const headers: Record<string, string> = {};
      if (issuer) headers["x-tamperlens-issuer"] = issuer;
      if (policy) headers["x-tamperlens-policy"] = JSON.stringify(policy);

      const result = await postDocument(config, file.bytes, headers);
      if ("error" in result) return fail(result.error);
      return ok(result.report, summarise(result.report, file.name));
    },
  );

  server.registerTool(
    "triage_document",
    {
      description:
        "CHEAP PRE-FLIGHT for document intake: is this file worth ingesting, and what does it " +
        "cost to open? Reads structure, metadata, signatures and presence flags (revisions " +
        "appended after the original, editor fingerprints, macros, JavaScript, embedded files, " +
        "signature coverage) WITHOUT the expensive per-page content walk — a fraction of the " +
        "I/O of `inspect_document`. Returns the risk band, the medium-or-high signals it CAN " +
        "see, and the measured cost: bytes read, bytes expanded (decompressed) and the " +
        "expansion ratio, so an agent can reject a decompression-heavy or high-risk file before " +
        "committing to a full parse.\n\n" +
        "NOT A CLEAN BILL OF HEALTH. A quiet triage means only that the cheap structural tells " +
        "were absent. Hidden text, redaction failure, altered arithmetic, glyph tampering, " +
        "embedded-image anomalies and broken certifications are NOT checked in this mode — they " +
        "need the page-content walk `inspect_document` runs. Use triage to ROUTE (reject now, or " +
        "escalate to `inspect_document`), never as the verdict. PDFs get the cheap scope; Office " +
        "documents and images have no separate expensive walk, so they return their full report.",
      inputSchema: z.object({
        path: z
          .string()
          .describe(
            "Absolute path to the document on this machine — PDF, Office document or image. " +
              "Max 10 MB.",
          ),
      }),
    },
    async ({ path: filePath }) => {
      const file = await readDocument(filePath);
      if ("error" in file) return fail(file.error);

      const result = await postDocument(config, file.bytes, {}, { triage: true });
      if ("error" in result) return fail(result.error);
      return ok(result.report, triageSummary(result.report, file.name));
    },
  );

  server.registerTool(
    "check_redaction",
    {
      description:
        "Check whether a PDF's redactions actually removed anything. Covering text with a " +
        "black box hides it from a reader and removes nothing from the file, so the words " +
        "stay extractable. This reads paint order to catch a plain drawn rectangle — which " +
        "carries no redaction annotation at all and is the failure behind most published " +
        "redaction leaks — and separately catches redaction marks that were never applied. " +
        "Use this before a document is filed or released.",
      inputSchema: z.object({
        path: z
          .string()
          .optional()
          .describe(
            "Absolute path to the PDF on this machine. Max 10 MB. Give this OR url, not both.",
          ),
        url: z
          .string()
          .optional()
          .describe(
            "http:/https: URL to fetch the PDF from. The fetch runs LOCALLY, over this " +
              "machine's own network (not from the Tamperlens server), and only the bytes " +
              "are sent on. Only http/https; redirects re-checked; max 10 MB, enforced on " +
              "the bytes received. Give this OR path, not both.",
          ),
      }),
    },
    async ({ path: filePath, url }) => {
      const file = await loadDocument({ path: filePath, url });
      if ("error" in file) return fail(file.error);

      const result = await postDocument(config, file.bytes);
      if ("error" in result) return fail(result.error);

      const signals = Array.isArray(result.report.signals) ? result.report.signals : [];
      const redaction = signals.filter(
        (s) => (s as { id?: string }).id === "redaction-exposure",
      );

      // A clean answer here is a real answer, and it has to be stated as one —
      // an empty array would read to a model as "the check did not run".
      if (redaction.length === 0) {
        return ok(
          { exposed: false, findings: [], mediaType: result.report.mediaType },
          `${file.name}: no exposed text found under a covering shape, and no unapplied ` +
            "redaction marks. Blind spots remain: content inside form XObjects is not " +
            "walked, and a flattened or image-only page has no text layer to search.",
        );
      }

      return ok(
        { exposed: true, findings: redaction },
        `${file.name}: REDACTION FAILURE — text is still present under a covering shape, ` +
          "or redaction marks were left unapplied. The recovered words are in the findings " +
          "below; anyone receiving this file can read them too.",
      );
    },
  );

  server.registerTool(
    "compare_documents",
    {
      description:
        "Compare a candidate document against the original you already hold, and answer " +
        "the question a single-file check cannot: is this the same file, unchanged? Reports " +
        "byte identity (the only proof), revision ancestry when the candidate contains the " +
        "original as a byte prefix, or a field-by-field structural diff when both were " +
        "rewritten whole. Renders nothing and compares no pixels.",
      inputSchema: z.object({
        originalPath: z
          .string()
          .optional()
          .describe(
            "Absolute path to the document you trust. Give this OR originalUrl, not both.",
          ),
        originalUrl: z
          .string()
          .optional()
          .describe(
            "http:/https: URL to fetch the trusted document from. Fetched LOCALLY over this " +
              "machine's network (not from the Tamperlens server); http/https only, redirects " +
              "re-checked, max 10 MB on the bytes received. Give this OR originalPath, not both.",
          ),
        candidatePath: z
          .string()
          .optional()
          .describe(
            "Absolute path to the document being checked. Give this OR candidateUrl, not both.",
          ),
        candidateUrl: z
          .string()
          .optional()
          .describe(
            "http:/https: URL to fetch the document being checked from. Fetched LOCALLY over " +
              "this machine's network (not from the Tamperlens server); http/https only, " +
              "redirects re-checked, max 10 MB on the bytes received. Give this OR " +
              "candidatePath, not both.",
          ),
      }),
    },
    async ({ originalPath, originalUrl, candidatePath, candidateUrl }) => {
      const original = await loadDocument({ path: originalPath, url: originalUrl });
      if ("error" in original) return fail(`original: ${original.error}`);
      const candidate = await loadDocument({ path: candidatePath, url: candidateUrl });
      if ("error" in candidate) return fail(`candidate: ${candidate.error}`);

      if (!config.apiKey) {
        return fail(
          "compare_documents needs an API key — set TAMPERLENS_API_KEY. " +
            "A free key covers 50 documents a month and comparison is metered as two.",
        );
      }

      // Random boundary (not Date.now, which is guessable and can collide across
      // two calls in the same millisecond) so it cannot appear in the payload by
      // prediction. The filename is document-derived, so strip the three bytes
      // that would break out of the quoted `filename="..."` header — `"` closes
      // the quote, CR/LF start a new header line — before it is interpolated.
      const boundary = `----tamperlens-mcp-${randomBytes(16).toString("hex")}`;
      const safeName = (filename: string): string =>
        filename.replace(/["\r\n]/g, "_");
      const part = (name: string, filename: string): Buffer =>
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="${name}"; ` +
            `filename="${safeName(filename)}"\r\nContent-Type: application/octet-stream\r\n\r\n`,
        );
      const body = Buffer.concat([
        part("original", original.name),
        original.bytes,
        Buffer.from("\r\n"),
        part("candidate", candidate.name),
        candidate.bytes,
        Buffer.from(`\r\n--${boundary}--\r\n`),
      ]);

      let response: Response;
      try {
        response = await fetch(`${config.baseUrl}/api/v1/compare`, {
          method: "POST",
          headers: {
            "content-type": `multipart/form-data; boundary=${boundary}`,
            ...authHeaders(config),
          },
          body: new Uint8Array(body),
        });
      } catch (err) {
        return fail(`could not reach ${config.baseUrl}: ${(err as Error).message}`);
      }
      if (!response.ok) return fail(await describeHttpFailure(response));

      // The compare body carries the RAW values of /Title, /Creator, /Producer
      // and the XMP fields — the exact carriers `inspect_document` elides. This
      // tool result is a model's context too, so the same criterion runs over it
      // before it is returned: an injection planted in a metadata field does not
      // get a clean ride out through compare. See redact-payload.ts.
      const report = redactUntrustedPayloadsInCompareBody(
        (await response.json()) as Record<string, unknown>,
      );
      const relationship =
        typeof report.relationship === "string" ? report.relationship : "unknown";
      const gloss: Record<string, string> = {
        identical: "the files are byte-identical — this is the only result that is a proof",
        "candidate-extends-original":
          "the candidate contains the original verbatim and appends revisions to it",
        "candidate-truncates-original": "the candidate is a prefix of the original",
        rewritten: "both files were written whole, so only a structural diff is possible",
      };
      return ok(
        report,
        `${original.name} vs ${candidate.name}: ${relationship}` +
          (gloss[relationship] ? ` — ${gloss[relationship]}` : ""),
      );
    },
  );

  return server;
}
