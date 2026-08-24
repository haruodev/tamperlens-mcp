/**
 * The minimal report shapes the redaction reads.
 *
 * The engine's full type surface is not part of this client — only the two
 * fields `redact-payload.ts` touches are modelled here, so the published mirror
 * ships no more of the engine's internals than it actually uses.
 */
export interface Signal {
  evidence: Record<string, unknown> & { payloadIsUntrusted?: boolean };
  [key: string]: unknown;
}

export interface InspectionReport {
  signals: Signal[];
  [key: string]: unknown;
}
