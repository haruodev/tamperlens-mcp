#!/usr/bin/env node
/**
 * stdio entry point for the Tamperlens MCP server.
 *
 * Separate from server.ts so the server can be constructed and driven in tests
 * (over an in-memory transport) without a process that owns stdin and stdout.
 *
 * Anything written to stdout here would be parsed as JSON-RPC and corrupt the
 * stream, so the startup line goes to stderr — which is also where an MCP host
 * looks when a server fails to come up.
 */
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { configFromEnv, createMcpServer } from "./server.js";

const config = configFromEnv();

void serveStdio(() => createMcpServer(config));

console.error(
  `tamperlens MCP server on stdio → ${config.baseUrl}` +
    (config.apiKey ? " (authenticated)" : " (anonymous: 10 documents/hour)"),
);
