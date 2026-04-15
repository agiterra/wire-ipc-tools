#!/usr/bin/env bun
/**
 * Wire IPC MCP server — runtime-agnostic adapter.
 *
 * Provides the send_message tool for outbound Ed25519-signed IPC messaging.
 * Sender identity is verified by the Wire server's built-in JWT validator.
 *
 * Config env vars:
 *   WIRE_URL            default http://localhost:9800
 *   AGENT_ID            required or auto-generated
 *   AGENT_NAME           display name (for registration)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { sendSignedMessage, importKeyPair, type KeyPair } from "@agiterra/wire-tools";

const WIRE_URL = process.env.WIRE_URL ?? "http://localhost:9800";
const AGENT_ID =
  process.env.AGENT_ID ?? `claude-${crypto.randomUUID().slice(0, 8)}`;
const AGENT_NAME =
  process.env.AGENT_NAME ?? AGENT_ID;

let keyPair: KeyPair | null = null;

// --- MCP server ---

const mcp = new Server(
  { name: "wire-ipc", version: "0.1.0" },
  {
    capabilities: { tools: {} },
    instructions:
      "This plugin provides IPC messaging via The Wire. " +
      "Use the send_message tool to send Ed25519-signed messages to other agents. " +
      "Messages are routed through the Wire message broker.",
  },
);

// --- Tools ---

mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "send_message",
      description: "Send an Ed25519-signed IPC message via The Wire",
      inputSchema: {
        type: "object" as const,
        properties: {
          topic: {
            type: "string",
            description: "Routing topic (e.g. 'ipc', 'ipc.task')",
          },
          payload: {
            description: "Message payload (any JSON value)",
          },
          dest: {
            type: "string",
            description: "Optional unicast destination agent ID",
          },
        },
        required: ["topic", "payload"],
      },
    },
  ],
}));

mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name === "send_message") {
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    const topic = args.topic;
    const payload = args.payload;
    const dest = args.dest;

    // Reject malformed calls explicitly. Without this, undefined topic gets
    // url-interpolated into /broadcast/undefined and a null payload sails through.
    if (typeof topic !== "string" || topic.length === 0) {
      return {
        content: [{ type: "text" as const, text: `send_message: 'topic' is required (string). Got: ${JSON.stringify(topic)}. Did you pass 'subject' or 'to' instead? Schema: { topic, payload, dest? }.` }],
        isError: true,
      };
    }
    if (payload === undefined) {
      return {
        content: [{ type: "text" as const, text: `send_message: 'payload' is required (any JSON value, including null). Did you pass 'body' instead? Schema: { topic, payload, dest? }.` }],
        isError: true,
      };
    }
    if (dest !== undefined && typeof dest !== "string") {
      return {
        content: [{ type: "text" as const, text: `send_message: 'dest' must be a string if provided. Got: ${JSON.stringify(dest)}.` }],
        isError: true,
      };
    }
    const knownKeys = new Set(["topic", "payload", "dest"]);
    const extras = Object.keys(args).filter((k) => !knownKeys.has(k));
    if (extras.length > 0) {
      return {
        content: [{ type: "text" as const, text: `send_message: unknown argument(s) ${extras.join(", ")}. Schema: { topic, payload, dest? }. Did you mean payload?` }],
        isError: true,
      };
    }

    try {
      if (!keyPair) throw new Error("not initialized");
      const { seq } = await sendSignedMessage(
        WIRE_URL,
        AGENT_ID,
        keyPair.privateKey,
        topic,
        payload,
        dest as string | undefined,
      );
      return {
        content: [{ type: "text" as const, text: `sent seq=${seq}` }],
      };
    } catch (e: any) {
      return {
        content: [
          { type: "text" as const, text: `send failed: ${e.message}` },
        ],
        isError: true,
      };
    }
  }
  throw new Error(`unknown tool: ${req.params.name}`);
});

// --- Main ---

export async function startServer(): Promise<void> {
  // Load agent key (base64 PKCS8). Crew-launched agents get their own key
  // via CREW_PRIVATE_KEY which takes precedence over .env's WIRE_PRIVATE_KEY.
  const rawKey = process.env.CREW_PRIVATE_KEY ?? process.env.WIRE_PRIVATE_KEY;
  if (!rawKey) {
    console.error("[wire-ipc] WIRE_PRIVATE_KEY not set — IPC sending disabled");
  } else {
    keyPair = await importKeyPair(rawKey);
  }

  const transport = new StdioServerTransport();
  await mcp.connect(transport);

  console.error(`[wire-ipc] ready (agent=${AGENT_ID})`);
}
