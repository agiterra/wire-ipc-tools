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
    const { topic, payload, dest } = req.params.arguments as {
      topic: string;
      payload: unknown;
      dest?: string;
    };
    try {
      if (!keyPair) throw new Error("not initialized");
      const { seq } = await sendSignedMessage(
        WIRE_URL,
        AGENT_ID,
        keyPair.privateKey,
        topic,
        payload ?? null,
        dest,
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
