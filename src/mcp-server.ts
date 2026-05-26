#!/usr/bin/env bun
/**
 * Wire IPC MCP server — runtime-agnostic adapter.
 *
 * Provides the send_message tool for outbound Ed25519-signed IPC messaging.
 * Sender identity is verified by the Wire server's built-in JWT validator.
 *
 * Agent registration lives in @agiterra/wire-tools' MCP server, NOT here.
 * wire-ipc-tools is solely concerned with the IPC channel. Per Tim 2026-05-15:
 * "wire-ipc-tools is ONLY concerned with the IPC channel." Registration is
 * a Wire-primitive concern, not an IPC-plugin concern.
 *
 * Config env vars:
 *   WIRE_URL            default http://localhost:9800
 *   AGENT_ID            required or auto-generated
 *   AGENT_NAME          display name
 *   AGENT_PRIVATE_KEY   Ed25519 PKCS8 base64 (required for sending)
 *
 * Exports for consolidation (bridge-claude-code et al.):
 *   - WIRE_IPC_TOOLS — the tool definitions array (for ListTools concatenation)
 *   - handleWireIpcToolCall — handler dispatch function (for CallTool routing)
 *   - WireIpcDeps — the deps shape (wire_url + agent_id + key_pair)
 *
 * startServer remains a thin wrapper that builds deps from env and runs its
 * own MCP Server. Standalone wire-ipc-claude-code and wire-ipc-codex
 * adapters keep working unchanged.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  sendSignedMessage,
  importKeyPair,
  type KeyPair,
} from "@agiterra/wire-tools";

// --- Public types + tool definitions ---

export interface WireIpcDeps {
  wire_url: string;
  agent_id: string;
  key_pair: KeyPair | null;
}

export interface ToolCallResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

export const WIRE_IPC_TOOLS = [
  {
    name: "send_message",
    description:
      "Send an Ed25519-signed IPC message via The Wire.\n" +
      "Schema: { topic, payload, dest? OR broadcast: true }.\n" +
      "EXACTLY ONE of `dest` (unicast) or `broadcast: true` (broadcast) is required. " +
      "Omitting both is rejected — broadcast must be explicit so accidental fan-out " +
      "is caught at the source rather than spamming every topic subscriber.\n" +
      "Example (unicast to another agent):\n" +
      "  { topic: 'ipc', dest: 'fondant', payload: { text: 'hello' } }\n" +
      "Example (broadcast on a topic):\n" +
      "  { topic: 'ipc.task', broadcast: true, payload: { kind: 'help', text: '...' } }\n" +
      "DO NOT pass `to`, `from`, `subject`, or `body` as top-level keys — " +
      "the recipient is `dest`, and the message content (any shape: text, " +
      "object, etc.) goes INSIDE `payload`.",
    inputSchema: {
      type: "object" as const,
      properties: {
        topic: {
          type: "string",
          description:
            "Required. Routing topic (e.g. 'ipc', 'ipc.task'). Determines which channel/plugin receives the message.",
        },
        payload: {
          description:
            "Required. Message content as any JSON value (object, string, null, etc.). Put your subject/body/text fields INSIDE this — never as top-level keys.",
        },
        dest: {
          type: "string",
          description:
            "Recipient agent ID for unicast (e.g. 'fondant', 'brioche'). Either this OR `broadcast: true` is required. NOT to be confused with a `to` field.",
        },
        broadcast: {
          type: "boolean",
          description:
            "Set to `true` for an explicit broadcast (fan-out to every subscriber of `topic`). Mutually exclusive with `dest`. Either this OR `dest` is required — omitting both is rejected.",
        },
      },
      required: ["topic", "payload"],
      additionalProperties: false,
    },
  },
] as const;

export async function handleWireIpcToolCall(
  name: string,
  args: Record<string, unknown>,
  deps: WireIpcDeps,
): Promise<ToolCallResult> {
  if (name !== "send_message") {
    throw new Error(`wire-ipc: unknown tool: ${name}`);
  }

  const topic = args.topic;
  const payload = args.payload;
  const dest = args.dest;
  const broadcast = args.broadcast;

  if (typeof topic !== "string" || topic.length === 0) {
    return {
      content: [
        {
          type: "text",
          text: `send_message: 'topic' is required (string). Got: ${JSON.stringify(topic)}. Did you pass 'subject' or 'to' instead? Schema: { topic, payload, dest? OR broadcast: true }.`,
        },
      ],
      isError: true,
    };
  }
  if (payload === undefined) {
    return {
      content: [
        {
          type: "text",
          text: `send_message: 'payload' is required (any JSON value, including null). Did you pass 'body' instead? Schema: { topic, payload, dest? OR broadcast: true }.`,
        },
      ],
      isError: true,
    };
  }
  if (dest !== undefined && typeof dest !== "string") {
    return {
      content: [
        {
          type: "text",
          text: `send_message: 'dest' must be a string if provided. Got: ${JSON.stringify(dest)}.`,
        },
      ],
      isError: true,
    };
  }
  if (broadcast !== undefined && typeof broadcast !== "boolean") {
    return {
      content: [
        {
          type: "text",
          text: `send_message: 'broadcast' must be a boolean if provided. Got: ${JSON.stringify(broadcast)}.`,
        },
      ],
      isError: true,
    };
  }
  const hasDest = typeof dest === "string" && dest.length > 0;
  const isBroadcast = broadcast === true;
  if (hasDest && isBroadcast) {
    return {
      content: [
        {
          type: "text",
          text: `send_message: 'dest' and 'broadcast: true' are mutually exclusive — choose one. Unicast: { dest: 'agent-id' }. Broadcast: { broadcast: true }.`,
        },
      ],
      isError: true,
    };
  }
  if (!hasDest && !isBroadcast) {
    return {
      content: [
        {
          type: "text",
          text: `send_message: must specify either 'dest' (unicast) or 'broadcast: true' (broadcast to topic subscribers). Omitting both is rejected so accidental fan-out is caught at the source.`,
        },
      ],
      isError: true,
    };
  }
  const knownKeys = new Set(["topic", "payload", "dest", "broadcast"]);
  const extras = Object.keys(args).filter((k) => !knownKeys.has(k));
  if (extras.length > 0) {
    return {
      content: [
        {
          type: "text",
          text: `send_message: unknown argument(s) ${extras.join(", ")}. Schema: { topic, payload, dest? OR broadcast: true }. Did you mean payload?`,
        },
      ],
      isError: true,
    };
  }

  try {
    if (!deps.key_pair) throw new Error("not initialized (AGENT_PRIVATE_KEY missing)");
    const { seq } = await sendSignedMessage(
      deps.wire_url,
      deps.agent_id,
      deps.key_pair.privateKey,
      topic,
      payload,
      isBroadcast ? undefined : (dest as string),
    );
    return { content: [{ type: "text", text: `sent seq=${seq} (${isBroadcast ? "broadcast" : "to " + dest})` }] };
  } catch (e) {
    return {
      content: [{ type: "text", text: `send failed: ${(e as Error).message}` }],
      isError: true,
    };
  }
}

// --- Standalone server (existing entry point — unchanged behavior) ---

export async function startServer(): Promise<void> {
  const WIRE_URL = process.env.WIRE_URL ?? "http://localhost:9800";
  const AGENT_ID = process.env.AGENT_ID ?? `claude-${crypto.randomUUID().slice(0, 8)}`;
  const rawKey = process.env.AGENT_PRIVATE_KEY;

  let key_pair: KeyPair | null = null;
  if (!rawKey) {
    console.error("[wire-ipc] AGENT_PRIVATE_KEY not set — IPC sending disabled");
  } else {
    key_pair = await importKeyPair(rawKey);
  }

  const deps: WireIpcDeps = { wire_url: WIRE_URL, agent_id: AGENT_ID, key_pair };

  const mcp = new Server(
    { name: "wire-ipc", version: "0.2.0" },
    {
      capabilities: { tools: {} },
      instructions:
        "This plugin provides IPC messaging via The Wire. " +
        "Use the send_message tool to send Ed25519-signed messages to other agents. " +
        "Messages are routed through the Wire message broker. " +
        "Agent registration is handled by the `wire` plugin (mcp__plugin_wire_wire__register_agent), not this one.",
    },
  );

  mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [...WIRE_IPC_TOOLS],
  }));

  mcp.setRequestHandler(CallToolRequestSchema, async (req): Promise<any> => {
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    return handleWireIpcToolCall(req.params.name, args, deps);
  });

  const transport = new StdioServerTransport();
  await mcp.connect(transport);

  console.error(`[wire-ipc] ready (agent=${AGENT_ID})`);
}
