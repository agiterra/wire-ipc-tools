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
 *   AGENT_NAME          display name (for registration)
 *   AGENT_PRIVATE_KEY   Ed25519 PKCS8 base64 (required for sending)
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
  generateKeyPair,
  exportPrivateKey,
  derivePublicKeyB64,
  register,
  type KeyPair,
} from "@agiterra/wire-tools";

function titleCase(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

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
      name: "register_agent",
      description:
        "Sponsor-register a Wire agent. Two modes:\n\n" +
        "  (1) Default: generates a fresh Ed25519 keypair, registers the " +
        "public key on Wire as `id` using the caller's identity as sponsor, " +
        "and returns the base64 PKCS8 private key for the caller to pass on " +
        "to crew `agent_launch` as `env.AGENT_PRIVATE_KEY`.\n\n" +
        "  (2) BYO pubkey: pass `pubkey` (base64 raw Ed25519, 32 bytes) and " +
        "the call skips keypair generation. Returns no private_key_b64 — the " +
        "caller already has the private key. Useful for re-registering a " +
        "previously-reaped ephemeral when you've kept its keypair around, or " +
        "for callers who manage keys client-side. Wire's existing auth path " +
        "handles reaped-readmission (same id + same pubkey → un-greyed).\n\n" +
        "Typical mode-1 flow:\n" +
        "  const { agent_id, display_name, private_key_b64 } = await register_agent({ id: 'danish' });\n" +
        "  await agent_launch({ env: { AGENT_ID: agent_id, AGENT_PRIVATE_KEY: private_key_b64, ... } });\n\n" +
        "Typical mode-2 flow (re-register a reaped agent):\n" +
        "  await register_agent({ id: 'danish', pubkey: '<stashed-base64-pubkey>' });\n" +
        "  await agent_launch({ env: { AGENT_ID: 'danish', AGENT_PRIVATE_KEY: '<stashed-base64-privkey>', ... } });\n\n" +
        "Keys never touch disk inside this tool — they flow through env. The " +
        "sponsor's AGENT_PRIVATE_KEY signs the registration request; Wire " +
        "trusts the sponsor's JWT and accepts the new (or re-registered) " +
        "agent's public key.\n\n" +
        "If an agent with this id already exists with a DIFFERENT pubkey the " +
        "call fails with HTTP 409 `agent_exists_pubkey_mismatch` to prevent " +
        "silently rotating the keypair out from under any process still " +
        "holding the previous key. Pass `force_rotate: true` to override — " +
        "but only when you've confirmed no live process holds the old key.",
      inputSchema: {
        type: "object" as const,
        properties: {
          id: {
            type: "string",
            description: "New agent's ID (the name it will register under and use as `env.AGENT_ID`).",
          },
          display_name: {
            type: "string",
            description: "Optional display name. Defaults to TitleCase(id).",
          },
          pubkey: {
            type: "string",
            description: "Optional. Base64 raw Ed25519 public key (32 bytes). When supplied, the tool skips keypair generation and registers this pubkey on Wire as `id`. Returns no private_key_b64. Use for re-registering a previously-reaped ephemeral whose keypair you've stashed, or for client-side key management.",
          },
          force_rotate: {
            type: "boolean",
            description: "Default false. When true, replaces the keypair on an existing/reaped agent — permanently locking out any process still holding the previous private key. Use only when you've confirmed no live process holds the old key.",
          },
        },
        required: ["id"],
        additionalProperties: false,
      },
    },
    {
      name: "send_message",
      description:
        "Send an Ed25519-signed IPC message via The Wire.\n" +
        "Schema: { topic, payload, dest? }.\n" +
        "Example (unicast to another agent):\n" +
        "  { topic: 'ipc', dest: 'fondant', payload: { text: 'hello' } }\n" +
        "Example (broadcast on a topic):\n" +
        "  { topic: 'ipc.task', payload: { kind: 'help', text: '...' } }\n" +
        "DO NOT pass `to`, `from`, `subject`, or `body` as top-level keys — " +
        "the recipient is `dest`, and the message content (any shape: text, " +
        "object, etc.) goes INSIDE `payload`.",
      inputSchema: {
        type: "object" as const,
        properties: {
          topic: {
            type: "string",
            description: "Required. Routing topic (e.g. 'ipc', 'ipc.task'). Determines which channel/plugin receives the message.",
          },
          payload: {
            description: "Required. Message content as any JSON value (object, string, null, etc.). Put your subject/body/text fields INSIDE this — never as top-level keys.",
          },
          dest: {
            type: "string",
            description: "Optional. Recipient agent ID for unicast (e.g. 'fondant', 'brioche'). Omit for broadcast on `topic`. NOT to be confused with a `to` field.",
          },
        },
        required: ["topic", "payload"],
        additionalProperties: false,
      },
    },
  ],
}));

mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name === "register_agent") {
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    const id = args.id;
    const displayName = args.display_name;
    const forceRotate = args.force_rotate;
    const providedPubkey = args.pubkey;

    if (typeof id !== "string" || id.length === 0) {
      return {
        content: [{ type: "text" as const, text: `register_agent: 'id' is required (string). Got: ${JSON.stringify(id)}.` }],
        isError: true,
      };
    }
    if (displayName !== undefined && typeof displayName !== "string") {
      return {
        content: [{ type: "text" as const, text: `register_agent: 'display_name' must be a string if provided. Got: ${JSON.stringify(displayName)}.` }],
        isError: true,
      };
    }
    if (forceRotate !== undefined && typeof forceRotate !== "boolean") {
      return {
        content: [{ type: "text" as const, text: `register_agent: 'force_rotate' must be a boolean if provided. Got: ${JSON.stringify(forceRotate)}.` }],
        isError: true,
      };
    }
    if (providedPubkey !== undefined && typeof providedPubkey !== "string") {
      return {
        content: [{ type: "text" as const, text: `register_agent: 'pubkey' must be a base64 string if provided. Got: ${JSON.stringify(providedPubkey)}.` }],
        isError: true,
      };
    }
    if (!keyPair) {
      return {
        content: [{ type: "text" as const, text: `register_agent: sponsor not initialized. Set AGENT_PRIVATE_KEY in the caller's env.` }],
        isError: true,
      };
    }

    try {
      const resolvedName = displayName ?? titleCase(id);

      // Smart-refresh: when no pubkey was supplied and force_rotate isn't
      // requested, probe Wire for an existing row at this id. If found,
      // re-register with the existing pubkey — Wire's reaped-readmission
      // path un-greys the row and the live agent process (which still
      // holds the matching private key) keeps working.
      //
      // Per Tim 2026-05-15: "If the Wire has the pub key in hand, then
      // brioche should just be able to re-register eclair2 without sending
      // the pub key, and The Wire should just mark her as active."
      let pubkeyToRegister = providedPubkey as string | undefined;
      let returnPrivate: string | undefined;
      let didLookup = false;

      if (!pubkeyToRegister && !forceRotate) {
        try {
          const res = await fetch(`${WIRE_URL}/agents?kind=all`);
          if (res.ok) {
            const all = (await res.json()) as Array<{ id: string; pubkey: string }>;
            const existing = all.find((a) => a.id === id);
            if (existing) {
              pubkeyToRegister = existing.pubkey;
              didLookup = true;
            }
          }
        } catch {
          // Network blip — fall through to keypair generation. Worst case
          // is a pubkey mismatch error from /agents/register downstream,
          // which surfaces clearly to the caller.
        }
      }

      // Still no pubkey → mint a fresh keypair, return the private key.
      if (!pubkeyToRegister) {
        const kp = await generateKeyPair();
        returnPrivate = await exportPrivateKey(kp.privateKey);
        pubkeyToRegister = await derivePublicKeyB64(kp.privateKey);
      }

      await register(
        WIRE_URL,
        AGENT_ID,
        id,
        resolvedName,
        pubkeyToRegister,
        keyPair.privateKey,
        forceRotate ? { force_rotate: true } : undefined,
      );

      const response: Record<string, string> = {
        agent_id: id,
        display_name: resolvedName,
        pubkey: pubkeyToRegister,
      };
      if (returnPrivate) response.private_key_b64 = returnPrivate;
      if (didLookup) response.mode = "refresh-existing";
      return {
        content: [{ type: "text" as const, text: JSON.stringify(response) }],
      };
    } catch (e: any) {
      return {
        content: [{ type: "text" as const, text: `register failed: ${e.message}` }],
        isError: true,
      };
    }
  }

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
  const rawKey = process.env.AGENT_PRIVATE_KEY;
  if (!rawKey) {
    console.error("[wire-ipc] AGENT_PRIVATE_KEY not set — IPC sending disabled");
  } else {
    keyPair = await importKeyPair(rawKey);
  }

  const transport = new StdioServerTransport();
  await mcp.connect(transport);

  console.error(`[wire-ipc] ready (agent=${AGENT_ID})`);
}
