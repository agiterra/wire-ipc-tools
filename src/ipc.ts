/**
 * IPC helpers — webhook registration and signed message sending.
 *
 * Uses signBody from @agiterra/exchange-tools for Ed25519 signing.
 */

import { signBody } from "../../exchange-tools/src/crypto.js";

export async function registerIpcWebhook(
  url: string,
  agentId: string,
  validator: string,
): Promise<void> {
  const res = await fetch(`${url}/agents/${agentId}/webhooks`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ plugin: "ipc", validator }),
  });
  if (!res.ok) {
    throw new Error(
      `IPC webhook registration failed (${res.status}): ${await res.text()}`,
    );
  }
}

export async function sendSignedMessage(
  url: string,
  agentId: string,
  privateKey: CryptoKey,
  topic: string,
  payload: unknown,
  dest?: string,
): Promise<{ seq: number }> {
  const body: Record<string, unknown> = { source: agentId, topic, payload };
  if (dest) body.dest = dest;

  const targetAgent = dest ?? agentId;
  const bodyStr = JSON.stringify(body);
  const signature = await signBody(privateKey, bodyStr);

  const res = await fetch(`${url}/webhooks/${targetAgent}/ipc`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Exchange-Signature": signature,
    },
    body: bodyStr,
  });
  if (!res.ok) {
    throw new Error(
      `IPC send failed (${res.status}): ${await res.text()}`,
    );
  }
  return (await res.json()) as { seq: number };
}
