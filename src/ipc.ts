/**
 * IPC helpers — webhook registration and JWT-authenticated message sending.
 */

import { createJwt, hashBody, type JwtClaims } from "./jwt.js";

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
  const targetAgent = dest ?? agentId;
  const bodyStr = JSON.stringify(payload);
  const body_hash = await hashBody(bodyStr);

  const claims: JwtClaims = {
    iss: agentId,
    iat: Math.floor(Date.now() / 1000),
    topic,
    body_hash,
  };
  if (dest) claims.dest = dest;

  const token = await createJwt(privateKey, claims);

  const res = await fetch(`${url}/webhooks/${targetAgent}/ipc`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
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
