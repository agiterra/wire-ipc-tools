/**
 * IPC helpers — JWT-authenticated message sending.
 */

import { createJwt, hashBody, type JwtClaims } from "./jwt.js";

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
    body_hash,
  };

  const token = await createJwt(privateKey, claims);

  const res = await fetch(`${url}/webhooks/${targetAgent}/${topic}`, {
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
