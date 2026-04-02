/**
 * Minimal JWT (EdDSA/Ed25519) — no external dependencies.
 *
 * Used for Authorization: Bearer <JWT> across all Wire endpoints.
 */

export type JwtClaims = {
  iss: string;        // sender agent ID
  iat: number;        // issued-at (unix seconds)
  body_hash: string;  // SHA-256 hex of request body
};

// --- Base64url ---

function base64urlEncode(data: Uint8Array): string {
  let str = "";
  for (const b of data) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(str: string): Uint8Array {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// Static header: {"alg":"EdDSA","typ":"JWT"}
const HEADER_B64 = base64urlEncode(
  new TextEncoder().encode(JSON.stringify({ alg: "EdDSA", typ: "JWT" })),
);

// --- Create ---

export async function createJwt(
  privateKey: CryptoKey,
  claims: JwtClaims,
): Promise<string> {
  const payloadB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(claims)),
  );
  const signingInput = `${HEADER_B64}.${payloadB64}`;
  const sig = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    new TextEncoder().encode(signingInput),
  );
  const sigB64 = base64urlEncode(new Uint8Array(sig));
  return `${signingInput}.${sigB64}`;
}

// --- Verify ---

export async function verifyJwt(
  token: string,
  publicKeyB64: string,
): Promise<JwtClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid JWT: expected 3 parts");

  const [headerB64, payloadB64, sigB64] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;

  const pubBytes = Uint8Array.from(atob(publicKeyB64), (c) =>
    c.charCodeAt(0),
  );
  const key = await crypto.subtle.importKey(
    "raw",
    pubBytes,
    "Ed25519",
    false,
    ["verify"],
  );
  const sigBytes = base64urlDecode(sigB64);
  const valid = await crypto.subtle.verify(
    "Ed25519",
    key,
    sigBytes,
    new TextEncoder().encode(signingInput),
  );
  if (!valid) throw new Error("invalid JWT signature");

  const claims = JSON.parse(
    new TextDecoder().decode(base64urlDecode(payloadB64)),
  ) as JwtClaims;
  return claims;
}

// --- Body hash ---

export async function hashBody(body: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(body),
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
