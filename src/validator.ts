/**
 * IPC webhook validator — JWT (EdDSA/Ed25519) verification.
 *
 * Reads Authorization: Bearer <JWT>, verifies Ed25519 signature,
 * checks body_hash, and returns routing + verified identity.
 *
 * JWT claims: iss (sender), iat, topic, dest?, body_hash (SHA-256 hex).
 *
 * Throwing any error rejects the request with 401.
 *
 * VM context: (headers, body, secrets, crypto, directory, rawBody)
 */
export const IPC_VALIDATOR = `
// --- Extract JWT ---
const authHeader = headers['authorization'] || '';
if (!authHeader.startsWith('Bearer ')) throw new Error('missing bearer token');
const token = authHeader.slice(7);

const parts = token.split('.');
if (parts.length !== 3) throw new Error('invalid JWT: expected 3 parts');
const [headerB64, payloadB64, sigB64] = parts;

// --- base64url helpers ---
function b64urlDecode(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// --- Decode claims ---
const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64)));
const sender = claims.iss;
if (!sender) throw new Error('missing iss claim');

// --- Lookup sender ---
const agent = directory[sender];
if (!agent) throw new Error('unknown sender: ' + sender);

// --- Verify EdDSA signature ---
const pubBytes = Uint8Array.from(atob(agent.pubkey), c => c.charCodeAt(0));
const key = await crypto.subtle.importKey('raw', pubBytes, 'Ed25519', false, ['verify']);
const sigBytes = b64urlDecode(sigB64);
const signingInput = headerB64 + '.' + payloadB64;
const valid = await crypto.subtle.verify('Ed25519', key, sigBytes, new TextEncoder().encode(signingInput));
if (!valid) throw new Error('invalid JWT signature');

// --- Verify body hash ---
const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rawBody));
const bodyHash = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
if (bodyHash !== claims.body_hash) throw new Error('body hash mismatch');

// --- Return routing + verified identity ---
return {
  source: sender,
  dest: claims.dest || undefined,
  topic: claims.topic || 'ipc',
  verified_sender: sender,
  sender_display_name: agent.display_name,
};
`;
