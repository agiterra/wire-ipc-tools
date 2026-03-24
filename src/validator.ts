/**
 * Reference IPC webhook validator — Ed25519 signature verification.
 *
 * Returns a validator_result object with:
 *   - source: verified sender agent ID
 *   - dest: intended recipient (if specified in body)
 *   - topic: routing topic (if specified in body)
 *   - verified_sender: same as source (explicit field for channel handlers)
 *
 * The server uses source/dest/topic for routing. The validator_result
 * (including verified_sender) is passed through SSE to the client's
 * channel handler, which can trust it without re-verifying.
 *
 * Throwing any error rejects the request with 401.
 *
 * VM context: (headers, body, secrets, crypto, directory, rawBody)
 */
export const IPC_VALIDATOR = `
const sig = headers['x-exchange-signature'];
if (!sig) throw new Error('missing signature');

const parsed = typeof body === 'string' ? JSON.parse(body) : body;
const sender = parsed.sender || parsed.source;
if (!sender) throw new Error('missing sender');

const agent = directory[sender];
if (!agent) throw new Error('unknown sender: ' + sender);

const pubkeyBytes = Uint8Array.from(atob(agent.pubkey), c => c.charCodeAt(0));
const key = await crypto.subtle.importKey('raw', pubkeyBytes, 'Ed25519', false, ['verify']);
const sigBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
const valid = await crypto.subtle.verify('Ed25519', key, sigBytes, new TextEncoder().encode(rawBody));
if (!valid) throw new Error('invalid signature');

// Return routing + verified identity for the client-side channel handler
return {
  source: sender,
  dest: parsed.dest || undefined,
  topic: parsed.topic || 'ipc',
  verified_sender: sender,
  sender_display_name: agent.display_name,
};
`;
