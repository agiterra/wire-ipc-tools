import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair } from "@agiterra/wire-tools";
import { WIRE_IPC_TOOLS, handleWireIpcToolCall, type WireIpcDeps } from "./mcp-server.js";

// A fake broker: records every POST and answers with a seq. The send must happen BEFORE and REGARDLESS of the lint.
const received: Array<{ path: string; body: unknown }> = [];
let server: ReturnType<typeof Bun.serve>;
let deps: WireIpcDeps;

beforeAll(async () => {
  server = Bun.serve({
    port: 0,
    async fetch(req) {
      received.push({ path: new URL(req.url).pathname, body: await req.json() });
      return Response.json({ seq: received.length });
    },
  });
  deps = { wire_url: `http://localhost:${server.port}`, agent_id: "test-agent", key_pair: await generateKeyPair() };
  const dir = mkdtempSync(join(tmpdir(), "ipc-ste-"));
  process.env.STE_GLOSSARY_PATH = join(dir, "glossary.md");
  process.env.STE_RULES_PATH = join(dir, "rules.md");
  writeFileSync(process.env.STE_GLOSSARY_PATH, "| Approved name | Banned synonyms | Meaning |\n|---|---|---|\n| worktree | checkout, clone | a git worktree |\n");
  writeFileSync(process.env.STE_RULES_PATH, "```json ste-lint-config\n{\"max_words_strict\": 20}\n```\n");
});
afterAll(() => server.stop(true));

const text = (r: { content: Array<{ text: string }> }) => r.content[0].text;

describe("send_message STE lint (AGI-154)", () => {
  test("a banned synonym and a 40-word sentence: SENT, then warnings appended", async () => {
    const long = Array.from({ length: 40 }, (_, i) => `w${i}`).join(" ") + ".";
    const r = await handleWireIpcToolCall("send_message", { topic: "ipc", dest: "brioche", payload: { text: `Open the checkout. ${long}` } }, deps);
    expect(r.isError).toBeUndefined();
    expect(received.at(-1)!.path).toBe("/webhooks/brioche/ipc");
    expect(text(r)).toMatch(/^sent seq=\d+ \(to brioche\)/);
    expect(text(r)).toContain("warn-only — the message was sent");
    expect(text(r)).toContain('"checkout": write "worktree"');
    expect(text(r)).toContain("Sentence has 40 words (cap 20)");
  });

  test("a clean message: result is exactly the old one", async () => {
    const r = await handleWireIpcToolCall("send_message", { topic: "ipc", dest: "brioche", payload: { text: "I merged PR 41. CI is green." } }, deps);
    expect(text(r)).toMatch(/^sent seq=\d+ \(to brioche\)$/);
  });

  test("a non-ipc topic is not linted", async () => {
    const r = await handleWireIpcToolCall("send_message", { topic: "rpc.request", dest: "x", payload: { text: "Open the checkout; now." } }, deps);
    expect(text(r)).toMatch(/^sent seq=\d+ \(to x\)$/);
  });

  test("an unreadable glossary still sends and says so", async () => {
    const saved = process.env.STE_GLOSSARY_PATH;
    process.env.STE_GLOSSARY_PATH = "/nonexistent/glossary.md";
    try {
      const before = received.length;
      const r = await handleWireIpcToolCall("send_message", { topic: "ipc", broadcast: true, payload: "a plain string payload here" }, deps);
      expect(received.length).toBe(before + 1);
      expect(text(r)).toContain("glossary not loaded from /nonexistent/glossary.md");
    } finally {
      process.env.STE_GLOSSARY_PATH = saved;
    }
  });

  test("the tool description carries the core rules and the glossary path", () => {
    expect(WIRE_IPC_TOOLS[0].description).toContain("/opt/agiterra/pod-tools/share/ste/glossary/glossary.md");
    expect(WIRE_IPC_TOOLS[0].description).toContain("20 words or fewer");
  });
});
