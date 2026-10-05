export type AuditRecord = {
  id: string;
  seq: number;
  tool: string;
  pebble: string;
  surprise_bits: number | null;
  rules: string[];
  decision: "allow" | "hold" | "block";
  would_have?: "allow" | "hold" | "block";
  reason: string;
  tainted: boolean;
  args_digest?: string;
  latency_ms?: number;
};
const vocabulary = new Set(
  "read write edit delete exec fetch send install spawn proj-file proj-config home-dotfile secret-store system-path tmp-file skill-file agent-config guard-config shell-rc cron-entry test-runner build-tool vcs pkg-manager interpreter unknown-binary downloaded-code net-local net-allow net-unknown pkg-registry unknown-object via shell file-tool web-tool mcp skill tainted sudo pipe encoded remote-code bulk outside-cwd new-host .".split(
    " ",
  ),
);
const verdict = (value: unknown): value is AuditRecord["decision"] =>
  ["allow", "hold", "block"].includes(String(value));
export function parseAudit(text: string): AuditRecord[] {
  if (new TextEncoder().encode(text).length > 5 * 1024 * 1024)
    throw new Error("Choose an audit smaller than 5 MB.");
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  if (!text.trim()) throw new Error("This audit has no records.");
  if (lines.length > 10000)
    throw new Error("Choose an audit with at most 10,000 records.");
  return lines.map((line, index) => {
    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(line);
    } catch {
      throw new Error(`Line ${index + 1} is not valid JSON.`);
    }
    if (
      typeof raw !== "object" ||
      !raw ||
      Array.isArray(raw) ||
      typeof raw.pebble !== "string" ||
      !verdict(raw.decision)
    )
      throw new Error(
        `Line ${index + 1} needs a Pebble sentence and allow, hold or block decision.`,
      );
    const tokens = raw.pebble.trim().split(/\s+/);
    if (tokens.length > 512 || tokens.some((token) => !vocabulary.has(token)))
      throw new Error(
        `Line ${index + 1} contains values outside the closed action vocabulary. Raw arguments must not appear in an audit sentence.`,
      );
    const sentences = raw.pebble.trim().split(".").map(part => part.trim()).filter(Boolean);
    const allowedVerbs = new Set("read write edit delete exec fetch send install spawn".split(" "));
    const allowedChannels = new Set("shell file-tool web-tool mcp skill".split(" "));
    const allowedFlags = new Set("tainted sudo pipe encoded remote-code bulk outside-cwd new-host".split(" "));
    if (!raw.pebble.trim().endsWith(".") || sentences.some(sentence => {
      const words = sentence.split(/\s+/);
      return words.length < 4 || !allowedVerbs.has(words[0]) || !vocabulary.has(words[1]) || allowedVerbs.has(words[1]) || allowedChannels.has(words[1]) || allowedFlags.has(words[1]) || words[1] === "via" || words[1] === "." || words[2] !== "via" || !allowedChannels.has(words[3]) || words.slice(4).some(flag => !allowedFlags.has(flag));
    })) throw new Error(`Line ${index + 1} does not follow the closed action vocabulary grammar.`);
    const score =
      typeof raw.surprise_bits === "number" &&
      Number.isFinite(raw.surprise_bits) &&
      raw.surprise_bits >= 0
        ? raw.surprise_bits
        : null;
    return {
      id: `import-${index + 1}`,
      seq: index + 1,
      tool: tokens[tokens.indexOf("via") + 1] ?? "action",
      pebble: tokens.join(" "),
      surprise_bits: score,
      rules: Array.isArray(raw.rules)
        ? raw.rules
            .filter(
              (rule): rule is string =>
                typeof rule === "string" && /^[a-z0-9-]{1,80}$/.test(rule),
            )
            .slice(0, 16)
        : [],
      decision: raw.decision,
      would_have: verdict(raw.would_have) ? raw.would_have : undefined,
      reason: ["rule", "surprise", "error", "mode"].includes(String(raw.reason))
        ? String(raw.reason)
        : "Imported decision. Inspect the recorded policy rules and model signal.",
      tainted: tokens.includes("tainted"),
      args_digest:
        typeof raw.args_digest === "string" &&
        /^sha256:[a-f0-9]{64}$/.test(raw.args_digest)
          ? raw.args_digest
          : undefined,
      latency_ms:
        typeof raw.latency_ms === "number" &&
        Number.isFinite(raw.latency_ms) &&
        raw.latency_ms >= 0
          ? raw.latency_ms
          : undefined,
    };
  });
}
