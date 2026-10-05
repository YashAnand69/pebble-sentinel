export type DailyAction = {
  verb: "read" | "write";
  object: string;
  channel: "file-tool";
  flags: [];
};
export type DailyVerdict = "allow" | "hold" | "block";
export type DailyCheck = {
  decision: DailyVerdict;
  record: {
    id: string;
    pebble: string;
    rules: string[];
    reason: string;
    surprise_bits: number | null;
  };
  model: { parameters: number; calibrated: boolean };
  policy: "daily-workspace-v1";
};
export const MAX_FILE_BYTES = 256 * 1024;
export const MAX_HISTORY = 24;
export function validateLocalFile(name: string, size: number) {
  if (!/\.(txt|md|json|csv)$/i.test(name))
    throw new Error("Choose a .txt, .md, .json, or .csv document.");
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_FILE_BYTES)
    throw new Error("Documents must be 256 KB or smaller.");
}
export function validateDraftName(name: string) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._ -]{0,99}\.(txt|md|json|csv)$/i.test(name) || name.includes(".."))
    throw new Error("Use a simple filename ending in .md, .txt, .json, or .csv; no paths.");
  return name;
}
export function classifyDocument(name: string): string {
  const lower = name.toLowerCase();
  if (/(secret|credential|password|private[-_ ]?key|token|\.env)/.test(lower))
    return "secret-store";
  if (/(sentinel|guard)[-_ .]*(config|settings|policy)/.test(lower)) return "guard-config";
  if (/(agent)[-_ .]*(config|settings)/.test(lower)) return "agent-config";
  if (/(bashrc|zshrc|shell[-_ .]*(rc|config))/.test(lower)) return "shell-rc";
  if (/^\./.test(lower)) return "home-dotfile";
  if (/(config|settings)/.test(lower)) return "proj-config";
  return "proj-file";
}
export function documentAction(verb: DailyAction["verb"], name: string): DailyAction {
  return { verb, object: classifyDocument(name), channel: "file-tool", flags: [] };
}
export function workspacePayload(history: DailyAction[], action: DailyAction) {
  if (history.length >= MAX_HISTORY)
    throw new Error(
      "This workspace has reached 24 completed actions. Clear it to start a fresh session.",
    );
  return {
    history: history.map((a) => ({
      verb: a.verb,
      object: a.object,
      channel: "file-tool" as const,
      flags: [],
    })),
    action: { verb: action.verb, object: action.object, channel: "file-tool" as const, flags: [] },
  };
}
export function parseDailyCheck(value: unknown): DailyCheck {
  if (!value || typeof value !== "object")
    throw new Error("The guard returned an invalid response. Nothing was opened or downloaded.");
  const v = value as Record<string, unknown>;
  const r = v.record as Record<string, unknown> | undefined;
  const m = v.model as Record<string, unknown> | undefined;
  if (
    !["allow", "hold", "block"].includes(String(v.decision)) ||
    v.policy !== "daily-workspace-v1" ||
    !r ||
    r.decision !== v.decision ||
    typeof r.id !== "string" ||
    !/^[a-zA-Z0-9_-]{1,100}$/.test(r.id) ||
    typeof r.pebble !== "string" ||
    !/^(read|write) (proj-file|proj-config|home-dotfile|secret-store|shell-rc|agent-config|guard-config) via file-tool \.$/.test(
      r.pebble,
    ) ||
    !Array.isArray(r.rules) ||
    r.rules.some((x) => typeof x !== "string" || !/^[a-zA-Z0-9_.:-]{1,80}$/.test(x)) ||
    typeof r.reason !== "string" ||
    r.reason.length > 1000 ||
    !(
      r.surprise_bits === null ||
      (typeof r.surprise_bits === "number" &&
        Number.isFinite(r.surprise_bits) &&
        r.surprise_bits >= 0)
    ) ||
    !m ||
    m.parameters !== 1288368 ||
    m.calibrated !== true
  )
    throw new Error("The guard response could not be verified. Nothing was opened or downloaded.");
  if (
    v.decision !== "block" &&
    !/^(read (proj-file|proj-config)|write proj-file) via file-tool \.$/.test(r.pebble as string)
  )
    throw new Error(
      "The guard permitted an out-of-scope action. Nothing was opened or downloaded.",
    );
  return {
    decision: v.decision as DailyVerdict,
    record: {
      id: r.id,
      pebble: r.pebble,
      rules: r.rules as string[],
      reason: r.reason,
      surprise_bits: r.surprise_bits as number | null,
    },
    model: { parameters: m.parameters, calibrated: m.calibrated },
    policy: "daily-workspace-v1",
  };
}
export function approvalMatches(
  held: { revision: number; action: DailyAction },
  revision: number,
  action: DailyAction,
) {
  return held.revision === revision && JSON.stringify(held.action) === JSON.stringify(action);
}

export function formatLocalJson(text: string) {
  return JSON.stringify(JSON.parse(text), null, 2) + "\n";
}

export type DailyAudit = {
  id: string;
  action: DailyAction;
  decision: DailyVerdict;
  completed: boolean;
  approved: boolean;
  surprise_bits: number | null;
  rules: string[];
};
export const MAX_AUDIT = 64;
export function upsertDailyAudit(records: DailyAudit[], next: DailyAudit) {
  const existing = records.findIndex((record) => record.id === next.id);
  return (
    existing < 0
      ? [...records, next]
      : records.map((record, index) => (index === existing ? next : record))
  ).slice(-MAX_AUDIT);
}
export function serializeDailyAudit(records: DailyAudit[]) {
  return (
    records
      .slice(-MAX_AUDIT)
      .map((record, index) =>
        JSON.stringify({
          id: record.id,
          seq: index + 1,
          tool: "file-tool",
          pebble: `${record.action.verb} ${record.action.object} via file-tool .`,
          decision: record.decision,
          rules: record.rules,
          surprise_bits: record.surprise_bits,
          completed: record.completed,
          approved: record.approved,
          completion: record.completed
            ? record.approved
              ? "completed-after-human-approval"
              : "completed-after-allow"
            : "not-completed",
          source: "browser-daily-workspace",
          integrity: "local-metadata-only",
        }),
      )
      .join("\n") + "\n"
  );
}
