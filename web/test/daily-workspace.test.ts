import { parseAudit } from "../src/audit.ts";
import test from "node:test";
import assert from "node:assert/strict";
import {
  approvalMatches,
  classifyDocument,
  documentAction,
  formatLocalJson,
  parseDailyCheck,
  validateDraftName,
  validateLocalFile,
  workspacePayload,
  serializeDailyAudit,
  upsertDailyAudit,
} from "../src/daily-workspace.ts";
test("local file constraints and sensitive filename classification are conservative", () => {
  validateLocalFile("notes.md", 262144);
  assert.throws(() => validateLocalFile("run.js", 10));
  assert.throws(() => validateLocalFile("notes.md", 262145));
  assert.equal(classifyDocument("private-key.txt"), "secret-store");
  assert.equal(classifyDocument("guard-config.json"), "guard-config");
  assert.equal(classifyDocument("meeting.md"), "proj-file");
  assert.throws(() => validateDraftName("../notes.md"));
  assert.throws(() => validateDraftName("run.exe"));
});
test("payload excludes filenames and all content; history is bounded", () => {
  const action = documentAction("read", "very-private-meeting.md");
  assert.deepEqual(workspacePayload([], action), {
    history: [],
    action: { verb: "read", object: "proj-file", channel: "file-tool", flags: [] },
  });
  assert.throws(() => workspacePayload(Array(24).fill(action), action));
  assert.ok(!JSON.stringify(workspacePayload([], action)).includes("meeting"));
});
const valid = {
  decision: "hold",
  record: {
    id: "record_1",
    decision: "hold",
    pebble: "read proj-file via file-tool .",
    rules: [],
    reason: "Review this action.",
    surprise_bits: 2,
  },
  model: { parameters: 1288368, calibrated: true },
  policy: "daily-workspace-v1",
};
test("unexpected or inconsistent responses fail closed", () => {
  assert.equal(parseDailyCheck(valid).decision, "hold");
  for (const changed of [
    { decision: "bypass" },
    { policy: "unknown" },
    { record: { ...valid.record, decision: "allow" } },
    { record: { ...valid.record, pebble: "run arbitrary shell" } },
    { model: { parameters: 2, calibrated: true } },
    { record: { ...valid.record, surprise_bits: NaN } },
  ])
    assert.throws(() => parseDailyCheck({ ...valid, ...changed }));
});
test("human approval binds exact revision and closed action", () => {
  const action = documentAction("write", "notes.md"),
    held = { revision: 1, action };
  assert.equal(approvalMatches(held, 1, action), true);
  assert.equal(approvalMatches(held, 2, action), false);
  assert.equal(approvalMatches(held, 1, documentAction("write", "credentials.md")), false);
});

test("local JSON formatting creates an editable draft and rejects invalid input", () => {
  assert.equal(formatLocalJson('{\"a\":1}'), '{\n  \"a\": 1\n}\n');
  assert.throws(() => formatLocalJson("bad json"));
});
test("non-block out-of-scope responses and uncalibrated models fail closed", () => {
  assert.throws(() =>
    parseDailyCheck({
      ...valid,
      record: { ...valid.record, pebble: "read secret-store via file-tool ." },
    }),
  );
  assert.throws(() =>
    parseDailyCheck({ ...valid, model: { parameters: 1288368, calibrated: false } }),
  );
});

test("workspace export imports through existing audit viewer and omits raw local values", () => {
  const record = {
    id: "r1",
    action: documentAction("read", "private-meeting-notes.md"),
    decision: "hold" as const,
    completed: false,
    approved: false,
    surprise_bits: 8,
    rules: [],
  };
  const approved = { ...record, completed: true, approved: true };
  const records = upsertDailyAudit([record], approved);
  assert.equal(records.length, 1);
  const output = serializeDailyAudit(records);
  assert.ok(!output.includes("private-meeting-notes"));
  assert.ok(!output.includes("document content"));
  const parsed = parseAudit(output);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].pebble, "read proj-file via file-tool .");
  assert.equal(parsed[0].decision, "hold");
  assert.equal(JSON.parse(output).completion, "completed-after-human-approval");
});
test("audit retains at most 64 checks and updates held record rather than duplicating", () => {
  let records: Parameters<typeof serializeDailyAudit>[0] = [];
  for (let i = 0; i < 100; i++)
    records = upsertDailyAudit(records, {
      id: `r${i}`,
      action: documentAction("read", "notes.md"),
      decision: "block",
      completed: false,
      approved: false,
      surprise_bits: null,
      rules: [],
    });
  assert.equal(records.length, 64);
  assert.equal(records[0].id, "r36");
  assert.equal(parseAudit(serializeDailyAudit(records)).length, 64);
});
