import test from "node:test";
import assert from "node:assert/strict";
import { parseAudit } from "../src/audit.ts";
const record = {
  pebble: "read secret-store via shell tainted .",
  decision: "block",
  reason: "rule",
  rules: ["deny-secret-read-tainted"],
  args_digest: "sha256:" + "a".repeat(64),
  surprise_bits: 8.1,
};
test("local audit keeps only typed decision metadata", () => {
  const rows = parseAudit(
    JSON.stringify({
      ...record,
      raw_args: "private-canary",
      reason: "private-canary",
      session: "private-canary",
    }),
  );
  assert.equal(rows[0].decision, "block");
  assert.equal(rows[0].tainted, true);
  assert.equal(rows[0].args_digest, record.args_digest);
  assert.ok(!JSON.stringify(rows).includes("private-canary"));
});
test("rejects raw values in action sentences and invalid verdicts", () => {
  assert.throws(
    () =>
      parseAudit(
        JSON.stringify({
          ...record,
          pebble: "read /private/secret via shell .",
        }),
      ),
    /closed action vocabulary/,
  );
  assert.throws(
    () => parseAudit(JSON.stringify({ ...record, decision: "approved" })),
    /allow, hold or block/,
  );
});
test("rejects malformed, empty and excessively long audit records", () => {
  assert.throws(() => parseAudit(""), /no records/);
  assert.throws(() => parseAudit("{"), /valid JSON/);
  assert.throws(
    () => parseAudit(JSON.stringify({ ...record, pebble: "read ".repeat(40) })),
    /closed action vocabulary/,
  );
  assert.throws(() => parseAudit("x".repeat(5 * 1024 * 1024 + 1)), /5 MB/);
});
test("strips unsafe rule identifiers, digests, nonfinite scores", () => {
  const [row] = parseAudit(
    JSON.stringify({
      ...record,
      rules: ["deny-secret-read-tainted", "<script>"],
      args_digest: "canary",
      surprise_bits: -1,
    }),
  );
  assert.deepEqual(row.rules, ["deny-secret-read-tainted"]);
  assert.equal(row.args_digest, undefined);
  assert.equal(row.surprise_bits, null);
});

test("imports compound effect records and rejects malformed closed-token input",()=>{
 const [row]=parseAudit(JSON.stringify({...record,pebble:"read proj-file via file-tool . exec test-runner via shell ."}));
 assert.equal(row.pebble,"read proj-file via file-tool . exec test-runner via shell .");
 assert.throws(()=>parseAudit(JSON.stringify({...record,pebble:"read read read ."})),/closed action vocabulary grammar/);
});
