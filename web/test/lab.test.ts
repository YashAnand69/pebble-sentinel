import test from "node:test";
import assert from "node:assert/strict";
import { parseLaunch, summarizeRun } from "../src/lab.ts";
test("launch links only select reviewed scenarios and closed modes", () => {
  assert.deepEqual(
    parseLaunch("?scenario=injection-exfiltration&mode=shadow", [
      "injection-exfiltration",
    ]),
    {
      scenario: "injection-exfiltration",
      mode: "shadow",
      reviewedLink: true,
      rejectedScenario: false,
    },
  );
  assert.equal(
    parseLaunch("?scenario=run-shell-command&mode=bypass", [
      "injection-exfiltration",
    ]).scenario,
    null,
  );
  assert.equal(
    parseLaunch("?scenario=run-shell-command&mode=bypass", [
      "injection-exfiltration",
    ]).mode,
    "enforce",
  );
});
test("enforce summaries anchor first intervention, not a hypothetical later block", () => {
  const result = summarizeRun(
    [
      { decision: "allow" },
      { decision: "hold", executed: false },
      { decision: "block", executed: false },
    ],
    "enforce",
    "simulation",
  );
  assert.equal(result.index, 1);
  assert.equal(result.decision, "hold");
  assert.equal(result.hypotheticalAfter, 1);
  assert.match(result.title, /action 2: held/);
});
test("shadow reports predicted block while acknowledging actions stayed allowed", () => {
  const result = summarizeRun(
    [
      { decision: "allow", would_have: "hold" },
      { decision: "allow", would_have: "block" },
    ],
    "shadow",
    "simulation",
  );
  assert.equal(result.decision, "block");
  assert.match(result.title, /would block action 2/);
  assert.equal(result.hypotheticalAfter, -1);
});
test("learn, composed analysis and imported audit never claim real execution protection", () => {
  assert.match(
    summarizeRun([{ decision: "allow" }], "learn", "simulation").title,
    /Recorded only/,
  );
  assert.equal(
    summarizeRun([{ decision: "block" }], "enforce", "composed")
      .hypotheticalAfter,
    -1,
  );
  assert.match(
    summarizeRun([{ decision: "block" }], "enforce", "import").description,
    /not been re-scored/,
  );
});
