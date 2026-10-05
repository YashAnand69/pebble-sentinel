export type GuardMode = "learn" | "shadow" | "enforce";
export type Verdict = "allow" | "hold" | "block";
export type LabEvent = {
  decision: Verdict;
  would_have?: Verdict;
  executed?: boolean;
};
export function parseLaunch(search: string, allowedScenarios: string[]) {
  const params = new URLSearchParams(search);
  const candidate = params.get("scenario");
  const candidateMode = params.get("mode");
  return {
    scenario:
      candidate && allowedScenarios.includes(candidate) ? candidate : null,
    mode: (candidateMode === "learn" ||
    candidateMode === "shadow" ||
    candidateMode === "enforce"
      ? candidateMode
      : "enforce") as GuardMode,
    reviewedLink: Boolean(candidate && allowedScenarios.includes(candidate)),
    rejectedScenario: Boolean(
      candidate && !allowedScenarios.includes(candidate),
    ),
  };
}
export function summarizeRun(
  events: LabEvent[],
  mode: GuardMode,
  source: "simulation" | "import" | "composed",
): {
  index: number;
  decision: Verdict;
  title: string;
  description: string;
  hypotheticalAfter: number;
} {
  const firstBoundary = events.findIndex((event) => event.decision !== "allow");
  const predictedBlock = events.findIndex(
    (event) => event.would_have === "block",
  );
  const predictedHold = events.findIndex(
    (event) => event.would_have === "hold",
  );
  if (source === "import")
    return {
      index: firstBoundary < 0 ? 0 : firstBoundary,
      decision: firstBoundary < 0 ? "allow" : events[firstBoundary].decision,
      title: "Your recorded decisions, locally inspected.",
      description:
        "These imported records have not been re-scored. No file content was sent to the guard service.",
      hypotheticalAfter: -1,
    };
  if (mode === "learn")
    return {
      index: 0,
      decision: "allow",
      title: "Recorded only. No boundary applied.",
      description:
        "Learn mode logs the typed sequence without scoring or enforcing policy. This is an observation run, not a safety verdict.",
      hypotheticalAfter: -1,
    };
  if (mode === "shadow") {
    const strongest = predictedBlock >= 0 ? predictedBlock : predictedHold;
    return {
      index: strongest < 0 ? 0 : strongest,
      decision:
        predictedBlock >= 0 ? "block" : predictedHold >= 0 ? "hold" : "allow",
      title:
        strongest < 0
          ? "Shadow run: no boundary predicted."
          : `Shadow run: would ${predictedBlock >= 0 ? "block" : "hold"} action ${strongest + 1}.`,
      description: source === "composed"
        ? "No tools execute in this analysis. Shadow mode permits the typed sequence while recording recommendations."
        : "All fixture actions remain permitted in shadow mode. Recommendations describe what the guard predicts; they are not enforced actions.",
      hypotheticalAfter: -1,
    };
  }
  if (source === "composed")
    return {
      index: firstBoundary < 0 ? 0 : firstBoundary,
      decision: firstBoundary < 0 ? "allow" : events[firstBoundary].decision,
      title:
        firstBoundary < 0
          ? "No boundary flagged in this typed sequence."
          : `Action ${firstBoundary + 1} needs a boundary.`,
      description:
        "This is analysis of typed actions only. No real tool or shell command was executed.",
      hypotheticalAfter: -1,
    };
  return {
    index: firstBoundary < 0 ? 0 : firstBoundary,
    decision: firstBoundary < 0 ? "allow" : events[firstBoundary].decision,
    title:
      firstBoundary < 0
        ? "This fixture completed without intervention."
        : `Replay stopped at action ${firstBoundary + 1}: ${events[firstBoundary].decision === "block" ? "blocked" : "held"}.`,
    description:
      firstBoundary < 0
        ? "The reviewed fixture was permitted. That does not establish that every similar real-world action is safe."
        : "The boundary acts before this action executes. All later steps are hypothetical and were not executed.",
    hypotheticalAfter: firstBoundary,
  };
}
