import { useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent } from "react";
import { parseAudit } from "./audit";
import Evaluation from "./Evaluation";
import {
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronDown,
  Download,
  Eye,
  FileJson,
  Github,
  LockKeyhole,
  Pause,
  Play,
  ShieldCheck,
  Upload,
  X,
  Terminal,
  Layers,
  Fingerprint,
} from "lucide-react";

type Mode = "learn" | "shadow" | "enforce";
type Verdict = "allow" | "hold" | "block";
type Scenario = {
  id: string;
  title: string;
  description?: string;
  family?: string;
};
type Event = {
  id: string;
  seq: number;
  tool: string;
  pebble: string;
  surprise_bits: number | null;
  rules: string[];
  decision: Verdict;
  would_have?: Verdict;
  reason: string;
  tainted?: boolean;
  args_digest?: string;
  latency_ms?: number;
  executed?: boolean;
  effect?: string;
};
type Report = { events: Event[]; [key: string]: unknown };
const repo = "https://github.com/YashAnand69/pebble-sentinel";
const verbs = [
  "read",
  "write",
  "edit",
  "delete",
  "exec",
  "fetch",
  "send",
  "install",
  "spawn",
];
const objects = [
  "proj-file",
  "proj-config",
  "home-dotfile",
  "secret-store",
  "shell-rc",
  "cron-entry",
  "agent-config",
  "guard-config",
  "tmp-file",
  "skill-file",
  "system-path",
  "test-runner",
  "build-tool",
  "vcs",
  "pkg-manager",
  "interpreter",
  "downloaded-code",
  "unknown-binary",
  "net-local",
  "net-allow",
  "net-unknown",
  "pkg-registry",
  "unknown-object",
];
const channels = ["shell", "file-tool", "web-tool", "mcp", "skill"];
const allFlags = [
  "tainted",
  "sudo",
  "pipe",
  "encoded",
  "remote-code",
  "bulk",
  "outside-cwd",
  "new-host",
];
function isVerdict(value: unknown): value is Verdict {
  return value === "allow" || value === "hold" || value === "block";
}
function normalizeEvent(raw: Record<string, unknown>, index: number): Event {
  const decision = isVerdict(raw.decision) ? raw.decision : "hold";
  const rules = Array.isArray(raw.rules) ? raw.rules.map(String) : [];
  const explanations: Record<string, string> = {
    "deny-guard-tamper":
      "The action targets the guard’s own configuration or plugin files. Self-protection policy refuses it.",
    "deny-secret-read-tainted":
      "The session has ingested untrusted content. Reading a secret store now violates the boundary.",
    "deny-secret-then-send":
      "A secret was read earlier in this session. Sending to an unknown host is refused.",
    "deny-persistence-tainted":
      "After untrusted input, modifying startup files, scheduled jobs, or agent configuration is refused.",
    "hold-remote-code":
      "Downloaded code needs a person’s review before execution.",
    "hold-sudo": "An action requesting elevated privileges needs human review.",
    "hold-new-host-send":
      "Sending to a new or unknown destination needs human review.",
  };
  const reason =
    raw.reason === "rule"
      ? rules
          .map((rule) => explanations[rule] ?? `Policy rule ${rule} fired.`)
          .join(" ") || "A hard policy rule fired."
      : raw.reason === "surprise"
        ? raw.model &&
          typeof raw.model === "object" &&
          (raw.model as Record<string, unknown>).calibrated === false
          ? "Calibration is pending. This preliminary model uses cautious holds until a benign calibration is available."
          : "The model’s sequence surprise crossed an empirical threshold. The score measures rarity, not malicious intent."
        : raw.reason === "error"
          ? "The guard could not complete scoring. Enforce mode pauses uncertain actions."
          : raw.reason === "normal"
            ? "No policy rule or empirical surprise boundary flagged this action. This is not a guarantee of safety."
            : raw.reason === "mode"
              ? "This observation mode records the action without enforcing a boundary."
              : String(
                  raw.reason ?? "Inspect the rule and model signal below.",
                );
  return {
    id: String(raw.id ?? `action-${index + 1}`),
    seq: Number(raw.seq ?? index + 1),
    tool: String(raw.tool ?? raw.channel ?? "action"),
    pebble: String(raw.pebble ?? raw.sentence ?? raw.action ?? "unavailable"),
    surprise_bits:
      typeof raw.surprise_bits === "number"
        ? raw.surprise_bits
        : typeof raw.surprise === "number"
          ? raw.surprise
          : null,
    rules,
    decision,
    would_have: isVerdict(raw.would_have)
      ? raw.would_have
      : isVerdict(raw.would_decide)
        ? raw.would_decide
        : undefined,
    reason,
    tainted:
      Boolean(raw.tainted) || String(raw.pebble ?? "").includes(" tainted"),
    args_digest:
      typeof raw.args_digest === "string" ? raw.args_digest : undefined,
    latency_ms: typeof raw.latency_ms === "number" ? raw.latency_ms : undefined,
    executed: typeof raw.executed === "boolean" ? raw.executed : undefined,
    effect: typeof raw.effect === "string" ? raw.effect : undefined,
  };
}
function normalizeReport(raw: Record<string, unknown>): Report {
  const rows = raw.events ?? raw.trace ?? raw.actions ?? raw.records ?? [];
  return {
    ...raw,
    events: Array.isArray(rows)
      ? rows
          .filter((x) => x && typeof x === "object")
          .map((x, i) => normalizeEvent(x, i))
      : [],
  };
}
async function request(path: string, body?: unknown) {
  let response: Response;
  try {
    response = await fetch(path, {
      method: body ? "POST" : "GET",
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error(
      "The guard service is unreachable. Check your connection and try again.",
    );
  }
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(
      "The guard service returned an unreadable response. Please try again.",
    );
  }
  if (!response.ok)
    throw new Error(
      data.error ??
        data.detail ??
        "The guard service could not complete this request.",
    );
  return data;
}
function Status({ value }: { value: Verdict }) {
  return (
    <span className={`status ${value}`}>
      {value === "allow" ? (
        <Check size={12} />
      ) : value === "hold" ? (
        <Pause size={11} />
      ) : (
        <X size={12} />
      )}{" "}
      {value}
    </span>
  );
}
function Stone({ small = false }: { small?: boolean }) {
  return (
    <span className={`stone ${small ? "small" : ""}`} aria-hidden="true">
      <span />
      <span />
      <span />
    </span>
  );
}
function ShieldScene({ reduced }: { reduced: boolean }) {
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const node = root.current;
    if (!node || reduced) return;
    let raf = 0;
    const update = () => {
      if (raf) return;
      raf = requestAnimationFrame(() => {
        const rect = node.getBoundingClientRect();
        const progress = Math.max(
          -1,
          Math.min(1, (innerHeight / 2 - rect.top) / innerHeight),
        );
        node.style.setProperty("--scroll", String(progress));
        raf = 0;
      });
    };
    window.addEventListener("scroll", update, { passive: true });
    update();
    return () => {
      window.removeEventListener("scroll", update);
      cancelAnimationFrame(raf);
    };
  }, [reduced]);
  return (
    <div
      className={`scene ${reduced ? "motion-reduced" : ""}`}
      ref={root}
      aria-label="Conceptual 3D guard: an agent action passes through encoding, scoring and policy before a decision"
    >
      <div className="scene-grid" />
      <div className="orbit orbit-one" />
      <div className="orbit orbit-two" />
      <div className="shield-stack">
        <div className="shield-plane plane-back">
          <span>POLICY</span>
        </div>
        <div className="shield-plane plane-middle">
          <span>MODEL</span>
        </div>
        <div className="shield-plane plane-front">
          <ShieldCheck strokeWidth={0.8} />
          <div className="core" />
        </div>
      </div>
      <div className="scene-token token-in">
        <span className="tiny-dot" /> read secret-store
      </div>
      <div className="scene-token token-out">
        <X size={13} /> block <span>before execution</span>
      </div>
      <div className="scene-coordinate">SENTINEL / ACTION BOUNDARY</div>
      <div className="scene-axis">x + y + z</div>
    </div>
  );
}
function App() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]),
    [scenario, setScenario] = useState(""),
    [mode, setMode] = useState<Mode>("enforce"),
    [report, setReport] = useState<Report | null>(null),
    [selected, setSelected] = useState(0),
    [pending, setPending] = useState(false),
    [error, setError] = useState(""),
    [catalogError, setCatalogError] = useState(""),
    [source, setSource] = useState<"simulation" | "import" | "composed">(
      "simulation",
    ),
    [panel, setPanel] = useState<"replay" | "compose" | "audit">("replay"),
    [evaluation, setEvaluation] = useState<Record<string, unknown> | null>(
      null,
    ),
    [evaluationError, setEvaluationError] = useState(""),
    [verb, setVerb] = useState("read"),
    [object, setObject] = useState("proj-file"),
    [channel, setChannel] = useState("file-tool"),
    [flags, setFlags] = useState<string[]>([]),
    [composed, setComposed] = useState<Record<string, unknown>[]>([]),
    [copied, setCopied] = useState(false),
    [model, setModel] = useState<Record<string, unknown> | null>(null),
    [reducedMotion, setReducedMotion] = useState(
      () => matchMedia("(prefers-reduced-motion: reduce)").matches,
    );
  const fileInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    let alive = true;
    request("/api/health")
      .then((data) => alive && setModel(data.model))
      .catch(() => {});
    request("/api/scenarios")
      .then((data) => {
        if (!alive) return;
        const list = Array.isArray(data) ? data : (data.scenarios ?? []);
        setScenarios(list);
        setScenario(list[0]?.id ?? "");
      })
      .catch((e) => alive && setCatalogError(e.message));
    request("/api/evaluate")
      .then((data) => alive && setEvaluation(data))
      .catch((e) => alive && setEvaluationError(e.message));
    return () => {
      alive = false;
    };
  }, []);
  const events = report?.events ?? [],
    active = events[selected],
    current = scenarios.find((x) => x.id === scenario),
    counts = useMemo(
      () =>
        events.reduce(
          (acc, event) => ({
            ...acc,
            [event.decision]: acc[event.decision] + 1,
          }),
          { allow: 0, hold: 0, block: 0 },
        ),
      [events],
    ),
    pageStart = Math.floor(selected / 100) * 100;
  async function run() {
    setPending(true);
    setError("");
    try {
      const data = await request(
        panel === "compose" ? "/api/check" : "/api/simulate",
        panel === "compose" ? { actions: composed, mode } : { scenario, mode },
      );
      setReport(normalizeReport(data));
      if (data.model) setModel(data.model);
      setSelected(0);
      setSource(panel === "compose" ? "composed" : "simulation");
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Unable to evaluate this scenario.",
      );
    } finally {
      setPending(false);
    }
  }
  async function importAudit(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setError("");
    try {
      if (file.size > 5 * 1024 * 1024)
        throw new Error("Choose an audit smaller than 5 MB.");
      const rows = parseAudit(await file.text());
      setReport({ events: rows });
      setSource("import");
      setSelected(0);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "This file is not valid Sentinel JSONL.",
      );
    }
    e.target.value = "";
  }
  function download() {
    if (!report) return;
    const blob = new Blob(
      [events.map((event) => JSON.stringify(event)).join("\n") + "\n"],
      { type: "application/x-ndjson" },
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sentinel-${source}-audit.jsonl`;
    link.click();
    URL.revokeObjectURL(url);
  }
  const sampleCommand =
    "python -m sentinel.cli simulate injection-exfiltration --mode enforce";
  async function copyCommand() {
    try {
      await navigator.clipboard.writeText(sampleCommand);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setError(
        "Copy is unavailable in this browser. Select the command in the install section.",
      );
    }
  }
  return (
    <>
      <a className="skip-link" href="#playground">
        Skip to playground
      </a>
      <header className="nav">
        <a className="brand" href="#">
          <Stone small />
          <span>
            pebble <span className="brand-divider">/</span>{" "}
            <strong>SENTINEL</strong>
          </span>
        </a>
        <nav aria-label="Main navigation">
          <a href="#architecture">How it works</a>
          <a href="#playground">Playground</a>
          <a href="#evidence">Evidence</a>
        </nav>
        <a className="nav-github" href={repo} target="_blank" rel="noreferrer">
          <Github size={15} /> Open source <ArrowUpRight size={13} />
        </a>
      </header>
      <main>
        <section className="hero">
          <div className="hero-copy">
            <div className="eyebrow">
              <span className="tiny-dot" /> OPEN SOURCE · RUNTIME GUARD
            </div>
            <h1>
              Give your agent
              <br />a <em>second instinct.</em>
            </h1>
            <p className="hero-description">
              An agent can follow the wrong instruction.
              <br />
              Its next action doesn’t have to follow through.
            </p>
            <p className="hero-detail">
              Pebble Sentinel turns tool calls into a language of behavior. A
              tiny model and transparent rules decide what runs, what waits, and
              what stops.
            </p>
            <div className="hero-actions">
              <a className="button primary" href="#playground">
                Replay an attack <ArrowRight size={16} />
              </a>
              <a className="text-link" href="#architecture">
                Meet the guard <ChevronDown size={15} />
              </a>
            </div>
            <div className="hero-footnote">
              <LockKeyhole size={12} /> Safe canary scenarios. No commands
              executed here.
            </div>
          </div>
          <ShieldScene reduced={reducedMotion} />
        </section>
        <div className="section-divider">
          <span>TRUST THE AGENT. VERIFY THE ACTION.</span>
          <span>01 — THE BOUNDARY</span>
        </div>
        <section className="decisions">
          <div className="decision-card">
            <div className="decision-icon allow">
              <Check />
            </div>
            <h2>Keep the flow.</h2>
            <p>
              Ordinary project work moves forward. The guard observes each
              action before it reaches a tool.
            </p>
            <span className="mono-label">01 / ALLOW</span>
          </div>
          <div className="decision-card">
            <div className="decision-icon hold">
              <Pause />
            </div>
            <h2>Make room for judgment.</h2>
            <p>
              An uncertain action pauses for a person. A warning is useful only
              when you can understand it.
            </p>
            <span className="mono-label">02 / HOLD</span>
          </div>
          <div className="decision-card">
            <div className="decision-icon block">
              <X />
            </div>
            <h2>Stop the wrong turn.</h2>
            <p>
              Secret access after untrusted input, guard tampering, and risky
              chains meet an explicit boundary.
            </p>
            <span className="mono-label">03 / BLOCK</span>
          </div>
        </section>
        <section className="architecture section" id="architecture">
          <div className="section-heading">
            <div>
              <div className="eyebrow">A SMALL LANGUAGE. A CLEAR DECISION.</div>
              <h2>
                Not another prompt
                <br />
                to persuade.
              </h2>
            </div>
            <p>
              The guard works with typed actions, rather than instructions
              inside a webpage. Raw content stays outside the scoring
              vocabulary.
            </p>
          </div>
          <div className="pipeline">
            <article>
              <span className="step-number">01</span>
              <Layers size={22} />
              <h3>Encode the action</h3>
              <p>
                Tool arguments become deterministic classes. Sensitive values
                become digests in the audit.
              </p>
              <code>read secret-store via shell tainted .</code>
            </article>
            <span className="pipeline-arrow">
              <ArrowRight />
            </span>
            <article>
              <span className="step-number">02</span>
              <Fingerprint size={22} />
              <h3>Score the sequence</h3>
              <p>
                A model trained on benign workflows measures how surprising the
                next action is in context.
              </p>
              <div className="micro-bars" aria-hidden="true">
                {[20, 28, 23, 41, 32, 58, 88, 50, 30, 24, 62, 98].map(
                  (height, i) => (
                    <i key={i} style={{ height: `${height}%` }} />
                  ),
                )}
              </div>
              <span className="diagram-label">
                Conceptual score visualization
              </span>
            </article>
            <span className="pipeline-arrow">
              <ArrowRight />
            </span>
            <article>
              <span className="step-number">03</span>
              <ShieldCheck size={22} />
              <h3>Apply the boundary</h3>
              <p>
                Hard rules and calibrated thresholds produce a decision with a
                reason you can inspect.
              </p>
              <div className="pipeline-status">
                <Status value="allow" />
                <Status value="hold" />
                <Status value="block" />
              </div>
            </article>
          </div>
        </section>
        <section className="playground section" id="playground">
          <div className="section-heading">
            <div>
              <div className="eyebrow">SAFE TO EXPLORE</div>
              <h2>
                See the moment
                <br />
                an action changes.
              </h2>
            </div>
            <p>
              Replay reviewed scenarios, compose typed actions, or inspect a
              local audit. Every score below comes from the guard service or
              your imported file.
            </p>
          </div>
          <div className="console">
            <div className="console-top">
              <span>
                <Terminal size={15} /> Guard playground
              </span>
              <span className="console-label">
                {source === "import"
                  ? "LOCAL AUDIT"
                  : source === "composed"
                    ? "TYPED ACTIONS"
                    : "CANARY SIMULATION"}
              </span>
            </div>
            <div
              className="console-tabs"
              role="tablist"
              aria-label="Playground input"
              onKeyDown={(event) => {
                const tabs = ["replay", "compose", "audit"] as const;
                const current = tabs.indexOf(panel);
                const next =
                  event.key === "ArrowRight"
                    ? tabs[(current + 1) % 3]
                    : event.key === "ArrowLeft"
                      ? tabs[(current + 2) % 3]
                      : event.key === "Home"
                        ? tabs[0]
                        : event.key === "End"
                          ? tabs[2]
                          : null;
                if (!next) return;
                event.preventDefault();
                setPanel(next);
                event.currentTarget
                  .querySelector<HTMLButtonElement>(`#${next}-tab`)
                  ?.focus();
              }}
            >
              {(["replay", "compose", "audit"] as const).map((tab) => (
                <button
                  key={tab}
                  id={`${tab}-tab`}
                  tabIndex={panel === tab ? 0 : -1}
                  aria-controls={`${tab}-panel`}
                  role="tab"
                  aria-selected={panel === tab}
                  className={panel === tab ? "active" : ""}
                  onClick={() => setPanel(tab)}
                >
                  {tab === "replay" ? (
                    <Play size={13} />
                  ) : tab === "compose" ? (
                    <Layers size={13} />
                  ) : (
                    <FileJson size={13} />
                  )}{" "}
                  {tab === "replay"
                    ? "Replay scenario"
                    : tab === "compose"
                      ? "Compose actions"
                      : "Import audit"}
                </button>
              ))}
            </div>
            {source !== "import" && model?.calibrated === false && (
              <div className="calibration-banner">
                <Pause size={12} />
                <span>
                  Preliminary model: calibration is pending. Cautious holds here
                  are not calibrated anomaly detections.
                </span>
              </div>
            )}
            <div className="console-body">
              <aside
                className="controls"
                id={`${panel}-panel`}
                role="tabpanel"
                aria-labelledby={`${panel}-tab`}
              >
                {panel === "replay" ? (
                  <>
                    <label htmlFor="scenario">SCENARIO</label>
                    {catalogError ? (
                      <div className="inline-error">
                        Scenarios unavailable. {catalogError}
                        <button
                          onClick={() => {
                            setCatalogError("");
                            request("/api/scenarios")
                              .then((data) => {
                                const list = Array.isArray(data)
                                  ? data
                                  : (data.scenarios ?? []);
                                setScenarios(list);
                                setScenario(list[0]?.id ?? "");
                              })
                              .catch((error) => setCatalogError(error.message));
                          }}
                        >
                          Retry scenarios
                        </button>
                      </div>
                    ) : (
                      <select
                        id="scenario"
                        value={scenario}
                        onChange={(e) => setScenario(e.target.value)}
                        disabled={!scenarios.length}
                      >
                        <option value="" disabled>
                          Choose a scenario
                        </option>
                        {scenarios.map((item) => (
                          <option value={item.id} key={item.id}>
                            {item.title}
                          </option>
                        ))}
                      </select>
                    )}
                    <div className="scenario-description">
                      {current?.family && (
                        <span className="family-tag">{current.family}</span>
                      )}
                      <p>
                        {current?.description ??
                          "Select a reviewed scenario to inspect the action chain."}
                      </p>
                    </div>
                  </>
                ) : panel === "compose" ? (
                  <>
                    <label htmlFor="verb">TYPED ACTION</label>
                    <div className="compose-fields">
                      <select
                        id="verb"
                        value={verb}
                        onChange={(e) => setVerb(e.target.value)}
                      >
                        {verbs.map((x) => (
                          <option key={x}>{x}</option>
                        ))}
                      </select>
                      <select
                        aria-label="Object class"
                        value={object}
                        onChange={(e) => setObject(e.target.value)}
                      >
                        {objects.map((x) => (
                          <option key={x}>{x}</option>
                        ))}
                      </select>
                      <select
                        aria-label="Channel"
                        value={channel}
                        onChange={(e) => setChannel(e.target.value)}
                      >
                        {channels.map((x) => (
                          <option key={x}>{x}</option>
                        ))}
                      </select>
                    </div>
                    <div className="flag-options">
                      {allFlags.map((flag) => (
                        <label key={flag}>
                          <input
                            type="checkbox"
                            checked={flags.includes(flag)}
                            onChange={(e) =>
                              setFlags(
                                e.target.checked
                                  ? [...flags, flag]
                                  : flags.filter((x) => x !== flag),
                              )
                            }
                          />
                          {flag}
                        </label>
                      ))}
                    </div>
                    <button
                      className="button secondary"
                      onClick={() =>
                        setComposed([
                          ...composed,
                          {
                            verb,
                            object,
                            channel,
                            flags: allFlags.filter((x) => flags.includes(x)),
                          },
                        ])
                      }
                      disabled={composed.length >= 24}
                    >
                      Add to sequence <ArrowRight size={14} />
                    </button>
                    <ol className="composed-list">
                      {composed.map((action, i) => (
                        <li key={i}>
                          <code>
                            {String(action.verb)} {String(action.object)}
                          </code>
                          <button
                            aria-label={`Remove action ${i + 1}`}
                            onClick={() =>
                              setComposed(composed.filter((_, j) => j !== i))
                            }
                          >
                            <X size={12} />
                          </button>
                        </li>
                      ))}
                    </ol>
                    <p className="control-note">
                      Closed vocabulary only. This composer never runs tools or
                      accepts secrets.
                    </p>
                  </>
                ) : (
                  <>
                    <div className="import-icon">
                      <Upload />
                    </div>
                    <h3>Your audit. Your browser.</h3>
                    <p className="control-note">
                      Import Sentinel JSONL to inspect existing decisions. The
                      file stays on this device and is never sent to the
                      service.
                    </p>
                    <input
                      ref={fileInput}
                      type="file"
                      accept=".jsonl,.ndjson,.json,text/plain,application/x-ndjson"
                      onChange={importAudit}
                      hidden
                    />
                    <button
                      className="button secondary"
                      onClick={() => fileInput.current?.click()}
                    >
                      <Upload size={14} /> Choose local audit
                    </button>
                    <p className="control-note">
                      Up to 5 MB · 10,000 records. Only classes, digests, scores
                      and decisions are displayed.
                    </p>
                  </>
                )}
                {panel !== "audit" && (
                  <>
                    <label className="mode-label">GUARD MODE</label>
                    <div
                      className="mode-toggle"
                      role="group"
                      aria-label="Guard mode"
                    >
                      {(["learn", "shadow", "enforce"] as const).map((x) => (
                        <button
                          key={x}
                          aria-pressed={mode === x}
                          className={mode === x ? "active" : ""}
                          onClick={() => setMode(x)}
                        >
                          {x}
                        </button>
                      ))}
                    </div>
                    <p className="control-note">
                      {mode === "enforce"
                        ? "Decisions are applied to the simulated action chain. Held and blocked actions do not execute."
                        : mode === "shadow"
                          ? "Observe what the guard would decide. Simulated actions remain allowed."
                          : "Record the typed sequence without model or policy decisions."}
                    </p>
                    <button
                      className="button primary run"
                      onClick={run}
                      disabled={
                        pending ||
                        (panel === "replay" ? !scenario : !composed.length)
                      }
                    >
                      {pending ? (
                        <span className="spinner" />
                      ) : (
                        <Play size={14} />
                      )}{" "}
                      {pending
                        ? "Evaluating…"
                        : panel === "compose"
                          ? "Check sequence"
                          : "Run simulation"}
                      <ArrowRight size={14} />
                    </button>
                  </>
                )}
              </aside>
              <div className="trace-area" aria-live="polite">
                {error && (
                  <div className="error-message" role="alert">
                    {error}
                  </div>
                )}
                {!report ? (
                  <div className="trace-empty">
                    <div className="empty-rings">
                      <ShieldCheck />
                    </div>
                    <span className="mono-label">WAITING FOR AN ACTION</span>
                    <h3>A decision should leave a trail.</h3>
                    <p>
                      Run a scenario to see the sequence, the signal, and the
                      exact reason behind every boundary.
                    </p>
                    <div className="empty-legend">
                      <Status value="allow" />
                      <Status value="hold" />
                      <Status value="block" />
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="trace-summary">
                      <div>
                        <strong>{events.length}</strong>
                        <span>actions</span>
                      </div>
                      <div>
                        <strong className="allow-text">{counts.allow}</strong>
                        <span>allowed</span>
                      </div>
                      <div>
                        <strong className="hold-text">{counts.hold}</strong>
                        <span>held</span>
                      </div>
                      <div>
                        <strong className="block-text">{counts.block}</strong>
                        <span>blocked</span>
                      </div>
                      <button
                        title="Download redacted audit"
                        aria-label="Download redacted audit"
                        onClick={download}
                      >
                        <Download size={16} />
                      </button>
                    </div>
                    {events.length > 100 && (
                      <div className="trace-pagination">
                        <button
                          disabled={pageStart === 0}
                          onClick={() =>
                            setSelected(Math.max(0, pageStart - 100))
                          }
                        >
                          Previous
                        </button>
                        <span>
                          {pageStart + 1}–
                          {Math.min(pageStart + 100, events.length)} of{" "}
                          {events.length} records
                        </span>
                        <button
                          disabled={pageStart + 100 >= events.length}
                          onClick={() => setSelected(pageStart + 100)}
                        >
                          Next
                        </button>
                      </div>
                    )}
                    <div className="trace-table" aria-label="Action trace">
                      {events
                        .slice(pageStart, pageStart + 100)
                        .map((event, pageIndex) => {
                          const index = pageStart + pageIndex;
                          return (
                            <button
                              key={`${event.id}-${index}`}
                              className={`trace-row ${selected === index ? "selected" : ""}`}
                              onClick={() => setSelected(index)}
                              aria-label={`Action ${index + 1}: ${event.pebble}, ${event.decision}. Inspect decision`}
                            >
                              <span className="trace-seq">
                                {String(index + 1).padStart(2, "0")}
                              </span>
                              <span className="trace-action">
                                <code>{event.pebble}</code>
                                <span>
                                  {event.tool}
                                  {event.tainted
                                    ? " · after untrusted input"
                                    : ""}
                                  {event.executed === false
                                    ? " · not executed"
                                    : ""}
                                </span>
                              </span>
                              <span className="trace-score">
                                {event.surprise_bits === null
                                  ? "—"
                                  : event.surprise_bits.toFixed(2)}
                                <small>bits</small>
                              </span>
                              <Status value={event.decision} />
                            </button>
                          );
                        })}
                    </div>
                    {active && (
                      <div className="decision-detail">
                        <div className="detail-heading">
                          <Eye size={14} />
                          <span>DECISION EXPLAINED</span>
                          <Status value={active.decision} />
                        </div>
                        <p>{active.reason}</p>
                        {active.would_have &&
                          active.would_have !== active.decision && (
                            <div className="shadow-note">
                              This mode allowed the action. In enforce mode:{" "}
                              <strong>{active.would_have}</strong>.
                            </div>
                          )}
                        <dl>
                          {active.effect && (
                            <div>
                              <dt>Execution</dt>
                              <dd>{active.effect}</dd>
                            </div>
                          )}
                          <div>
                            <dt>Policy rules</dt>
                            <dd>
                              {active.rules.length
                                ? active.rules.map((rule) => (
                                    <code key={rule}>{rule}</code>
                                  ))
                                : "No hard rule fired"}
                            </dd>
                          </div>
                          <div>
                            <dt>Model signal</dt>
                            <dd>
                              {active.surprise_bits === null
                                ? "Not scored in this record"
                                : `${active.surprise_bits.toFixed(3)} bits of maximum token surprise`}
                            </dd>
                          </div>
                          {active.args_digest && (
                            <div>
                              <dt>Arguments</dt>
                              <dd>
                                <code className="digest">
                                  {active.args_digest}
                                </code>
                              </dd>
                            </div>
                          )}
                        </dl>
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
            <div className="console-footer">
              <LockKeyhole size={11} />
              {source === "import"
                ? "Imported records are processed locally. The guard has not re-scored this file."
                : "Reviewed synthetic actions only. This website is a demonstration, not protection for your own agent."}
            </div>
          </div>
        </section>
        <section className="evidence section" id="evidence">
          <div className="section-heading">
            <div>
              <div className="eyebrow">SHOW THE WORK</div>
              <h2>
                Evidence over
                <br />
                confidence theater.
              </h2>
            </div>
            <p>
              Open weights are only part of the story. The data, evaluation
              protocol, missed cases, and implementation boundaries belong in
              the open too.
            </p>
          </div>
          {model && (
            <div className="model-provenance">
              <span>
                <Fingerprint size={14} />{" "}
                {Number(model.parameters).toLocaleString()} parameters
              </span>
              <span>Trained in {String(model.trained_in ?? "Pebble")}</span>
              <span>{String(model.inference_backend ?? "CPU inference")}</span>
              <span
                className={`calibration-tag ${model.calibrated === true ? "ready" : "pending"}`}
              >
                {model.calibrated === true
                  ? "Empirically calibrated"
                  : "Calibration pending · cautious holds"}
              </span>
              <a
                href={`${repo}/blob/main/MODEL_CARD.md`}
                target="_blank"
                rel="noreferrer"
              >
                Model provenance <ArrowUpRight size={12} />
              </a>
            </div>
          )}
          <div className="evidence-grid">
            <article className="evidence-results">
              <div className="evidence-header">
                <span>MEASURED EVALUATION</span>
                <a
                  href={`${repo}/tree/main/results`}
                  target="_blank"
                  rel="noreferrer"
                >
                  View artifacts <ArrowUpRight size={13} />
                </a>
              </div>
              {evaluation ? (
                <Evaluation data={evaluation} />
              ) : (
                <div className="evaluation-pending">
                  <Fingerprint size={24} />
                  <p>
                    {evaluationError
                      ? "Evaluation could not be loaded. The committed artifacts remain available."
                      : "Loading measured evaluation…"}
                  </p>
                  {evaluationError && (
                    <button
                      className="button secondary"
                      onClick={() => {
                        setEvaluationError("");
                        request("/api/evaluate")
                          .then(setEvaluation)
                          .catch((error) => setEvaluationError(error.message));
                      }}
                    >
                      Retry evaluation
                    </button>
                  )}
                </div>
              )}
            </article>
            <article className="limits">
              <span className="mono-label">THE BOUNDARY OF THE BOUNDARY</span>
              <h3>A guard, not a guarantee.</h3>
              <p>
                Synthetic workflows are a starting point. Mimicry can evade
                anomaly scores. Tool calls that bypass the adapter cannot be
                protected.
              </p>
              <p>
                Use human approvals and operating-system isolation alongside
                Sentinel. Start in shadow mode and evaluate your own workflow.
              </p>
              <a
                href={`${repo}/blob/main/THREAT_MODEL.md`}
                target="_blank"
                rel="noreferrer"
              >
                Read the threat model <ArrowUpRight size={14} />
              </a>
            </article>
          </div>
        </section>
        <section className="install section" id="open-source">
          <div>
            <div className="eyebrow">BUILT TO BE OPENED</div>
            <h2>
              Take the guard
              <br />
              with you.
            </h2>
            <p>
              Code, authored data, model artifacts, and documentation are open
              source under MIT. Run locally, inspect the decisions, and help
              build the next adapter.
            </p>
            <div className="install-actions">
              <a
                className="button primary"
                href={repo}
                target="_blank"
                rel="noreferrer"
              >
                <Github size={16} /> Explore the repository{" "}
                <ArrowUpRight size={14} />
              </a>
              <a
                className="text-link"
                href={`${repo}/blob/main/CONTRIBUTING.md`}
                target="_blank"
                rel="noreferrer"
              >
                Make a contribution <ArrowRight size={14} />
              </a>
            </div>
          </div>
          <div className="install-terminal">
            <div>
              <span className="terminal-dot" />
              <span className="terminal-dot" />
              <span className="terminal-dot" />
              <span>local / reviewed simulation</span>
            </div>
            <pre>
              <span>$ </span>git clone {repo}.git
              <br />
              <span>$ </span>cd pebble-sentinel
              <br />
              <span>$ </span>python -m pip install -e .<br />
              <span>$ </span>
              {sampleCommand}
            </pre>
            <button onClick={copyCommand}>
              {copied ? <Check size={13} /> : <Terminal size={13} />}{" "}
              {copied ? "Copied" : "Copy simulation command"}
            </button>
            <p>
              Follow the README for model setup and harness installation. The
              hosted demo does not install a guard on your device.
            </p>
          </div>
        </section>
      </main>
      <footer>
        <a className="brand" href="#">
          <Stone small /> pebble / SENTINEL
        </a>
        <span>A second instinct. An explicit boundary.</span>
        <div>
          <button
            className="motion-toggle"
            aria-pressed={reducedMotion}
            onClick={() => setReducedMotion((x) => !x)}
          >
            {reducedMotion ? "Motion off" : "Reduce motion"}
          </button>
          <a
            href={`${repo}/blob/main/LICENSE`}
            target="_blank"
            rel="noreferrer"
          >
            MIT license
          </a>
          <a
            href={`${repo}/blob/main/MODEL_CARD.md`}
            target="_blank"
            rel="noreferrer"
          >
            Model card
          </a>
          <a href={`${repo}/blob/main/DATA_CARD.md`} target="_blank" rel="noreferrer">Data card</a>
          <a href={`${repo}/blob/main/web/THIRD_PARTY_NOTICES.md`} target="_blank" rel="noreferrer">Third-party notices</a>
          <a
            href="https://github.com/YashAnand69/pebble"
            target="_blank"
            rel="noreferrer"
          >
            Pebble language <ArrowUpRight size={11} />
          </a>
        </div>
      </footer>
    </>
  );
}
export default App;
