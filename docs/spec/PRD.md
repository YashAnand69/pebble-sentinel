> Planning document, updated for the requested build: MIT applies to all original code, data, weights and documentation. A full accessible animated web interface and local audit viewer are in scope. Planned metrics and experiments are targets until measured. Runtime skill instructions below describe the product after installation; they do not assert that it is currently installed.

# PRD: Pebble Sentinel

Version 0.1 | 2026-10-05 | Status: draft for the Hacktoberfest Hack Day

## 1. Summary

Pebble Sentinel is an open-source runtime guard for AI agents. It turns every agent action (shell command, file access, network call, skill install) into a short sentence in Pebble Action Language, scores how unusual that action is with a small from-scratch model (about 1 to 2 million parameters), applies hard rules, and decides to allow, hold or block the action before it runs.

One-line pitch: a seatbelt for AI agents, built on a model we trained ourselves, fully open source.

## 2. Problem

Agents act with the user's credentials. Anything they read can try to steer them (prompt injection), and anything they install can misbehave (malicious skills).

- Snyk scanned 3,984 agent skills in February 2026 and found security flaws in about 36 percent of them.
- Antiy counted 1,184 malicious skill packages in the OpenClaw skill marketplace by 5 February 2026.
- Researchers showed indirect prompt injection can backdoor an agent host.

Existing defences have gaps:

- Pattern-based approval (for example the roughly 47 built-in dangerous-command patterns in Hermes Agent) only matches known-bad single commands.
- Static skill scanners inspect files before install, not behaviour at runtime.
- LLM-based guards read untrusted text, so the guard itself can be targeted by injection, and they add cost and latency.

Sentinel's angle: watch behaviour (sequences of typed actions), not text. The guard never reads web or file content, only deterministic action tokens from a closed vocabulary.

Sources: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ , https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/ , https://arxiv.org/pdf/2505.03574

## 3. Users

| ID | User | Need |
|----|------|------|
| U1 | Agent user running Hermes locally or on a cloud droplet | Stop destructive or exfiltrating actions without reading every approval prompt |
| U2 | Hack Day judge | See an attack blocked live in 90 seconds and understand why |
| U3 | Contributor | Add an adapter, scenario or workflow as a data file plus a test |

## 4. Goals and non-goals

Goals

- G1: Block injection-driven and malicious-skill action chains at a low false-alarm rate.
- G2: Add under 5 ms p95 per action on a laptop CPU (target; measured and reported).
- G3: Release everything: generator, data, code, weights, cards.
- G4: Every hold or block is explainable: the Pebble sentence, the signal, the rule.
- G5: Contributions are cheap to review: data file plus passing test.

Non-goals

- Not a sandbox, antivirus or OS-level isolation.
- Not a replacement for human approval prompts or container isolation.
- Not a text or content filter.
- No cloud service, no telemetry, no accounts.
- No claim of complete protection or production certification.
- UI and dashboard are out of scope for this document set. The audit log schema in ARCHITECTURE.md is the contract a UI can consume.

## 5. Scope tiers

| Tier | Items |
|------|-------|
| P0 (must ship) | Encoder, taint tracking, scorer, hard rules, decision engine, three modes, Hermes plugin adapter, audit log, CLI, trace generator, training pipeline, eval harness, simulation sandbox, SKILL.md, all documents |
| P1 (should) | MCP proxy adapter, hash-chained audit log, train on a user's own traces, extra attack families |
| P2 (could) | DigitalOcean one-click deploy recipe, adapters for other harnesses |

## 6. Functional requirements

| ID | Requirement | Acceptance |
|----|-------------|------------|
| FR-1 | Encoder maps each tool call to one Pebble action sentence, deterministically | Same input gives same output; every recorded fixture maps; unknown inputs map to an unknown-* class and never raise |
| FR-2 | Taint tracking flags actions taken after the agent ingested untrusted content (web, MCP output, files outside the project) | Flag appears on every later action in the session until a human clears it; unit tested |
| FR-3 | Scorer returns per-action surprise: the maximum token negative log-probability (bits) within the action, given up to 256 tokens of session history | Matches a reference implementation on fixtures; runs on CPU |
| FR-4 | Hard rules in YAML over the current action, short history and taint, with actions allow, hold, deny | Default rule pack ships; each rule has a positive and a negative test |
| FR-5 | Decision engine combines rules and surprise into allow, hold or block | Rule deny always blocks; thresholds come from calibration; see ARCHITECTURE.md |
| FR-6 | Modes: learn (log only), shadow (score and log, never block), enforce | Mode is human-set; switching is logged |
| FR-7 | Fail-safe: internal error in enforce mode results in hold | Fault-injection test passes |
| FR-8 | Append-only JSONL audit log with secrets redacted to class and digest | Schema validated in tests; no raw secret strings in logs |
| FR-9 | Hermes adapter via pre_tool_call plugin hook | A blocked call returns a clear message to the agent; a held call asks the human |
| FR-10 | CLI: status, review, explain, mode, train, eval, simulate | Each command has help text and a test |
| FR-11 | Trace generator with benign workflow templates and at least five attack families | Seeded and deterministic; attack families live in data files |
| FR-12 | Training pipeline, one command, seeded, exports weights and tokenizer | Reproduces within noise across three seeds |
| FR-13 | Eval harness outputs metrics table (JSON and markdown) and latency report | Matches EVAL_PLAN.md |
| FR-14 | Simulation sandbox using canary secrets and a localhost sink | No real credentials or external hosts are ever touched |
| FR-15 | SKILL.md lets an agent explain and review Sentinel but never change it | Skill contains the human-only rules; verified by reading |

## 7. Non-functional requirements

- Latency: p95 under 5 ms per action for encoder, scorer and policy together, batch size 1, CPU only. This is a target. Report the measured value.
- Footprint: model file under 20 MB; no GPU required at runtime.
- Privacy: all processing local; no network calls from Sentinel.
- Reproducibility: seeds and configs committed; generator deterministic.
- Licensing: MIT for code, weights and generated data; MIT for the Pebble spec and docs; dependency licences checked.
- Safety: demos use canary secrets and localhost only.
- Self-protection: Sentinel config and plugin paths are denied to the agent by a hard rule.

## 8. Success metrics

Hackathon

- Public GitHub repo with an OSI licence, a README and a runnable demo.
- Live attack blocked on stage, plus a judge-driven attempt.
- Results table with baselines, including failures.

Technical (reported, not promised)

- Sentinel beats the pattern-only baseline on held-out attack families at equal false-alarm rate.
- Detection before the harmful final action, per family.
- False alarms per 1,000 benign actions at each operating point.
- p50 and p95 latency.

If a trigram baseline matches the transformer, say so. The pitch then becomes: a tiny model is enough, and here is the fully open pipeline.

## 9. Prize criteria mapping

| Card criterion | How Sentinel meets it |
|----------------|-----------------------|
| Build with open-source or open-weight AI | From-scratch open model; open-weight agent brain (DigitalOcean serverless inference or local Ollama) |
| Agent skills | SKILL.md |
| Model harnesses | Hermes plugin adapter |
| Applications | CLI plus simulation sandbox (UI excluded from this set) |
| Publish on GitHub with an open-source licence | MIT, public repo |

## 10. Milestones (assumes about 10 hours; the Hack Day may be 3 to 12)

| Milestone | Window | Exit criteria |
|-----------|--------|---------------|
| M0 | T+0:00 to 0:45 | Repo public with licence and README; Hermes hook proven to block one tool call (else fallback loop chosen) |
| M1 | T+0:45 to 2:45 | PEBBLE_SPEC v0 implemented; encoder passes fixtures |
| M2 | T+2:45 to 4:45 | Generator produces traces; first model trained |
| M3 | T+4:45 to 6:45 | Scorer, rules, decisions wired into the adapter |
| M4 | T+6:45 to 8:45 | Eval table; simulate runs attacks end to end in terminal |
| M5 | T+8:45 to 10:00 | Cards, README results, fallback video, final checklist |

Cut order if time runs short: DigitalOcean deploy, MCP proxy, train on own traces, extra families, extra baselines.

## 11. Risks

| ID | Risk | Mitigation |
|----|------|------------|
| R1 | Hermes hook API differs from docs | Prove in M0; adapter interface keeps the core independent; fallback agent loop |
| R2 | Detector is weak or threshold-sensitive | Report operating curves; hard rules are the backbone |
| R3 | n-gram baseline matches the transformer | Reframe honestly (section 8) |
| R4 | Synthetic benign traces are unrealistic | Disclose in DATA_CARD; P1 learn mode on real sessions |
| R5 | Live demo fails | Deterministic replay via simulate; fallback video |
| R6 | Judges see it as only rules | Show a held-out family that rules miss and the model catches, only if the eval confirms it |
| R7 | Guard evaded by agent self-modification | Self-protection rule; recommend OS-level file permissions |
| R8 | Time overrun | Cut order in section 10 |

## 12. Open questions

- Submission cutoff and Hack Day length.
- Team size and who owns which milestone.
- Installed Hermes version and plugin loading behaviour.
- Which open-weight model acts as the agent brain.
- Which tokens from the existing Pebble lexicon to reuse in the action language.
