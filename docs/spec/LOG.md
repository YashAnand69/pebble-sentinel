> Planning document, updated for the requested build: MIT applies to all original code, data, weights and documentation. A full accessible animated web interface and local audit viewer are in scope. Planned metrics and experiments are targets until measured. Runtime skill instructions below describe the product after installation; they do not assert that it is currently installed.

# LOG

Project and decision log for Pebble Sentinel. This is the build log, not the runtime audit log (see ARCHITECTURE.md, Audit log). Newest entries go at the bottom of each section. Keep entries short and dated.

Entry format: `YYYY-MM-DD HH:MM | author | what happened | why it matters | next`

## Decision log

| ID | Date | Decision | Why |
|----|------|----------|-----|
| D-001 | 2026-10-05 | Build Sentinel, a runtime guard for AI agents; drop Beacon | Prize card is "Best Open-Source AI Project" (agent skills, harnesses, applications). Winners are chosen by the host from demos. Hack Days run 3 to 12 hours. Judgment scores on a rubric weighted for those facts: Sentinel 92, Forge 80, static skill scanner 78, Beacon 66. These are judgments, not measurements |
| D-002 | 2026-10-05 | MIT for code, weights, data; MIT for spec and docs | Prize requires an open-source licence; OSI's open-source AI definition asks for data information, code and parameters under OSI-approved terms. Not legal advice |
| D-003 | 2026-10-05 | Model of 1 to 2M parameters, word-level vocab near 150, context 256, retrained on action traces | Closed vocabulary and regular behaviour need little capacity; speed matters because every action is checked. Existing Pebble text weights are not reused (different corpus); the training pipeline is |
| D-004 | 2026-10-05 | Train on benign traces only | Attacks are unknown by definition; attack families are for rules and held-out evaluation |
| D-005 | 2026-10-05 | Decisions allow, hold, block; modes learn, shadow, enforce | Shadow mode lets users trust it before enforcing |
| D-006 | 2026-10-05 | Internal error in enforce mode means hold | Fail safe |
| D-007 | 2026-10-05 | UI excluded from the document set; terminal is the minimum demo surface; audit log schema is the UI contract | Requested scope |
| D-008 | 2026-10-05 | Demos use canary secrets and a localhost sink only | Safety and judging optics |

## Research notes

| Date | Finding | Source |
|------|---------|--------|
| 2026-10-05 | Hack Days are one-day events running 3 to 12 hours; host picks winners from challenge rules and demos | https://hacktoberfest.com/questions/ , https://dev.to/alexgeorgiev17/hacktoberfest-2026-changed-the-rules-heres-how-to-actually-join-in-this-october-5 |
| 2026-10-05 | Snyk: about 36 percent of 3,984 scanned agent skills had security flaws | https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ |
| 2026-10-05 | Antiy: 1,184 malicious skill packages in the OpenClaw marketplace by 5 Feb 2026 (other sources give different counts) | https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/ |
| 2026-10-05 | Hermes Agent: MIT, model-agnostic harness; plugin pre_tool_call hooks can block tool calls; built-in dangerous-command approval uses about 47 hardcoded patterns | https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks , https://hermes-agent.nousresearch.com/docs/user-guide/security |
| 2026-10-05 | DeepLog: next-event prediction over normal sequences for anomaly detection is an established technique | https://acmccs.github.io/papers/p1285-duA.pdf |
| 2026-10-05 | A public log-anomaly experiment saw F1 swing from 0.13 to 0.67 from threshold tuning alone | https://github.com/ajaykumar76/hdfs-log-anomaly-detection |
| 2026-10-05 | LlamaFirewall paper: LLM-based alignment checks add latency and can themselves be targeted by injection | https://arxiv.org/pdf/2505.03574 |
| 2026-10-05 | DigitalOcean serverless inference lists open-weight models including gpt-oss and Gemma | https://docs.digitalocean.com/products/inference/details/models/ |

## Assumptions

- A1: Hack Day lasts about 10 hours. Plan scales down by the cut order in PRD.md section 10.
- A2: Hermes pre_tool_call hook behaves as documented. Verify in M0.
- A3: Synthetic benign traces are a reasonable first baseline for normal behaviour.
- A4: Team can train a 1 to 2M parameter model in minutes on a laptop GPU.

## Open questions

- Q1: Submission cutoff and exact judging rubric (ask the organizers).
- Q2: Team size and milestone owners.
- Q3: Installed Hermes version.
- Q4: Agent brain: DigitalOcean serverless or local Ollama.
- Q5: Which existing Pebble tokens are reused in the action language.

## Build log

| Date | Author | Entry |
|------|--------|-------|
| 2026-10-05 | team | Direction chosen (D-001). Documents drafted: PRD, ESSENTIALS, SKILL, LOG, README, CONTRIBUTING, THREAT_MODEL, SECURITY, PEBBLE_SPEC, ARCHITECTURE, EVAL_PLAN, MODEL_CARD, DATA_CARD, DEMO_SCRIPT, PR template. Next: M0 |

## Experiments

| ID | Date | Config | Seed | Result | Notes |
|----|------|--------|------|--------|-------|
| E-001 | | | | | |

## AI assistance disclosure

Planning, research and the first drafts of these documents were produced with AI assistance (Claude) and reviewed by the team. Contributors must disclose AI assistance in pull requests (see CONTRIBUTING.md).
