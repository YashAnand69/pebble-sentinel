> Planning document, updated for the requested build: MIT applies to all original code, data, weights and documentation. A full accessible animated web interface and local audit viewer are in scope. Planned metrics and experiments are targets until measured. Runtime skill instructions below describe the product after installation; they do not assert that it is currently installed.

# ESSENTIALS: read this first

Context file for humans and AI coding assistants. Copy or link it into GEMINI.md, CLAUDE.md, AGENTS.md or .antigravity/rules. Keep it short and current.

## What this is

Pebble Sentinel: an open-source runtime guard for AI agents. Every agent action becomes a Pebble sentence; a small from-scratch model (about 1 to 2M parameters) scores how unusual it is; hard rules and thresholds decide allow, hold or block.

Event: Hacktoberfest Hack Day, prize "Best Open-Source AI Project" (MLH with DigitalOcean). Requirement from the card: open-source or open-weight AI, published on GitHub with an open-source licence.

Date started: 2026-10-05. Status: pre-build, documents drafted.

## Locked decisions

| ID | Decision |
|----|----------|
| D-001 | Project is Sentinel, not Beacon |
| D-002 | MIT for code, weights, data; MIT for Pebble spec and docs |
| D-003 | Model: decoder-only transformer, 1 to 2M parameters, word-level vocab near 150, context 256 |
| D-004 | Train on benign traces only; attacks are for rules and evaluation |
| D-005 | Decisions are allow, hold, block; modes are learn, shadow, enforce |
| D-006 | Internal error in enforce mode means hold |
| D-007 | UI is out of scope; terminal output is the minimum demo surface |
| D-008 | Demos use canary secrets and a localhost sink only |

Full rationale is in LOG.md.

## Glossary

- Agent: an AI system that acts (files, shell, web), not only chats.
- Tool call: one action the agent asks the harness to perform.
- Prompt injection: hidden instructions in content the agent reads.
- Pebble action sentence: deterministic text form of a tool call; see PEBBLE_SPEC.md.
- Surprise: maximum token negative log-probability, in bits, within one action.
- Taint: flag on actions taken after untrusted content was read.
- Hold: pause and ask the human. Block: refuse and tell the agent.

## Repo map

```
pebble-sentinel/
  README.md  PRD.md  ESSENTIALS.md  SKILL.md  LOG.md
  ARCHITECTURE.md  PEBBLE_SPEC.md  THREAT_MODEL.md  EVAL_PLAN.md
  MODEL_CARD.md  DATA_CARD.md  DEMO_SCRIPT.md
  CONTRIBUTING.md  SECURITY.md  LICENSE
  sentinel/  encoder/ scorer/ policy/ audit/ adapters/ cli/
  gen/  train/  eval/  scenarios/  workflows/  tests/
  .github/PULL_REQUEST_TEMPLATE.md
```

## CLI (planned)

```
sentinel status
sentinel review
sentinel explain <id>
sentinel mode learn|shadow|enforce
sentinel train --traces <dir>
sentinel eval
sentinel simulate <scenario>
```

## Conventions

- Python 3.10 or newer; tests with pytest; format with ruff.
- No comments in code. Names carry the meaning. Explain in docs instead.
- In docs, show pseudocode next to working code.
- Scenarios and workflows are data files with a test, never hard-coded.
- Every change that touches decisions needs a test.

## Never

- Never write or publish real malware or malicious skills.
- Never use real credentials, real secrets or external attacker hosts in any demo or test.
- Never let the agent edit Sentinel config, rules, thresholds, plugin files or the audit log.
- Never weaken a rule or threshold to make a demo pass.
- Never commit secrets, model checkpoints with private traces, or personal data.
- Never claim complete protection.

## Definition of done

- [ ] Public GitHub repo, MIT LICENSE added with GitHub's licence picker
- [ ] README with results table and honest limits
- [ ] `sentinel simulate` runs at least five attack families end to end
- [ ] Eval table with baselines and latency
- [ ] MODEL_CARD and DATA_CARD filled with real numbers
- [ ] 90-second fallback video recorded
- [ ] AI assistance disclosed in README and PR descriptions

## Pitch lines

10 seconds: Sentinel is a seatbelt for AI agents, built on a tiny model we trained ourselves, fully open source.

30 seconds: Agents act with your credentials, and one bad web page or skill can hijack them. Sentinel watches what the agent does, not what it reads, so it cannot be talked out of its job. It learns your agent's normal behaviour and blocks the strange.

## Agent brain options

- DigitalOcean serverless inference with an open-weight model.
- Local Ollama with a 7B coder model on a laptop GPU.
- Hermes Agent (MIT) as the harness; install per its README and verify the plugin hook first.
