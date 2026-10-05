> Planning document, updated for the requested build: MIT applies to all original code, data, weights and documentation. A full accessible animated web interface and local audit viewer are in scope. Planned metrics and experiments are targets until measured. Runtime skill instructions below describe the product after installation; they do not assert that it is currently installed.

# ARCHITECTURE

## 1. Overview

```
Agent harness (Hermes)
        | tool call
        v
   Adapter --> Encoder --> Pebble sentence + taint
                                  |
                    +-------------+-------------+
                    v                           v
               Hard rules                Scorer (model)
                    |                           |
                    +-------------+-------------+
                                  v
                          Decision engine
                      allow | hold | block
                                  |
                         Audit log (JSONL)
```

## 2. Components

| Component | Job | Path |
|-----------|-----|------|
| Adapter | Receives tool calls from the harness, returns a decision | `sentinel/adapters/` |
| Encoder | Tool call to PAL sentence (PEBBLE_SPEC.md) | `sentinel/encoder/` |
| Taint tracker | Sets and holds the taint flag per session | `sentinel/encoder/` |
| Scorer | Per-action surprise from the model | `sentinel/scorer/` |
| Rules | YAML hard rules over action, history and taint | `sentinel/policy/` |
| Decision engine | Combines rules and surprise | `sentinel/policy/` |
| Audit log | Append-only JSONL | `sentinel/audit/` |
| CLI | status, review, explain, mode, train, eval, simulate | `sentinel/cli/` |
| Generator | Benign traces and attack scenarios | `gen/` |
| Trainer | Seeded training, exports weights and tokenizer | `train/` |
| Evaluator | Metrics and latency | `eval/` |
| Simulator | Canary secrets, localhost sink, scenario replay | `sentinel/cli/` |

## 3. Scoring

Surprise of an action is the largest token negative log-probability (bits) inside that action, given the last 256 tokens of session history.

Pseudocode

```
history = last 256 tokens of the session
for each token in the new action:
    nll = -log2 P(token | history)
    history.append(token)
surprise = max(nll over the action's tokens)
```

Working code

```python
import math


def action_surprise(token_probabilities):
    return max(-math.log2(p) for p in token_probabilities)
```

## 4. Decisions

Pseudocode

```
if any rule says deny: block
else if surprise >= block_threshold: block
else if surprise >= hold_threshold or any rule says hold: hold
else: allow
in learn or shadow mode: always allow, log the would-have decision
```

Working code

```python
def decide(surprise, rule_verdicts, hold_threshold, block_threshold):
    if "deny" in rule_verdicts:
        return "block"
    if surprise >= block_threshold:
        return "block"
    if surprise >= hold_threshold or "hold" in rule_verdicts:
        return "hold"
    return "allow"


def apply_mode(decision, mode):
    if mode == "enforce":
        return decision
    return "allow"
```

## 5. Threshold calibration

Thresholds come from benign validation scores only.

Pseudocode

```
sort benign scores
threshold = score at position (1 - target_false_alarm_rate) of the sorted list
```

Working code

```python
def calibrate(benign_scores, false_alarm_rate=0.001):
    ordered = sorted(benign_scores)
    index = min(len(ordered) - 1, int(len(ordered) * (1 - false_alarm_rate)))
    return ordered[index]
```

Defaults: hold at 0.1 percent per-action false alarms, block at 0.01 percent. Evaluation also reports 1 percent.

## 6. Default rule pack

| Rule ID | Verdict | Condition |
|---------|---------|-----------|
| deny-guard-tamper | deny | write, edit or delete on `guard-config`, always |
| deny-secret-read-tainted | deny | read on `secret-store` while tainted |
| deny-secret-then-send | deny | send on `net-unknown` after any read on `secret-store` in the session |
| deny-persistence-tainted | deny | write or edit on `shell-rc`, `cron-entry` or `agent-config` while tainted |
| hold-remote-code | hold | exec on `downloaded-code`, or flag `remote-code` |
| hold-sudo | hold | any action with `sudo` |
| hold-new-host-send | hold | send with `new-host` |

## 7. Modes and failure behaviour

| Mode | Scores | Rules | Acts on decision | Logs |
|------|--------|-------|------------------|------|
| learn | no | no | no | trace only |
| shadow | yes | yes | no | decision and would-have |
| enforce | yes | yes | yes | decision |

Internal error in enforce mode: hold. In learn and shadow: allow and log the error.

## 8. Audit log

File: `~/.sentinel/audit.jsonl`, one JSON object per line. Raw arguments are never stored, only a digest.

Example

```json
{"id":"a-000123","ts":"2026-10-05T10:15:30Z","session":"s-01","seq":42,"tool":"terminal","pebble":"read secret-store via shell tainted .","args_digest":"sha256:ab12cd34","surprise_bits":11.7,"rules":["deny-secret-read-tainted"],"decision":"block","mode":"enforce","reason":"rule"}
```

| Field | Meaning |
|-------|---------|
| id | Unique, increasing |
| ts | UTC time |
| session, seq | Session id and action number |
| tool | Harness tool name |
| pebble | The action sentence |
| args_digest | Hash of the raw arguments |
| surprise_bits | Surprise (null in learn mode) |
| rules | Rule ids that fired |
| decision | allow, hold or block |
| mode | learn, shadow or enforce |
| reason | rule, surprise, error or mode |

A UI, if built later, only needs to tail this file.

## 9. Adapter contract

Input: tool name, arguments, session id. Output: allow, hold or block with a short message.

| Result | What the harness does |
|--------|-----------------------|
| allow | Runs the call |
| block | Skips the call and returns the message to the agent |
| hold | Asks the human, then runs or skips |

Hermes: register a `pre_tool_call` plugin hook. Hermes documents plugin hooks that can block a call; confirm the plugin location, enabling steps and argument names on the installed version in M0. Avoid patching Hermes internals.

## 10. Model

| Setting | Planned value |
|---------|---------------|
| Type | Decoder-only transformer |
| Layers | 5 to 6 |
| Width | 128 to 160 |
| Heads | 4 |
| Context | 256 tokens |
| Vocabulary | Word-level, under 150 (about 50 in v0) |
| Parameters | about 1.2 to 1.6M (estimate: 12 x width squared x layers, plus embeddings) |

The parameter sweep in EVAL_PLAN.md checks whether this size is adequate.

## 11. Files and protection

```
~/.sentinel/config.yaml
~/.sentinel/rules.yaml
~/.sentinel/model/
~/.sentinel/audit.jsonl
```

The agent runs as the same user, so file permissions alone cannot stop it. Defences: the `deny-guard-tamper` rule, read-only file permissions for the model and rules, and running the harness in a container or separate user where possible.

## 12. Performance budget (targets, to be measured)

| Stage | Budget |
|-------|--------|
| Encoder and taint | under 0.5 ms |
| Scorer | under 4 ms |
| Rules and decision | under 0.5 ms |
| Total p95 | under 5 ms on a laptop CPU |

## 13. Deployment

- Local: install the plugin next to Hermes on the developer machine.
- Cloud: run Hermes and Sentinel on a droplet (P2).
- Agent brain: DigitalOcean serverless inference with an open-weight model, or a local Ollama model.
