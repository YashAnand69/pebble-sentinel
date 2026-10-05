# Pebble Sentinel

A pre-execution guard for AI agents, built around a small Transformer trained **in Pebble**. Sentinel converts tool effects into typed actions, combines anomaly scores with explicit rules, and asks for approval or blocks risky calls before execution.

The useful problem: an agent can mistake instructions inside a web page, skill or tool response for permission to read credentials, send them away or change its own guard. Sentinel puts a separate decision point between those instructions and a tool's effects.

## Try it

**[Open the live laboratory](https://pebble-sentinel.vercel.app/)** · [Two-minute demo script](docs/DEMO_SCRIPT.md)

The web laboratory includes seven reviewed scenarios, learn/shadow/enforce modes, a typed-action composer, private browser-side audit inspection and the actual evaluation results. It is a simulation; it does not protect your computer or execute visitor commands. The interface includes scroll-linked 3D artwork, responsive layouts and reduced-motion controls.

```sh
git clone https://github.com/YashAnand69/pebble-sentinel.git
cd pebble-sentinel
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/sentinel status
.venv/bin/sentinel simulate injection-exfiltration
.venv/bin/sentinel simulate compound-exfiltration --local-effects
.venv/bin/sentinel simulate compound-exfiltration --mode shadow --local-effects
```

The local-effect demo uses only a temporary fake credential and a localhost sink. Enforce prevents its delivery; shadow records the recommendation while allowing the synthetic demonstration. No scenario shell command is executed. See [integration instructions](docs/core.md) for a real tool harness, Hermes hooks and the MCP JSON-RPC gate.

## What is built

- Closed Pebble Action Language encodings for shell, file, network, skill and MCP effects, including compound calls.
- Persistent session taint and secret exposure beyond the model's 256-token context; conservative handling of parallel calls and untrusted error output.
- Explicit policy rules, calibrated anomaly scoring, human approval, fail-safe holds and non-overridable blocks in the adapters.
- Redacted hash-chained local audit logs and a browser-only audit viewer.
- CLI, local harness, Hermes plugin hooks and a transport-independent MCP gate with durable session ledgers.
- Three genuinely trained **1,288,368-parameter** PAL Transformers; original data, weights, reports, parity checks and reproducible Pebble training code.

Pebble defines the architecture, data generation and training loop; TensorFlow.js WASM supplies numerical kernels and differentiation. NumPy supplies production inference. This is a separate model from the [exactly 2M-parameter Pebble language model](https://github.com/YashAnand69/pebble-llm). No weights from that model or TinyTransformer were reused.

## Evidence and limits

At the default checkpoint, the model and the combined guard detect all six authored attack episodes across five families. **Rules alone also detect all six.** The trigram baseline detects three with zero false alarms on this synthetic test. Default false alarms per 1,000 benign actions are 9.613 for the model, 34.727 for rules and 44.340 for the combined system. These comparisons do not establish model superiority or necessity.

Short-context scorer p95 is 2.039 ms; exact mature-window scoring p95 is **48.387 ms**, so the general 5 ms target was not met. Calibration templates contain repeated contexts; zero observed calibration false alarms is not a future guarantee. There is no real-world detection-rate claim, live agent-brain evaluation or completed parameter/context/taint ablation sweep.

The actual upstream Hermes router proof verifies blocked callbacks, denied approval and approved calls using harmless dummy tools and an isolated temporary configuration. It is not an installed-agent security evaluation.

Read the [model card](MODEL_CARD.md), [data card](DATA_CARD.md), [measured results](results/METRICS.md), [research](docs/RESEARCH.md), [threat model](THREAT_MODEL.md) and [security boundaries](SECURITY.md). A guard is an additional approval layer, not an OS sandbox. Same-privilege attackers can defeat an unanchored audit chain; use one writer per log. Hermes session state is in memory; the MCP adapter provides a durable ledger.

## Development and reproduction

Use Python 3.12 and Node 24. The checkout contains released weights, so training is optional.

```sh
.venv/bin/python -m pytest
.venv/bin/python eval/verify_artifacts.py
npm --prefix web ci
npm --prefix web test
npm --prefix web run build
npm --prefix model ci
```

See [model reproduction commands](MODEL_CARD.md) and [contribution guide](CONTRIBUTING.md). Vercel serves `web/dist` and the Python API using `vercel.json`; no external model API key is required. Training is local, not a Vercel request.

Original code, data and model weights are MIT licensed. Third-party fonts and packages retain their own licenses, included in [notices](web/THIRD_PARTY_NOTICES.md). Development used AI assistance; published metrics come from executed training and evaluation, with unsuccessful cases retained. Draft planning documents are in `docs/spec`; measured results and current security boundaries supersede aspirational claims there.
