# Local guard and safe demonstration

Sentinel checks typed action classes before a harness executes a tool. It is an additional approval layer, not a sandbox or a complete security boundary. The hosted laboratory never runs commands entered by visitors. A hosted result shows what the local guard would decide; it does not install protection on the visitor's computer.

## Run locally

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/sentinel --help
.venv/bin/sentinel simulate injection-exfiltration
.venv/bin/sentinel simulate compound-exfiltration --local-effects
.venv/bin/sentinel simulate compound-exfiltration --mode shadow --local-effects
.venv/bin/sentinel status
.venv/bin/sentinel review
.venv/bin/sentinel explain ACTION_ID
.venv/bin/pytest tests/test_core.py
```

The local-effect demonstration creates one fake canary in a temporary directory and a temporary HTTP listener bound only to `127.0.0.1`. It never launches scenario shell commands, downloads remote code, contacts the scenario's `.invalid` addresses, or reads actual credentials. Enforce prevents delivery; shadow demonstrates the same would-have decision while allowing only the synthetic canary delivery. Later actions after the first enforce intervention are hypothetical replay entries with `executed: false`.

The CLI keeps mode and redacted audit files under the supplied `--workspace` directory (default `.sentinel-demo`). It does not install plugins or change global agent configuration. CLI simulations, the hosted lab and the Hermes adapter use the actual released transformer by default. Add `--rules-only` to a CLI simulation to explicitly select the policy baseline. A missing or invalid model stops the CLI before any synthetic effects run; it never silently downgrades. `sentinel status` reports the real model's checkpoint hash, parameter count and calibrated readiness. An uncalibrated checkpoint cautiously holds actions. A rules-only run has zero model parameters and no fabricated anomaly score. Library callers can explicitly choose their own scorer.

The human operator command `sentinel mode learn|shadow|enforce` writes only the chosen workspace's `mode.json` and logs the change. The next CLI simulation reads that validated setting unless an explicit `--mode` overrides it for one run. Hermes reads `.sentinel-demo/mode.json` under its project working directory when registering a new guard; restart that harness after changing the setting. Invalid mode files fail closed. The command does not hot-reconfigure an existing process and does not change the browser laboratory's per-request mode. Use the same project working directory and workspace for CLI settings and the adapter. These are human operator controls; an agent must not invoke them to weaken its own protection.

## Integrate a tool harness

```python
from sentinel import Sentinel
from sentinel.scorer import TransformerScorer
from sentinel.adapters.local import LocalHarness

guard = Sentinel(project_root='.', scorer=TransformerScorer(), audit_path='.sentinel-demo/audit.jsonl')
harness = LocalHarness(guard, tools={'read_file': your_file_reader}, approval=your_human_approval_function)
result = harness.call('read_file', {'path': 'README.md'}, session='session-01')
```

Without an approval callback, a hold never executes. Human approval applies to that one call. Block decisions cannot be overridden by the local adapter. Taint is committed after actual untrusted output is observed, including error responses: attacker-controlled error text is still untrusted content. Blocked and skipped calls do not set it. An actually dispatched secret read retains exposure even if it returns a partial-data error. Pending ingestion is treated conservatively during parallel tool checks so a concurrently requested secret read and network send cannot evade the session rule. Persistent taint and `secret_seen` live separately from the model's bounded history. Clearing taint does not clear secret exposure.

Shell classification is conservative and incomplete. Compound calls produce **all recognized PAL effects**, including credential reads, redirects, upload sources and sends; this intentionally replaces the draft's one-sentence pipeline rule. A compound tool call receives its strongest decision before any part executes. Unknown programs, inline interpreter content, substitutions and unsupported syntax are held. Path classification resolves relative paths and symlinks before applying protected-path classes. Real shell expansion, dynamically generated paths, remote processes, and custom tools still require isolation and approval.

## Hermes plugin

`sentinel.adapters.hermes.HermesAdapter` registers the documented Python plugin hooks using `ctx.register_hook`. Its pre hook accepts `tool_name, args, task_id, **kwargs`; its post hook accepts `tool_name, args, result, task_id, duration_ms, **kwargs`. A hold returns `action: approve`, which means **ask the human**, not automatic approval. A block returns `action: block`. The adapter reads only the result's error status, never its content. It does not write or enable anything in `~/.hermes`.

The adapter module provides `register(ctx)` using the released transformer. Loading failures are not silently replaced with rules-only scoring. Version-specific plugin packaging/enabling remains an operator step; no installed Hermes instance was modified or executed during development. Callback signatures and directives were verified against the [official Hermes hooks documentation](https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks) on 2026-10-05. Contract tests cover the local adapter. A separate integration proof uses the actual upstream manager and tool router, detailed below; this is not a claim of an installed live agent deployment.

## Audit and policy

`policy/default.yaml` contains independently tested rules. Internal scorer errors and nonfinite scores hold in enforce. A deny remains a block even if scoring or audit writing fails. Learn records traces without rules or scoring; shadow records the same recommendations as enforce but allows execution.

Audit JSONL contains only closed-vocabulary PAL, argument digests, rule ids, scores and generic error classes. Raw command arguments, file content and tool output are never written. Entries are SHA-256 chained and verified when opened. A hash chain detects changed existing entries; it cannot prove an unanchored log has not been deleted or truncated. The audit implementation assumes one guard writer per log file; use separate logs for different harness processes. All state is local; session state is in memory and must survive for the life of the agent session. Restarting the guard starts a new session and loses prior taint/exposure unless the harness replays a trusted session ledger.

No latency, real-world detection rate or universal prevention claim follows from passing these fixtures. The separately published evaluation reports its measured synthetic-data performance and baselines.

## Verified upstream routing

`results/hermes-integration.json` records an execution against actual [Hermes source at commit bdef06de3b8c0d190cd7f69edc911ac6961ca358](https://github.com/NousResearch/hermes-agent/tree/bdef06de3b8c0d190cd7f69edc911ac6961ca358). The proof registers Sentinel through the upstream `PluginContext` and `PluginManager`, then routes requests through the real `model_tools.handle_function_call` and registry:

- Guard-tamper block: the dummy tool callback ran zero times.
- Hold: upstream consumed `action: approve` and invoked the human approval gate. A fixture denial kept the callback count at zero.
- Approved hold: a fixture approval let the dummy callback run once.

The human interaction function was replaced by deterministic yes/no responses. Dummy tool handlers had no filesystem or network effects. Hermes configuration was isolated with a temporary `HERMES_HOME`; no user's installed Hermes configuration or plugin was changed. No agent brain, API key or remote model call was involved. Optional real terminal/web tools were not exercised. The result proves the actual hook-to-tool gate, rather than only our own adapter's return values.

To reproduce, clone the upstream repository into a temporary directory and check out the pinned commit. In an isolated temporary Python environment, install `PyYAML`, `ruamel.yaml`, `python-dotenv`, `pydantic`, `requests`, `rich`, `platformdirs`, `numpy`, and `threadpoolctl`. Set `HERMES_HOME` and `HERMES_BUNDLED_PLUGINS` to fresh temporary directories, and `PYTHONPATH` to the upstream clone and Sentinel checkout, then run `scripts/prove-hermes.py`. The proof refuses non-temporary Hermes homes or a different upstream revision.

## MCP JSON-RPC adapter

`sentinel.adapters.mcp.MCPProxy` gates MCP `tools/call` requests before invoking a caller-supplied upstream transport. Unknown tool semantics hold. An operator-authored manifest maps known names to canonical encodings, so a file tool's actual path and a network tool's actual URL are still classified; naming a tool `reader` does not automatically make secret reads safe.

```python
from sentinel.adapters.mcp import MCPProxy

proxy = MCPProxy(
    guard,
    upstream=your_json_rpc_transport,
    manifest={'read_project_file': 'read_file', 'send_request': 'http_post'},
    state_path='.sentinel-demo/mcp-sessions.json',
    approval=your_human_approval_function,
)
response = proxy.handle(json_rpc_request, session='opaque-client-session-id')
```

The optional session ledger atomically persists only PAL history, taint and exposure, keyed by a session digest. Restarting this proxy therefore retains a secret read across context rollover. The ledger itself is protected against tool writes. Holds without an explicit approval callback and all blocks are returned as MCP error results and never forwarded. Fixture upstream tests prove withheld calls are absent from the upstream callback and observed ingestion remains tainted across a proxy restart. MCP `isError` responses also taint the session, because their text can contain an injection; a trusted local block message does not.

This is a transport-independent adapter library, not a globally installed MCP server. Connect it to an operator-owned transport. Its scope is `tools/call`: discovery and other methods pass through. MCP resources, prompts, server-initiated operations and arbitrary direct connections must be separately gated by the host; do not describe this adapter as covering those surfaces. It assumes one proxy writer per durable ledger.
