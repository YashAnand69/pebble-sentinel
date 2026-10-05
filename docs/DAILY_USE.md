# Use Sentinel with a daily project workspace

DailyWorkspace is a small local reference integration for reviewing meeting notes, reading project documents, and writing a reviewed text report. An operator chooses one existing folder. An assistant can request its two file operations, and Sentinel checks each request before the real file callback runs. It does not grant access to your whole computer.

The website's Daily Workspace is a separate browser workflow for documents you select and reports you download. It does not install a guard into other agents or monitor your computer. This local example shows how an agent developer can put the same check before their own file tools.

## Use it directly on the website

[Open the Daily Workspace](https://pebble-sentinel.vercel.app/#daily-workspace). For example, turn meeting notes into a reviewed list of decisions and owners, prepare a project progress report, or format a JSON document for a teammate.

1. Choose a `.txt`, `.md`, `.json`, or `.csv` document of at most 256 KB. Choosing a file selects it; it does not read its contents yet.
2. Press **Guard & open locally**. An ALLOW opens a local preview. A HOLD asks you to approve that exact read once. A BLOCK has no override.
3. Use **Use file as draft**, or **Format JSON into draft** for JSON. Edit your own meeting notes, project report, or task list. This is a manual document workspace; it does not claim to generate an AI summary.
4. Set a simple download filename and press **Guard & download draft**. Sentinel checks again before preparing a new download. Your original file is never modified. Changing the selection, draft, or filename cancels any pending approval.

A fresh session's first download can be held as unfamiliar by the actual model. Review the action and approve once if appropriate; anomalies ask the person rather than automatically blocking daily work. Hard restrictions still block sensitive or protected action classes. Filename classification is deliberately limited and is not a secret-content scanner.

The guard request contains only closed-vocabulary action classes and up to 24 completed actions. Filenames, document contents, and draft contents are not sent to the API. Documents and drafts live in this tab's memory, with no persistent document storage. **Clear workspace** removes them and starts a fresh history; it does not delete any files already downloaded.

**Download redacted audit** exports the last 64 checks, including completed and human-approved status. You can inspect it in the laboratory's **Import audit** tab. This browser export contains local metadata, not a tamper-evident hash chain; the local agent integration below has a separate hash-chained audit. This website guards only its own open/download buttons and does not monitor other apps, execute shell commands, or protect your computer globally.

## Try the actual local callbacks

On macOS or Linux, with Python 3.10 or newer:

```sh
git clone https://github.com/YashAnand69/pebble-sentinel.git
cd pebble-sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python examples/daily_workspace.py --demo
```

The demo creates and deletes a fresh temporary project, reads synthetic notes, and writes a deterministic summary. It then attempts to change the guard audit file and call an unsupported shell tool. Its JSON proof includes the actual model identity, decisions, callback counts, file effects, and audit-chain verification. The checked run made one read and one write, blocked guard tampering, withheld the unknown tool, and verified the audit chain. It performed no network calls or shell execution.

The demo can approve at most one HOLD for the exact synthetic summary-write arguments. That fixture authorization is explicitly scoped to `--demo`; it never approves other requests. The checked run needed no approval. These are reproducible integration checks, not a real-world security success rate or an LLM-generated summary.

## Work on your own folder

Create a JSON request file outside the selected project if desired:

```json
[
  {"tool":"read_file","arguments":{"path":"notes.md"}},
  {"tool":"write_file","arguments":{"path":"summary.md","content":"Reviewed notes: follow up on the project changes.\n"}}
]
```

Read-only is the default. The write above will be blocked:

```sh
python examples/daily_workspace.py --project /path/to/my-project --requests requests.json
```

To opt into writes and ask the human operator about held actions:

```sh
python examples/daily_workspace.py --project /path/to/my-project --requests requests.json --allow-writes --interactive
```

The interactive approval requires a terminal and an explicit `yes` for each HOLD. Without an approval callback, or in a noninteractive process, held actions remain withheld. Approval never overrides a hard BLOCK. Requests run in order within one session. There is no agent-facing switch to enable writes or change the guard mode.

Only `read_file` and `write_file` are supported, with the exact argument fields shown above. Files must be UTF-8 regular files of at most 256 KiB; directories must already exist. Absolute paths, traversal, symlinks, `.git`, `.sentinel-demo`, `.env*`, `.netrc`, `credentials`, `id_rsa`, and `id_ed25519` are refused. Existing files without read or write permission bits are respected. Writes use a temporary file and an atomic replacement inside the pinned project directory. The operator-owned `.sentinel-demo/daily-audit.jsonl` is created even when the exposed file tools are read-only; it records digests and decisions, not document contents.

## Connect an assistant's tools

```python
from sentinel.daily_workspace import DailyWorkspace

# Implement this in the trusted operator UI. Return True only for an
# explicit human approval of this specific decision; never auto-approve.
def ask_operator(record):
    return False

with DailyWorkspace("./my-project", approval=ask_operator) as workspace:
    result = workspace.call("read_file", {"path": "notes.md"})
    if result["executed"]:
        notes = result["result"]["content"]
        # Supply notes to your assistant through your own integration.
```

Bind assistant requests to `workspace.call`, rather than directly exposing filesystem callbacks. Set `allow_writes=True` only in trusted operator code when the task needs it. Unsupported tools are never dispatched, even if a caller supplies an approval callback. The example does not run a shell, contact a model provider, or execute generated text.

## Pilot behavior and limits

The default scorer is the bundled trained PAL transformer, with its released calibration. There is no silent rules-only fallback. This daily pilot routes model anomalies to HOLD by setting this instance's model block threshold to infinity; its hold threshold remains the released calibrated value. Hard policy violations still BLOCK, and the workspace adds strict path, secret, and read-only restrictions. The default Sentinel profile, published benchmark results, and model artifacts are unchanged. This pilot has not been evaluated as a new security-rate claim.

The model learned a narrow synthetic workflow distribution and can flag legitimate activity. Evaluate and calibrate against your own benign workflows before considering unattended use. In particular, the default MCP profile can flag a normal MCP read; this daily file-tool pilot is not a recommendation to deploy that profile unattended.

Session history and exposure flags live in this process. Restarting creates a new session: the persistent audit does not automatically restore prior exposure state. The separate MCP adapter has its own durable session ledger; see [the core integration notes](core.md). Neither adapter guards tools that bypass it. The pinned directory and symlink checks constrain these callbacks; they are not an operating-system sandbox against a malicious concurrent process, a compromised caller, or tools exposed elsewhere. The POSIX directory-descriptor implementation is intended for macOS/Linux, not Windows.

Source and model are open under the repository's MIT license.
