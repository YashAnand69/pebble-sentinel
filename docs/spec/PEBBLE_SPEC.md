> Planning document, updated for the requested build: MIT applies to all original code, data, weights and documentation. A full accessible animated web interface and local audit viewer are in scope. Planned metrics and experiments are targets until measured. Runtime skill instructions below describe the product after installation; they do not assert that it is currently installed.

# Pebble Action Language (PAL): spec v0 draft

Status: draft. Reconcile token names with the existing Pebble lexicon where possible. Any change to the vocabulary bumps the version and requires regenerating data and retraining.

## 1. Purpose

PAL is a closed, deterministic text form of agent tool calls. A small model learns normal sequences of PAL sentences, so it can flag unusual ones.

Properties

- Closed vocabulary: about 50 tokens in v0 (limit 150 for growth).
- Deterministic: the same tool call always gives the same sentence.
- No free text and no raw arguments. Raw values go to the audit log as a digest only.
- Human-readable.

## 2. Grammar

```
episode     = "<bos>" , action , { action } , "<eos>" ;
action      = verb , object , "via" , channel , { flag } , "." ;
verb        = "read" | "write" | "edit" | "delete" | "exec" | "fetch" | "send" | "install" | "spawn" ;
object      = file-class | exec-class | net-class | "unknown-object" ;
file-class  = "proj-file" | "proj-config" | "home-dotfile" | "secret-store" | "system-path"
            | "tmp-file" | "skill-file" | "agent-config" | "guard-config" | "shell-rc" | "cron-entry" ;
exec-class  = "test-runner" | "build-tool" | "vcs" | "pkg-manager" | "interpreter"
            | "unknown-binary" | "downloaded-code" ;
net-class   = "net-local" | "net-allow" | "net-unknown" | "pkg-registry" ;
channel     = "shell" | "file-tool" | "web-tool" | "mcp" | "skill" ;
flag        = "tainted" | "sudo" | "pipe" | "encoded" | "remote-code" | "bulk" | "outside-cwd" | "new-host" ;
```

Flags appear in the fixed order listed above.

## 3. Examples

Normal work

```
<bos> read proj-file via file-tool . exec test-runner via shell . edit proj-file via file-tool . exec test-runner via shell . <eos>
```

Injection then exfiltration (the fetch itself is untainted; later actions are tainted)

```
fetch net-unknown via web-tool . read secret-store via shell tainted . send net-unknown via shell tainted encoded .
```

Malicious skill install chain

```
install skill-file via skill . fetch net-unknown via skill remote-code . exec downloaded-code via shell remote-code .
```

Persistence

```
write shell-rc via file-tool tainted . write agent-config via file-tool tainted .
```

## 4. Encoding rules

| ID | Rule |
|----|------|
| E1 | One tool call gives one sentence. Compound shell commands split on `;`, `&&` and `||` into one sentence per part, in order. A pipeline is one sentence with `pipe`; a download piped into an interpreter also gets `remote-code` |
| E2 | Raw arguments never appear in the sentence. Only classes do |
| E3 | Classification uses ordered rule tables in data files; the first match wins |
| E4 | Unmatched values map to `unknown-binary`, `unknown-object` or `net-unknown`. The encoder never raises |
| E5 | Taint is set when the agent ingests content from a `net-*` object, `mcp` output or a file outside the project. It clears only by human action |
| E6 | One episode is one agent session. Sentences are about 8 to 10 tokens, so 256 tokens of context holds about 25 actions |

## 5. Harness mapping (Hermes; verify names against the installed version in M0)

| Harness tool | Verb |
|--------------|------|
| terminal | exec, or read, write, fetch, send by command analysis |
| read file tool | read |
| write_file | write |
| patch | edit |
| web_search and web fetch | fetch |
| MCP tool call | exec on `unknown-binary` via `mcp`, refined by the adapter manifest |
| delegate_task | spawn |
| skill install | install |

## 6. Path classification

Pseudocode

```
for each (pattern, class) in ordered rules:
    if path matches pattern:
        return class
if path is inside the project root:
    return proj-file
return unknown-object
```

Working code

```python
import fnmatch
import os

PATH_RULES = [
    ("~/.ssh/*", "secret-store"),
    ("~/.aws/*", "secret-store"),
    ("~/.env", "secret-store"),
    ("*/.env", "secret-store"),
    ("~/.bashrc", "shell-rc"),
    ("~/.zshrc", "shell-rc"),
    ("~/.sentinel/*", "guard-config"),
    ("~/.hermes/plugins/*", "guard-config"),
    ("~/.hermes/skills/*", "skill-file"),
    ("~/.hermes/*", "agent-config"),
    ("/etc/*", "system-path"),
    ("/tmp/*", "tmp-file"),
]


def object_class_for_path(path, project_root):
    expanded = os.path.abspath(os.path.expanduser(path))
    for pattern, label in PATH_RULES:
        if fnmatch.fnmatch(expanded, os.path.expanduser(pattern)):
            return label
    root = os.path.abspath(project_root)
    try:
        if os.path.commonpath([expanded, root]) == root:
            return "proj-file"
    except ValueError:
        return "unknown-object"
    return "unknown-object"
```

## 7. Versioning

- Spec version: v0. Vocabulary file: `pal_vocab_v0.json`.
- Breaking changes: new major version, regenerate data, retrain, update MODEL_CARD.

## 8. Open items

- Map tokens to the existing Pebble lexicon.
- Decide whether `mcp` calls need per-server classes.
- Add classes for browser automation if the harness supports it.
