# Security scope and reporting

Sentinel is an experimental pre-execution guard, not an operating-system sandbox or a complete security guarantee. Its protection applies only to calls routed through a supported adapter. Keep human approvals, least privilege and operating-system isolation.

The hosted application executes no visitor commands. It runs reviewed synthetic scenarios and scores closed-vocabulary actions. Local audit imports remain in the browser; they are not uploaded. The local-effects simulator creates its own temporary canary and ephemeral localhost sink. It never runs scenario shell commands or reads real credentials.

The shell encoder is conservative, not a complete shell interpreter. Dynamic code, unknown tools, ambiguous commands and risky effects are held. Human review remains important. Model surprise measures rarity, not malicious intent. Synthetic evaluation does not certify behavior on real workflows.

Hermes session state is in memory for a running adapter; a restart clears it. The MCP library offers a durable session ledger. Operators should protect configuration, model, rules and audit files from the agent with separate permissions or users. The same-user rules are best effort; direct calls that bypass the adapter are outside the threat model.

The audit hash chain detects modifications during verification but is not a signature or externally anchored proof. A privileged writer can rewrite and rehash the entire file. Audit writers are single-process; concurrent external writers are rejected. Classes, times and argument digests may still reveal metadata or allow guesses about low-entropy arguments; protect audit files even though raw values are not logged.

To report a vulnerability, use GitHub's private vulnerability reporting if enabled, or contact the repository maintainer through their GitHub profile before publishing details. Do not post real secrets or executable malicious packages. A reviewed canary-only fixture and a description of the affected adapter are sufficient.
