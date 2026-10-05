> Planning document, updated for the requested build: MIT applies to all original code, data, weights and documentation. A full accessible animated web interface and local audit viewer are in scope. Planned metrics and experiments are targets until measured. Runtime skill instructions below describe the product after installation; they do not assert that it is currently installed.

# THREAT MODEL

## 1. Assets

- Credentials and secrets the agent can reach.
- Files and code on the host.
- Host integrity (no persistence, no tampering).
- The agent's own configuration, memory and skills.
- Sentinel's rules, model and audit log.

## 2. Adversaries

| ID | Adversary | Capability |
|----|-----------|------------|
| A1 | Web or document injector | Plants instructions in content the agent reads |
| A2 | Malicious skill author | Publishes a skill that runs harmful actions |
| A3 | Malicious MCP server | Returns hostile tool output |
| A4 | Compromised agent behaviour | Agent drifts or is steered into unusual actions |

## 3. What Sentinel defends

- Runtime actions routed through the harness adapter.
- Chains such as reading a secret then sending data to an unknown host.
- Download-then-execute chains.
- Persistence writes (shell startup, scheduled jobs, agent config) after untrusted input.
- Tampering with Sentinel itself through the agent.

## 4. What Sentinel does not defend

- A compromised operating system, root access or a malicious user.
- Actions that bypass the adapter (a harness feature that never reports a tool call).
- Perfect mimicry: an attacker who only performs actions that look normal.
- Malware executed outside the agent.
- Supply-chain attacks on Sentinel's own dependencies, model or training data.
- Data poisoning of learn mode if the traces were already compromised.
- Confidentiality of data the agent legitimately sends to a trusted host.

## 5. Trust boundaries and assumptions

- The guard sees typed action tokens from a deterministic encoder, never raw content. Injected text cannot reach it as an instruction.
- The encoder and rules are trusted code. Arguments are parsed, not interpreted by a model.
- The agent and Sentinel run as the same user unless the operator separates them. Self-protection is therefore best effort.
- Benign training data is vetted before use.

## 6. Failure modes

| Failure | Effect | Handling |
|---------|--------|----------|
| False alarm | Harmless action held | Report rates; tunable thresholds; shadow mode first |
| Missed attack | Harm occurs | Hard rules as backbone; report misses per family honestly |
| Encoder misclassification | Wrong class, wrong decision | Fixtures per class; unknown maps to the cautious classes |
| Internal error | No decision | Enforce mode holds |
| Guard tampering | Weaker protection | `deny-guard-tamper`, read-only permissions, container advice |
| Slow-drip exfiltration | Many small normal-looking sends | Held-out family F5 in evaluation; known weak spot |

## 7. Known limitations

- Anomaly scores are sensitive to the chosen threshold. Results are reported at several operating points.
- Synthetic benign traces may not match real use.
- Attack families are authored by the team, so measured detection can be optimistic.
- Sentinel is one layer. Keep approval prompts and isolation.

## 8. Safe-demo rules

1. Canary secrets only: fake files created for the demo.
2. A localhost sink stands in for the attacker host. No external hosts.
3. No real malware, no real malicious skills, nothing published.
4. Scenarios are data files reviewed before running.
5. Do not run demos on a machine holding real credentials without isolation.
6. Disclose AI assistance in demos and write-ups.
