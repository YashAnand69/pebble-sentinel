# Research and product rationale

Verified against primary sources on 5 October 2026. Statistics below describe each publisher's historical sample, not a current ecosystem prevalence estimate.

## A concrete problem

Agent extensions can request operations using the operator's access to files, tools and credentials. A useful guard must inspect the proposed operation before execution, preserve session context, and leave an understandable decision record.

[Snyk's ToxicSkills study](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) examined 3,984 skills as of 5 February 2026. It reported 36.82% with at least one security issue, 534 with critical issues, and 76 human-confirmed malicious payloads. These are different categories; the 1,467 skills with any issue must not be described as 1,467 confirmed malware packages.

[Antiy's ClawHavoc analysis](https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/) separately reported 1,184 malicious packages in ClawHub's historical repository by 5 February. Its sample and counting method differ from Snyk's, so the counts are not added or treated as directly comparable.

## Where Sentinel helps

A developer using a local agent can run a pre-execution adapter in shadow mode, review class-only audit records, then choose enforcement. Rules address specific harmful effects; a model trained on benign action sequences adds a signal for departures from those workflows. The web application demonstrates this with reviewed simulated scenarios and can inspect local JSONL records without uploading them.

The deployed website is a demo and audit viewer, not a guard secretly installed on the visitor's device. Real protection requires routing tool execution through the local adapter. This separation is explicit in the interface and installation guide.

## Existing work and integration

[Hermes' official hook documentation](https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks) describes `pre_tool_call` plugin interception in CLI and gateway sessions. `action: block` prevents execution; `action: approve` requests the human approval gate. The post hook reports success, error or blocked status. Hook names and return contracts are verified in the adapter tests, with the observed upstream revision recorded in integration documentation. Installation is opt-in.

[DeepLog](https://acmccs.github.io/papers/p1285-duA.pdf) establishes learning normal event sequences as an anomaly-detection approach. Sentinel applies this idea to a small typed action vocabulary. That supports the direction, not an assertion that our synthetic benchmark predicts production security performance.

[LlamaFirewall](https://arxiv.org/abs/2505.03574) is an existing open-source agent guardrail system. Sentinel is a narrower experiment: inspect typed behavior rather than asking a text model to judge arbitrary untrusted content. We do not claim to replace established guardrails, content defenses or isolation.

## What remains an assumption

- A closed action vocabulary can lose details that distinguish safe from unsafe intent. Conservative unknown classifications and multiple shell effects reduce this gap but do not remove it.
- A small synthetic benign corpus may poorly match real workflows. False alarms on held-out workflow templates are reported, not hidden.
- An attacker can mimic normal behavior or bypass an uninstrumented tool path. The model is not a proof of safety.
- The 5 ms p95 requirement is a target. Only measured results can justify a latency claim.
- A transformer may not outperform a trigram. Both are measured, and the simpler model remains a legitimate baseline.

## Hack-day presentation

The meaningful demo is a normal workflow followed by a suspicious action chain, its pre-execution decision, and the precise rule or surprise signal. A judge can compose closed-vocabulary actions and inspect the result. A simulated outcome is labeled as such; a local canary harness demonstrates actual gating without accessing real credentials.

[Hacktoberfest's official FAQ](https://hacktoberfest.com/questions/) defines event participation. Local judging criteria and submission deadlines are organizer-specific; this project does not claim a guaranteed prize or automatic Hacktoberfest contribution eligibility.
