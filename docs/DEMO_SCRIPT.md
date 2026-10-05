# Two-minute demonstration

1. Explain the problem: an agent reads a malicious instruction in a seemingly useful skill or web response; permission to read it is not permission to send credentials.
2. Open the laboratory, select injection/exfiltration and enforce, and run the replay. Inspect the typed credential-read/network-send effects, rule explanation and blocked outcome.
3. Switch to shadow. Show the same would-have decision and clearly identify simulated execution. The website never runs visitor commands.
4. Run the two local compound-exfiltration commands from the README. The temporary localhost canary is delivered only in shadow, providing an observable harmless consequence.
5. Show slow-drip: exposure remains tracked after the model's context rolls over. Inspect the audit locally and export only the sanitized trace.
6. Open Evidence. Show three trained seeds, baselines, false alarms and the long-window latency. Explain that rules already catch these attacks; real traces and stronger held-out evaluation remain future work.
7. Close with the public MIT source, training weights and real Hermes router proof. Invite useful contributions: reviewed tool encodings, benign workflows and independently designed attack cases.

Keep a local checkout and generated results available if the network fails. Do not demonstrate with real credentials or attacker infrastructure.
