# Evaluation protocol

Run `python eval/evaluate.py --seeds 2026,2027,2028 --benchmark-actions 10000` after training all three seeds. The evaluator waits for each complete training report, then calibrates thresholds only on benign validation templates. It does not execute scenario arguments or fetch URLs.

B0 is the actual shipped rule pack without a model. It includes persistent taint and secret-access state, plus cautious extra holds, so this is a stronger baseline than a single-command regular expression. B1 is an additive-smoothed word trigram (alpha 0.1), trained on the same benign sequences. B2 is the real Transformer only. B3 combines the real model with B0. A held or blocked action at or before the first harmful action counts as detection.

Three separate random initialization/minibatch seeds are trained for the same architecture and schedule. Seed 2026 is the default, declared before evaluation. Mean and sample standard deviation describe variability across these three actual runs; they are not a population confidence interval. The authored scenario count is reported per family. Small scenario counts and repeated synthetic traces do not support broad security claims.

Threshold operating points are 1%, 0.1% and 0.01% nominal per-action calibration rates. The next float above the selected empirical upper quantile handles exact ties conservatively with the engine's `>=` comparison. Every result includes the actual observed calibration rate, tie count and nominal sample resolution. See DATA_CARD for the much smaller number of distinct context/action pairs.

The main batch-size-one CPU scorer benchmark runs 10,000 actions after 100 warm-up calls, using held-out short workflow episodes (up to 151 preceding/action tokens). A separate 1,000-action benchmark after 100 warm-up calls measures mature sessions with an exact moving 256-token window. Both publish raw latency samples. Encoder, policy, audit I/O, cold start and cloud/network latency are excluded. The project's **under 5 ms total p95** remains a target unless a complete end-to-end benchmark demonstrates it. The exact full-window scorer misses this target; learned absolute positions require recomputation when the window moves.

`python eval/verify_artifacts.py` verifies checkpoint/source/data/result hashes and calibrated default weights. Tests compare NumPy cached inference against a full causal reference and Pebble-exported next-token losses, including window rollover.

Unrun experiments are explicitly listed in results: parameter-size/context sweeps, taint ablation, real-user traces and a live Hermes model evaluation. An upstream Hermes routing/approval smoke test is a separate adapter result, not evidence of model detection performance.
