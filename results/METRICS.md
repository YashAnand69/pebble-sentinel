# Measured results

Default seed 2026, nominal 0.1% benign calibration operating point. Counts are detected authored episodes / episodes, not real-world success rates. The full rule pack is stateful and contains cautious extra holds.

| System | F1 | F2 | F3 | F4 | F5 | False alarms / 1,000 benign actions | Short-episode p95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| B0 · Rules | 2/2 | 1/1 | 1/1 | 1/1 | 1/1 | 34.727 | 0.009 |
| B1 · Trigram | 1/2 | 1/1 | 0/1 | 1/1 | 0/1 | 0.000 | 0.006 |
| B2 · Transformer | 2/2 | 1/1 | 1/1 | 1/1 | 1/1 | 9.613 | 2.039 |
| B3 · Transformer + rules | 2/2 | 1/1 | 1/1 | 1/1 | 1/1 | 44.340 | 2.167 |

Latency stages differ: B0/B3 include structured PAL validation, policy and decision record; B1/B2 are scorer only. Every short benchmark has 10,000 calls after 100 warm-up calls, batch size one, CPU. None includes raw tool encoding, audit disk I/O, cold start, HTTP or cloud/network cost. Short workflows have at most 151 context/action tokens.

Exact mature 256-token scorer: p50 **45.993 ms**, p95 **48.387 ms**, p99 **49.973 ms**, measured over 1,000 calls after 100 warm-up calls. The under-5-ms total p95 target is **not achieved** generally. Learned absolute positions require exact window recomputation.

## Actual three-seed runs

| Seed | Best step / 500 | Best benign validation CE, nats | Training seconds | Model-only test false alarms / 1,000 | Full-system test false alarms / 1,000 |
|---|---:|---:|---:|---:|---:|
| 2026 | 450 | 0.388906 | 418.670 | 9.613 | 44.340 |
| 2027 | 300 | 0.400744 | 425.858 | 25.835 | 60.562 |
| 2028 | 350 | 0.390815 | 426.045 | 9.613 | 44.340 |

## Operating points, across three seeds

| Nominal calibration rate | System | Mean test false alarms / 1,000 | Sample standard deviation across seeds |
|---|---|---:|---:|
| 1.00% | B2_model_only | 18.225 | 14.916 |
| 1.00% | B3_model_plus_rules | 52.952 | 14.916 |
| 0.10% | B2_model_only | 15.020 | 9.366 |
| 0.10% | B3_model_plus_rules | 49.748 | 9.366 |
| 0.01% | B2_model_only | 15.020 | 9.366 |
| 0.01% | B3_model_plus_rules | 49.748 | 9.366 |

All three model runs detect all six authored attack episodes at every reported operating point. Rules already detect all six. The trigram misses F3/F5 and one F1 at the default point, but has fewer false alarms; these unequal observed false-alarm rates do not prove the Transformer is necessary. No parameter sweep or real-user evaluation was run.

Calibration contains 10,860 actions but only 129 distinct context/action pairs. Its 0.1% and 0.01% default quantiles both equal 7.867925 bits because of 89 exact ties; conservative comparison yields zero calibration flags. Default held-out model test flags are 9.613/1,000, demonstrating distribution shift despite the nominal target. The full system flags 44.340/1,000, including cautious holds on legitimate interpreter/delegation activity. These values are not real-world guarantees.

Machine: Apple M5 Pro, macOS 27.0.1, Python 3.12.14, NumPy 2.3.5, Apple Accelerate BLAS. A single-thread limit was requested, but Accelerate thread count is not exposed by threadpoolctl; it is not verified. Training used Node 24.19.0 and TensorFlow.js/WASM 4.22.0 through Pebble runtime 2.1.1.

Reproduce: `python eval/evaluate.py --seeds 2026,2027,2028 --benchmark-actions 10000` then `python eval/complete_report.py`. Raw latency samples, per-episode decisions, checkpoint hashes and all operating-point results are published alongside this file.
