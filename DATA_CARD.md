# Pebble Sentinel synthetic data card

All authored workflow definitions and generated PAL traces are released under MIT. No real user traces, credentials, web pages, external datasets or attack execution were used. This dataset describes typed actions only; it contains no raw arguments or untrusted document content.

The generator runs in Pebble (`model/prepare.pebble`) with seed 20261005. A closed 51-token PAL vocabulary includes 47 action/grammar tokens plus BOS, EOS, PAD and UNK. Episodes repeat an authored development workflow two to five times. Taint persists after network or MCP ingestion. Only benign workflows train the model; attack scenarios are separate, descriptive JSON fixtures used for evaluation after calibration.

| Split | Templates | Episodes | Actions | Tokens, including BOS/EOS | Distinct episodes |
|---|---:|---:|---:|---:|---:|
| Train | 16 | 256 | 3,713 | 20,165 | 64 |
| Early stopping | 6 | 36 | 538 | 2,935 | 22 |
| Benign calibration | Same 6 validation templates | 720 | 10,860 | 59,219 | 24 |
| Test | 6 templates never used to train or calibrate | 480 | 8,322 | 43,805 | 24 |

Template IDs and full action sequences are disjoint between train, validation and test. Short action motifs, verbs and object classes are shared. Early-stopping and calibration instances use the same validation templates, with independently generated repetition counts; they are not independent workflow domains.

The nominal calibration resolution is 1/10,860 actions (about 0.0092%). However, calibration has only 129 distinct context/action pairs and test has 148. Duplicate synthetic traces are not independent observations. In particular, this corpus cannot establish a real-world 0.01% false-alarm guarantee. Exact-score ties are counted and thresholds use the next representable float above the selected upper quantile to keep the `>=` comparison conservative on calibration data.

Coverage includes editing, tests, builds, version control, temporary files, package installation, interpreter use, trusted/local fetches, delegated/MCP activity and ordinary work after taint. It does not represent deployment credentials, administrative maintenance, arbitrary shell syntax, real agent trajectories or organization-specific policies. Some legitimate activities intentionally conflict with cautious default rules (for example an interpreter or unknown delegated object); those holds are counted as false alarms in the reported rule/system evaluation.

The authored attack files cover injection/exfiltration, a download/execute chain, persistence/guard tampering, outside-project deletion and delayed secret sending. They contain fake paths and reserved `.invalid` hostnames; evaluation encodes arguments without executing commands or making network requests. The sandbox demo uses canary files and a localhost sink. Family labels F3–F5 were designated held out by the supplied evaluation plan, but the documented rule pack already contains persistence/destruction/exfiltration knowledge, so results are not evidence of catching independently novel attacks.

Reproduce generation with `cd model && npm ci && npm run prepare:data`. `model/data/manifest.json` records the seed and episode counts. `results/provenance.json` records SHA-256 hashes for reproducibility. Real-world rollout should collect reviewed local traces in shadow mode, validate policies against legitimate work and measure missed attacks and false alarms before enforcement.
