# Contributing to Pebble Sentinel

Useful contributions include a realistic benign workflow, a reviewed canary scenario, a conservative encoder fixture, an adapter integration or a privacy-preserving audit-viewer improvement. Keep original contributions MIT licensed; retain third-party license notices.

Start with Python 3.12 and Node 24:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
npm --prefix web ci
npm --prefix web test
npm run build
```

A scenario contribution should be a JSON data file plus a positive and negative test. Never use real credentials, external attacker hosts or executable malware. The simulator does not execute scenario command strings. Describe exactly which effects the adapter represents and which it cannot classify.

Training and generation remain Pebble programs. Numerical inference uses the tested NumPy reference and cache; do not replace the trained scorer with canned outputs or a hosted model API. Preserve cross-runtime parity and learned-position window semantics.

Rules and model thresholds may be developed against designated development scenarios and benign calibration data. Do not tune on reserved workflow templates or held-out families. If a held-out evaluation guides a change, introduce a new version of the protocol and clearly identify the old set as development data. Publish failures, false alarms and timing limits.

The original planning documents are in `docs/spec/`. The actual release scope, results and licenses in the README and model/data cards take precedence over historical draft targets. New experiments need real logs and a reproducible command; unrun experiments stay labeled unrun.

Describe AI assistance and human review in pull requests. Contributions must be useful, reviewed changes; repository topics do not guarantee Hacktoberfest eligibility or a prize.
