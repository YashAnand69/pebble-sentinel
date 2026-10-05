# Benign workflow generator

The actual generator is [`model/prepare.pebble`](../model/prepare.pebble). It runs in the Pebble interpreter and emits only original synthetic benign PAL traces under MIT. Workflow definitions live in `model/workflows.json` and are split by template ID. Taint persists after network or MCP ingestion, including across repeated workflow cycles.

Run `cd model && npm ci && npm run prepare:data`. Generation seed is 20261005. Attack scenarios are never used for training, early stopping or threshold calibration. The authored scenario files in `scenarios/` are evaluated separately.
