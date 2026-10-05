# Training in Pebble

This model is a new PAL behavior model, trained from random initialization. It does not reuse PebbleLM character-model weights.

```sh
cd model
npm ci
npm run prepare:data
npm run train -- --seed 2026 --steps 500
npm run train -- --seed 2027 --steps 500
npm run train -- --seed 2028 --steps 500
npm run parity
cd ..
python eval/evaluate.py --seeds 2026,2027,2028 --benchmark-actions 10000
```

`transformer.pebble` defines all five Transformer blocks, attention, residuals, feed-forward layers, the tied output and parameter count. `train.pebble` controls random initialization, batch construction, the full 500-step optimization loop, learning-rate schedule, validation and best-checkpoint selection. `prepare.pebble` generates the original benign synthetic data using template definitions. These programs run through the MIT Pebble runtime pinned in the lockfile. TensorFlow.js 4.22.0's Apache-2.0 WASM kernels and automatic differentiation perform numerical operations; Pebble's host ML extension supplies AdamW primitives. Neither a Python trainer nor an external text-generation service supplies model behavior.

The local Python scorer uses NumPy to load the same little-endian float32 checkpoint and run CPU inference. It requests one BLAS thread where the backend supports threadpool control and caches exact prefix attention keys/values. Apple Accelerate thread count is not exposed by threadpoolctl; the reported benchmark identifies this limitation. When the 256-token window moves, it recomputes the window so learned absolute positional embeddings remain correct. It computes each next-token surprise from past context and returns the largest token surprise in the action, in bits. No scenario matching or trained-output lookup replaces inference.

Training batch size is 2, sequence length 256; all 256 positions are supervised. Episodes are packed with BOS/EOS, without a separate attention reset at document boundaries. Early stopping uses 36 validation episodes. The released default seed is 2026, declared before evaluation; the other seeds measure training variability.

Everything authored here, including synthetic data and exported weights, is MIT. Dependencies retain their own licenses. This is an experimental anomaly detector; model scores are not proof that an action is safe or unsafe.
