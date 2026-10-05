from pathlib import Path
import json
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.evaluate import load_split, Trigram, parse_effect
from sentinel.engine import Sentinel, SessionState, RuleOnlyScorer
from sentinel.scorer import TransformerScorer
import numpy as np
from threadpoolctl import threadpool_info


def percentiles(samples, stage):
    return {'stage':stage,'actions':10000,'warmup_actions':100,'batch_size':1,'p50_ms':float(np.percentile(samples,50)),'p95_ms':float(np.percentile(samples,95)),'p99_ms':float(np.percentile(samples,99)),'mean_ms':statistics.mean(samples)}


def measure_engine(scorer, episodes, name):
    engine = Sentinel('/sentinel-evaluation-project', scorer=scorer)
    corpus=[]
    for episode in episodes:
        state=SessionState()
        for sentence in episode['actions']:
            effect=parse_effect(sentence)
            corpus.append((SessionState(state.tainted,state.secret_seen,list(state.history)),effect.to_dict()))
            Sentinel._ingest(state,effect)
            state.history.append(sentence)
    samples=[]
    for i in range(10100):
        state,effect=corpus[i%len(corpus)]
        engine.sessions['benchmark']=SessionState(state.tainted,state.secret_seen,list(state.history))
        engine.pending.clear()
        action={key:effect[key] for key in ('verb','object','channel','flags')}
        started=time.perf_counter_ns()
        engine.inspect_actions([action],session='benchmark')
        elapsed=(time.perf_counter_ns()-started)/1_000_000
        if i>=100:samples.append(elapsed)
    (ROOT/f'results/{name}-latency-samples.json').write_text(json.dumps(samples)+'\n')
    return percentiles(samples,'structured PAL validation, policy, decision record; excludes raw tool encoder, audit I/O, HTTP, cold start')


def measure_trigram(scorer, episodes):
    corpus=[(ep['actions'][:i],a) for ep in episodes for i,a in enumerate(ep['actions'])]
    samples=[]
    for i in range(10100):
        history,sentence=corpus[i%len(corpus)]
        started=time.perf_counter_ns();scorer.score(history,sentence);elapsed=(time.perf_counter_ns()-started)/1_000_000
        if i>=100:samples.append(elapsed)
    (ROOT/'results/trigram-latency-samples.json').write_text(json.dumps(samples)+'\n')
    return percentiles(samples,'trigram scorer only; excludes encoder/policy/audit/HTTP/cold start')


def rate_cell(detection,family):
    data=detection['families'][family]
    return f"{data['detected']}/{data['episodes']}"


def main():
    path=ROOT/'results/metrics.json'
    metrics=json.loads(path.read_text())
    if len(metrics['runs'])!=3:raise ValueError('Three complete seeded evaluations required')
    metrics['environment'].pop('blas_threads',None)
    metrics['environment'].update(numpy_blas_backend=np.show_config(mode='dicts')['Build Dependencies']['blas']['name'],blas_thread_limit_requested=1,blas_threads_controllable=bool(threadpool_info()),threadpool_info=threadpool_info(),thread_limit_note='Apple Accelerate does not expose thread count through threadpoolctl; limit request is not a measured thread-count claim')
    test=load_split('test')
    metrics['baseline_rules']['latency']=measure_engine(RuleOnlyScorer(),test,'rules')
    vocabulary=json.loads((ROOT/'model/pal_vocab_v0.json').read_text())
    metrics['baseline_trigram']['latency']=measure_trigram(Trigram(vocabulary,load_split('train')),test)
    metrics['runs'][0]['combined_latency']=measure_engine(TransformerScorer(),test,'combined')
    for item in metrics['aggregate']:
        point=(0.01,0.001,0.0001).index(item['target_calibration_rate'])
        families={}
        for family in ('F1','F2','F3','F4','F5'):
            values=[run['operating_points'][point][item['system']]['detection']['families'][family]['rate'] for run in metrics['runs']]
            families[family]={'mean':statistics.mean(values),'sample_std':statistics.stdev(values),'seeds':len(values)}
        item['family_detection_across_seeds']=families
    metrics['claim_gates']={'beats_rules':False,'transformer_necessary':False,'size_adequacy_sweep':False,'total_p95_under_5ms':False,'novel_real_world_attacks':False,'measured_tradeoff':'Model catches all six authored episodes in all three seeds; trigram misses some but has lower false alarms. Rules already catch every authored episode. No superiority claim at equal false-alarm rates.'}
    path.write_text(json.dumps(metrics,indent=2)+'\n')
    run=metrics['runs'][0];point=run['operating_points'][1]
    rows=[('B0 · Rules',metrics['baseline_rules']['detection'],metrics['baseline_rules']['false_alarms_per_1000'],metrics['baseline_rules']['latency']['p95_ms']),('B1 · Trigram',metrics['baseline_trigram']['operating_points'][1]['detection'],metrics['baseline_trigram']['operating_points'][1]['false_alarms_per_1000'],metrics['baseline_trigram']['latency']['p95_ms']),('B2 · Transformer',point['B2_model_only']['detection'],point['B2_model_only']['false_alarms_per_1000'],run['latency']['p95_ms']),('B3 · Transformer + rules',point['B3_model_plus_rules']['detection'],point['B3_model_plus_rules']['false_alarms_per_1000'],run['combined_latency']['p95_ms'])]
    table='| System | F1 | F2 | F3 | F4 | F5 | False alarms / 1,000 benign actions | Short-episode p95 ms |\n|---|---:|---:|---:|---:|---:|---:|---:|\n'
    for name,detect,fa,p95 in rows:table+='| '+name+' | '+' | '.join(rate_cell(detect,f) for f in ('F1','F2','F3','F4','F5'))+f' | {fa:.3f} | {p95:.3f} |\n'
    text='# Measured results\n\nDefault seed 2026, nominal 0.1% benign calibration operating point. Counts are detected authored episodes / episodes, not real-world success rates. The full rule pack is stateful and contains cautious extra holds.\n\n'+table+'\nLatency stages differ: B0/B3 include structured PAL validation, policy and decision record; B1/B2 are scorer only. Every short benchmark has 10,000 calls after 100 warm-up calls, batch size one, CPU. None includes raw tool encoding, audit disk I/O, cold start, HTTP or cloud/network cost. Short workflows have at most 151 context/action tokens.\n\n'
    text+=f"Exact mature 256-token scorer: p50 **{run['rollover_latency']['p50_ms']:.3f} ms**, p95 **{run['rollover_latency']['p95_ms']:.3f} ms**, p99 **{run['rollover_latency']['p99_ms']:.3f} ms**, measured over 1,000 calls after 100 warm-up calls. The under-5-ms total p95 target is **not achieved** generally. Learned absolute positions require exact window recomputation.\n\n"
    text+='## Actual three-seed runs\n\n| Seed | Best step / 500 | Best benign validation CE, nats | Training seconds | Model-only test false alarms / 1,000 | Full-system test false alarms / 1,000 |\n|---|---:|---:|---:|---:|---:|\n'
    for r in metrics['runs']:
        p=r['operating_points'][1]
        text+=f"| {r['seed']} | {r['training']['bestStep']} | {r['training']['bestValidationLoss']:.6f} | {r['training']['elapsedSeconds']:.3f} | {p['B2_model_only']['false_alarms_per_1000']:.3f} | {p['B3_model_plus_rules']['false_alarms_per_1000']:.3f} |\n"
    text+='\n## Operating points, across three seeds\n\n| Nominal calibration rate | System | Mean test false alarms / 1,000 | Sample standard deviation across seeds |\n|---|---|---:|---:|\n'
    for a in metrics['aggregate']:text+=f"| {100*a['target_calibration_rate']:.2f}% | {a['system']} | {a['false_alarms_per_1000_mean']:.3f} | {a['false_alarms_per_1000_sample_std']:.3f} |\n"
    text+='\nAll three model runs detect all six authored attack episodes at every reported operating point. Rules already detect all six. The trigram misses F3/F5 and one F1 at the default point, but has fewer false alarms; these unequal observed false-alarm rates do not prove the Transformer is necessary. No parameter sweep or real-user evaluation was run.\n\nCalibration contains 10,860 actions but only 129 distinct context/action pairs. Its 0.1% and 0.01% default quantiles both equal 7.867925 bits because of 89 exact ties; conservative comparison yields zero calibration flags. Default held-out model test flags are 9.613/1,000, demonstrating distribution shift despite the nominal target. The full system flags 44.340/1,000, including cautious holds on legitimate interpreter/delegation activity. These values are not real-world guarantees.\n\nMachine: Apple M5 Pro, macOS 27.0.1, Python 3.12.14, NumPy 2.3.5, Apple Accelerate BLAS. A single-thread limit was requested, but Accelerate thread count is not exposed by threadpoolctl; it is not verified. Training used Node 24.19.0 and TensorFlow.js/WASM 4.22.0 through Pebble runtime 2.1.1.\n\nReproduce: `python eval/evaluate.py --seeds 2026,2027,2028 --benchmark-actions 10000` then `python eval/complete_report.py`. Raw latency samples, per-episode decisions, checkpoint hashes and all operating-point results are published alongside this file.\n'
    (ROOT/'results/METRICS.md').write_text(text)
    model_card='# Pebble Sentinel PAL Transformer model card\n\nA from-scratch **1,288,368-parameter** decoder-only model for experimental agent-action anomaly scoring. It is a distinct behavior model, not the existing two-million-parameter character PebbleLM and not a conversational assistant. Model source, original generated data and trained weights are MIT.\n\n## Architecture and training\n\n| Property | Value |\n|---|---|\n| Vocabulary | 51 closed word-level PAL tokens |\n| Context | 256 tokens |\n| Transformer layers | 5 |\n| Width / heads / head width | 144 / 4 / 36 |\n| Feed-forward width | 576, tanh GELU |\n| Normalization | Pre-LN, non-affine, epsilon 1e-5; final non-affine LN |\n| Embeddings | Learned token and position; tied output |\n| Biases / dropout | None / none |\n| Parameter tensors | 22; tokens 7,344 + positions 36,864 + blocks 1,244,160 |\n| Initialization | Seeded Gaussian 0.02; attention/output residual projections scaled by sqrt(2 × layers) |\n| Optimizer | AdamW, betas 0.9/0.95, decay 0.01, clip global gradient norm 1 |\n| Schedule | Peak 0.0015, 25-step warm-up, cosine to 10% of peak |\n| Batch / steps / tokens per run | 2 × 256 / 500 / 256,000 supervised next-token positions |\n| Actual seeds | 2026, 2027, 2028 |\n| Selection | Lowest 36-episode benign validation loss; default seed 2026 chosen before attack evaluation |\n\nGenerator, tokenizer, Transformer and the training schedule/loop are Pebble programs. TensorFlow.js/WASM supplies CPU tensor kernels and automatic differentiation; Pebble host primitives perform AdamW numerical updates. Python/NumPy is the numerical deployment scorer and evaluator, not a substitute trainer. Training started from new random weights; no text-LM checkpoint, real user trace or attack label was used to train the model.\n\nThe scorer computes max next-token negative log probability in bits over an action, conditioned on up to the last 256 past tokens. Exact-prefix KV caching agrees with a full reference; shifted windows are rebuilt because absolute positions change. Exported Pebble token-loss fixtures also agree with NumPy, including >256-token rollover. All position embeddings receive supervised gradients in full-length packed training batches; there are no dummy padding parameters to inflate the count.\n\n## Actual evaluation\n\n'+table+'\n'+f"Short scorer p95 {run['latency']['p95_ms']:.3f} ms over 10,000 measured calls; mature 256-token scorer p95 {run['rollover_latency']['p95_ms']:.3f} ms over 1,000. Timing excludes cold start, network and audit I/O. See [full measured results](results/METRICS.md) for stage definitions, all three seeds and every operating point.\n\n"
    model_card+='## Intended use and limitations\n\nUse for local research, shadow-mode observation and demonstrations of typed behavior monitoring. The human-readable PAL abstraction excludes document content and raw secrets, making decisions explainable. Hard rules remain the backbone. This is not a sandbox, security certification, general LLM or guarantee of safety.\n\nSynthetic workflows share motifs and repeat heavily; only 129 distinct calibration context/action pairs support the thresholds. The nominal 0.1%/0.01% calibration rates do not generalize to unseen legitimate templates: default model test flags 9.613/1,000 and full-system flags 44.340/1,000. Several benign interpreter/delegation actions conflict with cautious hard rules. All six authored episodes are already caught by the rule pack; the model does not demonstrate necessity or superior protection at equal false-alarm rates. Trigram catches fewer authored attacks but has lower false alarms. Perfect mimicry, encoding errors, trusted-host exfiltration and actions bypassing the adapter remain weaknesses.\n\nThe under 5 ms total p95 target fails for exact mature windows. Real-user traces, poisoning resistance, parameter/context sweeps and taint ablations were not evaluated. The separate upstream Hermes adapter routing smoke test is not a live-agent model-quality evaluation.\n\n## Reproduction and release\n\nSee [training instructions](model/README.md), [data card](DATA_CARD.md), [evaluation protocol](eval/README.md) and [SHA-256 provenance](results/provenance.json). Checkpoints for all three actual seeds, original templates/data, loss histories, calibration, attack scores, raw latency samples and measured results are committed. Node 24 and Python 3.12 were used on an Apple M5 Pro CPU. Dependency licenses retain their terms; all authored artifacts are MIT. AI assisted implementation and evaluation; no generated metric was accepted without executing the corresponding experiment.\n'
    (ROOT/'MODEL_CARD.md').write_text(model_card)
    print('Final metrics table and model card created from three actual seeded runs',flush=True)


if __name__=='__main__':main()
