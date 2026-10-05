from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import platform
import os
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    runtime=json.loads((ROOT/'model/node_modules/pebble/package.json').read_text())
    files=[]
    selected=[]
    for folder in ('model/data','model/reports','model/weights'):
        selected+=list((ROOT/folder).glob('*'))
    selected+=list((ROOT/'model').glob('*.pebble'))+list((ROOT/'model').glob('*.json'))
    selected+=list((ROOT/'sentinel/scorer').glob('*.py'))+list((ROOT/'eval').glob('*.py'))
    selected+=[ROOT/f'results/{name}' for name in ('metrics.json','METRICS.md','calibration.json','attack-scores.json','benign-score-summary.json','latency-samples.json','rollover-latency-samples.json','rules-latency-samples.json','trigram-latency-samples.json','combined-latency-samples.json','training-curve.svg','training-curve.png')]
    for path in sorted(set(selected)):
        if path.is_file():files.append({'path':str(path.relative_to(ROOT)),'bytes':path.stat().st_size,'sha256':digest(path)})
    node = subprocess.run(["node", "--version"], capture_output=True, text=True, check=True).stdout.strip().removeprefix("v")
    measured = json.loads((ROOT / "results/metrics.json").read_text())["environment"]
    if platform.system() == "Darwin":
        memory_bytes = int(subprocess.run(["/usr/sbin/sysctl", "-n", "hw.memsize"], capture_output=True, text=True, check=True).stdout)
    else:
        memory_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    reports=[json.loads((ROOT/f'model/reports/seed-{seed}.json').read_text()) for seed in (2026,2027,2028)]
    metadata={'schema_version':1,'created_utc':datetime.now(timezone.utc).isoformat(),'project':'Pebble Sentinel PAL behavior model','license':'MIT','parameters':1_288_368,'default_seed':2026,'config':reports[0]['config'],'runtime':{'package':runtime['name'],'version':runtime['version'],'source_commit':runtime['sourceCommit'],'release_url':'https://github.com/YashAnand69/pebble/releases/download/v2.1.1/pebble-runtime-2.1.1.tgz','node':node,'tensorflow_js':'4.22.0','tensor_backend':'wasm','trainer_language':'Pebble','host_boundary':'TensorFlow.js/WASM numerical kernels/autodiff; host AdamW primitives; NumPy deployment inference/evaluation'},'machine':{'cpu':measured['cpu'],'memory_gib':memory_bytes/(1024**3),'machine':platform.machine(),'python':platform.python_version(),'training_gpu':False,'inference_gpu':False},'commands':['cd model && npm ci','npm run prepare:data','npm run train -- --seed 2026 --steps 500','npm run train -- --seed 2027 --steps 500','npm run train -- --seed 2028 --steps 500','npm run parity','cd .. && python eval/evaluate.py --seeds 2026,2027,2028 --benchmark-actions 10000','python eval/complete_report.py','python eval/write_provenance.py','python eval/verify_artifacts.py'],'training_runs':reports,'selection':'Lowest benign validation loss within each seed; default seed 2026 fixed before attacks; no old PebbleLM weights used','corpus':'Original synthetic MIT benign PAL workflows, generator seed 20261005, template splits; no real private traces or attack training','limitations':'Synthetic repeated workflows; nominal low-FAR quantiles do not generalize; rules catch all authored families; 5ms total mature-window target not met; no model-necessity or real-world novelty claim','files':files}
    (ROOT/'results/provenance.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(f'Wrote {len(files)} source/data/checkpoint/result SHA-256 entries')


if __name__=='__main__':main()
