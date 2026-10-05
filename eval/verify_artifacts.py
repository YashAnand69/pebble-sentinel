import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sentinel.scorer import TransformerScorer


def main():
    manifest = json.loads((ROOT / 'results/provenance.json').read_text())
    for item in manifest['files']:
        relative = Path(item['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Invalid artifact path')
        actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        if actual != item['sha256']:
            raise ValueError('Artifact hash mismatch: ' + item['path'])
    default = TransformerScorer()
    if not default.metadata['calibrated']:
        raise ValueError('Default trained checkpoint has no matching benign calibration')
    for seed in (2026, 2027, 2028):
        scorer = TransformerScorer(ROOT / f'model/weights/seed-{seed}.pebble-weights')
        if scorer.parameters != 1_288_368 or scorer.metadata['seed'] != seed:
            raise ValueError('Checkpoint parameter count or seed mismatch')
    print(f"Verified {len(manifest['files'])} SHA-256 artifacts, three real trained checkpoints and matching default calibration")


if __name__ == '__main__':
    main()
