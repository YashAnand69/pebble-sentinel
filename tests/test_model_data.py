import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_workflow_template_splits_are_disjoint():
    workflows = json.loads((ROOT / 'model/workflows.json').read_text())
    ids = {split: {item['id'] for item in templates} for split, templates in workflows.items()}
    assert not ids['train'] & ids['validation']
    assert not ids['train'] & ids['test']
    assert not ids['validation'] & ids['test']
    sequences = {split: {tuple(item['actions']) for item in templates} for split, templates in workflows.items()}
    assert not sequences['train'] & sequences['validation']
    assert not sequences['train'] & sequences['test']


def test_generated_benign_pal_is_closed_and_taint_persists():
    vocabulary = set(json.loads((ROOT / 'model/pal_vocab_v0.json').read_text()))
    for path in (ROOT / 'model/data').glob('*.json'):
        if path.name == 'manifest.json':
            continue
        for episode in json.loads(path.read_text()):
            tainted = False
            for sentence in episode['actions']:
                words = sentence.split()
                assert set(words) <= vocabulary
                assert ('tainted' in words) == tainted
                assert words[2] == 'via' and words[-1] == '.'
                if words[0] == 'fetch' or words[3] == 'mcp':
                    tainted = True
            assert episode['tokens'][0] == 0
            assert episode['tokens'][-1] == 1
