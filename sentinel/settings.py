from pathlib import Path
import json

MODES={'learn','shadow','enforce'}

def read_mode(workspace):
    path=Path(workspace)/'mode.json'
    if not path.exists(): return 'enforce'
    config=json.loads(path.read_text())
    if not isinstance(config,dict) or set(config)!={'mode'} or config['mode'] not in MODES:
        raise ValueError('Invalid workspace mode configuration')
    return config['mode']
