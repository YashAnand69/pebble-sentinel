from pathlib import Path
import json
import threading

from .simulation import list_scenarios, run_simulation, evaluate_actions
from .engine import VERBS, OBJECTS, CHANNELS
from .encoder import FLAG_ORDER

ROOT = Path(__file__).resolve().parent.parent
SCORER = None
MODEL_LOCK = threading.RLock()


def model_scorer():
    global SCORER
    if SCORER is None:
        from .scorer import TransformerScorer
        SCORER = TransformerScorer()
    return SCORER


def model_info(scorer):
    return {
        **scorer.metadata,
        'kind': 'transformer',
        'name': scorer.name,
        'parameters': scorer.parameters,
        'sha256': scorer.sha256,
        'config': scorer.config,
        'trained_in': 'Pebble',
        'inference_backend': 'NumPy CPU',
        'license': 'MIT',
    }


def dispatch(route, method='GET', payload=None):
    if route == 'scenarios' and method == 'GET':
        return 200, {'scenarios': list_scenarios(), 'execution': 'reviewed fixture simulation only'}
    if route == 'vocabulary' and method == 'GET':
        return 200, {'verbs': sorted(VERBS), 'objects': sorted(OBJECTS), 'channels': sorted(CHANNELS), 'flags': list(FLAG_ORDER)}
    if route == 'evaluate' and method == 'GET':
        path = ROOT / 'results' / 'metrics.json'
        if not path.is_file():
            return 503, {'error': 'Measured evaluation is not available yet.'}
        return 200, json.loads(path.read_text())
    if route == 'health' and method == 'GET':
        with MODEL_LOCK:
            scorer = model_scorer()
            return 200, {'status': 'ready', 'product': 'Pebble Sentinel', 'model': model_info(scorer), 'hosted_scope': 'simulation and analysis only; no visitor tools executed'}
    if route not in ('simulate', 'check'):
        return 404, {'error': 'Unknown endpoint.'}
    if method != 'POST':
        return 405, {'error': 'This endpoint requires POST.'}
    if not isinstance(payload, dict):
        return 400, {'error': 'Request must be a JSON object.'}
    mode = payload.get('mode', 'enforce')
    if mode not in ('learn', 'shadow', 'enforce'):
        return 400, {'error': 'Choose learn, shadow or enforce mode.'}
    if route == 'simulate':
        scenario = payload.get('scenario')
        if not isinstance(scenario, str) or scenario not in {item['id'] for item in list_scenarios()}:
            return 400, {'error': 'Choose a reviewed scenario from the scenario list.'}
        with MODEL_LOCK:
            scorer = model_scorer()
            result = run_simulation(scenario, mode=mode, scorer=scorer, local_effects=False)
            result['model'] = model_info(scorer)
        return 200, result
    actions = payload.get('actions')
    if not isinstance(actions, list) or not 1 <= len(actions) <= 32:
        return 400, {'error': 'Provide between 1 and 32 typed actions.'}
    for action in actions:
        if not isinstance(action, dict) or set(action) - {'verb', 'object', 'channel', 'flags'}:
            return 400, {'error': 'An action must contain only verb, object, channel and flags.'}
        if any(not isinstance(action.get(key), str) for key in ('verb', 'object', 'channel')) or action.get('verb') not in VERBS or action.get('object') not in OBJECTS or action.get('channel') not in CHANNELS:
            return 400, {'error': 'Action values must come from the closed vocabulary.'}
        flags = action.get('flags', [])
        if not isinstance(flags, list) or len(flags) > len(FLAG_ORDER) or any(flag not in FLAG_ORDER for flag in flags):
            return 400, {'error': 'Action flags must come from the closed vocabulary.'}
    with MODEL_LOCK:
        scorer = model_scorer()
        result = evaluate_actions(actions, mode=mode, scorer=scorer)
        result['model'] = model_info(scorer)
    return 200, result
