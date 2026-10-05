"""Typed checks for the browser's consent-based local workspace.

This endpoint cannot access client files. It evaluates one action against the
client's bounded, completed-action history; it is not a remote agent session.
"""
import math
import uuid

from .encoder import Effect, FLAG_ORDER
from .engine import Sentinel, VERBS, OBJECTS, CHANNELS

POLICY = 'daily-workspace-v1'
PERMITTED = {('read', 'proj-file'), ('read', 'proj-config'), ('write', 'proj-file')}


def valid_action(action):
    if not isinstance(action, dict) or set(action) - {'verb', 'object', 'channel', 'flags'}:
        return False
    if any(not isinstance(action.get(key), str) for key in ('verb', 'object', 'channel')):
        return False
    flags = action.get('flags', [])
    return (action['verb'] in VERBS and action['object'] in OBJECTS
            and action['channel'] in CHANNELS and isinstance(flags, list)
            and len(flags) <= len(FLAG_ORDER)
            and all(isinstance(flag, str) and flag in FLAG_ORDER for flag in flags))


def in_scope(action):
    return ((action['verb'], action['object']) in PERMITTED
            and action['channel'] == 'file-tool' and not action.get('flags'))


def check_workspace(payload, scorer, model):
    if not isinstance(payload, dict) or set(payload) != {'history', 'action'}:
        return 400, {'error': 'Provide only completed typed history and one typed action.'}
    history, action = payload['history'], payload['action']
    if (not isinstance(history, list) or len(history) > 24
            or any(not valid_action(item) or not in_scope(item) for item in history)
            or not valid_action(action)):
        return 400, {'error': 'Use at most 24 completed workspace actions and the closed action vocabulary.'}
    if model.get('parameters') != 1288368 or model.get('calibrated') is not True:
        return 503, {'error': 'The calibrated guard is not ready. No local action should run.'}
    # Pilot policy: unfamiliar model behavior asks the person, rather than
    # denying ordinary daily work. Hard denies retain their normal precedence.
    guard = Sentinel(scorer=scorer, block_threshold=math.inf)
    session = uuid.uuid4().hex
    state = guard.state(session)
    state.history = [Effect(item['verb'], item['object'], item['channel']).sentence for item in history]
    state.seq = len(history)
    record = guard.inspect_actions([action], session=session)
    if not in_scope(action):
        record['decision'] = record['would_have'] = 'block'
        record['rules'] = list(dict.fromkeys([*record['rules'], 'daily-workspace-scope']))
        record['reason'] = 'rule'
    guard.commit_result(record, executed=False)
    return 200, {
        'decision': record['decision'], 'record': record, 'model': model,
        'policy': POLICY,
        'scope': 'Only this website\'s local file opening and download preparation; no server file access.',
        'anomaly_policy': 'Human approval for anomalies; hard-rule and workspace-scope violations block.',
    }
