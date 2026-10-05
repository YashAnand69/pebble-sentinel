import json
import pytest
from sentinel.daily_service import check_workspace
from sentinel.scorer import TransformerScorer
from sentinel.web_service import dispatch


@pytest.fixture(scope='module')
def scorer():
    return TransformerScorer()


def action(verb='read', obj='proj-file'):
    return {'verb': verb, 'object': obj, 'channel': 'file-tool', 'flags': []}


def check(scorer, current, history=None):
    return check_workspace({'history': history or [], 'action': current}, scorer, scorer.metadata)


def test_actual_model_allows_normal_local_read_write(scorer):
    code, read = check(scorer, action())
    assert code == 200 and read['decision'] == 'allow'
    code, write = check(scorer, action('write'), [action()])
    assert code == 200 and write['decision'] == 'allow'
    assert write['model']['parameters'] == 1288368 and write['policy'] == 'daily-workspace-v1'


def test_browser_scope_blocks_private_or_external_effects(scorer):
    for current in [action('read', 'secret-store'), action('write', 'guard-config'),
                    action('read', 'unknown-object'), {**action(), 'channel': 'mcp'},
                    {**action(), 'flags': ['outside-cwd']}]:
        code, response = check(scorer, current)
        assert code == 200 and response['decision'] == 'block'
        assert 'daily-workspace-scope' in response['record']['rules']


def test_anomalies_hold_without_weakening_hard_blocks(scorer):
    class Surprised:
        hold_threshold = scorer.hold_threshold
        metadata = scorer.metadata
        def score(self, **kw): return 100
    assert check(Surprised(), action())[1]['decision'] == 'hold'
    assert check(Surprised(), action('write', 'guard-config'))[1]['decision'] == 'block'


def test_daily_service_rejects_content_and_fabricated_history(scorer):
    cases = [
        {'history': [], 'action': {**action(), 'content': 'PRIVATE_MARKER'}},
        {'history': [action('read', 'secret-store')], 'action': action()},
        {'history': [action()] * 25, 'action': action()},
        {'history': [], 'action': {**action(), 'flags': [{}]}},
        {'history': [], 'action': action(), 'filename': 'PRIVATE_MARKER'},
    ]
    for payload in cases:
        code, response = check_workspace(payload, scorer, scorer.metadata)
        assert code == 400
        assert 'PRIVATE_MARKER' not in json.dumps(response)


def test_unready_model_cannot_authorize_local_action(scorer):
    code, response = check_workspace({'history': [], 'action': action()}, scorer, {**scorer.metadata, 'calibrated': False})
    assert code == 503


def test_daily_route_is_post_only_and_scope_is_stateless():
    assert dispatch('workspace-check', 'GET')[0] == 405
    assert dispatch('workspace-check', 'POST', {'history': [], 'action': action()})[0] == 200
