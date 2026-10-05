from sentinel.web_service import dispatch
from sentinel.engine import RuleOnlyScorer
import sentinel.web_service as service


def test_web_rejects_open_text_and_invalid_shapes():
    for actions in ([], ['rm -rf'], [{'verb': [], 'object': 'proj-file', 'channel': 'file-tool'}], [{'verb': 'read', 'object': 'proj-file', 'channel': 'file-tool', 'raw_secret': 'canary'}]):
        assert dispatch('check', 'POST', {'actions': actions})[0] == 400
    assert dispatch('simulate', 'POST', {'scenario': 'not-a-reviewed-scenario'})[0] == 400
    assert dispatch('check', 'GET')[0] == 405


def test_web_uses_same_policy_and_never_executes_user_actions(monkeypatch):
    class DemoScorer(RuleOnlyScorer):
        name = 'policy test fixture'
        parameters = 0
        sha256 = 'test-fixture'
        config = {}
    monkeypatch.setattr(service, 'SCORER', DemoScorer())
    code, result = dispatch('check', 'POST', {'actions': [{'verb': 'write', 'object': 'guard-config', 'channel': 'file-tool', 'flags': []}]})
    assert code == 200
    assert result['events'][0]['decision'] == 'block'
    assert result['execution'] == 'analysis only; no tools executed'
    assert result['events'][0]['rules'] == ['deny-guard-tamper']


def test_scenario_endpoint_has_reviewed_families():
    code, result = dispatch('scenarios')
    assert code == 200
    assert {item['family'] for item in result['scenarios']} >= {'F1', 'F2', 'F3', 'F4', 'F5'}
