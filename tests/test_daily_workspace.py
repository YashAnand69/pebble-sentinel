from pathlib import Path
import json
import pytest
from sentinel.daily_workspace import DailyWorkspace, WorkspaceRefusal, MAX_FILE_BYTES

class FamiliarScorer:
    metadata = {'kind': 'fixture-only', 'parameters': 0, 'calibrated': True}
    hold_threshold = 8.0
    def score(self, history, sentence):
        return 0.0

class UnusualScorer(FamiliarScorer):
    def score(self, history, sentence):
        return 30.0

@pytest.fixture
def root(tmp_path):
    (tmp_path / 'notes.md').write_text('Meeting notes\nReview the release.\n', encoding='utf8')
    return tmp_path


def test_real_read_and_atomic_write_callbacks(root):
    with DailyWorkspace(root, allow_writes=True, scorer=FamiliarScorer()) as workspace:
        read = workspace.call('read_file', {'path': 'notes.md'})
        assert read['executed'] and read['result']['content'].startswith('Meeting notes')
        written = workspace.call('write_file', {'path': 'summary.md', 'content': 'Reviewed the release.\n'})
        assert written['executed'] and (root / 'summary.md').read_text() == 'Reviewed the release.\n'
        assert workspace.callback_counts == {'read_file': 1, 'write_file': 1}
        assert workspace.file_effects == workspace.callback_counts
        assert workspace.status()['audit_chain_valid']
        assert 'Meeting notes' not in workspace.audit_path.read_text()


def test_read_only_default_is_a_hard_block_even_with_approval(root):
    approvals = []
    with DailyWorkspace(root, scorer=FamiliarScorer(), approval=lambda row: approvals.append(row) or True) as workspace:
        row = workspace.call('write_file', {'path': 'notes.md', 'content': 'Replacement'})
        assert not row['executed'] and row['decision']['decision'] == 'block'
        assert 'deny-daily-read-only' in row['decision']['rules']
        assert not approvals and workspace.callback_counts['write_file'] == 0
        with pytest.raises(WorkspaceRefusal):
            workspace._write_file('notes.md', 'Replacement')
    assert (root / 'notes.md').read_text().startswith('Meeting notes')


def test_pilot_anomaly_holds_and_human_approval_is_one_action(root):
    approvals = []
    def once(row):
        approvals.append(row['id'])
        return len(approvals) == 1
    with DailyWorkspace(root, scorer=UnusualScorer(), approval=once) as workspace:
        first = workspace.call('read_file', {'path': 'notes.md'})
        second = workspace.call('read_file', {'path': 'notes.md'})
        assert first['executed'] and first['decision']['decision'] == 'hold'
        assert not second['executed'] and second['decision']['decision'] == 'hold'
        assert workspace.callback_counts['read_file'] == 1
        assert len(approvals) == 2
        assert workspace.guard.block_threshold == float('inf')


def test_unapproved_and_unknown_calls_never_reach_a_callback(root):
    with DailyWorkspace(root, scorer=UnusualScorer()) as workspace:
        held = workspace.call('read_file', {'path': 'notes.md'})
        unknown = workspace.call('terminal', {'command': 'FIXTURE_NOT_EXECUTED'})
        assert not held['executed'] and not unknown['executed']
        assert workspace.callback_counts == {'read_file': 0, 'write_file': 0}
    with DailyWorkspace(root, scorer=FamiliarScorer(), approval=lambda row: True) as workspace:
        assert not workspace.call('unknown', {})['executed']
        assert workspace.callback_counts == {'read_file': 0, 'write_file': 0}


def test_hard_guard_tamper_cannot_be_approved(root):
    approved = []
    with DailyWorkspace(root, allow_writes=True, scorer=UnusualScorer(), approval=lambda row: approved.append(row) or True) as workspace:
        result = workspace.call('write_file', {'path': '.sentinel-demo/daily-audit.jsonl', 'content': 'FIXTURE_ONLY'})
        assert not result['executed'] and result['decision']['decision'] == 'block'
        assert 'deny-guard-tamper' in result['decision']['rules']
        assert not approved and workspace.callback_counts['write_file'] == 0
        assert workspace.guard.audit.verify()


@pytest.mark.parametrize('path', ['../outside.md', '/tmp/outside.md', 'nested/../../outside.md', './notes.md', '.git/config', '.env', '.env.production', '.netrc', 'credentials', 'id_rsa', 'id_ed25519', '.sentinel-demo/mode.json'])
def test_traversal_protected_and_secret_names_refused_before_dispatch(root, path):
    with DailyWorkspace(root, allow_writes=True, scorer=FamiliarScorer()) as workspace:
        for tool, arguments in [('read_file', {'path': path}), ('write_file', {'path': path, 'content': 'FIXTURE_ONLY'})]:
            result = workspace.call(tool, arguments)
            assert not result['executed'] and result['decision']['decision'] == 'block'
        assert workspace.callback_counts == {'read_file': 0, 'write_file': 0}
        with pytest.raises(WorkspaceRefusal):
            workspace._read_file(path)


def test_symlink_files_and_parent_directories_refused(root, tmp_path):
    target = root / 'safe-target.md'; target.write_text('LOCAL_FIXTURE')
    (root / 'alias.md').symlink_to(target)
    (root / 'alias-dir').symlink_to(root, target_is_directory=True)
    with DailyWorkspace(root, allow_writes=True, scorer=FamiliarScorer()) as workspace:
        for path in ('alias.md', 'alias-dir/notes.md'):
            assert not workspace.call('read_file', {'path': path})['executed']
            assert not workspace.call('write_file', {'path': path, 'content': 'CHANGED'})['executed']
            with pytest.raises(WorkspaceRefusal): workspace._read_file(path)
        assert workspace.callback_counts == {'read_file': 0, 'write_file': 0}
    assert target.read_text() == 'LOCAL_FIXTURE'


def test_size_utf8_permission_and_strict_argument_boundaries(root):
    (root / 'large.txt').write_bytes(b'x' * (MAX_FILE_BYTES + 1))
    (root / 'invalid.txt').write_bytes(b'\xff\xfe')
    (root / 'locked.txt').write_text('LOCAL_FIXTURE')
    (root / 'locked.txt').chmod(0o000)
    (root / 'readonly.txt').write_text('UNCHANGED')
    (root / 'readonly.txt').chmod(0o444)
    try:
        with DailyWorkspace(root, allow_writes=True, scorer=FamiliarScorer()) as workspace:
            for arguments in ({'path': 'large.txt'}, {'path': 'locked.txt'}, {'path': 'notes.md', 'url': 'INVALID'}, {'path': 7}):
                assert not workspace.call('read_file', arguments)['executed']
            assert workspace.callback_counts['read_file'] == 0
            assert not workspace.call('read_file', {'path': 'invalid.txt'})['executed']
            assert workspace.file_effects['read_file'] == 0
            for arguments in ({'path': 'new.txt', 'content': 'x' * (MAX_FILE_BYTES+1)}, {'path': 'new.txt', 'content': []}, {'path': 'readonly.txt', 'content': 'REPLACED'}):
                assert not workspace.call('write_file', arguments)['executed']
            assert workspace.callback_counts['write_file'] == 0
    finally:
        (root / 'locked.txt').chmod(0o600)
        (root / 'readonly.txt').chmod(0o600)
    assert not (root / 'new.txt').exists()
    assert (root / 'readonly.txt').read_text() == 'UNCHANGED'


def test_actual_released_model_is_the_default(root):
    with DailyWorkspace(root) as workspace:
        assert workspace.guard.scorer.metadata['kind'] == 'trained-pal-transformer'
        assert workspace.guard.scorer.metadata['calibrated']
        assert workspace.guard.hold_threshold == workspace.guard.scorer.hold_threshold
        assert workspace.guard.block_threshold == float('inf')
        result = workspace.call('read_file', {'path': 'notes.md'})
        assert result['executed']
        assert result['result']['content'].startswith('Meeting notes')
