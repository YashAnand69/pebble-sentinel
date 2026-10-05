from pathlib import Path
import argparse
import json
import sys
import tempfile
from sentinel.audit import digest
from sentinel.daily_workspace import DailyWorkspace


def interactive_approval(record):
    if not sys.stdin.isatty():
        return False
    print(f"Hold: {record['pebble']} Reason: {', '.join(record['rules']) or record['reason']}", file=sys.stderr)
    print('Approve this one action? Type yes: ', end='', file=sys.stderr, flush=True)
    return input().strip().lower() == 'yes'


def demo():
    with tempfile.TemporaryDirectory(prefix='pebble-daily-workspace-') as project:
        root = Path(project)
        root.joinpath('notes.md').write_text('Daily review\nReview the project changes and write a short report.\n', encoding='utf-8')
        approvals = []
        approved_digest = None
        approval_available = True
        def fixture_approval(record):
            nonlocal approval_available
            if approval_available and record['tool'] == 'write_file' and record['args_digest'] == approved_digest:
                approval_available = False
                approvals.append(record['id'])
                return True
            return False
        with DailyWorkspace(root, allow_writes=True, approval=fixture_approval) as workspace:
            read = workspace.call('read_file', {'path': 'notes.md'})
            if not read['executed']:
                return {'profile': 'daily-workspace-pilot', 'error': 'The released model held the first demonstration read. No automatic approval was used.', 'events': [read], **workspace.status()}
            content = read['result']['content']
            summary = '# Daily summary\n\nReviewed ' + str(len(content.splitlines())) + ' lines of synthetic meeting notes.\nNext step: review the changes and prepare a short report.\n'
            write_arguments = {'path': 'summary.md', 'content': summary}
            approved_digest = 'sha256:' + digest(write_arguments)
            written = workspace.call('write_file', write_arguments)
            tamper = workspace.call('write_file', {'path': '.sentinel-demo/daily-audit.jsonl', 'content': 'SYNTHETIC_FIXTURE_ONLY'})
            unknown = workspace.call('run_shell', {'command': 'FIXTURE_NOT_EXECUTED'})
            return {**workspace.status(), 'events': [read, written, tamper, unknown],
                    'summary_file_created': root.joinpath('summary.md').is_file(),
                    'fixture_approvals': len(approvals),
                    'fixture_approval_scope': 'At most one hold for the exact synthetic summary-write arguments; --demo authorizes this fixture only',
                    'network_calls': 0, 'shell_commands': 0,
                    'temporary_workspace_deleted_after_run': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description='A scoped local file workspace, guarded by the actual Sentinel model and hard rules')
    parser.add_argument('--demo', action='store_true', help='Run real safe file callbacks in a fresh temporary workspace')
    parser.add_argument('--project', type=Path, help='An operator-selected existing project root')
    parser.add_argument('--requests', type=Path, help='A JSON array of read_file/write_file requests')
    parser.add_argument('--allow-writes', action='store_true', help='Operator opt-in; otherwise the project is read-only')
    parser.add_argument('--interactive', action='store_true', help='Ask a human on an interactive terminal for each held action')
    args = parser.parse_args(argv)
    if args.demo:
        if args.project or args.requests or args.allow_writes or args.interactive:
            parser.error('--demo runs only its own fresh temporary fixture; do not combine it with project options')
        result = demo()
    else:
        if not args.project or not args.requests:
            parser.error('Choose --demo, or provide --project and --requests')
        if args.requests.stat().st_size > 1024 * 1024:
            parser.error('The requests file must be smaller than 1 MiB')
        requests = json.loads(args.requests.read_text(encoding='utf-8'))
        if not isinstance(requests, list) or len(requests) > 100:
            parser.error('Use a JSON array of at most 100 requests')
        if any(not isinstance(item, dict) or set(item) != {'tool', 'arguments'} or not isinstance(item['tool'], str) or not isinstance(item['arguments'], dict) for item in requests):
            parser.error('Each request must contain only a tool name and an arguments object')
        with DailyWorkspace(args.project, allow_writes=args.allow_writes, approval=interactive_approval if args.interactive else None) as workspace:
            events = [workspace.call(item['tool'], item['arguments']) for item in requests]
            result = {**workspace.status(), 'events': events}
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
