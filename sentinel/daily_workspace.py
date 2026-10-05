from pathlib import Path, PurePosixPath
from contextlib import contextmanager
import math
import os
import secrets
import stat
import threading
import uuid
from .adapters.local import LocalHarness
from .audit import digest
from .encoder import Effect
from .engine import Sentinel

MAX_FILE_BYTES = 256 * 1024
TOOLS = frozenset(('read_file', 'write_file'))

class WorkspaceRefusal(ValueError):
    pass

class DailyWorkspace:
    def __init__(self, project_root, *, allow_writes=False, approval=None, scorer=None):
        if type(allow_writes) is not bool:
            raise ValueError('allow_writes must be an operator-set boolean')
        requested = Path(project_root).expanduser()
        if requested.is_symlink():
            raise WorkspaceRefusal('The project root must not be a symlink')
        self.root = requested.resolve(strict=True)
        if not self.root.is_dir():
            raise WorkspaceRefusal('Choose an existing project directory')
        self.allow_writes = allow_writes
        self.session = 'daily-' + uuid.uuid4().hex
        self.lock = threading.RLock()
        self.callback_counts = {'read_file': 0, 'write_file': 0}
        self.file_effects = {'read_file': 0, 'write_file': 0}
        self._root_fd = None
        self._root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            state = self.root / '.sentinel-demo'
            if state.is_symlink():
                raise WorkspaceRefusal('The audit directory must not be a symlink')
            state.mkdir(mode=0o700, exist_ok=True)
            self.audit_path = state / 'daily-audit.jsonl'
            if self.audit_path.is_symlink():
                raise WorkspaceRefusal('The audit file must not be a symlink')
            if scorer is None:
                from .scorer import TransformerScorer
                scorer = TransformerScorer()
            hold_threshold = float(getattr(scorer, 'hold_threshold', 0.0))
            if not math.isfinite(hold_threshold) or hold_threshold < 0:
                raise ValueError('The scorer has no valid hold threshold')
            self.guard = Sentinel(self.root, mode='enforce', scorer=scorer, audit_path=self.audit_path,
                                  hold_threshold=hold_threshold, block_threshold=float('inf'))
            self.guard.policy.rules.extend([
                {'id': 'deny-daily-invalid-path', 'verdict': 'deny', 'verbs': ['read', 'write'],
                 'objects': ['unknown-object'], 'channels': ['file-tool']},
                {'id': 'deny-daily-secret-access', 'verdict': 'deny', 'verbs': ['read', 'write'],
                 'objects': ['secret-store'], 'channels': ['file-tool']},
                {'id': 'deny-daily-protected-read', 'verdict': 'deny', 'verbs': ['read'],
                 'objects': ['guard-config'], 'channels': ['file-tool']},
            ])
            if not allow_writes:
                self.guard.policy.rules.append({'id': 'deny-daily-read-only', 'verdict': 'deny', 'verbs': ['write']})
            self.harness = LocalHarness(self.guard, {'read_file': self._read_file, 'write_file': self._write_file}, approval)
        except Exception:
            self.close()
            raise

    def close(self):
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @staticmethod
    def _parts(path):
        if not isinstance(path, str) or not path or len(path) > 512 or '\x00' in path or '\\' in path:
            raise WorkspaceRefusal('Use a short, relative project filename')
        parsed = PurePosixPath(path)
        raw_parts = path.split('/')
        if parsed.is_absolute() or any(part in ('', '.', '..') for part in raw_parts):
            raise WorkspaceRefusal('Absolute paths and traversal are not permitted')
        for part in parsed.parts:
            name = part.lower()
            if name in ('.git', '.sentinel', '.sentinel-demo', '.netrc', 'credentials', 'id_rsa', 'id_ed25519') or name.startswith('.env'):
                raise WorkspaceRefusal('This filename is protected in the daily workspace')
        return parsed.parts

    @contextmanager
    def _parent(self, path):
        parts = self._parts(path)
        if self._root_fd is None:
            raise WorkspaceRefusal('This workspace is closed')
        directory = os.dup(self._root_fd)
        try:
            for part in parts[:-1]:
                next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = next_directory
            yield directory, parts[-1]
        except OSError as error:
            raise WorkspaceRefusal('The path is unavailable, outside scope, or contains a symlink') from error
        finally:
            os.close(directory)

    def _validate_arguments(self, tool, arguments):
        fields = {'path'} if tool == 'read_file' else {'path', 'content'}
        if not isinstance(arguments, dict) or set(arguments) != fields:
            raise WorkspaceRefusal('The request contains unsupported arguments')
        if tool == 'write_file':
            if not isinstance(arguments['content'], str):
                raise WorkspaceRefusal('Content must be UTF-8 text')
            try:
                size = len(arguments['content'].encode('utf-8'))
            except UnicodeError as error:
                raise WorkspaceRefusal('Content must be UTF-8 text') from error
            if size > MAX_FILE_BYTES:
                raise WorkspaceRefusal('Text files are limited to 256 KiB')
        with self._parent(arguments['path']) as (directory, name):
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise WorkspaceRefusal('Only regular files are permitted; symlinks are refused')
            if tool == 'read_file' and not info.st_mode & 0o444:
                raise WorkspaceRefusal('The selected file is not readable')
            if tool == 'write_file' and not info.st_mode & 0o222:
                raise WorkspaceRefusal('The destination is read-only')
            if tool == 'read_file' and info.st_size > MAX_FILE_BYTES:
                raise WorkspaceRefusal('Text files are limited to 256 KiB')

    def _read_file(self, path):
        self._validate_arguments('read_file', {'path': path})
        self.callback_counts['read_file'] += 1
        with self._parent(path) as (directory, name):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                    raise WorkspaceRefusal('Only UTF-8 regular files up to 256 KiB are permitted')
                raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise WorkspaceRefusal('Text files are limited to 256 KiB')
        try:
            content = raw.decode('utf-8')
        except UnicodeError as error:
            raise WorkspaceRefusal('The selected file is not UTF-8 text') from error
        self.file_effects['read_file'] += 1
        return {'content': content, 'bytes': len(raw)}

    def _write_file(self, path, content):
        if not self.allow_writes:
            raise WorkspaceRefusal('This workspace is read-only; only an operator can opt in to writes')
        self._validate_arguments('write_file', {'path': path, 'content': content})
        raw = content.encode('utf-8')
        self.callback_counts['write_file'] += 1
        with self._parent(path) as (directory, name):
            temporary = '.daily-' + secrets.token_hex(12) + '.tmp'
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    info = None
                if info and (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)):
                    raise WorkspaceRefusal('The destination changed into an unsafe file')
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
        self.file_effects['write_file'] += 1
        return {'written': True, 'bytes': len(raw)}

    def _refusal(self, tool, arguments, message):
        try:
            args_digest = digest(arguments)
        except (ValueError, TypeError):
            args_digest = digest({'invalid_arguments': True})
        verb = 'read' if tool == 'read_file' else 'write'
        effects = self.guard.encoder.encode(tool, arguments, self.guard.state(self.session).tainted)
        if not effects or any(effect.object not in ('guard-config', 'secret-store') for effect in effects):
            effects = [Effect(verb, 'unknown-object', 'file-tool')]
        record = self.guard._inspect(effects, tool, args_digest, self.session)
        self.guard.commit_result(record, executed=False)
        return {'executed': False, 'decision': record, 'error': message}

    def call(self, tool, arguments):
        with self.lock:
            if not isinstance(tool, str) or tool not in TOOLS:
                try:
                    digest(arguments)
                    safe_arguments = arguments
                except (TypeError, ValueError):
                    safe_arguments = {'invalid_arguments': True}
                record = self.guard.inspect('mcp_unknown', safe_arguments, self.session)
                self.guard.commit_result(record, executed=False)
                return {'executed': False, 'decision': record, 'error': 'This workspace provides only read_file and write_file; the unsupported tool was not dispatched'}
            try:
                self._validate_arguments(tool, arguments)
            except (WorkspaceRefusal, ValueError, TypeError) as error:
                return self._refusal(tool, arguments, str(error))
            try:
                return self.harness.call(tool, arguments, self.session)
            except (OSError, WorkspaceRefusal) as error:
                return {'executed': False, 'error': type(error).__name__, 'detail': 'The file operation could not complete within the workspace boundary'}

    def status(self):
        return {'profile': 'daily-workspace-pilot', 'read_only': not self.allow_writes,
                'model': self.guard.scorer.metadata, 'anomaly_response': 'hold',
                'callback_counts': dict(self.callback_counts), 'file_effects': dict(self.file_effects),
                'audit_chain_valid': self.guard.audit.verify()}
