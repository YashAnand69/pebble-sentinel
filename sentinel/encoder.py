from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse
import re
import shlex

FLAG_ORDER = ('tainted', 'sudo', 'pipe', 'encoded', 'remote-code', 'bulk', 'outside-cwd', 'new-host')

@dataclass(frozen=True)
class Effect:
    verb: str
    object: str
    channel: str
    flags: tuple[str, ...] = ()

    @property
    def sentence(self):
        return ' '.join((self.verb, self.object, 'via', self.channel, *self.flags, '.'))

    def to_dict(self):
        return {**asdict(self), 'sentence': self.sentence}

class Encoder:
    def __init__(self, project_root, allowed_hosts=(), protected_paths=()):
        self.root = Path(project_root).resolve()
        self.allowed_hosts = frozenset(allowed_hosts)
        self.protected_paths = frozenset(Path(p).expanduser().resolve() for p in protected_paths)

    def path_class(self, raw):
        raw = str(raw)
        path = Path(raw).expanduser()
        path = (self.root / path).resolve() if not path.is_absolute() else path.resolve()
        text = str(path)
        name = path.name.lower()
        if path in self.protected_paths or any(p in path.parents for p in self.protected_paths) or any(part in ('.sentinel','.sentinel-demo') for part in path.parts) or ('plugins' in path.parts and '.hermes' in path.parts) or 'pebble-sentinel' in path.parts and any(x in path.parts for x in ('policy','model','sentinel')):
            return 'guard-config'
        if name in ('.env', '.netrc', 'credentials', 'id_rsa', 'id_ed25519') or name.startswith('.env.') or any(x in path.parts for x in ('.ssh','.aws','.gnupg')):
            return 'secret-store'
        if name in ('.bashrc','.zshrc','.profile','.bash_profile'):
            return 'shell-rc'
        if 'cron' in text or 'crontab' in text:
            return 'cron-entry'
        if '.hermes' in path.parts:
            return 'skill-file' if 'skills' in path.parts else 'agent-config'
        if text.startswith(('/etc/','/usr/','/var/','/System/')):
            return 'system-path'
        if path.is_relative_to(self.root):
            return 'proj-config' if name in ('package.json','pyproject.toml','tsconfig.json') else 'proj-file'
        if text.startswith(('/tmp/','/private/tmp/')):
            return 'tmp-file'
        return 'home-dotfile' if name.startswith('.') else 'unknown-object'

    def net_class(self, raw):
        host = urlparse(str(raw)).hostname or ''
        if host in ('localhost','127.0.0.1','::1'):
            return 'net-local'
        if host in self.allowed_hosts:
            return 'net-allow'
        if host in ('pypi.org','registry.npmjs.org','files.pythonhosted.org'):
            return 'pkg-registry'
        return 'net-unknown'

    def encode(self, tool, arguments, tainted=False):
        try:
            if not isinstance(arguments, dict):
                arguments = {}
            flags = ['tainted'] if tainted else []
            name = str(tool).lower()
            def effect(verb, obj, channel, extra=()):
                fs = set(flags) | set(extra)
                return Effect(verb, obj, channel, tuple(x for x in FLAG_ORDER if x in fs))
            if name in ('terminal','shell','exec_command','bash'):
                return self._shell(str(arguments.get('command',arguments.get('cmd',''))), flags)
            if name in ('read_file','read','file_read','write_file','write','patch','edit_file','delete_file'):
                verb = 'read' if name in ('read_file','read','file_read') else 'delete' if name == 'delete_file' else 'edit' if name in ('patch','edit_file') else 'write'
                paths = arguments.get('paths') or [arguments.get('path', arguments.get('file_path', ''))]
                if isinstance(paths,str): paths = [paths]
                return [effect(verb,self.path_class(p) if p else 'unknown-object','file-tool', ('outside-cwd',) if p and not self._inside(p) else ()) for p in paths] or [effect(verb,'unknown-object','file-tool')]
            if name in ('web_search','web_fetch','fetch','browse'):
                obj = self.net_class(arguments.get('url',''))
                return [effect('fetch',obj,'web-tool',('new-host',) if obj == 'net-unknown' else ())]
            if name in ('http_post','send','network_send'):
                obj = self.net_class(arguments.get('url',''))
                return [effect('send',obj,'web-tool',('new-host',) if obj == 'net-unknown' else ())]
            if name in ('install_skill','skill_install'):
                return [effect('install','skill-file','skill',('remote-code',))]
            if name in ('delegate_task','spawn_agent'):
                return [effect('spawn','unknown-binary','skill')]
            return [effect('exec','unknown-binary','mcp' if name.startswith('mcp') else 'shell')]
        except Exception:
            return [Effect('exec','unknown-binary','shell',('tainted',) if tainted else ())]

    def _inside(self, raw):
        path = Path(str(raw)).expanduser()
        return ((self.root / path).resolve() if not path.is_absolute() else path.resolve()).is_relative_to(self.root)

    def _shell(self, command, inherited):
        base = set(inherited)
        if re.search(r'\bsudo\b', command): base.add('sudo')
        if '|' in command: base.add('pipe')
        if re.search(r'base64|\\x[0-9a-fA-F]{2}', command): base.add('encoded')
        result=[]
        def add(verb,obj,extra=()):
            fs = base | set(extra)
            e = Effect(verb,obj,'shell',tuple(x for x in FLAG_ORDER if x in fs))
            if e not in result: result.append(e)
        if not command.strip():
            add('exec','unknown-binary'); return result
        opaque = bool(re.search(r'\$\(|`|\$\{|\beval\b|\bsource\b|<<',command))
        for part in re.split(r'&&|\|\||[;\n|]', command):
            try: tokens=shlex.split(part, posix=True)
            except ValueError:
                add('exec','unknown-binary'); continue
            if not tokens: continue
            while tokens and (tokens[0] == 'sudo' or re.match(r'^\w+=',tokens[0])): tokens.pop(0)
            if not tokens: continue
            binary=Path(tokens[0]).name
            args=tokens[1:]
            for match in re.finditer(r'(?:>>?|\btee\s+(?:-a\s+)?)\s*([^\s;&|]+)', part):
                p=match.group(1).strip("'\"")
                add('write',self.path_class(p),('outside-cwd',) if not self._inside(p) else ())
            if binary in ('cat','head','tail','less','more','sed','awk','grep','rg','cp','mv'):
                candidates=[a for a in args if not a.startswith('-') and a not in ('>','>>')]
                if binary in ('sed','awk','grep','rg') and candidates: candidates=candidates[1:]
                sources=candidates[:-1] if binary in ('cp','mv') and len(candidates)>1 else candidates
                for p in sources:
                    if re.match(r'https?://',p): continue
                    add('read',self.path_class(p),('outside-cwd',) if not self._inside(p) else ())
                if binary in ('cp','mv') and len(candidates)>1: add('write',self.path_class(candidates[-1]))
                if binary=='sed' and any(a.startswith('-i') for a in args):
                    for p in candidates: add('edit',self.path_class(p))
            elif binary in ('rm','rmdir','unlink'):
                paths=[a for a in args if not a.startswith('-')]
                for p in paths:
                    extra=set()
                    if '*' in p or any('r' in a for a in args if a.startswith('-')): extra.add('bulk')
                    if not self._inside(p): extra.add('outside-cwd')
                    add('delete',self.path_class(p),extra)
            elif binary in ('curl','wget'):
                urls=re.findall(r'https?://[^\s\'"<>]+',part)
                sending=bool(re.search(r'--data|--upload|-d\b|-F\b|-T\b|-X\s*(POST|PUT|PATCH)',part))
                for a in args:
                    if a.startswith('@') and a!='@-': add('read',self.path_class(a[1:]))
                for i,a in enumerate(args):
                    if a in ('-T','--upload-file') and i+1<len(args): add('read',self.path_class(args[i+1]))
                for url in urls or ['']:
                    obj=self.net_class(url)
                    add('send' if sending else 'fetch',obj,('new-host',) if obj=='net-unknown' else ())
                if re.search(r'\|\s*(?:sudo\s+)?(?:bash|sh|python\w*|node)\b',command): add('exec','downloaded-code',('remote-code',))
            elif binary in ('bash','sh','zsh','python','python3','node','ruby','perl'):
                add('exec','interpreter')
                if '-c' in args or '-e' in args or re.search(r'\$|`',part): opaque=True
            elif binary in ('pytest','jest','vitest') or binary=='npm' and any(x in args for x in ('test','lint','check')):
                add('exec','test-runner')
            elif binary in ('make','vite','tsc') or binary=='npm' and 'build' in args: add('exec','build-tool')
            elif binary=='git':
                add('exec','vcs')
                if any(x in args for x in ('push','fetch','clone','pull')): add('send' if 'push' in args else 'fetch','net-unknown',('new-host',))
            elif binary in ('pip','pip3','uv','npm','pnpm','yarn'):
                add('exec','pkg-manager')
                if any(x in args for x in ('install','add','sync')): add('install','pkg-registry',('remote-code',))
            elif binary=='crontab': add('write','cron-entry')
            elif binary in ('echo','printf','pwd','ls','true','false'):
                if not any(e.verb=='write' for e in result): add('read','proj-file')
            else: add('exec','unknown-binary')
        if opaque: add('exec','unknown-binary')
        return result or [Effect('exec','unknown-binary','shell',tuple(inherited))]
