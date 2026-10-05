from pathlib import Path
import yaml

class Policy:
    def __init__(self, path=None):
        path = Path(path) if path else Path(__file__).resolve().parent.parent / 'policy/default.yaml'
        config = yaml.safe_load(path.read_text())
        self.rules = config['rules']
        if not isinstance(self.rules,list): raise ValueError('Rules must be a list')
        for rule in self.rules:
            if rule.get('verdict') not in ('allow','hold','deny') or not isinstance(rule.get('id'),str): raise ValueError('Invalid policy')
            if set(rule) - {'id','verdict','verbs','objects','channels','flags_any','tainted','secret_seen'}: raise ValueError('Unknown policy field')

    def matches(self, effect, state):
        result=[]
        for rule in self.rules:
            if 'verbs' in rule and effect.verb not in rule['verbs']: continue
            if 'objects' in rule and effect.object not in rule['objects']: continue
            if 'channels' in rule and effect.channel not in rule['channels']: continue
            if 'flags_any' in rule and not set(effect.flags).intersection(rule['flags_any']): continue
            if 'tainted' in rule and (state.tainted or 'tainted' in effect.flags) != rule['tainted']: continue
            if 'secret_seen' in rule and state.secret_seen != rule['secret_seen']: continue
            result.append(rule)
        return result

    def verdict(self, effect, state):
        rules=self.matches(effect,state)
        verdict='deny' if any(r['verdict']=='deny' for r in rules) else 'hold' if any(r['verdict']=='hold' for r in rules) else 'allow'
        return verdict,[r['id'] for r in rules]
