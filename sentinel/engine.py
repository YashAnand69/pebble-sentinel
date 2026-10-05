from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import math
import threading
import time
from .encoder import Encoder, Effect, FLAG_ORDER
from .policy import Policy
from .audit import AuditLog, digest

VERBS={'read','write','edit','delete','exec','fetch','send','install','spawn'}
OBJECTS={'proj-file','proj-config','home-dotfile','secret-store','system-path','tmp-file','skill-file','agent-config','guard-config','shell-rc','cron-entry','test-runner','build-tool','vcs','pkg-manager','interpreter','unknown-binary','downloaded-code','net-local','net-allow','net-unknown','pkg-registry','unknown-object'}
CHANNELS={'shell','file-tool','web-tool','mcp','skill'}

@dataclass
class SessionState:
    tainted: bool=False
    secret_seen: bool=False
    history: list[str]=field(default_factory=list)
    seq: int=0

class RuleOnlyScorer:
    metadata={'kind':'rules-only','parameters':0,'calibrated':False}
    def score(self, history, sentence): return 0.0

class Sentinel:
    def __init__(self, project_root='.', mode='enforce', scorer=None, audit_path=None, rules_path=None, hold_threshold=None, block_threshold=None, allowed_hosts=()):
        if mode not in ('learn','shadow','enforce'): raise ValueError('Invalid mode')
        self.mode=mode
        self.encoder=Encoder(project_root,allowed_hosts,protected_paths=[p for p in (audit_path,rules_path) if p])
        self.policy=Policy(rules_path)
        self.scorer=scorer or RuleOnlyScorer()
        self.hold_threshold=hold_threshold if hold_threshold is not None else getattr(self.scorer,'hold_threshold',float('inf'))
        self.block_threshold=block_threshold if block_threshold is not None else getattr(self.scorer,'block_threshold',float('inf'))
        if self.hold_threshold>self.block_threshold: raise ValueError('Hold threshold exceeds block threshold')
        self.audit=AuditLog(audit_path) if audit_path else None
        self.sessions={}
        self.lock=threading.RLock()
        self.pending={}

    def state(self, session):
        return self.sessions.setdefault(session,SessionState())

    def inspect(self, tool, arguments, session='demo'):
        effects=self.encoder.encode(tool,arguments,self.state(session).tainted)
        return self._inspect(effects, tool, digest(arguments), session)

    def inspect_actions(self, actions, session='demo'):
        effects=[]
        for a in actions:
            if set(a)-{'verb','object','channel','flags'}: raise ValueError('Unknown action field')
            flags=set(a.get('flags',[]))
            if a.get('verb') not in VERBS or a.get('object') not in OBJECTS or a.get('channel') not in CHANNELS or flags-set(FLAG_ORDER): raise ValueError('Action outside closed vocabulary')
            if self.state(session).tainted: flags.add('tainted')
            effects.append(Effect(a['verb'],a['object'],a['channel'],tuple(f for f in FLAG_ORDER if f in flags)))
        if not effects: raise ValueError('At least one action required')
        return self._inspect(effects,'structured-action',digest(actions),session)

    def _inspect(self,effects,tool,args_digest,session):
        with self.lock:
            start=time.perf_counter()
            state=self.state(session)
            state.seq+=1
            working=SessionState(state.tainted,state.secret_seen,list(state.history),state.seq)
            for pending_session,pending_effects,pending_decision in self.pending.values():
                if pending_session==session and pending_decision!='block':
                    for pending_effect in pending_effects: self._ingest(working,pending_effect)
            initial_taint=working.tainted
            initial_secret=working.secret_seen
            ids=[]; scores=[]; verdicts=[]; error=None
            try:
                processed=[]
                for effect in effects:
                    if working.tainted and 'tainted' not in effect.flags:
                        effect=replace(effect,flags=tuple(f for f in FLAG_ORDER if f in set(effect.flags)|{'tainted'}))
                    processed.append(effect)
                    if self.mode!='learn':
                        verdict,matched=self.policy.verdict(effect,working)
                        ids.extend(matched); verdicts.append(verdict)
                        score=float(self.scorer.score(history=working.history,sentence=effect.sentence))
                        if not math.isfinite(score) or score<0: raise ValueError('Invalid scorer output')
                        scores.append(score)
                    self._ingest(working,effect)
                    working.history.append(effect.sentence)
                effects=processed
                surprise=max(scores) if scores else None
                would='block' if 'deny' in verdicts or surprise is not None and surprise>=self.block_threshold else 'hold' if 'hold' in verdicts or surprise is not None and surprise>=self.hold_threshold else 'allow'
                reason='rule' if ids else 'surprise' if would!='allow' else 'normal'
            except Exception as exc:
                surprise=None; would='block' if 'deny' in verdicts else 'hold'; reason='error'; error=type(exc).__name__
            decision=would if self.mode=='enforce' else 'allow'
            record={'id':f'{digest(session)[:8]}-{state.seq:06d}','ts':datetime.now(timezone.utc).isoformat(),'session':digest(session)[:16],'seq':state.seq,'tool':str(tool) if str(tool) in ('terminal','read_file','write_file','patch','web_fetch','web_search','http_post','install_skill','structured-action') else 'other-tool','pebble':' '.join(e.sentence for e in effects),'actions':[e.to_dict() for e in effects],'args_digest':'sha256:'+args_digest,'surprise_bits':surprise,'rules':list(dict.fromkeys(ids)),'decision':decision,'would_have':would,'mode':self.mode,'reason':reason,'tainted':initial_taint,'secret_seen':initial_secret,'latency_ms':(time.perf_counter()-start)*1000,'model':getattr(self.scorer,'metadata',{'kind':'custom'})}
            if error: record['error']=error
            if self.audit:
                try: record=self.audit.append(record)
                except Exception:
                    record.update(decision=('block' if would=='block' else 'hold') if self.mode=='enforce' else 'allow',would_have='block' if would=='block' else 'hold',reason='error',error='AuditWriteError')
            self.pending[record['id']]=(session,effects,record['decision'])
            return record

    def commit_result(self, record, executed=True, human_approved=False, output_observed=False):
        with self.lock:
            item=self.pending.pop(record['id'],None)
            if item is None: return
            session,effects,decision=item
            if not (executed or output_observed) or decision=='block' or decision=='hold' and not human_approved: return
            state=self.state(session)
            for effect in effects:
                self._ingest(state,effect)
                state.history.append(effect.sentence)
            tokens=' '.join(state.history).split()
            while len(state.history)>1 and len(tokens)-len(state.history[0].split())>=256:
                state.history.pop(0); tokens=' '.join(state.history).split()

    @staticmethod
    def _ingest(state,effect):
        if 'tainted' in effect.flags: state.tainted=True
        if effect.verb=='read' and effect.object=='secret-store': state.secret_seen=True
        if effect.channel=='mcp' or effect.verb=='fetch' or effect.verb=='read' and 'outside-cwd' in effect.flags: state.tainted=True

    def set_mode(self, mode):
        if mode not in ('learn','shadow','enforce'): raise ValueError('Invalid mode')
        self.mode=mode
        if self.audit: self.audit.append({'event':'mode-change','mode':mode,'ts':datetime.now(timezone.utc).isoformat()})

    def clear_taint(self,session):
        self.state(session).tainted=False
        if self.audit: self.audit.append({'event':'human-clear-taint','session':digest(session)[:16],'ts':datetime.now(timezone.utc).isoformat()})
