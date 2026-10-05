from dataclasses import replace, asdict
from pathlib import Path
import json
import os
import threading
import tempfile
from sentinel.engine import SessionState
from sentinel.audit import digest

CANONICAL_TOOLS={'read_file','write_file','patch','web_fetch','web_search','http_post','terminal'}

class MCPProxy:
    def __init__(self,guard,upstream,manifest=None,state_path=None,approval=None):
        self.guard=guard
        self.upstream=upstream
        self.manifest=manifest or {}
        if set(self.manifest.values())-CANONICAL_TOOLS: raise ValueError('Unsupported MCP semantic mapping')
        self.state_path=Path(state_path).resolve() if state_path else None
        self.approval=approval
        self.lock=threading.RLock()
        self.saved={}
        if self.state_path:
            self.guard.encoder.protected_paths=frozenset((*self.guard.encoder.protected_paths,self.state_path))
            if self.state_path.exists():
                self.saved=json.loads(self.state_path.read_text())
                if not isinstance(self.saved,dict): raise ValueError('Invalid session ledger')

    def _restore(self,session):
        key=digest(session)
        if session not in self.guard.sessions and key in self.saved:
            value=self.saved[key]
            self.guard.sessions[session]=SessionState(bool(value['tainted']),bool(value['secret_seen']),list(value['history']),int(value['seq']))

    def _persist(self,session):
        if not self.state_path: return
        self.saved[digest(session)]=asdict(self.guard.state(session))
        self.state_path.parent.mkdir(parents=True,exist_ok=True)
        fd,temp=tempfile.mkstemp(prefix=self.state_path.name+'.',dir=self.state_path.parent)
        try:
            with os.fdopen(fd,'w') as f:
                json.dump(self.saved,f,sort_keys=True); f.flush(); os.fsync(f.fileno())
            os.replace(temp,self.state_path)
        finally:
            if os.path.exists(temp): os.unlink(temp)

    def handle(self,message,session='mcp-session'):
        if not isinstance(message,dict) or message.get('jsonrpc')!='2.0': raise ValueError('Expected JSON-RPC 2.0 object')
        if message.get('method')!='tools/call': return self.upstream(message)
        params=message.get('params',{})
        if not isinstance(params,dict) or not isinstance(params.get('name'),str) or not isinstance(params.get('arguments',{}),dict): raise ValueError('Invalid tools/call params')
        with self.lock:
            self._restore(session)
            name=params['name']; arguments=params.get('arguments',{})
            canonical=self.manifest.get(name)
            effects=self.guard.encoder.encode(canonical or 'mcp_unknown',arguments,self.guard.state(session).tainted)
            effects=[replace(effect,channel='mcp') for effect in effects]
            record=self.guard._inspect(effects,'mcp_tool',digest(arguments),session)
            approved=record['decision']=='hold' and self.approval is not None and self.approval(record) is True
            if record['decision']=='block' or record['decision']=='hold' and not approved:
                self.guard.commit_result(record,executed=False)
                self._persist(session)
                return {'jsonrpc':'2.0','id':message.get('id'),'result':{'isError':True,'content':[{'type':'text','text':f"Sentinel {record['decision']}: {record['pebble']} Reason: {', '.join(record['rules']) or record['reason']}"}]}}
            try:
                result=self.upstream(message)
                successful=not (isinstance(result,dict) and (result.get('error') or isinstance(result.get('result'),dict) and result['result'].get('isError')))
                self.guard.commit_result(record,executed=successful,output_observed=True,human_approved=approved)
                self._persist(session)
                return result
            except Exception:
                self.guard.commit_result(record,executed=False,output_observed=True,human_approved=approved)
                self._persist(session)
                raise
