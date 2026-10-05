from pathlib import Path
import json
from collections import defaultdict, deque
from sentinel.audit import digest
from sentinel.settings import read_mode
from sentinel import Sentinel

class HermesAdapter:
    def __init__(self, guard):
        self.guard=guard
        self.pending=defaultdict(deque)

    def pre_tool_call(self,tool_name,args,task_id,**kwargs):
        record=self.guard.inspect(tool_name,args,session=str(task_id))
        key=(str(task_id),str(tool_name),digest(args))
        self.pending[key].append(record)
        message=f"Sentinel {record['decision']}: {record['pebble']} Reason: {', '.join(record['rules']) or record['reason']}"
        if record['decision']=='block': return {'action':'block','message':message}
        if record['decision']=='hold': return {'action':'approve','message':message,'rule_key':'pebble-sentinel:'+record['id']}
        return None

    def post_tool_call(self,tool_name,args,result,task_id,duration_ms=0,**kwargs):
        key=(str(task_id),str(tool_name),digest(args))
        queue=self.pending.get(key)
        record=queue.popleft() if queue else None
        if record:
            try:
                payload=json.loads(result) if isinstance(result,str) else result
            except (ValueError,TypeError):
                payload={}
            success=not (isinstance(payload,dict) and payload.get('error')) and not kwargs.get('error') and kwargs.get('status','success') not in ('error','blocked','cancelled','denied')
            observed=kwargs.get('status','success') not in ('blocked','cancelled','denied') and result is not None
            self.guard.commit_result(record,executed=success,output_observed=observed,human_approved=observed and record['decision']=='hold')

    def register(self,ctx):
        ctx.register_hook('pre_tool_call',self.pre_tool_call)
        ctx.register_hook('post_tool_call',self.post_tool_call)


def register(ctx):
    try:
        from sentinel.scorer import TransformerScorer
        scorer=TransformerScorer()
        workspace=Path.cwd()/'.sentinel-demo'
        adapter=HermesAdapter(Sentinel(Path.cwd(),mode=read_mode(workspace),scorer=scorer,audit_path=workspace/'audit.jsonl'))
    except Exception:
        def unavailable(tool_name,args,task_id,**kwargs):
            return {'action':'block','message':'Sentinel failed to initialize. An operator must review the model and audit configuration before tools can run.'}
        ctx.register_hook('pre_tool_call',unavailable)
        return
    adapter.register(ctx)
