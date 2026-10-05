from pathlib import Path
import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
from .engine import Sentinel

SCENARIO_DIR=Path(__file__).resolve().parent.parent/'scenarios'

def list_scenarios():
    return [json.loads(p.read_text()) for p in sorted(SCENARIO_DIR.glob('*.json'))]

def run_simulation(scenario,mode='enforce',scorer=None,local_effects=False,audit_path=None):
    if isinstance(scenario,str):
        scenario=next((s for s in list_scenarios() if s['id']==scenario),None)
    if not scenario: raise ValueError('Unknown scenario')
    events=[]; deliveries=[]; server=None
    with tempfile.TemporaryDirectory(prefix='sentinel-canary-') as root:
        secret=Path(root)/'.env'
        secret.write_text('SENTINEL_DEMO_CANARY_NOT_A_REAL_CREDENTIAL')
        if local_effects:
            class Sink(BaseHTTPRequestHandler):
                def do_POST(self):
                    deliveries.append(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode())
                    self.send_response(204); self.end_headers()
                def log_message(self,*args): pass
            server=ThreadingHTTPServer(('127.0.0.1',0),Sink)
            threading.Thread(target=server.serve_forever,daemon=True).start()
        guard=Sentinel(root,mode,scorer,audit_path)
        stopped=False
        try:
            for call in scenario['actions']:
                record=guard.inspect(call['tool'],call['arguments'],scenario['id'])
                executed=record['decision']=='allow' and not stopped
                record['executed']=executed
                record['effect']='not executed' if not executed else 'fixture replay only'
                if local_effects and executed:
                    if any(e['verb']=='read' and e['object']=='secret-store' for e in record['actions']):
                        secret.read_text(); record['effect']='read synthetic canary inside temporary sandbox'
                    if any(e['verb']=='send' for e in record['actions']):
                        req=Request(f'http://127.0.0.1:{server.server_port}/sink',data=secret.read_bytes(),method='POST')
                        with urlopen(req,timeout=2) as response: response.read()
                        record['effect']='delivered synthetic canary to ephemeral localhost sink'
                guard.commit_result(record,executed=executed)
                if record['decision']!='allow': stopped=True
                events.append(record)
        finally:
            if server: server.shutdown(); server.server_close()
    return {'scenario':scenario['id'],'title':scenario['title'],'family':scenario['family'],'mode':mode,'events':events,'summary':{d:sum(e['decision']==d for e in events) for d in ('allow','hold','block')},'model':getattr(guard.scorer,'metadata',{}),'simulation':{'local_effects':local_effects,'canary_deliveries':len(deliveries),'arbitrary_commands_executed':False,'note':'Later actions are hypothetical after the first intervention; no user commands are executed.'}}

def evaluate_actions(actions,mode='enforce',scorer=None):
    guard=Sentinel('/sentinel-demo/project',mode,scorer)
    events=[]
    for action in actions:
        event=guard.inspect_actions([action]); guard.commit_result(event,executed=event['decision']=='allow'); events.append(event)
    return {'mode':mode,'events':events,'summary':{d:sum(e['decision']==d for e in events) for d in ('allow','hold','block')},'model':getattr(guard.scorer,'metadata',{}),'execution':'analysis only; no tools executed'}
