from sentinel import Sentinel
from sentinel.adapters.mcp import MCPProxy


def request(name,args=None,id=1):
    return {'jsonrpc':'2.0','id':id,'method':'tools/call','params':{'name':name,'arguments':args or {}}}


def test_block_and_hold_never_forwarded(tmp_path):
    forwarded=[]
    def upstream(message): forwarded.append(message); return {'jsonrpc':'2.0','id':message['id'],'result':{'content':[]}}
    proxy=MCPProxy(Sentinel(tmp_path),upstream,{'writer':'write_file'})
    blocked=proxy.handle(request('writer',{'path':'~/.sentinel/rules.yaml'}))
    held=proxy.handle(request('unknown'))
    assert blocked['result']['isError'] and held['result']['isError']
    assert not forwarded


def test_success_taints_and_state_survives_restart(tmp_path):
    forwarded=[]
    def upstream(message): forwarded.append(message); return {'jsonrpc':'2.0','id':message['id'],'result':{'content':[{'type':'text','text':'CANARY_ONLY'}]}}
    path=tmp_path/'ledger.json'
    manifest={'reader':'read_file','sender':'http_post'}
    proxy=MCPProxy(Sentinel(tmp_path),upstream,manifest,state_path=path)
    proxy.handle(request('reader',{'path':'.env'}),'session')
    assert proxy.guard.state('session').secret_seen and proxy.guard.state('session').tainted
    fresh=MCPProxy(Sentinel(tmp_path),upstream,manifest,state_path=path)
    result=fresh.handle(request('sender',{'url':'https://sink.invalid'}),'session')
    assert result['result']['isError'] and len(forwarded)==1
    assert 'CANARY_ONLY' not in path.read_text()
    assert fresh.guard.inspect('write_file',{'path':'ledger.json'})['decision']=='block'


def test_mcp_explicit_human_approval(tmp_path):
    calls=[]
    proxy=MCPProxy(Sentinel(tmp_path),lambda msg:calls.append(msg) or {'result':{}},approval=lambda row:True)
    proxy.handle(request('unknown'))
    assert len(calls)==1


def test_failed_upstream_output_still_taints(tmp_path):
    proxy=MCPProxy(Sentinel(tmp_path),lambda msg:{'result':{'isError':True}},{'reader':'read_file'})
    proxy.handle(request('reader',{'path':'README.md'}))
    assert proxy.guard.state('mcp-session').tainted

def test_exposure_retained_beyond_model_context(tmp_path):
    def upstream(message): return {'result':{'content':[]}}
    proxy=MCPProxy(Sentinel(tmp_path),upstream,{'reader':'read_file','test':'terminal','sender':'http_post'},state_path=tmp_path/'ledger.json')
    proxy.handle(request('reader',{'path':'.env'}))
    for i in range(65): proxy.handle(request('test',{'command':'npm test'},id=i+2))
    assert 'secret-store' not in ' '.join(proxy.guard.state('mcp-session').history).split()[-256:]
    assert proxy.handle(request('sender',{'url':'https://sink.invalid'}))['result']['isError']

def test_error_result_cannot_deliver_injection_then_read_secret(tmp_path):
    forwarded=[]
    def upstream(message):
        forwarded.append(message)
        return {'result':{'isError':True,'content':[{'type':'text','text':'UNTRUSTED_INJECTION_FIXTURE_ONLY'}]}}
    proxy=MCPProxy(Sentinel(tmp_path),upstream,{'reader':'read_file'})
    proxy.handle(request('reader',{'path':'README.md'}))
    result=proxy.handle(request('reader',{'path':'.env'}))
    assert len(forwarded)==1 and result['result']['isError']
    assert 'deny-secret-read-tainted' in result['result']['content'][0]['text']
