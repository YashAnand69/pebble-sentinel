import json
import os
import sys
import subprocess
from pathlib import Path
home=Path(os.environ['HERMES_HOME']).resolve()
assert str(home).startswith('/private/tmp/')
import hermes_cli.plugins as plugins
upstream_path=Path(plugins.__file__).resolve().parent.parent
upstream_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=upstream_path,text=True).strip()
assert upstream_commit=='bdef06de3b8c0d190cd7f69edc911ac6961ca358', 'Use the documented pinned upstream commit'
from sentinel import Sentinel
from sentinel.adapters.hermes import HermesAdapter
manager=plugins.PluginManager(scope_key=str(home))
manager._discovered=True
plugins._plugin_manager=manager
ctx=plugins.PluginContext(plugins.PluginManifest(name='sentinel-isolated-proof'),manager)
guard=Sentinel(home/'project')
HermesAdapter(guard).register(ctx)
import model_tools
import tools.approval as approval
calls=[]
def dummy_handler(args,**kwargs):
    calls.append(args)
    return json.dumps({'ok':True,'fixture':'no side effects'})
schema={'name':'write_file','parameters':{'type':'object','properties':{}}}
model_tools.registry.register('write_file','sentinel-proof',schema,dummy_handler,override=True)
model_tools.registry.register('sentinel_unknown','sentinel-proof',{'name':'sentinel_unknown','parameters':{'type':'object','properties':{}}},dummy_handler)
block_args={'path':str(home/'project/.sentinel-demo/guard.json'),'content':'CANARY_ONLY'}
block_directive=plugins.get_pre_tool_call_directive('write_file',block_args,task_id='block-proof')
block_result=json.loads(model_tools.handle_function_call('write_file',block_args,task_id='block-proof'))
assert block_directive[0]=='block'
assert len(calls)==0
assert 'error' in block_result
approval_requests=[]
def decline(tool_name,message,rule_key=None):
    approval_requests.append({'tool':tool_name,'rule_key':rule_key})
    return {'approved':False,'message':'Fixture human declined'}
approval.request_tool_approval=decline
hold_directive=plugins.get_pre_tool_call_directive('sentinel_unknown',{},task_id='hold-proof')
hold_result=json.loads(model_tools.handle_function_call('sentinel_unknown',{},task_id='hold-proof'))
assert hold_directive[0]=='approve'
assert len(approval_requests)==1 and len(calls)==0
assert 'error' in hold_result
def approve(tool_name,message,rule_key=None):
    approval_requests.append({'tool':tool_name,'rule_key':rule_key})
    return {'approved':True}
approval.request_tool_approval=approve
allowed_result=json.loads(model_tools.handle_function_call('sentinel_unknown',{},task_id='approved-proof'))
assert len(calls)==1
assert allowed_result['ok'] is True
result={'upstream_commit':'bdef06de3b8c0d190cd7f69edc911ac6961ca358','upstream':'https://github.com/NousResearch/hermes-agent','actual_components':['PluginManager','PluginContext.register_hook','get_pre_tool_call_directive','model_tools.handle_function_call','ToolRegistry.dispatch','approval directive resolver'],'block':{'directive':block_directive[0],'dummy_callback_runs':0,'result_has_error':'error' in block_result},'hold':{'directive':hold_directive[0],'human_gate_called':True,'human_declined_dummy_callback_runs':0,'result_has_error':'error' in hold_result},'approved_hold':{'dummy_callback_runs':len(calls),'result':allowed_result},'boundary':'Fresh upstream source, isolated HERMES_HOME, direct real tool routing. Human gate fixture replaced request_tool_approval; dummy tools only. No model API, real shell command, real credentials, global plugin installation, or user Hermes configuration.'}
print(json.dumps(result,indent=2))
