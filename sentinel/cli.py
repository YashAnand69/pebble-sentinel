from pathlib import Path
import argparse
import json
import subprocess
import sys
from .audit import AuditLog
from .simulation import list_scenarios, run_simulation
from .engine import RuleOnlyScorer
from .settings import read_mode

def load_model():
    from .scorer import TransformerScorer
    return TransformerScorer()

def main(argv=None):
    parser=argparse.ArgumentParser(description='Pebble Sentinel: local action guard and safe fixture laboratory')
    parser.add_argument('--workspace',default='.sentinel-demo',help='Workspace-local state; never changes global settings')
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('status',help='Show workspace mode and audit counts')
    sub.add_parser('review',help='Review held and blocked actions')
    explain=sub.add_parser('explain',help='Explain a redacted action'); explain.add_argument('id')
    mode=sub.add_parser('mode',help='Human-operated workspace mode setting'); mode.add_argument('mode',choices=['learn','shadow','enforce'])
    sim=sub.add_parser('simulate',help='Replay safe canary scenarios; never execute shell commands'); sim.add_argument('scenario',choices=[s['id'] for s in list_scenarios()]+['all']); sim.add_argument('--mode',choices=['learn','shadow','enforce'],default=None); sim.add_argument('--local-effects',action='store_true'); sim.add_argument('--rules-only',action='store_true',help='Explicitly run the policy baseline without the trained model')
    for name in ('train','eval'):
        pipeline=sub.add_parser(name,help=f'Run the published {name} pipeline')
        if name=='train':
            pipeline.add_argument('--seed',type=int,default=2026)
            pipeline.add_argument('--steps',type=int,default=500)
        else:
            pipeline.add_argument('--seeds',default='2026,2027,2028')
            pipeline.add_argument('--benchmark-actions',type=int,default=10000)
    args=parser.parse_args(argv)
    workspace=Path(args.workspace)
    config=workspace/'mode.json'; log=AuditLog(workspace/'audit.jsonl')
    if args.command=='mode':
        workspace.mkdir(parents=True,exist_ok=True); config.write_text(json.dumps({'mode':args.mode}))
        log.append({'event':'mode-change','mode':args.mode})
        result={'mode':args.mode,'workspace':str(workspace)}
    elif args.command=='status':
        try:
            selected_mode=read_mode(workspace)
        except Exception:
            parser.error('Invalid workspace mode file; no guard configuration was applied')
        try:
            scorer=load_model()
            model={**scorer.metadata,'name':getattr(scorer,'name','Pebble PAL Transformer'),'ready':bool(scorer.metadata.get('calibrated'))}
        except Exception as exc:
            model={'kind':'unavailable','ready':False,'calibrated':False,'error':type(exc).__name__}
        rows=log.read(); result={'mode':selected_mode,'actions':sum('decision' in r for r in rows),'chain_valid':log.verify(),'model':model}
    elif args.command=='review': result=[r for r in log.read() if r.get('decision') in ('hold','block')]
    elif args.command=='explain': result=next((r for r in log.read() if r.get('id')==args.id),{'error':'Unknown action id'})
    elif args.command=='simulate':
        try:
            selected_mode=args.mode or read_mode(workspace)
            scorer=RuleOnlyScorer() if args.rules_only else load_model()
        except Exception:
            parser.error('Sentinel could not initialize the requested model or mode; no simulation actions were executed. Review the workspace settings and released checkpoint, or explicitly choose --rules-only for the baseline.')
        scenarios=list_scenarios() if args.scenario=='all' else [args.scenario]
        result=[run_simulation(s,selected_mode,scorer=scorer,local_effects=args.local_effects,audit_path=workspace/'audit.jsonl') for s in scenarios]
    else:
        root=Path(__file__).resolve().parent.parent
        script=root/('model/train.pebble' if args.command=='train' else 'eval/evaluate.py')
        if not script.exists(): parser.error(f'{args.command} pipeline unavailable; see model documentation')
        command=['npm','run','train','--','--seed',str(args.seed),'--steps',str(args.steps)] if args.command=='train' else [sys.executable,str(script),'--seeds',args.seeds,'--benchmark-actions',str(args.benchmark_actions)]
        return subprocess.call(command,cwd=root/'model' if args.command=='train' else root)
    print(json.dumps(result,indent=2))
    return 0

if __name__=='__main__': raise SystemExit(main())
