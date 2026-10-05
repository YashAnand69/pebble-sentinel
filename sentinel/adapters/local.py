class LocalHarness:
    def __init__(self,guard,tools,approval=None):
        self.guard=guard
        self.tools=tools
        self.approval=approval

    def call(self,tool,arguments,session='local'):
        record=self.guard.inspect(tool,arguments,session)
        approved=record['decision']=='hold' and self.approval is not None and self.approval(record) is True
        if record['decision']=='block' or record['decision']=='hold' and not approved:
            self.guard.commit_result(record,executed=False)
            return {'executed':False,'decision':record}
        try:
            result=self.tools[tool](**arguments)
            self.guard.commit_result(record,executed=True,human_approved=approved)
            return {'executed':True,'decision':record,'result':result}
        except Exception:
            self.guard.commit_result(record,executed=False,output_observed=True,human_approved=approved)
            raise
