"""Durable service/file coordination. Caller validates release/baseline authority."""
import json
import time
from monitor_services import UNITS


class ServiceTransaction:
    def __init__(self,transaction_store,services):self.tx,self.services=transaction_store,services
    def prepare(self,token):
        folder=self.tx._folder(token)
        try:
            self.tx._load(folder)
            try:self.tx._read(folder,'services.json',65536)
            except FileNotFoundError:pass
            else:raise ValueError('Service state already captured')
            state=dict(schema=1,phase='prepared',before=self.services.states(),last_failure=None)
            state['before_modules']=self.services.health(())['modules'] if state['before'][UNITS[0]] else []
            self.tx._write(folder,'services.json',json.dumps(state).encode())
        finally:
            import os;os.close(folder)
    def run(self,token,required,*,rollback=False,checkpoint=lambda _:None,after_files=lambda:None):
        import os
        folder=self.tx._folder(token)
        try:
            self.tx._load(folder)
            state=json.loads(self.tx._read(folder,'services.json',65536))
            phases=('prepared','stopping','applying','starting','healthy','rollback_stopping','restoring_files','restoring_services','rolled_back')
            if state.get('schema')!=1 or state.get('phase') not in phases or set(state.get('before',{}))!=set(UNITS) or any(type(v) is not bool for v in state['before'].values()):raise ValueError('Invalid service journal')
            if not isinstance(state.get('before_modules'),list) or len(state['before_modules'])>32 or any(not isinstance(i,str) for i in state['before_modules']):raise ValueError('Invalid prior module identity')
            def save(phase):
                state['phase']=phase;self.tx._write(folder,'services.json',json.dumps(state).encode());checkpoint(phase)
            rollback=rollback or state['phase'] in ('rollback_stopping','restoring_files','restoring_services','rolled_back')
            if state['phase']=='rolled_back':return state
            if state['phase']=='healthy' and not rollback:return state
            def health(required,started):
                if not state['before'][UNITS[0]]:return
                deadline=time.monotonic()+45
                while True:
                    try:self.services.health(required,not_before=started);return
                    except (OSError,ValueError,RuntimeError,KeyError):
                        if time.monotonic()>=deadline:raise
                        time.sleep(.2)
            try:
                if not rollback:
                    save('stopping');self.services.stop()
                    save('applying');self.tx.run(token);after_files()
                    save('starting');self.services.reload();started=time.time();self.services.restore(state['before'])
                    health(required,started)
                    save('healthy');return state
            except Exception as error:
                state['last_failure']=type(error).__name__;rollback=True
            if rollback:
                save('rollback_stopping');self.services.stop()
                save('restoring_files');self.tx.run(token,rollback=True)
                save('restoring_services');self.services.reload();started=time.time();self.services.restore(state['before'])
                health(state['before_modules'],started)
                save('rolled_back');return state
        finally:os.close(folder)
