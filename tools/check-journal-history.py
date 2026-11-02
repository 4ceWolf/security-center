#!/usr/bin/python3
"""Read-only host journal check using an isolated temporary history database."""
import datetime,json,pathlib,resource,sys,tempfile
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'securityd'))
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'initramfs'))
import collector,history

def main():
    seen=set(); batches=0; events=0
    with tempfile.TemporaryDirectory(prefix='security-center-journal-check-') as folder:
        database=pathlib.Path(folder)/'history.sqlite'
        for _ in range(32):
            store=history.History(database)
            cursor=store.journal_cursor()
            batch=collector.journal_batch(cursor)
            if batch['gap']:
                raise RuntimeError('Journal changed during verification; retry needed')
            if batch['cursor'] == cursor and batch['backlog']:
                raise RuntimeError('Journal did not advance')
            data={'generated_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  'modules':[],'events':batch['events'],'_journal_batch':batch}
            rows=store.record(data)
            if history.History(database).journal_cursor() != batch['cursor']:
                raise RuntimeError('Position did not survive database reopen')
            batches+=1;events+=len(batch['events'])
            if not batch['backlog']:
                break
            if batch['cursor'] in seen:
                raise RuntimeError('Repeated journal position')
            seen.add(batch['cursor'])
        else:
            raise RuntimeError('Catch-up exceeds bounded verification run')
        report={'passed':True,'batches':batches,'normalized_events':events,'retained_events':len(rows),
                'cursor_survived_reopen':True,'caught_up':True,'host_settings_changed':False,
                'python_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                'child_peak_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}
        print(json.dumps(report,indent=2))

if __name__=='__main__':main()
