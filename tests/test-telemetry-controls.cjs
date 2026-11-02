const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
let focused=null,downloads=[],created=[],revoked=[],calls=[],pending=null,failure=null,output=null;
class Element{
 constructor(){this.textContent='';this.children=[];this.listeners={};this.disabled=false;this.hidden=false;this.value='';this.checked=false;this.dataset={};this.classList={toggle(){}};}
 addEventListener(name,fn){this.listeners[name]=fn}setAttribute(){}append(...children){this.children.push(...children)}replaceChildren(...children){this.children=children}
 focus(){focused=this}click(){downloads.push(this)}remove(){}
}
const ids={};for(const id of ['diagnostic-download','diagnostic-clear','diagnostic-resolution','diagnostic-hours','diagnostic-processes','diagnostic-clear-review','diagnostic-clear-cancel','diagnostic-clear-confirm','diagnostic-action-status','diagnostic-export-options','telemetry-scroll','telemetry-status','telemetry-table','telemetry-rows','telemetry-metric','telemetry-caption','modules','overall-title','overview-description','freshness','events','refresh','notice','event-search','history-status','event-count','more-events'])ids[id]=new Element();
ids['diagnostic-resolution'].value='hourly';ids['diagnostic-hours'].value='24';ids['diagnostic-clear-review'].hidden=true;
const state={schema_version:1,generated_at:new Date(Date.now()-1000).toISOString(),overall:'unknown',modules:[],events:[]};
const cockpit={spawn(args,options){
 if(args[2].endsWith('/client.py'))return Promise.resolve(JSON.stringify(state));
 assert.deepEqual(Array.from(args),['/usr/bin/python3','-I','/usr/local/lib/security-center/telemetry-helper.py']);assert.equal(options.superuser,'require');
 let resolve,reject;const child=new Promise((a,b)=>{resolve=a;reject=b});
 child.input=(raw,stream)=>{
  assert.equal(stream,false);const request=JSON.parse(raw);calls.push(request);
  if(failure){reject(failure);return;}
  let response=output;
  if(response===null)response=request.operation==='export'?JSON.stringify({schema:1,kind:'local_diagnostic_export',resolution:request.resolution,window_hours:request.hours,process_details_included:request.include_processes,rows:[],row_count:0}):JSON.stringify({schema:1,kind:'local_diagnostic_erasure',removed_samples:3,removed_hours:1,recording_continues:true,forensic_erasure:false,erased_at_unix:Date.now()/1000});
  if(pending){pending.resolve=resolve;pending.response=response;}else resolve(response);
 };return child;
}};
const document={getElementById:id=>ids[id],createElement:()=>new Element(),body:new Element(),querySelector:()=>new Element(),querySelectorAll:()=>[]};
const ctx=vm.createContext({document,window:{cockpit},cockpit,setInterval(){},setTimeout(fn){fn()},Date,Number,Set,JSON,Error,Blob,URL:{createObjectURL(blob){created.push(blob);return 'blob:local'},revokeObjectURL(url){revoked.push(url)}}});
for(const file of ['cockpit/app.js','cockpit/telemetry-controls.js'])vm.runInContext(fs.readFileSync(file,'utf8'),ctx);
const click=id=>ids[id].listeners.click();
(async()=>{
 await vm.runInContext('refresh()',ctx);assert.equal(calls.length,0,'No automatic elevation');
 await click('diagnostic-download');assert.equal(calls[0].include_processes,false);assert.equal(downloads.length,1);assert.equal(created.length,1);assert.equal(revoked.length,1);assert.match(ids['diagnostic-action-status'].textContent,/Download started/);
 ids['diagnostic-processes'].checked=true;ids['diagnostic-resolution'].value='raw';ids['diagnostic-resolution'].listeners.change();
 assert.deepEqual(ids['diagnostic-hours'].children.map(c=>c.value),['1','6','24']);assert.equal(ids['diagnostic-hours'].value,'24');
 await click('diagnostic-download');assert.equal(calls.at(-1).include_processes,true);assert.equal(calls.at(-1).resolution,'raw');
 click('diagnostic-clear');assert.equal(focused,ids['diagnostic-clear-cancel']);const before=calls.length;
 click('diagnostic-clear-cancel');assert.equal(calls.length,before);assert.equal(focused,ids['diagnostic-clear']);assert.equal(ids['diagnostic-clear-review'].hidden,true);
 await click('diagnostic-clear-confirm');assert.equal(calls.length,before,'Hidden confirmation cannot erase');
 click('diagnostic-clear');ids['diagnostic-clear-review'].listeners.keydown({key:'Escape',preventDefault(){}});assert.equal(ids['diagnostic-clear-review'].hidden,true);assert.equal(calls.length,before);
 click('diagnostic-clear');await click('diagnostic-clear-confirm');assert.equal(calls.at(-1).confirmation,'erase_saved_telemetry');assert.match(ids['diagnostic-action-status'].textContent,/Cleared 3/);assert.match(ids['telemetry-status'].textContent,/Waiting for a new collector/);
 await vm.runInContext('refresh()',ctx);assert.match(ids['telemetry-status'].textContent,/Waiting for a new collector/,'A cached collector response cannot redisplay cleared history');
 state.generated_at=new Date(Date.now()+1000).toISOString();state.telemetry_history_status='not_recorded';await vm.runInContext('refresh()',ctx);assert.match(ids['telemetry-status'].textContent,/No diagnostic history/);
 failure={problem:'access-denied'};const count=downloads.length;await click('diagnostic-download');assert.match(ids['diagnostic-action-status'].textContent,/Administrator access/);assert.equal(downloads.length,count);failure=null;
 for(const raw of ['{','null',JSON.stringify({schema:1,kind:'local_diagnostic_export',resolution:'hourly'})]){output=raw;await click('diagnostic-download');assert.equal(downloads.length,count);}
 output=null;pending={};const inFlight=click('diagnostic-download');assert.equal(ids['diagnostic-download'].disabled,true);const at=calls.length;await click('diagnostic-download');click('diagnostic-clear');assert.equal(calls.length,at);pending.resolve(pending.response);await inFlight;pending=null;assert.equal(ids['diagnostic-download'].disabled,false);
 output=JSON.stringify({ok:false,error:'busy'});await click('diagnostic-download');assert.match(ids['diagnostic-action-status'].textContent,/busy/);
 console.log('PASS: no automatic elevation, exact helper, privacy/default/opt-in, download cleanup, raw bounds, erase review/cancel/Escape, focus, busy, denial, malformed response, stale-history suppression');
})().catch(error=>{console.error(error);process.exitCode=1});
