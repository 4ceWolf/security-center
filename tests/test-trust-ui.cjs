const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
class Element{
 constructor(){this.textContent='';this.dataset={};this.children=[];this.listeners={};this.hidden=false;this.isConnected=true;this.classList={toggle(){}};this.value='';}
 append(...children){this.children.push(...children)} replaceChildren(...children){this.children=[...children]}
 addEventListener(name,fn){this.listeners[name]=fn}setAttribute(){}focus(){focused=this}
}
let focused=null,fail=null,calls=[],pending=null;
const ids={};for(const id of ['modules','overall-title','overview-description','freshness','events','refresh','notice','event-search','history-status','event-count','more-events','telemetry-scroll','telemetry-status','telemetry-table','telemetry-rows','telemetry-metric','telemetry-caption','trust-load','trust-save','trust-cancel','trust-status','trust-lists','trust-connected','trust-saved','trust-review','trust-review-title','trust-review-action','trust-review-identity','trust-keyboard','trust-observation'])ids[id]=new Element();
const dev={transport:'usb',vendor:'046d',product:'c542',serial:'',port:'pci:0000:00:14.0/usb:1',interfaces:['03:01:01','03:01:02']};
const selected='a'.repeat(64),revision='b'.repeat(64);
let view={schema_version:1,revision,observation_status:'available',activation:{preboot:'outside_scope',postboot:'not_managed_by_candidate_editor'},connected:[{id:selected,device:dev,saved:false,internal:false}],saved:[]};
const cockpit={spawn(args,options){
 if(args[2].endsWith('/client.py'))return Promise.resolve(JSON.stringify({schema_version:1,generated_at:new Date().toISOString(),overall:'unknown',modules:[],events:[]}));
 assert.deepEqual(Array.from(args),['/usr/bin/python3','-I','/usr/local/lib/security-center/device-trust-helper.py']);assert.equal(options.superuser,'require');
 let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});
 promise.input=(raw,stream)=>{
  assert.equal(stream,false);const request=JSON.parse(raw);calls.push(request);
  if(fail){reject(fail);return;}
  let result=view;
  if(request.operation==='propose')result={schema_version:1,action:request.action,base_revision:revision,device_id:request.device_id,device:dev};
  if(request.operation==='apply'){assert.equal(request.proposal.base_revision,revision);view={...view,connected:[{id:selected,device:dev,saved:true}],saved:[{id:selected,device:dev,connected:true}]};result=view;}
  if(pending){pending.resolve=resolve;pending.raw=JSON.stringify({ok:true,result});return;}
  resolve(JSON.stringify({ok:true,result}));
 };return promise;
}};
const document={getElementById:id=>ids[id],createElement:()=>new Element(),querySelector:()=>new Element(),querySelectorAll:()=>[]};
const ctx=vm.createContext({document,window:{cockpit},cockpit,setInterval(){},Date,Number,Set,JSON,Error});
vm.runInContext(fs.readFileSync(process.argv[2],'utf8'),ctx);
const run=expression=>vm.runInContext(expression,ctx);
(async()=>{
 assert.equal(calls.length,0,'No automatic administrator prompt');
 await run('trustLoad()');assert.equal(ids['trust-connected'].children.length,1);assert.equal(ids['trust-lists'].hidden,false);
 const trigger=new Element();ctx.trigger=trigger;
 await run(`trustReview('add','${selected}',trigger)`);
 assert.equal(ids['trust-review'].hidden,false);assert.equal(ids['trust-keyboard'].hidden,false);assert.equal(focused,ids['trust-review-title']);
 ids['trust-cancel'].listeners.click();assert.equal(ids['trust-review'].hidden,true);assert.equal(focused,trigger);assert.equal(calls.filter(r=>r.operation==='apply').length,0);
 await run(`trustReview('add','${selected}',trigger)`);await run('trustSave()');
 assert.equal(ids['trust-review'].hidden,true);assert.match(ids['trust-status'].textContent,/Candidate change saved/);assert.match(ids['trust-status'].textContent,/Live USBGuard rules were not changed/);assert.equal(ids['trust-saved'].children.length,1);
 await run(`trustReview('remove','${selected}',trigger)`);assert.match(ids['trust-review-action'].textContent,/Remove/);
 fail={problem:'access-denied'};await run('trustSave()');assert.match(ids['trust-status'].textContent,/Administrator access/);assert.equal(ids['trust-review'].hidden,true);assert.equal(ids['trust-lists'].hidden,true);
 fail=null;pending={};const inFlight=run('trustLoad()');assert.equal(ids['trust-load'].disabled,true);const before=calls.length;await run('trustLoad()');assert.equal(calls.length,before);pending.resolve(pending.raw);await inFlight;pending=null;assert.equal(ids['trust-load'].disabled,false);
 fail=Error('unavailable');await run('trustLoad()');assert.equal(ids['trust-lists'].hidden,true);assert.match(ids['trust-status'].textContent,/may not be installed/);
 console.log('PASS: no automatic elevation, exact helper/require-root, load/review/cancel/save/remove, keyboard warning, focus, denial, busy and unavailable states');
})().catch(error=>{console.error(error);process.exitCode=1});
