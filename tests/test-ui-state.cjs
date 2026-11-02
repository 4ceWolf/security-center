// Test the security-critical unavailable/stale states without a browser login.
const fs=require('node:fs'), vm=require('node:vm'), assert=require('node:assert/strict');
class Element {
 constructor(){this.textContent='';this.className='';this.dataset={};this.children=[];this.listeners={};this.classList={toggle(){}};}
 append(...children){this.children.push(...children)} replaceChildren(){this.children=[]}
 addEventListener(event,callback){this.listeners[event]=callback} setAttribute(){}
}
const ids=Object.fromEntries(['telemetry-scroll','telemetry-status','telemetry-table','telemetry-rows','telemetry-metric','telemetry-caption','modules','overall-title','overview-description','freshness','events','refresh','notice','event-search','history-status','event-count','more-events'].map(x=>[x,new Element()]));
const overview=new Element(), buttons=['all','boot','network','applications'].map(x=>{const e=new Element();e.dataset.filter=x;return e});
let fail=false;
let data={schema_version:1,generated_at:new Date().toISOString(),overall:'secure',modules:[],events:[],event_status:'available'};
const cockpit={spawn:async()=>{if(fail)throw Error('Unavailable');return JSON.stringify(data)}};
const document={getElementById:id=>ids[id],createElement:()=>new Element(),querySelector:()=>overview,querySelectorAll:s=>s==='[data-filter]'?buttons:[]};
const ctx=vm.createContext({document,window:{cockpit},cockpit,setInterval(){},Date,Number,Set,JSON,Error});
vm.runInContext(fs.readFileSync(process.argv[2],'utf8'),ctx);
(async()=>{
 await vm.runInContext('refresh()',ctx);
 assert.equal(ids['overall-title'].textContent,'Secure');
 fail=true;await vm.runInContext('refresh()',ctx);
 assert.equal(ids['overall-title'].textContent,'Current status unavailable');
 buttons[1].listeners.click();
 assert.equal(ids['overall-title'].textContent,'Current status unavailable','Filtering must not restore a false secure state');
 assert.equal(overview.className,'overview unavailable');
 fail=false;data.generated_at=new Date(Date.now()-180000).toISOString();await vm.runInContext('refresh()',ctx);
 assert.equal(ids['overall-title'].textContent,'Current status unavailable');
 data.generated_at=new Date().toISOString();await vm.runInContext('refresh()',ctx);
 assert.equal(ids['overall-title'].textContent,'Secure');
 data.events=Array.from({length:250},(_,i)=>({timestamp:Date.now()/1000,source:'firewall',summary:'Observed item '+i,severity:'info',kind:'observation'}));
 await vm.runInContext('refresh()',ctx);
 assert.equal(ids['events'].children.length,100);
 ids['more-events'].listeners.click();assert.equal(ids['events'].children.length,200);
 ids['event-search'].value='item 249';ids['event-search'].listeners.input();
 assert.equal(ids['events'].children.length,1);assert.equal(ids['more-events'].hidden,true);
 ids['event-search'].value='NO_MATCH';ids['event-search'].listeners.input();
 assert.equal(ids['events'].children[0].textContent,'No events match your search.');
 const hour=Math.floor(Date.now()/3600000)*3600;
 data.telemetry_history_status='available';data.telemetry_history={window_hours:24,first_hour_unix:hour-23*3600,last_hour_unix:hour,rows:[{hour_unix:hour,samples:2,samples_with_issues:0,mixed_boots:false,metrics:{'cpu.cpu.busy_percent':{mean:20,min:10,max:30,count:2},'battery.BAT0.discharge_w':null}}]};
 await vm.runInContext('refresh()',ctx);
 assert.equal(ids['telemetry-rows'].children.length,24);
 assert.equal(ids['telemetry-rows'].children[0].children[1].textContent,'20.0');
 assert.equal(ids['telemetry-rows'].children[1].children[5].textContent,'No samples');
 ids['telemetry-scroll'].scrollTop=120;ids['telemetry-scroll'].scrollLeft=80;
 ids['telemetry-metric'].value='battery.BAT0.discharge_w';ids['telemetry-metric'].listeners.change();
 assert.equal(ids['telemetry-scroll'].scrollTop,120);assert.equal(ids['telemetry-scroll'].scrollLeft,80);
 assert.equal(ids['telemetry-rows'].children[0].children[1].textContent,'—');
 assert.equal(ids['telemetry-rows'].children[0].children[5].textContent,'No reading');
 fail=true;await vm.runInContext('refresh()',ctx);
 assert.match(ids['telemetry-scroll','telemetry-status'].textContent,/Previously loaded/);
 fail=false;data.telemetry_history_status='unavailable';await vm.runInContext('refresh()',ctx);
 assert.equal(ids['telemetry-table'].hidden,true);assert.equal(ids['telemetry-metric'].disabled,true);
 data.telemetry_history_status='not_recorded';await vm.runInContext('refresh()',ctx);
 assert.match(ids['telemetry-scroll','telemetry-status'].textContent,/No diagnostic history/);
 data.telemetry_history_status='available';data.telemetry_history.rows=[];await vm.runInContext('refresh()',ctx);
 assert.match(ids['telemetry-scroll','telemetry-status'].textContent,/No diagnostic samples/);
 data.modules=[{id:'boot_observation',name:'Initrd device observation',status:'unknown',summary:'Observed with limitations',details:{device_enforcement:'Not enabled',unlock_method:'Unknown'}}];
 await vm.runInContext('refresh()',ctx);
 vm.runInContext("filter='boot';render()",ctx);
 assert.equal(ids['modules'].children.length,1);
 assert.equal(ids['modules'].children[0].dataset.id,'boot_observation');
 assert.match(ids['modules'].children[0].children[1].textContent,/Not enabled/);
 console.log('PASS: fresh/error/stale/recovered states, history pagination, search, empty results and telemetry history states');
})().catch(e=>{console.error(e);process.exitCode=1});
