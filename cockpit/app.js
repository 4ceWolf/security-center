'use strict';
let snapshot = null;
let filter = 'all';
let collectorError = false;
let eventLimit = 100;
let telemetryClearedAt = 0;
function telemetryHistoryCleared(erasedAt){
 telemetryClearedAt=erasedAt*1000;
 renderTelemetry();
}
const labels = {secure:'Secure',attention:'Attention',action_required:'Action required',unknown:'Not verified',unavailable:'Unavailable'};
const groups = {integrity:['integrity'],audit:['audit'],boot:['secureboot','lockdown','tpm','luks','preboot','boot_observation'],network:['firewall','listeners'],applications:['apparmor','services','processes','telemetry'],devices:['usbguard','devices'],updates:['updates'],recovery:['luks','snapshots']};
function node(tag,text,className){const el=document.createElement(tag);el.textContent=text;if(className)el.className=className;return el;}
function render(){
 const modules=document.getElementById('modules');modules.replaceChildren();
 const openIds=new Set(window.openDetails||[]);
 snapshot.modules.filter(m=>filter==='all'||groups[filter].includes(m.id)).forEach(m=>{
  const detail=node('details','','check');detail.dataset.id=m.id;detail.open=openIds.has(m.id);
  detail.addEventListener('toggle',()=>{window.openDetails=[...document.querySelectorAll('details[open]')].map(d=>d.dataset.id);});
  const summary=node('summary','');summary.append(node('h3',m.name),node('span',m.summary),node('span',labels[m.status]||'Unknown','state '+m.status));
  detail.append(summary,node('pre',JSON.stringify({last_check:m.last_check,...m.details},null,2)));modules.append(detail);
 });
 const overall=labels[snapshot.overall]||'Not verified';document.getElementById('overall-title').textContent=overall;
 document.querySelector('.overview').className='overview '+snapshot.overall;
 document.getElementById('overview-description').textContent='Checks include settings that need attention or are not yet verified. Expand a row to inspect the evidence.';
 document.getElementById('freshness').textContent='Last checked '+new Date(snapshot.generated_at).toLocaleString()+' · refreshed by collector every 60 seconds';
 renderEvents();
 renderTelemetry();
}
function renderEvents(){
 if(!snapshot)return;
 const query=String(document.getElementById('event-search').value||'').trim().toLowerCase();
 const matches=snapshot.events.slice().reverse().filter(e=>[e.source,e.summary,e.severity,e.kind].join(' ').toLowerCase().includes(query));
 const events=document.getElementById('events');events.replaceChildren();
 document.getElementById('history-status').textContent=snapshot.history_status==='available'?'Local history: up to 2,000 events / 30 days. Journal entries resume from the saved position in batches of 256. Only retained logs are available; deleted logs may leave gaps.':'Persistent history unavailable; showing any current journal batch only.';
 if(snapshot.journal_status==='unavailable')document.getElementById('history-status').textContent+=' Journal reading is unavailable.';
 if(snapshot.journal_coverage?.backlog)document.getElementById('history-status').textContent+=' Catching up with queued entries.';
 if(snapshot.journal_coverage?.gap)document.getElementById('history-status').textContent+=' A missing journal position was detected; some events may be missing.';
 document.getElementById('event-count').textContent='Showing '+Math.min(eventLimit,matches.length)+' of '+matches.length+' matching events';
 if(!matches.length)events.append(node('li',query?'No events match your search.':snapshot.event_status==='unavailable'?'Timeline unavailable.':'No saved events yet.'));
 matches.slice(0,eventLimit).forEach(e=>{const li=node('li','');const time=node('time',new Date(e.timestamp*1000).toLocaleString());time.dateTime=new Date(e.timestamp*1000).toISOString();li.append(time,node('span',e.summary),node('small',' · '+e.source+' · '+(e.kind||'journal'),'muted'));events.append(li);});
 document.getElementById('more-events').hidden=matches.length<=eventLimit;
}

const telemetryLabels={'cpu.cpu.busy_percent':'CPU usage (%)','memory.used_percent':'Memory used (%)','battery.BAT0.percent':'Battery level (%)','battery.BAT0.discharge_w':'Battery discharge (W)'};
function renderTelemetry(){
 const status=document.getElementById('telemetry-status'), table=document.getElementById('telemetry-table'), rows=document.getElementById('telemetry-rows'), select=document.getElementById('telemetry-metric');
 const scroll=document.getElementById('telemetry-scroll'), position=[scroll.scrollTop||0,scroll.scrollLeft||0];
 rows.replaceChildren();table.hidden=true;select.disabled=true;
 if(telemetryClearedAt&&(!Number.isFinite(Date.parse(snapshot?.generated_at))||Date.parse(snapshot.generated_at)<=telemetryClearedAt)){
  status.textContent='History was cleared. Waiting for a new collector check; recording continues.';return;
 }
 const data=snapshot?.telemetry_history;
 if(snapshot?.telemetry_history_status!=='available'){
  status.textContent=snapshot?.telemetry_history_status==='not_recorded'?'No diagnostic history has been recorded yet.':'Diagnostic history is unavailable. Existing recordings have not been changed.';return;
 }
 if(!data||data.window_hours!==24||!Array.isArray(data.rows)||data.rows.length>24||!Number.isFinite(data.first_hour_unix)||!Number.isFinite(data.last_hour_unix)||data.last_hour_unix-data.first_hour_unix!==23*3600){status.textContent='Diagnostic history could not be read.';return;}
 if(!data.rows.length){status.textContent='No diagnostic samples in the last 24 hours.';return;}
 const byHour=new Map();
 for(const row of data.rows){
  if(!row||!Number.isFinite(row.hour_unix)||row.hour_unix<data.first_hour_unix||row.hour_unix>data.last_hour_unix||(row.hour_unix-data.first_hour_unix)%3600!==0||byHour.has(row.hour_unix)){status.textContent='Diagnostic history could not be read.';return;}
  byHour.set(row.hour_unix,row);
 }
 if(!telemetryLabels[select.value])select.value='cpu.cpu.busy_percent';
 const metric=select.value;select.disabled=false;table.hidden=false;
 document.getElementById('telemetry-caption').textContent=telemetryLabels[metric]+' · times shown in your local time zone';
 const old=collectorError||!Number.isFinite(Date.parse(snapshot.generated_at))||Date.now()-Date.parse(snapshot.generated_at)>150000;
 status.textContent=(old?'Previously loaded history; refresh is unavailable. ':'')+byHour.size+' of 24 hours have observations. Missing readings are not zero. Discharge is recorded only while discharging.';
 for(let hour=data.last_hour_unix;hour>=data.first_hour_unix;hour-=3600){
  const source=byHour.get(hour), value=source?.metrics?.[metric], tr=node('tr','');
  const heading=node('th',new Date(hour*1000).toLocaleString());heading.setAttribute('scope','row');tr.append(heading);
  const valid=value&&['mean','min','max'].every(k=>typeof value[k]==='number'&&Number.isFinite(value[k]))&&Number.isInteger(value.count)&&value.count>0;
  for(const key of ['mean','min','max'])tr.append(node('td',valid?value[key].toFixed(1):'—'));
  tr.append(node('td',valid?String(value.count):'—'));
  const coverage=!source?'No samples':!valid?'No reading':source.mixed_boots?'Includes a restart':source.samples_with_issues>0?'Some sources unavailable':source.samples_with_issues===0?'Observed samples':'Coverage not recorded';
  tr.append(node('td',coverage));rows.append(tr);
 }
 scroll.scrollTop=position[0];scroll.scrollLeft=position[1];
}

function stale(){
 if(snapshot)renderTelemetry();
 const isStale=snapshot&&(!Number.isFinite(Date.parse(snapshot.generated_at))||Date.now()-Date.parse(snapshot.generated_at)>150000);
 if(collectorError||isStale){
  if(isStale&&!collectorError)document.getElementById('notice').textContent='Status is stale. These results do not describe the current system.';
  document.getElementById('overall-title').textContent='Current status unavailable';
  document.querySelector('.overview').className='overview unavailable';
  document.getElementById('overview-description').textContent='Previously loaded checks may remain below. They do not confirm current protection.';
 }
}
async function refresh(){
 const button=document.getElementById('refresh');button.disabled=true;
 try{
  if(!window.cockpit)throw Error('Open this page through Cockpit to connect to the laptop.');
  const text=await cockpit.spawn(['/usr/bin/python3','-I','/usr/local/lib/security-center/client.py'],{superuser:false});
  const data=JSON.parse(text);if(data.error)throw Error(data.error);if(data.schema_version!==1||!Array.isArray(data.modules))throw Error('Unsupported collector response');
  collectorError=false;snapshot=data;document.getElementById('notice').textContent='';render();stale();
 }catch(error){collectorError=true;document.getElementById('notice').textContent=error.message||'Collector unavailable. Existing protections continue independently.';document.getElementById('overall-title').textContent='Current status unavailable';}
 finally{button.disabled=false;stale();}
}
document.getElementById('telemetry-metric').addEventListener('change',renderTelemetry);
document.getElementById('event-search').addEventListener('input',()=>{eventLimit=100;renderEvents();});
document.getElementById('more-events').addEventListener('click',()=>{eventLimit+=100;renderEvents();});
document.getElementById('refresh').addEventListener('click',refresh);
document.querySelectorAll('[data-filter]').forEach(button=>button.addEventListener('click',()=>{filter=button.dataset.filter;document.querySelectorAll('[data-filter]').forEach(b=>{b.classList.toggle('selected',b===button);b.setAttribute('aria-pressed',b===button?'true':'false');});if(snapshot)render();stale();}));
refresh();setInterval(()=>{if(!document.hidden)refresh();},60000);setInterval(stale,10000);

// On-demand trust management uses only the fixed administrator helper.
let trustBusy=false, trustProposal=null, trustTrigger=null;
const trustErrors={authorization_required:'Administrator access was not granted.',busy:'Another trust change is in progress. Reload devices and try again.',review_required:'The device or saved policy changed. Reload devices and review again.',unavailable:'Device management is unavailable. Its helper may not be installed.'};
async function trustRequest(request){
 if(!window.cockpit)throw Error('Open Security Center through Cockpit to manage devices.');
 const process=cockpit.spawn(['/usr/bin/python3','-I','/usr/local/lib/security-center/device-trust-helper.py'],{superuser:'require',err:'ignore'});
 process.input(JSON.stringify(request)+'\n',false);
 let raw;
 raw=await new Promise((resolve,reject)=>process.then(resolve,(error,output)=>{
  if(error.problem==='access-denied'||error.problem==='authentication-failed'){reject(Error(trustErrors.authorization_required));return;}
  if(typeof output==='string'&&output.length<=524288){
   try{const response=JSON.parse(output);if(response.ok===false&&Object.prototype.hasOwnProperty.call(trustErrors,response.error)){reject(Error(trustErrors[response.error]));return;}}catch(_error){}
  }
  reject(Error('Device management could not finish. Reload devices and review again. The helper may not be installed.'));
 }));
 if(typeof raw!=='string'||raw.length>524288)throw Error('Invalid device-management response.');
 const data=JSON.parse(raw);
 if(data.ok!==true)throw Error(trustErrors[data.error]||trustErrors.unavailable);
 return data.result;
}
function trustSetBusy(value){
 trustBusy=value;
 document.getElementById('trust-load').disabled=value;
 document.getElementById('trust-save').disabled=value;
 document.getElementById('trust-cancel').disabled=value;
 document.querySelectorAll('[data-trust-action]').forEach(button=>{button.disabled=value;});
}
function trustIdentity(device){
 const dl=node('dl','');
 const fields=[['USB ID',device.vendor+':'+device.product],['Serial',device.serial||'Not provided'],['Port',device.port],['Interfaces',device.interfaces.join(', ')]];
 for(const [label,value] of fields)dl.append(node('dt',label),node('dd',value));
 return dl;
}
function trustName(device){return device.vendor==='046d'&&device.product==='c542'?'Logitech receiver':device.vendor==='09da'&&device.product==='0025'?'A4tech receiver':'USB device '+device.vendor+':'+device.product;}
function trustHideReview(){trustProposal=null;document.getElementById('trust-review').hidden=true;}
function trustRender(data){
 if(!data||data.schema_version!==1||!Array.isArray(data.connected)||!Array.isArray(data.saved)||data.connected.length>128||data.saved.length>128||!/^[0-9a-f]{64}$/.test(data.revision))throw Error('Invalid device list.');
 // Candidate editing is separate from the independently observed live USBGuard policy.
 document.getElementById('trust-observation').textContent=(data.observation_status==='available'?'USB observation loaded'+(Number.isFinite(data.observed_at)?' at '+new Date(data.observed_at*1000).toLocaleString():'')+'. Reload to check for changes.':'USB observation unavailable; connection status is unknown.')+' Saved entries are candidates. This editor does not change live USBGuard rules; check its protection row for current device decisions.';
 const connected=document.getElementById('trust-connected'),saved=document.getElementById('trust-saved');
 connected.replaceChildren();saved.replaceChildren();
 function row(entry,action,label){
  const li=node('li','');li.append(node('h4',trustName(entry.device)),trustIdentity(entry.device),node('p',label,'muted'));
  if(action){const button=node('button',action==='add'?'Review trust':'Review removal');button.type='button';button.dataset.trustAction=action;button.setAttribute('aria-label',button.textContent+' for '+trustName(entry.device)+' at '+entry.device.port);button.addEventListener('click',()=>trustReview(action,entry.id,button));li.append(button);}
  return li;
 }
 for(const entry of data.connected)connected.append(row(entry,entry.saved||entry.internal?null:'add',entry.saved?'Saved candidate':entry.internal?'Listed as internal':'Not in saved trust list'));
 for(const entry of data.saved)saved.append(row(entry,'remove',entry.connected===true?'Connected':entry.connected===false?'Disconnected':'Connection unknown'));
 if(!data.connected.length)connected.append(node('li',data.observation_status==='available'?'No USB peripherals observed.':'Connected devices could not be read.'));
 if(!data.saved.length)saved.append(node('li','No saved trusted external devices.'));
 document.getElementById('trust-lists').hidden=false;
}
async function trustLoad(){
 if(trustBusy)return;trustSetBusy(true);trustHideReview();document.getElementById('trust-lists').hidden=true;
 document.getElementById('trust-status').textContent='Loading devices…';
 try{trustRender(await trustRequest({operation:'list'}));document.getElementById('trust-status').textContent='Device list loaded. Review a device to change saved trust.';}
 catch(error){document.getElementById('trust-status').textContent=error.message;}
 finally{trustSetBusy(false);}
}
async function trustReview(action,id,trigger){
 if(trustBusy)return;trustSetBusy(true);trustHideReview();trustTrigger=trigger;
 document.getElementById('trust-status').textContent='Checking the device and current policy…';
 try{
  const proposal=await trustRequest({operation:'propose',action,device_id:id});
  if(proposal?.schema_version!==1||proposal.action!==action||proposal.device_id!==id||!proposal.device||!Array.isArray(proposal.device.interfaces))throw Error('Invalid trust review. Reload devices.');
  trustProposal=proposal;
  document.getElementById('trust-review-action').textContent=(action==='add'?'Add to saved normal-mode trust: ':'Remove from saved normal-mode trust: ')+trustName(proposal.device);
  document.getElementById('trust-review-identity').replaceChildren(...trustIdentity(proposal.device).children);
  document.getElementById('trust-keyboard').hidden=!proposal.device.interfaces.some(i=>i==='03:01:01');
  document.getElementById('trust-save').textContent=action==='add'?'Save trusted-device candidate':'Remove saved trust';
  document.getElementById('trust-review').hidden=false;document.getElementById('trust-review-title').focus();
  document.getElementById('trust-status').textContent='Review the exact identity below before saving.';
 }catch(error){trustHideReview();document.getElementById('trust-status').textContent=error.message;}
 finally{trustSetBusy(false);}
}
async function trustSave(){
 if(trustBusy||!trustProposal)return;trustSetBusy(true);
 const proposal=trustProposal;document.getElementById('trust-status').textContent='Saving candidate change…';
 try{
  const data=await trustRequest({operation:'apply',proposal});trustHideReview();trustRender(data);
  document.getElementById('trust-status').textContent='Candidate change saved. Live USBGuard rules were not changed.';
 }catch(error){trustHideReview();document.getElementById('trust-lists').hidden=true;document.getElementById('trust-status').textContent=error.message+' Reload devices before another change.';}
 finally{trustSetBusy(false);document.getElementById('trust-load').focus();}
}
const trustLoadButton=document.getElementById('trust-load');
if(trustLoadButton){
 trustLoadButton.addEventListener('click',trustLoad);
 document.getElementById('trust-save').addEventListener('click',trustSave);
 document.getElementById('trust-cancel').addEventListener('click',()=>{if(trustBusy)return;trustHideReview();document.getElementById('trust-status').textContent='Review cancelled. No change was saved.';if(trustTrigger?.isConnected)trustTrigger.focus();else trustLoadButton.focus();});
}

// Read-only recovery review. Token presence never establishes successful unlock.
function automaticUnlockReview(data, failed, now=Date.now()){
 const generated=Date.parse(data?.generated_at);
 if(failed||!Number.isFinite(generated)||now-generated>150000||generated-now>30000||!Array.isArray(data?.modules))
  return {status:'Current checks are unavailable or stale. Refresh status before reviewing recovery.',checks:[],repair_available:false};
 const ids=['secureboot','lockdown','tpm','luks'];
 const checks=ids.map(id=>{
  const matches=data.modules.filter(m=>m&&m.id===id);
  if(matches.length!==1)return id+': check unavailable.';
  const m=matches[0];
  const title={secureboot:'Secure Boot',lockdown:'Kernel protection',tpm:'TPM',luks:'Disk encryption'}[id];
  return title+': '+(typeof m.summary==='string'?m.summary.slice(0,500):'Check unavailable.');
 });
 return {status:'These settings do not establish whether automatic unlock succeeded or why it failed. No repair has been performed.',checks,repair_available:false};
}
function showAutomaticUnlockReview(){
 const review=automaticUnlockReview(snapshot,collectorError);
 const panel=document.getElementById('unlock-review-panel');panel.hidden=false;
 document.getElementById('unlock-review-status').textContent=review.status;
 const list=document.getElementById('unlock-review-checks');list.replaceChildren();
 review.checks.forEach(text=>list.append(node('li',text)));
 document.getElementById('unlock-review-title').focus();
}
const unlockReviewButton=document.getElementById('unlock-review');
if(unlockReviewButton){
 unlockReviewButton.addEventListener('click',showAutomaticUnlockReview);
 document.getElementById('unlock-review-close').addEventListener('click',()=>{document.getElementById('unlock-review-panel').hidden=true;unlockReviewButton.focus();});
}
