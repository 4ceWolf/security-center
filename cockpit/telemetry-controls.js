'use strict';
// Loading or refreshing never requests administrator access.
(() => {
 const byId=id=>document.getElementById(id);
 const download=byId('diagnostic-download'),clear=byId('diagnostic-clear');
 if(!download||!clear)return;
 const resolution=byId('diagnostic-resolution'),hours=byId('diagnostic-hours');
 const processes=byId('diagnostic-processes'),review=byId('diagnostic-clear-review');
 const cancel=byId('diagnostic-clear-cancel'),confirm=byId('diagnostic-clear-confirm');
 const status=byId('diagnostic-action-status');let busy=false;
 const errors={authorization_required:'Administrator access was not granted.',busy:'The recorder is busy. Try again in a moment.',invalid_request:'The selection was rejected. Review your options and try again.',not_recorded:'No diagnostic database exists yet.',unavailable:'Diagnostic controls are unavailable. The helper may not be installed.'};
 function setBusy(value){
  busy=value;byId('diagnostic-export-options').disabled=value;
  for(const button of [download,clear,cancel,confirm])button.disabled=value;
 }
 function setWindow(){
  hours.replaceChildren();
  for(const [value,label] of (resolution.value==='raw'?[[1,'Last hour'],[6,'Last 6 hours'],[24,'Last 24 hours']]:[[24,'Last 24 hours'],[168,'Last 7 days'],[2160,'Last 90 days']])){
   const option=document.createElement('option');option.value=String(value);option.textContent=label;hours.append(option);
  }
  hours.value='24';
 }
 async function request(data){
  if(!window.cockpit)throw Error('Open Security Center through Cockpit to use diagnostic controls.');
  const child=cockpit.spawn(['/usr/bin/python3','-I','/usr/local/lib/security-center/telemetry-helper.py'],{superuser:'require',err:'ignore'});
  child.input(JSON.stringify(data)+'\n',false);
  const raw=await new Promise((resolve,reject)=>child.then(resolve,(error,output)=>{
   if(error.problem==='access-denied'||error.problem==='authentication-failed'){reject(Error(errors.authorization_required));return;}
   if(typeof output==='string'&&output.length<=4096){
    try{const result=JSON.parse(output);if(result.ok===false&&Object.prototype.hasOwnProperty.call(errors,result.error)){reject(Error(errors[result.error]));return;}}catch(_error){}
   }
   reject(Error('The operation could not finish. Check the current history before retrying; the helper may not be installed.'));
  }));
  if(typeof raw!=='string'||raw.length>32*1024*1024)throw Error('The diagnostic response is too large or invalid.');
  let result;try{result=JSON.parse(raw);}catch(_error){throw Error('The diagnostic response is incomplete. No download was created.');}
  if(result?.ok===false)throw Error(errors[result.error]||errors.unavailable);
  return {raw,result};
 }
 function closeReview(message){review.hidden=true;status.textContent=message;clear.focus();}
 resolution.addEventListener('change',()=>{if(!busy)setWindow();});
 download.addEventListener('click',async()=>{
  if(busy)return;review.hidden=true;setBusy(true);status.textContent='Preparing a private diagnostic download…';
  const selection={operation:'export',resolution:resolution.value,hours:Number(hours.value),include_processes:processes.checked};
  try{
   const {raw,result}=await request(selection);
   if(result?.schema!==1||result.kind!=='local_diagnostic_export'||result.resolution!==selection.resolution||result.window_hours!==selection.hours||result.process_details_included!==selection.include_processes||!Array.isArray(result.rows)||result.row_count!==result.rows.length||result.rows.length>(selection.resolution==='raw'?2880:2160))throw Error('The diagnostic response does not match your selection. No download was created.');
   const blob=new Blob([raw],{type:'application/json'});
   if(blob.size>32*1024*1024)throw Error('The diagnostic download is too large. Choose a shorter window.');
   const url=URL.createObjectURL(blob),link=document.createElement('a');
   try{
    link.href=url;link.download='security-center-diagnostics-'+selection.resolution+'-'+new Date().toISOString().slice(0,10)+'.json';
    link.hidden=true;document.body.append(link);link.click();
    status.textContent='Download started with '+result.row_count+' recorded '+(selection.resolution==='raw'?'samples':'hours')+'. Check your browser downloads. Nothing was uploaded.';
   }finally{link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  }catch(error){status.textContent=error.message;}
  finally{setBusy(false);download.focus();}
 });
 clear.addEventListener('click',()=>{if(busy)return;review.hidden=false;status.textContent='Review what clearing history removes before confirming.';cancel.focus();});
 cancel.addEventListener('click',()=>{if(!busy)closeReview('History kept. No change was made.');});
 review.addEventListener('keydown',event=>{if(event.key==='Escape'&&!busy){event.preventDefault();closeReview('History kept. No change was made.');}});
 confirm.addEventListener('click',async()=>{
  if(busy||review.hidden)return;setBusy(true);status.textContent='Clearing saved diagnostic history…';
  try{
   const {result}=await request({operation:'erase',confirmation:'erase_saved_telemetry'});
   if(result?.schema!==1||result.kind!=='local_diagnostic_erasure'||!Number.isInteger(result.removed_samples)||result.removed_samples<0||!Number.isInteger(result.removed_hours)||result.removed_hours<0||!Number.isFinite(result.erased_at_unix)||result.erased_at_unix<=0||result.recording_continues!==true||result.forensic_erasure!==false)throw Error('The response could not confirm removal. Reload current history before retrying.');
   if(typeof telemetryHistoryCleared==='function')telemetryHistoryCleared(result.erased_at_unix);
   review.hidden=true;
   status.textContent='Cleared '+result.removed_samples+' samples and '+result.removed_hours+' hourly summaries. Recording continues. Earlier downloads and backups remain.';
  }catch(error){review.hidden=true;status.textContent=error.message;}
  finally{setBusy(false);clear.focus();}
 });
})();
