'use strict';
(() => {
 const button=document.getElementById('unlock-disable');
 if(!button)return;
 const panel=document.getElementById('unlock-disable-panel');
 const confirm=document.getElementById('unlock-disable-confirm');
 const cancel=document.getElementById('unlock-disable-cancel');
 const acknowledge=document.getElementById('unlock-disable-ack');
 const status=document.getElementById('unlock-disable-status');
 let busy=false, proposal=null;
 function setBusy(value){busy=value;button.disabled=value;cancel.disabled=value;acknowledge.disabled=value;confirm.disabled=value||!proposal||!acknowledge.checked;}
 function clear(){proposal=null;panel.hidden=true;acknowledge.checked=false;confirm.disabled=true;}
 async function request(data){
  if(!window.cockpit)throw Error('Open Security Center in Cockpit to use this control.');
  const process=cockpit.spawn(['/usr/bin/python3','-I','/usr/local/lib/security-center/tpm-unlock-helper.py'],{superuser:'require',err:'ignore'});
  process.input(JSON.stringify(data)+'\n',false);
  let raw;
  try{raw=await process;}catch(_error){throw Error('Operation did not complete normally. Refresh and review before retrying; if disabling had begun, administrator inspection may be needed.');}
  if(typeof raw!=='string'||raw.length>8192)throw Error('Invalid helper response.');
  const response=JSON.parse(raw);
  if(response.ok!==true||!response.result)throw Error('Operation could not be verified. Refresh and review again.');
  return response.result;
 }
 button.addEventListener('click',async()=>{
  if(busy)return;clear();setBusy(true);status.textContent='Checking disk enrollment with administrator access…';
  try{
   const data=await request({operation:'review'});
   if(data.schema_version!==1||data.action!=='disable_tpm_unlock'||typeof data.state_sha256!=='string'||!/^[0-9a-f]{64}$/.test(data.state_sha256)||!Number.isInteger(data.issued_at)||!/^\d{1,2}$/.test(data.token_id))throw Error('Invalid review.');
   proposal=data;panel.hidden=false;
   document.getElementById('unlock-disable-identity').textContent='Encrypted disk '+data.device_uuid+' · TPM token '+data.token_id;
   document.getElementById('unlock-disable-title').focus();
   status.textContent='Review ready. Automatic unlock is still enabled. This review expires after two minutes.';
  }catch(error){clear();status.textContent=error.message;}
  finally{setBusy(false);}
 });
 acknowledge.addEventListener('change',()=>setBusy(busy));
 cancel.addEventListener('click',()=>{if(busy)return;clear();status.textContent='Cancelled. Automatic unlock was not changed.';button.focus();});
 confirm.addEventListener('click',async()=>{
  if(busy||!proposal||!acknowledge.checked)return;
  if(Date.now()/1000-proposal.issued_at>120){clear();status.textContent='Review expired. Review the current enrollment again.';return;}
  const reviewed=proposal;setBusy(true);status.textContent='Use the local disk-passphrase dialog. A protected backup will be verified before disabling.';
  try{
   const result=await request({operation:'disable',proposal:reviewed});
   if(result.disabled!==true||result.manual_slot_0_preserved!==true||result.boot_verified!==false)throw Error('Disable result could not be verified. Ask for administrator inspection.');
   clear();status.textContent='TPM automatic unlock disabled. Next startup requires your disk passphrase. The current session stays open; startup has not been tested.';
  }catch(error){clear();status.textContent=error.message;}
  finally{setBusy(false);button.focus();}
 });
})();
