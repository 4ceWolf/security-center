'use strict';
(() => {
 const load=document.getElementById('usb-policy-load');if(!load)return;
 const list=document.getElementById('usb-policy-list'),status=document.getElementById('usb-policy-status');
 const panel=document.getElementById('usb-policy-review'),confirm=document.getElementById('usb-policy-confirm'),cancel=document.getElementById('usb-policy-cancel');
 let busy=false,proposal=null;
 function clear(){proposal=null;panel.hidden=true;confirm.disabled=true;}
 function setBusy(value){busy=value;load.disabled=value;confirm.disabled=value||!proposal;cancel.disabled=value;list.querySelectorAll('button').forEach(b=>b.disabled=value);}
 async function review(action,id){
  if(busy)return;clear();setBusy(true);status.textContent='Reviewing the live USB policy…';
  try{
   const data=await trustRequest({operation:'native_review',action,selected_id:id});
   if(data.schema_version!==1||data.action!==action||data.selected_id!==id||typeof data.rule!=='string'||!Array.isArray(data.after_rules)||typeof data.before_sha256!=='string')throw Error('Invalid live-policy review.');
   proposal=data;panel.hidden=false;
   document.getElementById('usb-policy-action').textContent=action==='add'?'Trust this exact device on future reconnects':'Remove this device’s trust on future reconnects';
   document.getElementById('usb-policy-rule').textContent=data.rule;
   document.getElementById('usb-policy-diff').textContent=(action==='add'?'+ ':'− ')+data.rule+'\n\nPolicy before: '+data.before_sha256+'\nResulting rules:\n'+data.after_rules.join('\n');
   document.getElementById('usb-policy-keyboard').hidden=data.keyboard!==true;
   document.getElementById('usb-policy-title').focus();status.textContent='Review ready; it expires in two minutes. Current devices stay connected.';
  }catch(error){clear();status.textContent=error.message;}
  finally{setBusy(false);}
 }
 load.addEventListener('click',async()=>{
  if(busy)return;clear();setBusy(true);status.textContent='Loading live USBGuard policy…';list.replaceChildren();
  try{
   const data=await trustRequest({operation:'native_list'});
   if(data.schema_version!==1||!Array.isArray(data.connected_external)||!Array.isArray(data.trusted_external))throw Error('Invalid native device list.');
   function row(entry,action){
    const li=node('li',entry.rule);if(action==='add'&&entry.already_trusted===true){li.append(node('p','Exact allow rule already saved.'));list.append(li);return;}const button=node('button',action==='add'?'Review trusting device':'Review removing trust');button.type='button';
    button.addEventListener('click',()=>review(action,entry.id));li.append(button);list.append(li);
   }
   list.append(node('h4','Connected external devices'));data.connected_external.forEach(e=>row(e,'add'));
   list.append(node('h4','Trusted external rules'));data.trusted_external.forEach(e=>row(e,'remove'));
   status.textContent='Live policy loaded. USB identifiers can be imitated; trust is limited to the shown port and interfaces.';
  }catch(error){status.textContent=error.message;}
  finally{setBusy(false);}
 });
 cancel.addEventListener('click',()=>{if(busy)return;clear();status.textContent='Cancelled. The native policy was not changed.';load.focus();});
 confirm.addEventListener('click',async()=>{
  if(busy||!proposal)return;const exact=proposal;setBusy(true);status.textContent='Applying the reviewed native policy change…';
  try{
   const result=await trustRequest({operation:'native_apply',proposal:exact});
   if(result.phase!=='committed'||result.current_devices_changed!==false||result.reconnect_required!==true)throw Error('Native policy change needs administrator inspection.');
   clear();list.replaceChildren();status.textContent='Native trust policy saved and checked. Reconnect the device for the change to take effect. Current devices stay connected.';
  }catch(error){clear();list.replaceChildren();status.textContent=error.message+' If a change had begun, inspect the protected native-policy transaction before retrying.';}
  finally{setBusy(false);load.focus();}
 });
})();
