const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync('cockpit/unlock-controls.js','utf8');
class Element{constructor(){this.disabled=false;this.hidden=true;this.checked=false;this.textContent='';this.listeners={};} addEventListener(e,f){this.listeners[e]=f;}focus(){} async click(){await this.listeners.click();}}
const elements={};for(const id of ['unlock-disable','unlock-disable-panel','unlock-disable-confirm','unlock-disable-cancel','unlock-disable-ack','unlock-disable-status','unlock-disable-identity','unlock-disable-title'])elements[id]=new Element();
let requests=[],fail=false;
const proposed={schema_version:1,action:'disable_tpm_unlock',device_uuid:'fixture-uuid',token_id:'1',state_sha256:'a'.repeat(64),issued_at:Math.floor(Date.now()/1000)};
const cockpit={spawn(args,options){assert.deepEqual(Array.from(args),['/usr/bin/python3','-I','/usr/local/lib/security-center/tpm-unlock-helper.py']);assert.equal(options.superuser,'require');let req;
 return {input(raw){req=JSON.parse(raw);requests.push(req);},then(resolve,reject){if(fail)return Promise.reject(Error('failure')).then(resolve,reject);return Promise.resolve(JSON.stringify({ok:true,result:req.operation==='review'?proposed:{disabled:true,manual_slot_0_preserved:true,boot_verified:false}})).then(resolve,reject);}};}};
const ctx=vm.createContext({document:{getElementById:id=>elements[id]},window:{cockpit},cockpit,Date,Number,JSON,Error});
vm.runInContext(source,ctx);
(async()=>{
 await elements['unlock-disable-confirm'].click();assert.equal(requests.length,0);
 await elements['unlock-disable'].click();assert.equal(requests[0].operation,'review');assert.equal(elements['unlock-disable-confirm'].disabled,true);
 await elements['unlock-disable-cancel'].click();await elements['unlock-disable-confirm'].click();assert.equal(requests.length,1);
 await elements['unlock-disable'].click();elements['unlock-disable-ack'].checked=true;elements['unlock-disable-ack'].listeners.change();
 await elements['unlock-disable-confirm'].click();assert.equal(requests.at(-1).operation,'disable');assert.match(elements['unlock-disable-status'].textContent,/startup has not been tested/);
 assert.equal(elements['unlock-disable-panel'].hidden,true);
 fail=true;await elements['unlock-disable'].click();assert.match(elements['unlock-disable-status'].textContent,/inspection/);assert.equal(elements['unlock-disable-panel'].hidden,true);
 console.log('PASS: explicit review/acknowledgment, cancellation, fixed privileged helper, truthful success and failure states');
})().catch(e=>{console.error(e);process.exitCode=1;});
