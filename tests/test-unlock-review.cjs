const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync('cockpit/app.js','utf8');
const start=source.indexOf('function automaticUnlockReview('),end=source.indexOf('function showAutomaticUnlockReview()');
assert(start>=0&&end>start);
const ctx=vm.createContext({Date,Number,Array});vm.runInContext(source.slice(start,end),ctx);
const now=Date.now();
const data={generated_at:new Date(now).toISOString(),modules:[
 {id:'secureboot',summary:'Secure Boot enabled'}, {id:'lockdown',summary:'Kernel lockdown: integrity'},
 {id:'tpm',summary:'TPM detected; unseal not tested'}, {id:'luks',summary:'Encrypted root active; recovery slot present'}]};
ctx.data=data;ctx.now=now;
function review(failed=false){ctx.failed=failed;return vm.runInContext('automaticUnlockReview(data,failed,now)',ctx)}
let result=review();assert.equal(result.checks.length,4);assert.equal(result.repair_available,false);
assert.match(result.status,/do not establish/);assert.match(result.status,/No repair/);
assert.equal(review(true).checks.length,0);
for(const timestamp of ('invalid',new Date(now-150001).toISOString(),new Date(now+30001).toISOString())){
 data.generated_at=timestamp;assert.equal(review().checks.length,0);assert.equal(review().repair_available,false);
}
data.generated_at=new Date(now).toISOString();data.modules.push({id:'tpm',summary:'duplicate'});
assert.match(review().checks[2],/unavailable/);
data.modules.pop();data.modules[0].summary='<img src=x onerror=alert(1)>';
assert.equal(review().checks[0],'Secure Boot: <img src=x onerror=alert(1)>');
assert.match(source.slice(end),/textContent=review.status/);assert.match(source.slice(end),/node\('li',text\)/);
ctx.data=null;assert.equal(review().checks.length,0);
console.log('PASS: recovery review freshness/error/missing/duplicate states, text-only data, no repair-success inference');
