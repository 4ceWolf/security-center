#!/usr/bin/python3
"""Real Firefox DOM flow with synthetic native-policy replies; never administrator IPC."""
import importlib.util,json,pathlib,shutil,socket,subprocess,tempfile,time
ROOT=pathlib.Path('/home/user/Projects/security-center')
spec=importlib.util.spec_from_file_location('browser_fixture',ROOT/'tools/test-telemetry-browser.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
work=pathlib.Path(tempfile.mkdtemp(prefix='usb-controls-browser-',dir=ROOT/'work'));work.chmod(0o700)
profile=work/'profile';profile.mkdir()
probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
(profile/'user.js').write_text('user_pref("marionette.port",'+str(port)+');\nuser_pref("browser.shell.checkDefaultBrowser",false);\nuser_pref("toolkit.telemetry.enabled",false);\nuser_pref("datareporting.healthreport.uploadEnabled",false);\n')
for name in ('app.js','style.css','telemetry-controls.js','unlock-controls.js','usb-controls.js'):shutil.copyfile(ROOT/'cockpit'/name,work/name)
bridge=r'''window.fixture={calls:[],deny:false};window.cockpit={spawn(args,options){
 if(args[2]?.endsWith('/client.py'))return Promise.resolve(JSON.stringify({schema_version:1,generated_at:new Date().toISOString(),modules:[],events:[],overall:'unknown'}));
 if(!args[2]?.endsWith('/device-trust-helper.py')||options.superuser!=='require')throw Error('Unexpected native operation');
 let resolve,reject;const child=new Promise((a,b)=>{resolve=a;reject=b});
 child.input=raw=>{const data=JSON.parse(raw);fixture.calls.push(data);if(fixture.deny){reject({problem:'access-denied'});return;}
 const rule='allow id abcd:1234 serial "" name "<img src=x onerror=alert(1)>" hash "fake=" parent-hash "fake=" via-port "3-2" with-interface { 03:01:01 03:01:02 }';
 let result;
 if(data.operation==='native_list')result={schema_version:1,connected_external:[{id:99,rule}],trusted_external:[{id:8,rule}]};
 else if(data.operation==='native_review')result={schema_version:1,action:data.action,selected_id:data.selected_id,rule,before_sha256:'a'.repeat(64),after_rules:[rule,'block'],state_sha256:'b'.repeat(64),issued_at:Math.floor(Date.now()/1000),keyboard:true};
 else if(data.operation==='native_apply')result={phase:'committed',current_devices_changed:false,reconnect_required:true};
 else throw Error('Unexpected operation');
 resolve(JSON.stringify({ok:true,result}));};return child;
}};'''
(work/'fixture.js').write_text(bridge)
html=(ROOT/'cockpit/index.html').read_text().replace('<script src="../base1/cockpit.js"></script>','<script src="fixture.js"></script>')
(work/'index.html').write_text(html)
report={'scope':'Real Firefox synthetic native-policy UI only','passed':False,'checks':[],'work':str(work)}
browser=None;client=None
try:
 with (work/'browser.log').open('w') as log:
  browser=subprocess.Popen(['/usr/bin/firefox','--headless','--no-remote','--profile',str(profile),'--marionette','--remote-allow-system-access','about:blank'],stdout=log,stderr=subprocess.STDOUT)
  deadline=time.monotonic()+20
  while time.monotonic()<deadline:
   try:client=b.Marionette(port);break
   except OSError:time.sleep(.2)
  if client is None:raise RuntimeError('Browser did not start')
  client.call('WebDriver:NewSession',{'capabilities':{'alwaysMatch':{'acceptInsecureCerts':False}}})
  client.call('WebDriver:Navigate',{'url':(work/'index.html').as_uri()})
  def wait(expression):
   deadline=time.monotonic()+5
   while time.monotonic()<deadline:
    if client.script('return '+expression):return
    time.sleep(.05)
   raise AssertionError(expression)
  def click(element):client.script('document.querySelector('+json.dumps(element)+').click();return true')
  assert client.script('return fixture.calls.length')==0
  click('#usb-policy-load');wait('document.querySelectorAll("#usb-policy-list button").length===2')
  assert client.script('return document.querySelectorAll("#usb-policy-list img").length')==0
  click('#usb-policy-list button');wait('!document.getElementById("usb-policy-review").hidden')
  assert client.script('return !document.getElementById("usb-policy-keyboard").hidden')
  assert client.script('return document.activeElement.id')=='usb-policy-title'
  click('#usb-policy-cancel');assert client.script('return fixture.calls.filter(x=>x.operation==="native_apply").length')==0
  click('#usb-policy-list button');wait('!document.getElementById("usb-policy-confirm").disabled')
  click('#usb-policy-confirm');wait('document.getElementById("usb-policy-status").textContent.includes("Reconnect")')
  assert client.script('return fixture.calls.filter(x=>x.operation==="native_apply").length')==1
  report['checks']+=['No automatic elevation','Escaped device strings remain text','Exact review and keyboard warning','Cancellation performs no apply','Explicit apply and reconnect warning']
  client.script('fixture.deny=true;return true');click('#usb-policy-load');wait('document.getElementById("usb-policy-status").textContent.includes("not granted")')
  assert client.script('return document.querySelectorAll("#app-firewall-open,#app-firewall-stop").length')==0
  report['checks']+=['Administrator denial leaves review closed','Removed network controls are absent']
  screenshot=client.call('WebDriver:TakeScreenshot',{})
  import base64
  (work/'fixture.png').write_bytes(base64.b64decode(screenshot['value'] if isinstance(screenshot,dict) else screenshot))
  report['passed']=True
finally:
 if client:
  try:client.call('Marionette:Quit',{'flags':['eForceQuit']})
  except Exception:pass
  client.socket.close()
 if browser and browser.poll() is None:
  browser.terminate()
  try:browser.wait(timeout=5)
  except subprocess.TimeoutExpired:browser.kill();browser.wait()
 (work/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report))
