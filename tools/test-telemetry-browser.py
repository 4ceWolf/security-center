#!/usr/bin/python3
"""Disposable Firefox UI fixture; no Cockpit, elevation or real telemetry access."""
import base64
import contextlib
import json
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time

ROOT=pathlib.Path('/home/user/Projects/security-center')

class Marionette:
    def __init__(self,port):
        self.socket=socket.create_connection(('127.0.0.1',port),timeout=5)
        self.socket.settimeout(10);self.counter=0;self.receive()
    def receive(self):
        size=b''
        while not size.endswith(b':'):
            part=self.socket.recv(1)
            if not part:raise RuntimeError('Browser transport closed')
            size+=part
            if len(size)>12:raise ValueError('Invalid protocol prefix')
        count=int(size[:-1]);raw=bytearray()
        if count>16*1024*1024:raise ValueError('Oversized browser response')
        while len(raw)<count:
            part=self.socket.recv(min(65536,count-len(raw)))
            if not part:raise RuntimeError('Browser response interrupted')
            raw.extend(part)
        return json.loads(raw)
    def call(self,name,params=None):
        self.counter+=1;raw=json.dumps([0,self.counter,name,params or {}]).encode()
        self.socket.sendall(str(len(raw)).encode()+b':'+raw)
        response=self.receive()
        if response[:2]!=[1,self.counter] or response[2]:raise RuntimeError(str(response))
        return response[3]
    def script(self,script):
        return self.call('WebDriver:ExecuteScript',{'script':script,'args':[],'newSandbox':False})['value']
    def close(self):self.socket.close()


def main():
    work=pathlib.Path(tempfile.mkdtemp(prefix='telemetry-controls-browser-',dir=ROOT/'work'));work.chmod(0o700)
    profile=work/'profile';profile.mkdir();downloads=work/'downloads';downloads.mkdir()
    probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
    prefs={'marionette.port':port,'browser.shell.checkDefaultBrowser':False,'browser.startup.homepage':'about:blank',
           'browser.download.folderList':2,'browser.download.dir':str(downloads),'browser.download.useDownloadDir':True,
           'browser.helperApps.neverAsk.saveToDisk':'application/json','browser.download.always_ask_before_handling_new_types':False,
           'toolkit.telemetry.enabled':False,'datareporting.healthreport.uploadEnabled':False,
           'datareporting.policy.dataSubmissionEnabled':False,'app.normandy.enabled':False,
           'browser.safebrowsing.downloads.enabled':False,'browser.newtabpage.enabled':False}
    (profile/'user.js').write_text(''.join('user_pref('+json.dumps(k)+','+json.dumps(v)+');\n' for k,v in prefs.items()))
    for name in ('app.js','style.css','telemetry-controls.js'):shutil.copyfile(ROOT/'cockpit'/name,work/name)
    bridge='''window.fixture={calls:[],deny:false};
window.cockpit={spawn(args,options){
 if(args[2].endsWith('/client.py'))return Promise.resolve(JSON.stringify({schema_version:1,generated_at:new Date(Date.now()-1000).toISOString(),overall:'unknown',modules:[],events:[],telemetry_history_status:'not_recorded'}));
 if(!args[2].endsWith('/telemetry-helper.py')||options.superuser!=='require')throw Error('Unexpected fixture operation');
 let resolve,reject;const child=new Promise((a,b)=>{resolve=a;reject=b});
 child.input=raw=>{const data=JSON.parse(raw);fixture.calls.push(data);if(fixture.deny){reject({problem:'access-denied'});return;}
 resolve(JSON.stringify(data.operation==='export'?{schema:1,kind:'local_diagnostic_export',resolution:data.resolution,window_hours:data.hours,process_details_included:data.include_processes,rows:[],row_count:0}:{schema:1,kind:'local_diagnostic_erasure',removed_samples:0,removed_hours:0,recording_continues:true,forensic_erasure:false,erased_at_unix:Date.now()/1000}));};return child;
}};'''
    (work/'fixture.js').write_text(bridge)
    html=(ROOT/'cockpit/index.html').read_text().replace('<script src="../base1/cockpit.js"></script>','<script src="fixture.js"></script>').replace('THIS LAPTOP · SECURITY CENTER','LOCAL TEST FIXTURE · SYNTHETIC RESPONSES')
    (work/'index.html').write_text(html)
    report={'scope':'Local synthetic browser fixture only','work':str(work),'passed':False,'checks':[]}
    browser=None;client=None
    with (work/'firefox.log').open('w') as log:
        try:
            browser=subprocess.Popen(['/usr/bin/firefox','--headless','--no-remote','--profile',str(profile),'--marionette','--remote-allow-system-access','about:blank'],stdout=log,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                if browser.poll() is not None:raise RuntimeError('Firefox exited early')
                try:client=Marionette(port);break
                except (OSError,ConnectionError):time.sleep(.2)
            if client is None:raise RuntimeError('Browser control did not start')
            client.call('WebDriver:NewSession',{'capabilities':{'alwaysMatch':{'acceptInsecureCerts':False}}})
            client.call('WebDriver:Navigate',{'url':(work/'index.html').as_uri()})
            assert client.script('return fixture.calls.length')==0
            assert client.script("return !document.getElementById('diagnostic-processes').checked")
            client.script("document.getElementById('diagnostic-clear').click();return true")
            assert client.script('return document.activeElement.id')=='diagnostic-clear-cancel'
            client.call('WebDriver:PerformActions',{'actions':[{'type':'key','id':'keyboard','actions':[{'type':'keyDown','value':'\ue004'},{'type':'keyUp','value':'\ue004'}]}]})
            assert client.script('return document.activeElement.id')=='diagnostic-clear-confirm'
            client.call('WebDriver:PerformActions',{'actions':[{'type':'key','id':'keyboard','actions':[{'type':'keyDown','value':'\ue00c'},{'type':'keyUp','value':'\ue00c'}]}]})
            assert client.script("return document.getElementById('diagnostic-clear-review').hidden&&fixture.calls.length===0&&document.activeElement.id==='diagnostic-clear'")
            report['checks'].append('Native keyboard Tab/Escape and safe initial/restored focus')
            client.script("document.getElementById('diagnostic-download').click();return true")
            deadline=time.monotonic()+5;files=[]
            while time.monotonic()<deadline:
                files=list(downloads.glob('*.json'))
                if len(files)==1:
                    try:exported=json.loads(files[0].read_text());break
                    except json.JSONDecodeError:pass
                time.sleep(.1)
            else:raise RuntimeError('No complete JSON download arrived')
            assert exported['process_details_included'] is False
            report['checks'].append('Actual local JSON browser download; private process opt-in off')
            client.script("document.getElementById('diagnostic-clear').click();document.getElementById('diagnostic-clear-confirm').click();return true")
            assert client.script("return fixture.calls.at(-1).confirmation==='erase_saved_telemetry'")
            assert 'Waiting for a new collector' in client.script("return document.getElementById('telemetry-status').textContent")
            client.script("fixture.deny=true;document.getElementById('diagnostic-download').click();return true")
            assert 'Administrator access was not granted' in client.script("return document.getElementById('diagnostic-action-status').textContent")
            report['checks'].append('Fixture clear confirmation, cached-history suppression and denial recovery')
            layouts=[]
            for width,label in ((1080,'wide'),(540,'half-width'),(640,'narrow-zoom200')):
                client.call('WebDriver:SetWindowRect',{'width':width,'height':1100})
                if label=='narrow-zoom200':
                    # Privileged automation is enabled only for this throwaway
                    # synthetic profile. Set real browser page zoom, not CSS zoom.
                    client.call('Marionette:SetContext',{'value':'chrome'})
                    client.script('gBrowser.selectedBrowser.browsingContext.fullZoom=2;return true')
                    client.call('Marionette:SetContext',{'value':'content'})
                client.script("document.getElementById('diagnostic-controls-title').scrollIntoView();return true")
                result=client.script("return {width:innerWidth,pixelRatio:devicePixelRatio,pageWidth:document.documentElement.scrollWidth,bodyWidth:document.body.scrollWidth,downloadWidth:document.getElementById('diagnostic-download').getBoundingClientRect().width}")
                assert result['pageWidth']<=result['width'],result
                if label=='narrow-zoom200':assert result['width']<=320 and result['pixelRatio']>=1.99,result
                layouts.append(result)
                screenshot=client.call('WebDriver:TakeScreenshot',{'full':False})['value']
                (work/(label+'.png')).write_bytes(base64.b64decode(screenshot,validate=True))
            report['layouts']=layouts;report['checks'].append('Actual200% browser page zoom;320/540/1080 CSSpx layouts have no page overflow; screenshots saved')
            report['not_tested']=['Authenticated Cockpit/root helper','Screen reader','Production deletion','Live combined RAM']
            report['passed']=True
        except Exception as error:
            report['failure']=type(error).__name__+': '+str(error)
            raise
        finally:
            (work/'report.json').write_text(json.dumps(report,indent=2))
            if client:
                with contextlib.suppress(Exception):client.call('WebDriver:DeleteSession')
                client.close()
            if browser and browser.poll() is None:
                browser.terminate()
                try:browser.wait(timeout=5)
                except subprocess.TimeoutExpired:browser.kill();browser.wait(timeout=5)
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
