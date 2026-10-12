// Test-only Chromium CDP harness. No external packages, production hook or real profile.
import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
const [browser, profile, launch, outDir, attacker] = process.argv.slice(2);
const summary={desktop:false,mobile:false,reflow320:false,zoom200:false,keyboard:false,htmlInjectionBlocked:false,cookieHidden:false,cookieOnlyBlocked:false,codeReplayBlocked:false,crossOriginBlocked:false,refresh:false,logout:false,recoveryEnvelopeRetained:false,consoleErrors:[]};
const proc=spawn(browser,['--headless','--disable-gpu','--no-first-run','--disable-background-networking','--disable-component-update','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{stdio:['ignore','ignore','pipe']});
let stderr='';proc.stderr.on('data',b=>{stderr+=b.toString();if(stderr.length>16384)stderr=stderr.slice(-16384);});
let socket;let phase="browser startup";
const pending=new Map();let sequence=0;const events=[];
async function waitFor(fn,seconds=10){const end=Date.now()+seconds*1000;for(;;){const value=await fn();if(value)return value;if(Date.now()>end)throw new Error('Browser acceptance condition timed out');await new Promise(r=>setTimeout(r,50));}}
function send(method,params={}){const id=++sequence;return new Promise((resolve,reject)=>{pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});}
async function evalJS(expression){const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error('Browser expression failed');return r.result.value;}
async function screenshot(name){const r=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(outDir,name),Buffer.from(r.data,'base64'));}
function check(condition,label){if(!condition)throw new Error(label);}
try{
 const port=await waitFor(()=>{try{return fs.readFileSync(path.join(profile,'DevToolsActivePort'),'utf8').split('\n')[0];}catch{return false;}});
 const targets=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();const target=targets.find(t=>t.type==='page');check(target,'No browser page target');
 socket=new WebSocket(target.webSocketDebuggerUrl);await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
 socket.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);if(!p)return;pending.delete(m.id);if(m.error)p.reject(new Error(m.error.message));else p.resolve(m.result);}else{events.push(m);if(m.method==='Runtime.exceptionThrown')summary.consoleErrors.push('Runtime exception');}};
 await send('Page.enable');await send('Runtime.enable');await send('Accessibility.enable');await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});await send('Page.navigate',{url:launch});
 phase='inventory render';await waitFor(()=>evalJS("document.querySelectorAll('.device-card').length>=2"));
 check(await evalJS("!location.hash"),'Launch material retained in browser URL');
 summary.cookieHidden=await evalJS("!document.cookie.includes('kavern_ui_')");check(summary.cookieHidden,'HttpOnly browser cookie visible');
 await send('Page.bringToFront');await evalJS("document.querySelector('.device-card').focus()");check(await evalJS("document.activeElement.classList.contains('device-card')"),'Device button did not acquire keyboard focus');await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
 phase='keyboard device detail';await waitFor(()=>evalJS("document.querySelector('#detail .summary')!==null"));summary.keyboard=await evalJS("document.activeElement.id==='detail-heading'");check(summary.keyboard,'Keyboard activation did not return focus to device heading');
 summary.htmlInjectionBlocked=await evalJS("!window.syntheticInjection && document.querySelector('#detail h2').textContent.includes('<img') && document.querySelector('#detail img')===null");check(summary.htmlInjectionBlocked,'Untrusted name executed as HTML');
 const ax=await send('Accessibility.getFullAXTree');fs.writeFileSync(path.join(outDir,'w1-accessibility-summary.json'),JSON.stringify({roles:[...new Set(ax.nodes.filter(n=>!n.ignored).map(n=>n.role?.value))],focusedHeading:summary.keyboard},null,2));
 await fetch(new URL('/fixture/ready',attacker));await evalJS("document.querySelector('#refresh').click()");await waitFor(()=>evalJS("document.querySelector('#detail h2')?.textContent==='Studio workstation'"));
 await screenshot('w1-desktop.png');summary.desktop=true;
 phase='review delayed selection and authority observation';
 await evalJS(`(()=>{const original=globalThis.fetch;globalThis.reviewOriginalFetch=original;globalThis.reviewStatusBlocked=false;globalThis.reviewDelayEnabled=true;globalThis.fetch=async(...args)=>{const response=await original(...args);if(globalThis.reviewDelayEnabled&&String(args[0]).includes('api/devices/workstation/status')){globalThis.reviewDelayEnabled=false;globalThis.reviewStatusBlocked=true;await new Promise(resolve=>globalThis.reviewReleaseStatus=resolve);}return response;};document.querySelector('#refresh').click();})()`);
 await waitFor(()=>evalJS('globalThis.reviewStatusBlocked'));
 await evalJS("document.querySelectorAll('.device-card')[1].click();globalThis.reviewReleaseStatus();");
 await new Promise(r=>setTimeout(r,250));
 const reviewSelection=await evalJS("document.querySelector('#detail h2')?.textContent");
 await evalJS(`(()=>{globalThis.fetch=globalThis.reviewOriginalFetch;document.querySelectorAll('.device-card')[0].click();})()`);
 await waitFor(()=>evalJS("document.querySelector('#detail .summary')!==null"));
 await new Promise(r=>setTimeout(r,100));
 await evalJS(`(()=>{const original=globalThis.reviewOriginalFetch;globalThis.reviewStatusBlocked=false;globalThis.reviewDelayEnabled=true;globalThis.reviewUncertain=false;globalThis.fetch=async(...args)=>{if(globalThis.reviewUncertain&&String(args[0]).endsWith('api/status'))return new Response(JSON.stringify({health:'commit_uncertain',cleanup_pending:true}),{status:200,headers:{'Content-Type':'application/json'}});const response=await original(...args);if(globalThis.reviewDelayEnabled&&String(args[0]).includes('api/devices/workstation/status')){globalThis.reviewDelayEnabled=false;globalThis.reviewStatusBlocked=true;await new Promise(resolve=>globalThis.reviewReleaseStatus=resolve);}return response;};document.querySelector('#refresh').click();})()`);
 await waitFor(()=>evalJS('globalThis.reviewStatusBlocked'));
 await evalJS("globalThis.reviewUncertain=true;document.querySelector('#refresh').click();");
 await waitFor(()=>evalJS("document.querySelector('#detail h2')?.textContent==='Status unavailable'"));
 await evalJS('globalThis.reviewReleaseStatus()');
 await new Promise(r=>setTimeout(r,250));
 const reviewAuthority=await evalJS("({health:document.querySelector('#health').textContent,ready:document.querySelector('#detail .device-heading .pill')?.textContent})");
 check(reviewSelection==='Travel device'&&reviewAuthority.ready!=='Ready',`Review regressions: delayed selection=${reviewSelection}; health=${reviewAuthority.health}; ready=${reviewAuthority.ready}`);

 summary.latestSelectionFenced=true;summary.unavailableHealthFenced=true;
 // Restore the real fixture after the unavailable-authority assertion. Later
 // layout/error cases require healthy fixture authority, not forced uncertainty.
 await evalJS("globalThis.fetch=globalThis.reviewOriginalFetch;document.querySelector('#refresh').click();");
 await waitFor(()=>evalJS("document.querySelector('#health').textContent==='Daemon running'&&document.querySelector('#detail .summary')!==null"));
 await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});await evalJS("document.querySelector('#detail').scrollIntoView({block:'start'})");await screenshot('w1-mobile.png');summary.mobile=await evalJS("document.documentElement.scrollWidth<=window.innerWidth");check(summary.mobile,'Mobile layout overflow');
 await send('Emulation.setDeviceMetricsOverride',{width:320,height:844,deviceScaleFactor:1,mobile:true});summary.reflow320=await evalJS("document.documentElement.scrollWidth<=window.innerWidth");check(summary.reflow320,'320px reflow failed');await screenshot('w1-reflow-320.png');
 await send('Emulation.setDeviceMetricsOverride',{width:720,height:500,deviceScaleFactor:2,mobile:false});summary.zoom200=await evalJS("document.querySelector('#detail h2')!==null");await screenshot('w1-zoom-200.png');
 await fetch(new URL('/fixture/bind-failure',attacker));await evalJS("document.querySelector('#refresh').click()");await waitFor(()=>evalJS("document.querySelector('#detail .device-heading .pill')?.textContent==='Listener failed'"));await screenshot('w1-bind-failure.png');
 await evalJS("document.querySelectorAll('.device-card')[1].focus()");await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});await waitFor(()=>evalJS("document.querySelector('#detail h2')?.textContent==='Travel device'"));check(await evalJS("document.querySelector('#detail').textContent.includes('Agent disconnected')&&document.querySelector('#detail').textContent.includes('Not reported')"),'Offline client kind was invented');await screenshot('w1-offline-device.png');
 const base=new URL('.',launch).pathname;
 summary.cookieOnlyBlocked=await evalJS(`fetch(${JSON.stringify(base+'api/status')},{credentials:'same-origin'}).then(r=>r.status===401)`);check(summary.cookieOnlyBlocked,'Cookie alone authorized a private read');
 const code=new URL(launch).hash.slice('#launch='.length);
 summary.codeReplayBlocked=await evalJS(`fetch(${JSON.stringify(base+'session/bootstrap')},{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:${JSON.stringify(code)}})}).then(r=>r.status===401)`);check(summary.codeReplayBlocked,'One-use code replayed');
 await evalJS(`sessionStorage.setItem('synthetic-recovery-envelope','{"operation_id":"original","window":{"epoch":"1"}}')`);
 await send('Page.reload');await waitFor(()=>evalJS("document.querySelectorAll('.device-card').length>=2"));summary.refresh=true;
 // Cross-origin real browser fetch must fail preflight. Never serialize auth values.
 await send('Page.navigate',{url:attacker});await waitFor(()=>evalJS("document.title==='Synthetic attacker'"));summary.crossOriginBlocked=await evalJS(`fetch(${JSON.stringify(new URL(base+'session/bootstrap',launch).href)},{method:'POST',headers:{'Content-Type':'application/json'},body:'{"code":"synthetic"}'}).then(()=>false).catch(()=>true)`);check(summary.crossOriginBlocked,'Cross-origin browser request read the bridge');
 await send('Page.navigate',{url:new URL(base,launch).href});await waitFor(()=>evalJS("document.querySelectorAll('.device-card').length>=2"));
 await evalJS("document.querySelector('#logout').focus()");await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});await waitFor(()=>evalJS("document.querySelector('#health').textContent==='Session expired'"));summary.logout=true;summary.recoveryEnvelopeRetained=await evalJS("sessionStorage.getItem('synthetic-recovery-envelope')!==null");check(summary.recoveryEnvelopeRetained,'Auth expiry erased original recovery data');await screenshot('w1-expired-session.png');
 check(summary.consoleErrors.length===0,'Browser runtime exception');fs.writeFileSync(path.join(outDir,'w1-browser-summary.json'),JSON.stringify(summary,null,2));process.stdout.write('PASS: desktop/mobile/reflow, keyboard, safe rendering, auth, cross-origin, reload/logout and recovery retention\n');
}catch(e){try{if(socket){await screenshot('w1-failure.png');const visible=await evalJS('document.body?.innerText?.slice(0,2000)');fs.writeFileSync(path.join(outDir,'w1-failure-visible.txt'),String(visible));}}catch{};process.stderr.write(`FAIL: ${phase}: ${e.message}\n`);process.exitCode=1;}finally{if(socket)socket.close();proc.kill('SIGTERM');await Promise.race([new Promise(r=>proc.once('exit',r)),new Promise(r=>setTimeout(r,3000))]);if(proc.exitCode===null){proc.kill('SIGKILL');await new Promise(r=>proc.once('exit',r));process.stderr.write('FAIL: browser required forced recovery\n');process.exitCode=1;}}
