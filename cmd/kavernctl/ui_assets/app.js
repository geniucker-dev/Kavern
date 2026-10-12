const base = new URL('.', location.href).pathname;
const storageKey = `kavern-ui-auth:${base}`;
let token = '', next = '', usersNext = '', projectsNext = '', selected = '', loaded = 0, lastActivity = 0, healthState = 'unknown', healthEpoch = 0, healthRequest = 0, detailRequest = 0, detailController = null;
const $ = id => document.getElementById(id);
const node = (tag, text, className) => {
  const n=document.createElement(tag);
  if(text!==undefined)n.textContent=String(text);
  if(className)n.className=className;
  return n;
};
const notice = (text, error=false) => {
  $('notice').textContent=text;
  $('notice').className=error?'notice error':'notice';
};
function detailMessage(title,text,error=false,focus=false){
  const h=node('h2',title);
  h.id='detail-heading';
  h.tabIndex=-1;
  $('detail').replaceChildren(h,node('p',text,error?'detail-message error':'muted'));
  if(focus)h.focus();
}
function invalidateDetail(){
  detailRequest++;
  if(detailController)detailController.abort();
  detailController=null;
}
function clearSelection(){
  selected='';
  invalidateDetail();
  detailMessage('Choose a device','Select a device from this ownership scope to see a fresh server sample.');
}
function expire(){
  token='';
  healthState='unknown';
  healthEpoch++;
  healthRequest++;
  loaded++;
  invalidateDetail();
  try{
    sessionStorage.removeItem(storageKey);
  }catch{
  };
  $('health').textContent='Session expired';
  $('health').className='pill warning';
  $('device-list').replaceChildren();
  detailMessage('Local session expired','Open a fresh launch URL from kavernctl ui. Native agents and existing tunnels continue.');
  $('inventory-state').textContent='Authorization required';
  notice('The browser session ended. No server configuration changed.',true);
}
async function api(path, options={
}) {
  const headers={
    ...options.headers
  };
  if(token)headers['X-Kavern-UI-Token']=token;
  const requestToken=token;
  const response=await fetch(base+path,{
    ...options,headers,credentials:'same-origin',cache:'no-store'
  });
  const data=await response.json();
  if(path!=='session/bootstrap'&&requestToken!==token)throw new Error('session_expired');
  if(response.status===401){
    expire();
    throw new Error('session_expired');
  }if(!response.ok)throw new Error(data.code||'response_unconfirmed');
  return data;
}
function errorText(code){
  const texts={
    commit_uncertain:'Durability is uncertain. Ready state is unavailable. Recover state with the existing kavernctl online recover command.',capacity:'The private API is busy. Refresh after the current requests finish.',closed:'The daemon is unavailable.',response_unconfirmed:'The daemon response is unavailable or unconfirmed.',session_expired:'Open a fresh local launch URL.'
  };
  return texts[code]||'Status unavailable. Refresh to obtain a current server sample.';
}
function selectOptions(element,records,key,parentLabel){
  const value=element.value;
  const previous=element.selectedOptions[0]?.cloneNode(true);
  element.replaceChildren(node('option',parentLabel));
  element.firstChild.value='';
  for(const r of records){
    const o=node('option',r.Name?`${r.Name} · ${r.ID}`:r.ID);
    o.value=r.ID;
    element.append(o);
  }if(records.some(r=>r.ID===value))element.value=value;
  else if(value&&previous){
    element.append(previous);
    element.value=value;
  }
}
async function inventory(reset=true){
  if(!token)return;
  const ticket=++loaded;
  const user=$('user-filter').value;
  $('inventory-state').textContent='Loading owned devices…';
  $('more').disabled=true;
  try{
    if(reset){
      const users=await api('api/users');
      if(ticket!==loaded)return;
      selectOptions($('user-filter'),users.users||[],'ID','All users');
      usersNext=users.next||'';
      $('more-users').hidden=!usersNext;
      const projects=await api(`api/projects${user?'?user_id='+encodeURIComponent(user):''}`);
      if(ticket!==loaded)return;
      selectOptions($('project-filter'),projects.projects||[],'ID',user?'Choose a project':'All projects');
      projectsNext=projects.next||'';
      $('more-projects').hidden=!projectsNext;
      if(user&&!$('project-filter').value&&projects.projects?.length)$('project-filter').value=projects.projects[0].ID;
    }
    const currentProject=$('project-filter').value;
    if(user&&!currentProject){
      $('device-list').replaceChildren();
      $('inventory-state').textContent='Choose an owned project to view its devices.';
      $('more').hidden=true;
      return;
    }const q=new URLSearchParams();
    if(currentProject)q.set('project_id',currentProject);
    if(!reset&&next)q.set('after',next);
    const page=await api('api/devices'+(q.size?'?'+q:''));
    if(ticket!==loaded)return;
    if(reset)$('device-list').replaceChildren();
    for(const d of page.devices||[]){
      const b=node('button',undefined,'device-card');
      b.type='button';
      b.setAttribute('aria-pressed',String(d.ID===selected));
      b.append(node('strong',d.Name||d.ID),node('small',d.ID),node('small',`${d.ProjectID} · ${d.Enabled?'Enabled':'Disabled'}`));
      b.addEventListener('click',()=>choose(d.ID,true));
      $('device-list').append(b);
    }
    next=page.next||'';
    $('more').hidden=!next;
    $('inventory-state').textContent=$('device-list').children.length?`${$('device-list').children.length} device records shown`:'No devices in this project. Create records with the existing CLI.';
    $('more').disabled=false;
  }catch(e){
    if(token)notice(errorText(e.message),true);
    $('inventory-state').textContent='Inventory unavailable';
  }
}
function metric(label,value){
  const dl=node('dl',undefined,'metric');
  dl.append(node('dt',label),node('dd',value));
  return dl;
}
function fact(label,value){
  const group=node('div');
  group.append(node('dt',label),node('dd',value||'Not reported'));
  return group;
}
function statusLabel(status){
  if(!status.Device.Enabled)return ['Disabled','warning'];
  if(status.ready)return ['Ready','ready'];
  if(status.cleanup_pending)return ['Cleanup pending','warning'];
  if(status.Listeners.some(v=>v.state==='bind_failed'||v.state==='accept_failed'))return ['Listener failed','error'];
  if(!status.Session.present)return ['Agent disconnected','warning'];
  if(status.Session.protocol==='legacy_npc')return ['Legacy connected',''];
  return ['Connected · applying','warning'];
}
function render(configuration,status,focus){
  if(healthState!=='running')throw new Error('health_unavailable');
  if(configuration.Revision!==status.desired_revision){
    throw new Error('changing_revision');
  }const detail=$('detail');
  const heading=node('div',undefined,'device-heading');
  const names=node('div');
  const title=node('h2',configuration.Device.Name||configuration.Device.ID);
  title.id='detail-heading';
  title.tabIndex=-1;
  names.append(title,node('p',`${configuration.Device.ID} · Project ${configuration.Device.ProjectID} · User ${status.user_id}`,'identity'));
  const [label,tone]=statusLabel(status);
  heading.append(names,node('span',label,`pill ${tone}`));
  const summary=node('div',undefined,'summary');
  summary.append(metric('Desired revision',configuration.Revision),metric('Applied revision',status.Session.applied_revision||'Not reported'),metric('Live carriers',`${status.Session.carriers} / ${configuration.Policy.Carriers}`),metric('Renewals',status.Session.renewal_count||0),metric('Client protocol',status.Session.protocol==='kapv1'?'Kavern agent':status.Session.protocol==='legacy_npc'?'Legacy npc':'Not reported'),metric('Cleanup',status.cleanup_pending?'Pending':'No pending work'));
  const section=node('div',undefined,'section-heading');
  section.append(node('h3','TCP tunnels'),node('span',`${configuration.Tunnels.length} configured`,'muted'));
  const tunnels=node('div',undefined,'tunnels');
  const listeners=new Map(status.listeners.map(l=>[l.tunnel_id,l]));
  for(const t of configuration.Tunnels.slice(0,50)){
    const l=listeners.get(t.ID);
    const row=node('article',undefined,'tunnel');
    const top=node('div',undefined,'tunnel-top');
    top.append(node('h4',t.ID),node('span',!t.Enabled?'Disabled':l?.state||'Not reported','pill'));
    const facts=node('dl',undefined,'facts');
    facts.append(fact('Desired public listener',t.Listener),fact('Actual bound address',l?.bound_address),fact('Target on this device',t.TargetAddr),fact('Retry at',l?.retry_at||'No scheduled retry'));
    row.append(top,facts);
    tunnels.append(row);
  }if(!configuration.Tunnels.length)tunnels.append(node('p','No tunnels configured. The agent receives targets only from the server.','muted'));
  if(configuration.Tunnels.length>50)tunnels.append(node('p','Showing the first 50 tunnel records. Complete configuration remains on the server.','muted'));
  detail.replaceChildren(heading,summary,section,tunnels,node('p','Ready is a sampled server fact. Target reachability is unknown until traffic succeeds. Carrier policy is preserved and read-only.','note'));
  $('sample').textContent=`Sampled ${new Date().toLocaleTimeString()}`;
  if(focus)title.focus();
}
async function choose(id,focus=false){
  if(!token)return;
  const changed=selected!==id;
  // Polls share the in-flight sample. An explicit click always supersedes it.
  if(!changed&&!focus&&detailController)return;
  selected=id;
  invalidateDetail();
  for(const b of $('device-list').children)b.setAttribute('aria-pressed',String(b.querySelector('small')?.textContent===id));
  if(healthState!=='running'){
    detailMessage('Status unavailable','A current healthy daemon observation is required before showing device readiness.',true,focus);
    return;
  }
  if(changed)detailMessage('Loading device','Obtaining a fresh server sample for '+id+'.',false,focus);
  const ticket=detailRequest;
  const epoch=healthEpoch;
  const controller=new AbortController();
  detailController=controller;
  const current=()=>token&&selected===id&&ticket===detailRequest&&epoch===healthEpoch&&healthState==='running';
  try{
    const c=await api(`api/devices/${encodeURIComponent(id)}/configuration`,{signal:controller.signal});
    if(!current())return;
    const raw=await api(`api/devices/${encodeURIComponent(id)}/status`,{signal:controller.signal});
    if(!current())return;
    const s={...raw,Device:raw.device,Session:raw.session,Listeners:raw.listeners};
    render(c,s,focus);
  }catch(e){
    if(current()&&e.name!=='AbortError'){
      detailMessage('Status unavailable',errorText(e.message),true,focus);
      $('sample').textContent='Previous sample is stale';
      notice(errorText(e.message),true);
    }
  }finally{
    if(ticket===detailRequest)detailController=null;
  }
}
function unavailableHealth(label,message){
  healthState='unavailable';
  healthEpoch++;
  invalidateDetail();
  $('health').textContent=label;
  $('health').className='pill warning';
  detailMessage('Status unavailable',message,true);
  $('sample').textContent='Previous sample is stale';
  notice(message,true);
}
async function health(){
  if(!token)return;
  const ticket=++healthRequest;
  try{
    const s=await api('api/status');
    if(!token||ticket!==healthRequest)return;
    if(s.health!=='running'){
      unavailableHealth(s.health,'Daemon health requires attention. Configuration and readiness are unavailable.');
      return;
    }
    const recovered=healthState!=='running';
    healthState='running';
    $('health').textContent='Daemon running';
    $('health').className='pill ready';
    if(recovered&&selected)choose(selected);
  }catch(e){
    if(token&&ticket===healthRequest)unavailableHealth('Daemon unavailable',errorText(e.message));
  }
}
async function activity(event){
  if(!token||!event.isTrusted||Date.now()-lastActivity<30000)return;
  lastActivity=Date.now();
  try{
    await api('session/activity',{
      method:'POST',headers:{
        'Content-Type':'application/json'
      },body:'{}'
    });
  }catch{
  }
}
async function ownershipPage(kind){
  if(!token)return;
  const cursor=kind==='users'?usersNext:projectsNext;
  if(!cursor)return;
  const button=$(kind==='users'?'more-users':'more-projects');
  button.disabled=true;
  const user=$('user-filter').value;
  const q=new URLSearchParams({
    after:cursor
  });
  if(kind==='projects'&&user)q.set('user_id',user);
  try{
    const page=await api('api/'+kind+'?'+q);
    if(user!==$('user-filter').value)return;
    selectOptions($(kind==='users'?'user-filter':'project-filter'),page[kind]||[],'ID',kind==='users'?'All users':user?'Choose a project':'All projects');
    if(kind==='users')usersNext=page.next||'';
    else projectsNext=page.next||'';
    button.hidden=!page.next;
  }catch(e){
    if(token)notice(errorText(e.message),true);
  }finally{
    button.disabled=false;
  }
}
$('more-users').addEventListener('click',()=>ownershipPage('users'));
$('more-projects').addEventListener('click',()=>ownershipPage('projects'));
$('user-filter').addEventListener('change',()=>{
  $('project-filter').value='';clearSelection();inventory();
});
$('project-filter').addEventListener('change',()=>{
  clearSelection();inventory();
});
$('more').addEventListener('click',()=>inventory(false));
$('refresh').addEventListener('click',()=>{
  health();inventory();if(selected)choose(selected);
});
$('logout').addEventListener('click',async()=>{
  try{
    await api('session/logout',{
      method:'POST',headers:{
        'Content-Type':'application/json'
      },body:'{}'
    });
  }finally{
    expire();
  }
});
document.addEventListener('pointerdown',activity);
document.addEventListener('keydown',activity);
async function boot(){
  const fragment=location.hash;
  history.replaceState(null,'',location.pathname);
  try{
    if(fragment){
      const p=new URLSearchParams(fragment.slice(1));
      if([...p.keys()].length!==1||!p.has('launch'))throw new Error('session_expired');
      const s=await api('session/bootstrap',{
        method:'POST',headers:{
          'Content-Type':'application/json'
        },body:JSON.stringify({
          code:p.get('launch')
        })
      });
      token=s.request_token;
      try{
        sessionStorage.setItem(storageKey,token);
      }catch{
        notice('This browser cannot retain a session across reload; the current tab can still read status.');
      }
    }else{
      try{
        token=sessionStorage.getItem(storageKey)||'';
      }catch{
      }
    }
    if(!token){
      expire();
      return;
    }await health();
    await inventory();
    if(token)notice('Read-only connection established. Configuration remains owned by the daemon.');
  }catch{
    expire();
  }
}
boot();
setInterval(()=>{
  if(token&&!document.hidden&&selected)choose(selected);
},1000);
setInterval(()=>{
  if(token&&!document.hidden)health();
},5000);
