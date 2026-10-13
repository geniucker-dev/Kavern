// Nonsecret drafts and exact request envelopes are independent of auth lifetime.
const $=id=>document.getElementById(id);
const el=(tag,text)=>{
  const n=document.createElement(tag);
  if(text!==undefined)n.textContent=String(text);
  return n;
};
const clone=value=>JSON.parse(JSON.stringify(value));
let hooks, current=null, draft=null, baseline=null, busy=false, preparing=false, pending=[], editingKind='', deviceID='', canIssue=null, capabilityPending=false;
const pendingKey='kavern-ui-requests-v1', draftKey='kavern-ui-draft-v1';
function button(text,action){
  const b=el('button',text);
  b.type='button';
  b.addEventListener('click',action);
  return b;
}
function field(form,id,label,value='',checkbox=false){
  const l=el('label',label);
  l.htmlFor=id;
  const i=el('input');
  i.id=id;
  i.name=id;
  i.type=checkbox?'checkbox':'text';
  if(checkbox)i.checked=!!value;
  else i.value=value;
  i.required=!checkbox;
  i.maxLength=id.includes('name')?256:id.includes('target')||id.includes('listener')?512:id==='bootstrap-ca'?4096:128;
  form.append(l,i);
  return i;
}
function persistDraft(){
  try{
    sessionStorage.setItem(draftKey,JSON.stringify({
      draft,baseline,editingKind,deviceID
    }));
  }catch{
  }
}
function persistRequests(){
  const data=JSON.stringify(pending);
  if(pending.length>4||new TextEncoder().encode(data).length>2*1024*1024)throw new Error('Recovery capacity reached. Resolve or explicitly discard an existing request first.');
  sessionStorage.setItem(pendingKey,data);
  if(sessionStorage.getItem(pendingKey)!==data)throw new Error('Recovery request could not be retained. Nothing dispatched.');
}
function say(text,error=false){
  hooks.notice(text,error);
  const state=$('edit-state');
  if(state){
    state.textContent=text;
    state.className=error?'detail-message error':'detail-message';
    state.focus();
  }
}
function authorized(){
  return !!hooks?.healthy();
}
function requestIdentity(r){return r.device_id||r.device?.ID||r.project?.ID||r.user?.ID;}
function hasUnresolved(request){const id=requestIdentity(request);return !!id&&pending.some(entry=>!entry.resolved&&entry.request.kind===request.kind&&requestIdentity(entry.request)===id);}
function editorHasUnresolved(){const kind=editingKind==='device'||editingKind==='tunnel'?'put_device':editingKind==='rotation'?'rotate_credential':`create_${editingKind}`;return hasUnresolved({kind,device_id:baseline?.Device.ID||draft?.ID||deviceID});}
export function healthChanged(){
  if(authorized()&&canIssue===null&&!capabilityPending){
    capabilityPending=true;
    hooks.api('api/capabilities').then(v=>{
      canIssue=v.issuance_enabled===true;
    }).catch(()=>{
      canIssue=false;
    }).finally(()=>{
      capabilityPending=false;
      healthChanged();
    });
  }for(const kind of ['user','project','device']){
    const b=$('new-'+kind);
    if(b)b.disabled=busy||preparing||!authorized()||(kind==='device'&&canIssue!==true);
  }const save=$('edit-form')?.querySelector('button[type=submit]');if(save)save.disabled=busy||preparing||!authorized()||editorHasUnresolved();
 const fs=$('edit-fields');
  if(fs)fs.disabled=busy||preparing||!authorized();
  $('recover-daemon').disabled=busy||!hooks;
  renderOperations();
}
export function sessionEnded(){
  healthChanged();
  if(hooks)say('Authorization ended. Your draft and original requests remain available; export a request and import it into a freshly authorized bridge.',true);
}
export function updateDevice(c,status){
  current={
    configuration:clone(c),status
  };
  const detail=$('detail');
  queueMicrotask(()=>{
    if(current?.configuration.Device.ID!==c.Device.ID||!detail.querySelector('.device-heading'))return;
    const actions=el('div');
    actions.className='actions';
    actions.append(button('Edit device',()=>openDevice(c)),button('Add tunnel',()=>openTunnel(c)));
    const rotate=button('Rotate native credential',()=>openRotate(c));
    rotate.disabled=true;
    actions.append(rotate,button('Bootstrap template',()=>openBootstrap(c)));
    detail.append(actions);
    hooks.api(`api/devices/${encodeURIComponent(c.Device.ID)}/credential-kinds`).then(v=>{
      if(v.device_id===c.Device.ID)rotate.disabled=canIssue!==true||!v.credential_kinds?.includes('kapv1_device_secret');
    }).catch(()=>{
    });
    for(const t of c.Tunnels.slice(0,50)){
      const row=[...detail.querySelectorAll('.tunnel')].find(n=>n.querySelector('h4')?.textContent===t.ID);
      row?.append(button('Edit tunnel',()=>openTunnel(c,t)));
    }
  });
}
function shell(title){
  const editor=$('editor');
  editor.hidden=false;
  const h=el('h2',title);
  h.id='editor-heading';
  h.tabIndex=-1;
  const state=el('p');
  state.id='edit-state';
  state.tabIndex=-1;
  state.setAttribute('role','status');
  const form=el('form');
  form.id='edit-form';
  const fs=el('fieldset');
  fs.id='edit-fields';
  form.append(fs);
  editor.replaceChildren(h,state,form);
  h.focus();
  editor.scrollIntoView({
    block:'start'
  });
  return {
    form,fs
  };
}
function end(){
  draft=null;
  baseline=null;
  editingKind='';
  persistDraft();
  $('editor').hidden=true;
}
function submitControls(form,fs,onSubmit){
  const actions=el('div');
  actions.className='actions';
  const save=el('button','Save configuration');
  save.type='submit';
  save.className='primary';
  actions.append(save,button('Cancel',end));
  fs.append(actions);
  form.addEventListener('submit',async e=>{
    e.preventDefault();
    if(busy||preparing||!authorized())return;
    say('Preparing original recovery request…');
    await onSubmit();
  });
  healthChanged();
}
function openDevice(c){
  baseline=clone(c);
  draft=clone(c);
  editingKind='device';
  deviceID=c.Device.ID;
  const {
    form,fs
  }=shell('Edit device');
  fs.append(el('p',`${c.Device.ID} · Project ${c.Device.ProjectID} · Revision ${c.Revision}. Disabling stops this device’s active traffic. Ownership, all tunnels and carrier policy are preserved.`));
  const name=field(fs,'device-name','Device name',c.Device.Name);
  name.required=false;
  const enabled=field(fs,'device-enabled','Device enabled',c.Device.Enabled,true);
  const retain=()=>{
    draft.Device.Name=name.value;
    draft.Device.Enabled=enabled.checked;
    persistDraft();healthChanged();
  };
  form.addEventListener('input',retain);
  submitControls(form,fs,async()=>{
    retain();
    await save({
      kind:'put_device',device_id:c.Device.ID,expected_revision:c.Revision,configuration:draft
    });
  });
  persistDraft();
}
function openTunnel(c,t){
  baseline=clone(c);
  draft=clone(c);
  editingKind='tunnel';
  deviceID=c.Device.ID;
  const {
    form,fs
  }=shell(t?'Edit TCP tunnel':'Add TCP tunnel');
  fs.append(el('p',`Device ${c.Device.ID} · Revision ${c.Revision}. Listener and target changes close affected traffic. The complete configuration, including disabled tunnels and policy, is submitted.`));
  const id=field(fs,'tunnel-id','Tunnel ID',t?.ID||'');
  id.readOnly=!!t;
  const listener=field(fs,'tunnel-listener','Public listener on server',t?.Listener||'127.0.0.1:0');
  const target=field(fs,'tunnel-target','Target on this device',t?.TargetAddr||'');
  const enabled=field(fs,'tunnel-enabled','Tunnel enabled',t?.Enabled??true,true);
  const retain=()=>{
    const next={
      ID:id.value,DeviceID:c.Device.ID,Protocol:'tcp',Listener:listener.value,TargetAddr:target.value,Enabled:enabled.checked
    };
    draft=clone(baseline);
    if(t)draft.Tunnels=draft.Tunnels.map(v=>v.ID===t.ID?next:v);
    else draft.Tunnels.push(next);
    persistDraft();healthChanged();
  };
  form.addEventListener('input',retain);
  submitControls(form,fs,async()=>{
    retain();
    await save({
      kind:'put_device',device_id:c.Device.ID,expected_revision:c.Revision,configuration:draft
    });
  });
  persistDraft();
}
function openRotate(c){
  baseline=clone(c);
  draft=null;
  editingKind='rotation';
  deviceID=c.Device.ID;
  const {
    form,fs
  }=shell('Rotate native credential');
  fs.append(el('p','Rotation retires the current session and old credential. A new once-only secret goes to the configured private directory, never this browser. Retained retry cannot deliver it again.'));
  const ack=field(fs,'rotation-ack','I understand existing connections stop and must use the new protected credential',false,true);
  ack.required=true;
  submitControls(form,fs,()=>save({
    kind:'rotate_credential',device_id:c.Device.ID,expected_revision:c.Revision,credential_kind:'kapv1_device_secret'
  }));
}
function openNew(kind){
  baseline=null;
  draft=null;
  editingKind=kind;
  deviceID='';
  const {
    form,fs
  }=shell(`Create ${kind}`);
  const id=field(fs,'record-id',`${kind} ID`);
  const name=field(fs,'record-name',`${kind} name`);
  name.required=false;
  let parent,enabled;
  if(kind==='project')parent=field(fs,'record-parent','Owning user ID',$('user-filter').value);
  if(kind==='device'){
    parent=field(fs,'record-parent','Owning project ID',$('project-filter').value);
    enabled=field(fs,'record-enabled','Device enabled',true,true);
    fs.append(el('p','The native credential is saved once in the bridge’s private directory. The browser receives only a delivery path; saved does not mean connected or ready.'));
  }
  const collect=()=>{
    draft={
      ID:id.value,Name:name.value
    };
    if(kind==='project')draft.UserID=parent.value;
    if(kind==='device'){
      draft.ProjectID=parent.value;
      draft.Enabled=enabled.checked;
    }persistDraft();healthChanged();
  };
  form.addEventListener('input',collect);
  submitControls(form,fs,async()=>{
    collect();
    const request={
      kind:`create_${kind}`,[kind]:draft
    };
    if(kind==='device')request.credential_kind='kapv1_device_secret';
    await save(request);
  });
}
async function save(request){
  if(busy||preparing||!authorized())return;
 if(hasUnresolved(request)){say('Resolve or explicitly discard the original unconfirmed request before making a new save for this action.',true);return;}
  preparing=true;
  healthChanged();
  try{
    if(pending.length>=4)throw new Error('Resolve or discard an existing request before saving.');
    const window=await hooks.api('api/window');
    const envelope={
      ...clone(request),window,operation_id:crypto.randomUUID()
    };
    pending.push({
      request:envelope,state:'Prepared; not dispatched'
    });
    try{
      persistRequests();
    }catch(e){
      pending.pop();
      throw e;
    }renderOperations();
    await dispatch(pending[pending.length-1],false);
  }catch(e){
    say(e.message,true);
  }finally{
    preparing=false;
    healthChanged();
  }
}
async function dispatch(entry,retry){
  if(busy)return;
  busy=true;
  const originalResolved=entry.resolved===true;
  entry.state='Outcome unconfirmed; request dispatched';
  try{
    persistRequests();
  }catch{
    busy=false;
    say('Original request cannot be retained. Nothing dispatched.',true);
    return;
  }renderOperations();
  healthChanged();
  try{
    const v=await hooks.api('api/mutations',{
      method:'POST',headers:{
        'Content-Type':'application/json'
      },body:JSON.stringify({
        request:entry.request,retry
      })
    });
    if(!v.result?.saved)throw new Error('response_unconfirmed');
    entry.state=`Saved revision ${v.result.revision||'not applicable'}; runtime application is sampled separately.`;
    entry.resolved=true;
    entry.receipt=v.result;
    entry.delivery=v.delivery;
    entry.path=v.credential_path||'';
    say(entry.state);
    if(draft&&entry.request.kind==='put_device')end();
    await hooks.refresh(entry.request.device_id||entry.request.device?.ID);
  }catch(e){
    if(retry){
      entry.state=e.outcome==='rejected'?`Rejected: retry ${e.message}. ${originalResolved?'Original saved receipt remains known.':'Original outcome remains unknown; exact request retained.'}`:`Retry unconfirmed: ${e.message}. ${originalResolved?'Original saved receipt remains known.':'Original outcome remains unknown; exact request retained.'}`;
      entry.resolved=originalResolved;
    }else{
      entry.state=e.outcome==='rejected'?`Rejected: ${e.message}. Draft retained; load fresh state before a new save.`:`Outcome unconfirmed: ${e.message}. Resolve the exact original request; do not infer rollback.`;
      entry.resolved=e.outcome==='rejected';
    }
    say(entry.state,true);
    if(e.message==='commit_uncertain')hooks.uncertain();
    if(e.message==='revision_conflict')conflictReview();
  }finally{
    busy=false;
    try{
      persistRequests();
    }catch{
    }renderOperations();
    healthChanged();
  }
}
function conflictReview(){
  const box=el('div');
  box.className='draft-note';
  box.append(el('p','Your draft is retained. Fetch the current configuration, review it, then explicitly reload the editor; changes are never automatically merged or overwritten.'));
  box.append(button('Review current configuration',async()=>{
    try{
      const c=await hooks.api(`api/devices/${encodeURIComponent(deviceID)}/configuration`);
      const view=el('pre',JSON.stringify(c,null,2));
      box.append(view,button('Reload editor from current state',()=>{
        if(editingKind==='tunnel'){
          const changed=draft.Tunnels.find(t=>JSON.stringify(t)!==JSON.stringify(baseline.Tunnels.find(b=>b.ID===t.ID)));
          openTunnel(c,c.Tunnels.find(t=>t.ID===changed?.ID));
        }else openDevice(c);
      }));
    }catch(e){
      say(e.message,true);
    }
  }));
  $('editor').append(box);
}
function renderOperations(){
  const root=$('operation-list');
  root.replaceChildren();
  for(const entry of pending){
    const row=el('article');
    row.className='operation';
    row.append(el('h3',`${entry.request.kind} · ${entry.request.operation_id}`),el('p',entry.state));
    if(entry.delivery)row.append(el('p',`Credential delivery: ${entry.delivery}${entry.path?' · '+entry.path:''}. Lost credential material requires explicit rotation.`));
    const actions=el('div');
    actions.className='actions';
    actions.append(button('Export original request',()=>{
      $('request-envelope').value=JSON.stringify(entry.request,null,2);
      $('request-envelope').focus();
    }),button('Look up original receipt',()=>lookup(entry)),button('Retry exact original request',()=>dispatch(entry,true)),button('Discard retained request',()=>{
      if(!entry.resolved&&!confirm('Outcome may remain unknown. Discard this local recovery request? Export it first if needed.'))return;
      pending=pending.filter(e=>e!==entry);
      persistRequests();
      renderOperations();healthChanged();
    }));
    actions.children[2].disabled=!!entry.resolved;
    row.append(actions);
    for(const b of actions.children)if(!b.textContent.startsWith('Export'))b.disabled=b.disabled||busy||preparing||(!b.textContent.startsWith('Discard')&&!authorized());
    root.append(row);
  }
}
async function lookup(entry){
  try{
    const receipt=await hooks.api('api/lookup',{
      method:'POST',headers:{
        'Content-Type':'application/json'
      },body:JSON.stringify({
        request:entry.request,retry:false
      })
    });
    entry.receipt=receipt;
    entry.resolved=!!receipt.saved;
    if(receipt.saved)await hooks.refresh(entry.request.device_id||entry.request.device?.ID);
    entry.state=receipt.saved?`Saved revision ${receipt.revision||'not applicable'} confirmed by original receipt. Credential not reissued.`:'Outcome unconfirmed';
  }catch(e){
    if(e.message==='commit_uncertain')hooks.uncertain();
    entry.state=e.message==='operation_expired_or_unknown'?'Expired or unknown receipt. The previous outcome remains unknown; matching configuration is not proof.':`Receipt unavailable: ${e.message}. Original request retained.`;
  }persistRequests();
  renderOperations();healthChanged();
}
export function initEditor(dependencies){
  hooks=dependencies;
  try{
    const data=sessionStorage.getItem(pendingKey)||'[]';
    if(new TextEncoder().encode(data).length<=2*1024*1024){
      const values=JSON.parse(data);
      if(Array.isArray(values)&&values.length<=4)pending=values.filter(v=>validEnvelope(v.request));
    }
  }catch{
  }for(const kind of ['user','project','device'])$('new-'+kind).addEventListener('click',()=>openNew(kind));
  $('recover-daemon').addEventListener('click',async()=>{
    try{
      await hooks.api('api/recover',{
        method:'POST',headers:{
          'Content-Type':'application/json'
        },body:'{}'
      });
      hooks.notice('Durable state recovered. Resolve each original request; credentials are not recovered.');
      await hooks.refresh();
      renderOperations();
    }catch(e){
      hooks.notice('Recovery unavailable: '+e.message,true);
    }
  });
  $('import-request').addEventListener('click',()=>{
    try{
      const data=$('request-envelope').value;
      if(new TextEncoder().encode(data).length>1024*1024)throw new Error('Request exceeds the limit');
      const request=JSON.parse(data);
      if(!validEnvelope(request))throw new Error('Import only an original nonsecret request with its window and operation ID');
      if(pending.length>=4)throw new Error('Recovery capacity reached');
      pending.push({
        request,state:'Imported for lookup; not dispatched'
      });
      persistRequests();
      renderOperations();
    }catch(e){
      hooks.notice(e.message,true);
    }
  });
  try{
    const retained=JSON.parse(sessionStorage.getItem(draftKey)||'null');
    if(retained?.draft){
      const restore=button('Restore retained draft',()=>{
        const old=clone(retained);
        if(old.editingKind==='device'&&old.baseline){
          openDevice(old.baseline);
          $('device-name').value=old.draft.Device.Name;
          $('device-enabled').checked=old.draft.Device.Enabled;
          $('edit-form').dispatchEvent(new Event('input'));
        }else if(old.editingKind==='tunnel'&&old.baseline){
          const changed=old.draft.Tunnels.find(t=>JSON.stringify(t)!==JSON.stringify(old.baseline.Tunnels.find(b=>b.ID===t.ID)));
          if(!changed)return;
          openTunnel(old.baseline,old.baseline.Tunnels.find(t=>t.ID===changed.ID));
          $('tunnel-id').value=changed.ID;
          $('tunnel-listener').value=changed.Listener;
          $('tunnel-target').value=changed.TargetAddr;
          $('tunnel-enabled').checked=changed.Enabled;
          $('edit-form').dispatchEvent(new Event('input'));
        }
      });
      $('operations').prepend(restore);
    }
  }catch{
  }renderOperations();
  healthChanged();
}
function validEnvelope(r){
  return r&&secretFreeShape(r)&&typeof r==='object'&&['create_user','create_project','create_device','put_device','rotate_credential','delete_device'].includes(r.kind)&&typeof r.operation_id==='string'&&r.operation_id.length<=128&&r.window&&typeof r.window.lineage==='string'&&typeof r.window.epoch==='string'&&Object.keys(r).every(k=>['kind','operation_id','window','user','project','device','configuration','device_id','expected_revision','credential_kind','cascade'].includes(k));
}
function openBootstrap(c){
  const {
    form,fs
  }=shell('Native bootstrap template');
  fs.append(el('p','Only server address, device identity, secret environment reference and trust paths belong on the agent. This template contains no secret and changes no files or trust settings.'));
  const server=field(fs,'bootstrap-server','Server address','localhost:8024');
  const env=field(fs,'bootstrap-env','Secret environment variable name','KAVERN_DEVICE_SECRET');
  const ca=field(fs,'bootstrap-ca','Trusted CA file path','/path/to/ca.pem');
  const name=field(fs,'bootstrap-name','Optional TLS server name','');
  name.required=false;
  const output=el('pre');
  fs.append(button('Build secret-free template',()=>{
    output.textContent=JSON.stringify({
      server:server.value,device_id:c.Device.ID,secret_env:env.value,ca_file:ca.value,...(name.value?{
        server_name:name.value
      }:{
      })
    },null,2);
  }),output,button('Close',end));
  healthChanged();
}
function keysOnly(value,keys){
  return value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(k=>keys.includes(k));
}
function secretFreeShape(r){
  if(!keysOnly(r.window,['lineage','epoch']))return false;
  for(const [key,keys] of Object.entries({
    user:['ID','Name'],project:['ID','UserID','Name'],device:['ID','ProjectID','Name','Enabled']
  })){
    if(r[key]!==undefined&&!keysOnly(r[key],keys))return false;
  }if(r.configuration!==undefined){
    const c=r.configuration;
    if(!keysOnly(c,['Device','Revision','Policy','Tunnels'])||!keysOnly(c.Device,['ID','ProjectID','Name','Enabled'])||!keysOnly(c.Policy,['Carriers','MaxStreams','MaxInflight','MaxBuffer'])||!Array.isArray(c.Tunnels)||c.Tunnels.some(t=>!keysOnly(t,['ID','DeviceID','Protocol','Listener','TargetAddr','Enabled'])))return false;
  }return true;
}
