'use strict';
const $ = id => document.getElementById(id);
const credential = new URLSearchParams(location.hash.slice(1)).get('token');
if (credential) { sessionStorage.setItem('review-token', credential); history.replaceState(null, '', location.pathname); }
const token = credential || sessionStorage.getItem('review-token') || '';
let state, active, selected, timer, pending = Promise.resolve(), busy = false, closed = false;
let image, drag, imageUrl, previewUrl, selection, historyMap = new Map(), lastActivity = Date.now();
const text = (tag, value, cls) => { const e = document.createElement(tag); e.textContent = value ?? ''; if (cls) e.className = cls; return e; };
function message(value) { $('message').textContent = value; $('message').classList.toggle('hidden', !value); }
async function api(path = '', method = 'GET', body) {
  const r = await fetch('/api/review' + path, { method, headers: {'Authorization': 'Bearer ' + token, ...(body ? {'Content-Type': 'application/json'} : {})}, body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) { let value; try { value = (await r.json()).detail; } catch { value = 'Review server is unavailable.'; } throw new Error(typeof value === 'string' ? value : JSON.stringify(value)); }
  return r.json();
}
const file = () => state.files.find(f => f.path === active);
function queueEdit(edit) {
  $('saveStatus').textContent = 'Saving…';
  pending = pending.then(async () => { state = await api('', 'PUT', {revision: state.revision, ...edit}); $('saveStatus').textContent = 'All changes saved'; renderChrome(); }).catch(e => { $('saveStatus').textContent = 'Not saved'; message(e.message); throw e; });
  return pending;
}
async function flush() { clearTimeout(timer); if (file()?.kind === 'text' && $('editor').value !== file().proposed) await queueEdit({path: active, content: $('editor').value}); await pending; }
async function action(fn) { if (busy || closed) return; busy = true; controls(); message(''); try { await fn(); } catch (e) { message(e.message); pending = Promise.resolve(); } finally { busy = false; controls(); } }
function controls() { $('workspace').inert = busy; $('editor').readOnly = busy; ['validateButton','cancelButton'].forEach(id => $(id).disabled = busy); $('approveButton').disabled = busy || !state?.validation?.valid || state.validation.revision !== state.revision; }
function renderChrome() {
  $('repo').textContent = state.repository + ' / ' + state.branch;
  $('fileCount').textContent = state.files.length;
  $('findingCount').textContent = state.findings.length;
  $('reviewSummary').textContent = `${state.files.length} files · ${state.findings.length} findings`;
  $('sessionStatus').textContent = state.validation?.valid ? 'Ready to approve' : 'Review in progress';
  $('validationSummary').textContent = state.validation ? (state.validation.valid ? 'Latest changes validated. Ready for approval.' : `${state.validation.blockers.length} issues need your attention.`) : 'Changes stay in this session until you approve.';
  if (state.local_env_keys.length) $('validationSummary').textContent += ' Local .env: ' + state.local_env_keys.join(', ') + ' (not staged).';
  $('files').replaceChildren(...state.files.map(f => {
    const b = text('button', '', 'file-item' + (f.path === active ? ' selected' : '')); b.setAttribute('aria-current', f.path === active ? 'true' : 'false');
    const label = text('span', ''); label.append(text('strong', f.path), text('small', f.kind === 'unsupported' ? 'Needs external review' : f.original !== f.proposed || f.regions.length ? 'Proposed changes' : 'Staged file'));
    b.append(label, text('span', state.findings.filter(x => x.file_path === f.path).length, 'count'));
    b.onclick = () => action(async () => { await flush(); active = f.path; selected = null; await renderFile(); renderChrome(); }); return b;
  }));
  renderFindings(); controls();
}
function renderFindings() {
  const filter = $('filter').value;
  const list = state.findings.filter(f => (filter === 'all' || f.category === filter) && (!active || f.file_path === active));
  $('findings').replaceChildren();
  if (!list.length) { $('findings').append(text('p','No findings in this file. You can still edit or add redactions.','empty')); return; }
  for (const f of list) {
    const card = text('article','', 'finding-card' + (selected === f.id ? ' selected' : ''));
    const meta = text('div','','finding-meta'); meta.append(text('span',f.severity,'severity ' + f.severity), text('span', f.can_dismiss ? 'Review decision' : 'Enforced by policy','policy-lock'));
    const title = text('button', f.title, 'finding-title'); title.onclick = () => { selected = f.id; renderFindings(); highlightFinding(f); };
    card.append(meta,title,text('p',f.reason,'finding-reason'));
    if (f.replacement_snippet) { const details = text('details',''); details.append(text('summary','Suggested replacement'),text('pre',f.replacement_snippet)); card.append(details); }
    if (f.cross_file_context_used) { const d = text('details',''); d.append(text('summary','Cross-file evidence'),text('p',f.cross_file_context_used)); card.append(d); }
    const dismissed = state.decisions[f.id] === 'dismiss';
    const b = text('button', dismissed ? 'Undo dismissal' : 'Dismiss finding', 'dismiss'); b.disabled = !f.can_dismiss || busy;
    b.title = f.can_dismiss ? 'Keep the current proposed content and dismiss this finding' : 'This rule must be resolved before approval';
    b.onclick = () => action(async () => { await flush(); await queueEdit({decisions:{[f.id]:dismissed ? 'resolve' : 'dismiss'}}); });
    card.append(b); $('findings').append(card);
  }
}
function highlightFinding(f) {
  document.querySelectorAll('.focus-line').forEach(e=>e.classList.remove('focus-line'));
  if (f.line_start) { const line = $('original').children[f.line_start - 1]; if(line) {line.classList.add('focus-line');line.scrollIntoView({block:'nearest'});} }
  if (f.bbox_2d && file().kind === 'image') draw();
}
function gutter() { $('gutter').textContent = Array.from({length:$('editor').value.split('\n').length}, (_, i) => i + 1).join('\n'); }
async function renderFile() {
  const f = file(); $('noFiles').classList.toggle('hidden',!!f); if(!f) return;
  $('filename').textContent = f.path; $('fileState').textContent = f.kind === 'text' ? 'Changes are saved to this review session' : f.kind === 'image' ? 'Original image with proposed redactions' : 'Not scanned';
  ['textWorkspace','textTools'].forEach(id=>$(id).classList.toggle('hidden',f.kind !== 'text'));
  $('imageWorkspace').classList.toggle('hidden',f.kind !== 'image'); $('unsupported').classList.toggle('hidden',f.kind !== 'unsupported');
  $('splitButton').disabled = $('diffButton').disabled = f.kind !== 'text'; $('diff').classList.add('hidden');
  $('splitButton').setAttribute('aria-pressed','true');$('diffButton').setAttribute('aria-pressed','false');
  if(f.kind === 'text') {
    $('original').replaceChildren(...f.original.split('\n').map((line,i)=> {const row=text('div','','source-line');row.append(text('span',i+1,'line-number'),text('span',line));return row;}));
    $('editor').value=f.proposed; gutter();
    if(!historyMap.has(active)) historyMap.set(active,{undo:[],redo:[],last:f.proposed});
  } else if(f.kind === 'image') {
    if(imageUrl) URL.revokeObjectURL(imageUrl);
    const r=await fetch('/api/review/image?path='+encodeURIComponent(active),{headers:{Authorization:'Bearer '+token}});
    if(!r.ok) throw new Error('Could not load the staged image');
    imageUrl=URL.createObjectURL(await r.blob()); image=new Image(); image.onload=draw; image.src=imageUrl;
    $('imageStyle').value=f.style; $('imagePreview').classList.add('hidden');$('canvas').classList.remove('hidden');renderRegions();
  } else $('unsupported').textContent=f.reason;
}
$('editor').addEventListener('input',()=>{const h=historyMap.get(active);h.undo.push(h.last);h.redo=[];h.last=$('editor').value;gutter();state.validation=null;controls();$('saveStatus').textContent='Unsaved changes';clearTimeout(timer);timer=setTimeout(()=>action(flush),650);});
$('editor').addEventListener('scroll',()=>{$('gutter').scrollTop=$('editor').scrollTop;});
$('editor').addEventListener('keydown',e=>{if(e.key==='Tab'){e.preventDefault();const t=e.target;t.setRangeText('  ',t.selectionStart,t.selectionEnd,'end');t.dispatchEvent(new Event('input'));} if((e.ctrlKey||e.metaKey)&&e.key==='s'){e.preventDefault();action(flush);}});
function historyEdit(direction) {const h=historyMap.get(active), source=h[direction], dest=h[direction==='undo'?'redo':'undo'];if(!source.length)return;dest.push($('editor').value);$('editor').value=source.pop();h.last=$('editor').value;gutter();action(flush);}
$('undoButton').onclick=()=>historyEdit('undo');$('redoButton').onclick=()=>historyEdit('redo');
$('resetButton').onclick=()=>{$('editor').value=file().proposal;$('editor').dispatchEvent(new Event('input'));};
$('redactTextButton').onclick=()=>{selection=[$('editor').selectionStart,$('editor').selectionEnd];if(selection[0]===selection[1])return message('Select text in the proposed version first.');$('redactDialog').showModal();$('replacement').focus();};
$('cancelRedact').onclick=()=>$('redactDialog').close();$('confirmRedact').onclick=()=>{$('editor').setRangeText($('replacement').value,...selection,'select');$('editor').dispatchEvent(new Event('input'));$('redactDialog').close();$('editor').focus();};
$('splitButton').onclick=()=>{$('diff').classList.add('hidden');$('textWorkspace').classList.remove('hidden');$('splitButton').setAttribute('aria-pressed','true');$('diffButton').setAttribute('aria-pressed','false');};
$('diffButton').onclick=()=>action(async()=>{await flush();const d=await api('/preview');$('diff').textContent=d.files[active]||'No changes';$('diff').classList.remove('hidden');$('textWorkspace').classList.add('hidden');$('splitButton').setAttribute('aria-pressed','false');$('diffButton').setAttribute('aria-pressed','true');});
$('validateButton').onclick=()=>action(async()=>{await flush();$('sessionStatus').textContent='Validating changes…';const v=await api('/validate','POST',{revision:state.revision});state=await api();renderChrome();if(!v.valid)message(v.blockers.join('\n'));});
function terminal(approved){closed=true;$('terminalTitle').textContent=approved?'Review approved':'Commit cancelled';$('terminalMessage').textContent=approved?'Your reviewed changes have been staged. Git will continue in your terminal.':'Your original staged and working files are unchanged.';$('terminal').classList.remove('hidden');document.title=approved?'Review approved · Plutonium':'Commit cancelled · Plutonium';sessionStorage.removeItem('review-token');}
$('approveButton').onclick=()=>action(async()=>{await flush();await api('/approve','POST',{revision:state.revision});terminal(true);});
$('cancelButton').onclick=()=>$('cancelDialog').showModal();$('keepReviewing').onclick=()=>$('cancelDialog').close();$('confirmCancel').onclick=()=>action(async()=>{await pending.catch(()=>{});await api('/cancel','POST');$('cancelDialog').close();terminal(false);});
$('policyButton').onclick=()=>{$('policySource').textContent=state.policy_source;$('policyDetails').textContent=JSON.stringify(state.policy,null,2);$('policyDialog').showModal();};$('closePolicy').onclick=()=>$('policyDialog').close();
$('filter').onchange=renderFindings;$('filesToggle').onclick=()=>$('workspace').classList.toggle('show-files');$('findingsToggle').onclick=()=>$('workspace').classList.toggle('show-findings');
function draw(){if(!image?.complete||!file()||file().kind!=='image')return;const cv=$('canvas');cv.width=image.naturalWidth;cv.height=image.naturalHeight;const c=cv.getContext('2d');c.drawImage(image,0,0);for(const b of file().regions){c.fillStyle='#245de62b';c.strokeStyle='#245de6';c.lineWidth=Math.max(2,cv.width/500);const x=b[1]/1000*cv.width,y=b[0]/1000*cv.height,w=(b[3]-b[1])/1000*cv.width,h=(b[2]-b[0])/1000*cv.height;c.fillRect(x,y,w,h);c.strokeRect(x,y,w,h);}if(drag){c.strokeStyle='#20242c';c.strokeRect(drag[0]/1000*cv.width,drag[1]/1000*cv.height,(drag[2]-drag[0])/1000*cv.width,(drag[3]-drag[1])/1000*cv.height);}}
function point(e){const r=$('canvas').getBoundingClientRect();return [Math.max(0,Math.min(1000,Math.round((e.clientX-r.left)/r.width*1000))),Math.max(0,Math.min(1000,Math.round((e.clientY-r.top)/r.height*1000)))];}
$('canvas').onpointerdown=e=>{if(busy)return;const p=point(e);drag=[...p,...p];e.target.setPointerCapture(e.pointerId);};$('canvas').onpointermove=e=>{if(drag){drag.splice(2,2,...point(e));draw();}};
$('canvas').onpointerup=()=>{if(!drag)return;const [x,y,x2,y2]=drag;drag=null;if(Math.abs(x-x2)<2||Math.abs(y-y2)<2)return draw();const regions=[...file().regions,[Math.min(y,y2),Math.min(x,x2),Math.max(y,y2),Math.max(x,x2)]];action(async()=>{await queueEdit({path:active,regions});draw();renderRegions();});};$('canvas').onpointercancel=()=>{drag=null;draw();};
function renderRegions(){ $('regions').replaceChildren(...file().regions.map((box,i)=>{const row=text('div','','region-row');row.append(text('strong',`Region ${i+1}`));const inputs=box.map((n,j)=>{const label=text('label',['Top','Left','Bottom','Right'][j]);const input=document.createElement('input');input.type='number';input.min=0;input.max=1000;input.value=n;input.setAttribute('aria-label',`Region ${i+1} ${label.textContent}, per thousand`);label.append(input);row.append(label);return input;});const save=text('button','Update');save.onclick=()=>action(async()=>{const regions=file().regions.map(b=>[...b]);regions[i]=inputs.map(input=>Number(input.value));await queueEdit({path:active,regions});draw();renderRegions();});const remove=text('button','Remove');remove.onclick=()=>action(async()=>{await queueEdit({path:active,regions:file().regions.filter((_,j)=>j!==i)});draw();renderRegions();});row.append(save,remove);return row;}));}
$('imageStyle').onchange=()=>action(()=>queueEdit({path:active,style:$('imageStyle').value}));$('resetRegions').onclick=()=>action(async()=>{await queueEdit({path:active,regions:[]});draw();renderRegions();});
$('compareButton').onclick=()=>action(async()=>{if(!$('imagePreview').classList.contains('hidden')){$('imagePreview').classList.add('hidden');$('canvas').classList.remove('hidden');$('compareButton').textContent='Preview redacted image';return;}const r=await fetch('/api/review/image?proposed=true&path='+encodeURIComponent(active),{headers:{Authorization:'Bearer '+token}});if(!r.ok)throw new Error('Could not render preview');if(previewUrl)URL.revokeObjectURL(previewUrl);previewUrl=URL.createObjectURL(await r.blob());$('imagePreview').src=previewUrl;$('imagePreview').classList.remove('hidden');$('canvas').classList.add('hidden');$('compareButton').textContent='Back to regions';});
['pointerdown','keydown'].forEach(name=>document.addEventListener(name,()=>lastActivity=Date.now()));
setInterval(()=>{if(!closed&&Date.now()-lastActivity<30000)api('/heartbeat','POST').catch(()=>message('The review server has stopped. Return to your terminal.'));},15000);
window.addEventListener('beforeunload',e=>{if(!closed&&$('editor').value!==file()?.proposed){e.preventDefault();e.returnValue='';}});
action(async()=>{state=await api();if(state.state!=='reviewing')return terminal(state.state==='approved');active=state.files[0]?.path;renderChrome();await renderFile();if(state.coverage.length)message(state.coverage.join('\n'));});
