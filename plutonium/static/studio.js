
'use strict';
/* ===================================================================== utils */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const store = {
  get(k, d) { try { const v = localStorage.getItem('bg.' + k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem('bg.' + k, JSON.stringify(v)); } catch (e) {} },
};
const params = new URLSearchParams(location.search);
const ICON = {
  warn: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" class="flex-none mt-[2px]"><path d="M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>',
  link: '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M10 13a5 5 0 007.5.5l3-3a5 5 0 00-7-7l-1.7 1.7M14 11a5 5 0 00-7.5-.5l-3 3a5 5 0 007 7l1.7-1.7"/></svg>',
  chev: '<svg class="chev text-muted" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M9 6l6 6-6 6"/></svg>',
};
const warnBox = (w) => `<div class="mt-1.5 flex gap-2 items-start text-[12px] rounded-lg border border-[#EFDDA6] bg-[#FBF3DB] text-[#956400] px-2.5 py-1.5">${ICON.warn}<span>${esc(w)}</span></div>`;

function toast(msg, kind = 'info', ms = 4200) {
  const mark = { info: ['i', '#1F6C9F'], ok: ['', '#346538'], err: ['×', '#C8432B'], warn: ['!', '#B07A0C'] }[kind] || ['i', '#1F6C9F'];
  const el = document.createElement('div');
  el.className = 'toast px-3.5 py-3 text-[13px] flex gap-3 items-start';
  el.innerHTML = `<span class="mark" style="background:${mark[1]}">${mark[0]}</span><div class="flex-1 min-w-0 break-words pt-[1px]">${typeof msg === 'string' ? esc(msg) : ''}</div><button class="text-muted hover:text-ink px-1" aria-label="Dismiss">×</button>`;
  if (typeof msg !== 'string') el.querySelector('div').appendChild(msg);
  el.querySelector('button').onclick = () => el.remove();
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), ms);
}

async function api(path, opts = {}) {
  const init = { method: opts.method || (opts.body !== undefined ? 'POST' : 'GET'), headers: {} };
  if (opts.body !== undefined) {
    if (opts.body instanceof FormData) init.body = opts.body;
    else { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(opts.body); }
  }
  let res;
  try { res = await fetch(path, init); }
  catch (e) { throw new Error('Server unreachable — is `plutonium serve` running?'); }
  if (opts.raw) { if (!res.ok) throw new Error(await errText(res)); return res; }
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) {
    const d = data && data.detail;
    throw new Error(typeof d === 'string' ? d : (d ? JSON.stringify(d) : `HTTP ${res.status}`));
  }
  return data;
}
async function errText(res) { try { const j = await res.json(); return j.detail || `HTTP ${res.status}`; } catch (e) { return `HTTP ${res.status}`; } }

const ENGINE_THINK = {
  cloud_fast: 'Gemma 4 26B MoE', cloud_deep: 'Gemma 4 31B Dense',
  local_edge: 'Local gemma4:e4b', hybrid_smart: 'gemma4:e4b → Gemma 4 31B',
};
const engineMode = () => $('#engineMode').value;
const preset = () => $('#domainPreset').value;
const offline = () => $('#offlineToggle').checked;
const thinkerName = (mode) => offline() ? 'Offline heuristic engine' : (ENGINE_THINK[mode || engineMode()] || 'Gemma 4');

/** Overlay a skeleton loader with an elapsed-seconds counter. Returns stop(). */
function thinking(container, label, rows = 4) {
  const ov = document.createElement('div');
  ov.className = 'thinking';
  ov.innerHTML = `<div class="flex items-center gap-3"><div class="spinner"></div><div class="text-[14px] font-semibold">${esc(label)} is thinking <span class="tabular-nums text-accent el">0s</span></div></div>
    <div class="text-[12px] text-muted font-mono hint">${offline() ? 'deterministic regex + heuristic pass' : 'indexing → retrieving cross-file chunks → reasoning (10–60s on cloud)'}</div>
    ${Array.from({length: rows}, (_, i) => `<div class="skel h-${i % 2 ? 14 : 20}" style="opacity:${1 - i * .14}"></div>`).join('')}`;
  container.style.position = container.style.position || 'relative';
  container.appendChild(ov);
  const t0 = Date.now();
  const iv = setInterval(() => { const s = Math.floor((Date.now() - t0) / 1000); ov.querySelector('.el').textContent = s + 's'; }, 250);
  return () => { clearInterval(iv); ov.remove(); };
}

function setBusy(btn, busy, text) {
  if (!btn) return;
  if (busy) { btn.dataset.html = btn.innerHTML; btn.disabled = true; btn.innerHTML = `<span class="spinner sm"></span> ${esc(text || 'Working…')}`; }
  else { if (btn.dataset.html) btn.innerHTML = btn.dataset.html; btn.disabled = false; }
}

/* =================================================================== highlight */
function langFor(file) {
  const ext = (file || '').split('.').pop().toLowerCase();
  return { py: 'python', ipynb: 'python', js: 'javascript', ts: 'typescript', tsx: 'typescript', jsx: 'javascript', diff: 'diff', patch: 'diff',
    yaml: 'yaml', yml: 'yaml', json: 'json', sql: 'sql', sh: 'bash', env: 'bash', md: 'markdown' }[ext] || 'plaintext';
}
function highlight(code, lang) {
  if (window.hljs) {
    try { if (lang !== 'plaintext' && hljs.getLanguage(lang)) return hljs.highlight(code, { language: lang, ignoreIllegals: true }).value; } catch (e) {}
  }
  return esc(code);
}
/** Split highlighted HTML into lines while keeping <span> nesting balanced on each line. */
function splitHtmlLines(html) {
  const lines = []; const stack = []; let cur = '';
  const re = /<span[^>]*>|<\/span>|\n|[^<\n]+|</g; let m;
  while ((m = re.exec(html))) {
    const t = m[0];
    if (t === '\n') { lines.push(cur + '</span>'.repeat(stack.length)); cur = stack.join(''); }
    else if (t.startsWith('<span')) { stack.push(t); cur += t; }
    else if (t === '</span>') { stack.pop(); cur += t; }
    else cur += t;
  }
  lines.push(cur + '</span>'.repeat(stack.length));
  return lines;
}
const codeLines = (code, file, start = 1) => splitHtmlLines(highlight(code, langFor(file)))
  .map((h, j) => `<div class="cl"><span class="ln">${start + j}</span><span class="lc">${h || ' '}</span></div>`).join('');

/* ====================================================================== status */
let STATUS = null;
async function loadStatus() {
  try {
    const s = await api('/api/status');
    STATUS = s;
    setDot('#cloudDot', s.engines.cloud); setDot('#ollamaDot', s.engines.ollama);
    if (!(SCAN.data && SCAN.data.index)) setIndex(s.index);
    $('#footerRoot').textContent = s.root || '';
    if (!s.engines.cloud && !s.engines.ollama && store.get('offline', null) === null) {
      $('#offlineToggle').checked = true; syncOffline();
    }
  } catch (e) { toast(e.message, 'err'); }
}
function setDot(sel, on) {
  const el = $(sel);
  el.querySelector('.pulse-dot').className = 'pulse-dot ' + (on ? 'on' : 'off');
  const mk = el.querySelector('.mark'); mk.textContent = on ? '' : '×';
  mk.className = 'mark font-semibold ' + (on ? 'text-good' : 'text-faint');
}
function setIndex(ix) {
  if (!ix) return;
  $('#indexIndicator').textContent = `Indexed: ${ix.chunks ?? 0} Chunks / ${ix.symbols ?? 0} Symbols`;
}
function syncOffline() {
  store.set('offline', offline());
  $('#statusPill').classList.toggle('is-offline', offline());
}

/* ======================================================================== tabs */
function showTab(id) {
  $$('.tab-btn').forEach(b => { const on = b.dataset.tab === id; b.classList.toggle('active', on); b.setAttribute('aria-selected', on); });
  $$('.tab-panel').forEach(p => p.classList.toggle('active', p.id === id));
  store.set('tab', id);
  if (id === 'tab-image' && !IMG.listLoaded) loadImages();
  if (id === 'tab-image' && IMG.img) requestAnimationFrame(drawCanvas);
  if (id === 'tab-policy' && !POLICY.loaded) loadPolicy();
  if (id === 'tab-benchmark') loadLastBench();
}

/* ==================================================================== TAB 1 */
const SCAN = { data: null, decisions: {}, activeFile: null, filter: 'all', lineMap: {} };
const LEAK_ACTIONS = [
  ['synthetic_twin', ' Swap Synthetic Twin'], ['env_extract', 'Extract to .env'], ['solid_mask', 'Hard Mask'], ['whitelist', 'Keep / Whitelist'],
];
const BUG_ACTIONS = [['code_patch', ' Apply Bug Fix Patch'], ['whitelist', 'Keep Original (Ignore)']];
const isBug = f => f.category === 'logical_bug';

async function runScenario(name) {
  $$('.scenario-btn').forEach(b => b.classList.toggle('is-active', b.dataset.scenario === name));
  const stop = thinking($('#findingsWrap'), thinkerName(), 5);
  disableScanButtons(true);
  try {
    let data;
    if (name === '__staged') {
      data = await api('/api/scan/staged', { body: { mode: engineMode(), preset: preset(), offline: offline() } });
    } else {
      // show code immediately while the model thinks
      try {
        const s = await api('/api/samples/' + encodeURIComponent(name));
        const files = {}; (s.targets || [s.target_file]).forEach(t => { if (s.files[t] !== undefined) files[t] = s.files[t]; });
        SCAN.data = null; renderFiles(files, s.target_file, s.title);
      } catch (e) {}
      const pr = preset() === 'all' ? 'all' : preset();
      data = await api('/api/scan', { body: { scenario: name, mode: engineMode(), preset: pr, offline: offline() } });
    }
    SCAN.data = data;
    SCAN.decisions = {};
    (data.findings || []).forEach(f => { SCAN.decisions[f.id] = defaultAction(f); });
    renderScan();
    const n = (data.findings || []).length;
    toast(`${data.verdict}: ${n} finding${n === 1 ? '' : 's'} via ${data.engine_used} in ${data.elapsed_s ?? '?'}s`, data.verdict === 'PASS' ? 'ok' : 'warn');
  } catch (e) {
    toast('Scan failed: ' + e.message, 'err');
  } finally { stop(); disableScanButtons(false); }
}
function disableScanButtons(d) { $$('.scenario-btn').forEach(b => b.disabled = d); }

function actionsFor(f) {
  if (isBug(f)) return BUG_ACTIONS;
  // PII leaks whose safe fix is a code change (e.g. logging customer.__dict__) get a patch option first.
  if (f.recommended_action === 'code_patch' && f.replacement_snippet) return [['code_patch', ' Apply Safe Fix Patch'], ...LEAK_ACTIONS.map(([v, l]) => [v, l.replace(' ', '')])];
  return LEAK_ACTIONS;
}
function defaultAction(f) {
  const opts = actionsFor(f).map(a => a[0]);
  return opts.includes(f.recommended_action) ? f.recommended_action : opts[0];
}

function renderFiles(files, active, title) {
  SCAN.files = files;
  const keys = Object.keys(files);
  SCAN.activeFile = keys.includes(active) ? active : keys[0];
  const tabs = $('#fileTabs');
  tabs.innerHTML = keys.map(k => `<button class="file-tab ${k === SCAN.activeFile ? 'on' : ''}" data-file="${esc(k)}">${esc(k)}<span class="cnt"></span></button>`).join('');
  $$('.file-tab', tabs).forEach(b => b.onclick = () => { SCAN.activeFile = b.dataset.file; renderFiles(SCAN.files, b.dataset.file, title); });
  $('#codeTitle').textContent = title || '';
  renderCode();
}

function fileOfFinding(f) {
  const d = SCAN.data; if (d && d.finding_files && d.finding_files[f.id]) return d.finding_files[f.id];
  const keys = Object.keys(SCAN.files || {});
  return keys.find(k => k === f.file_path || (f.file_path || '').endsWith('/' + k) || k.split('/').pop() === (f.file_path || '').split('/').pop()) || keys[0];
}

function renderCode() {
  const file = SCAN.activeFile; const code = (SCAN.files || {})[file];
  const viewer = $('#codeViewer');
  if (code === undefined) return;
  const marks = {};
  const findings = (SCAN.data && SCAN.data.findings) || [];
  findings.forEach(f => {
    if (fileOfFinding(f) !== file || !f.line_start) return;
    const end = Math.max(f.line_start, f.line_end || f.line_start);
    for (let l = f.line_start; l <= Math.min(end, f.line_start + 40); l++) {
      marks[l] = marks[l] === 'leak' ? 'leak' : (isBug(f) ? 'bug' : 'leak');
    }
  });
  const lines = splitHtmlLines(highlight(code, langFor(file)));
  viewer.innerHTML = '<div class="hljs">' + lines.map((h, i) => {
    const n = i + 1; const m = marks[n];
    return `<div class="cl${m ? ' hl-' + m : ''}" data-line="${n}"><span class="ln">${n}</span><span class="lc">${h || ' '}</span></div>`;
  }).join('') + '</div>';
  // counts on file tabs
  $$('.file-tab').forEach(b => {
    const c = findings.filter(f => fileOfFinding(f) === b.dataset.file).length;
    b.querySelector('.cnt').innerHTML = c ? `<span class="count">${c}</span>` : '';
  });
}

function jumpTo(f) {
  const file = fileOfFinding(f);
  if (file && file !== SCAN.activeFile && SCAN.files[file] !== undefined) { SCAN.activeFile = file; renderFiles(SCAN.files, file, $('#codeTitle').textContent); }
  const row = $(`#codeViewer .cl[data-line="${f.line_start}"]`);
  if (!row) return;
  row.scrollIntoView({ block: 'center', behavior: 'smooth' });
  for (let l = f.line_start; l <= (f.line_end || f.line_start); l++) {
    const r = $(`#codeViewer .cl[data-line="${l}"]`); if (r) { r.classList.remove('flash'); void r.offsetWidth; r.classList.add('flash'); }
  }
}

function setStamp(el, v) {
  el.className = 'stamp ' + (v === 'BLOCK' ? 'block' : v === 'WARN' ? 'warn' : 'pass');
  el.textContent = v;
  void el.offsetWidth; el.classList.add('hit');
}

function renderScan() {
  const d = SCAN.data; if (!d) return;
  renderFiles(d.files || {}, (d.target_files || [])[0], d.scenario ? (d.scenario + ' · ' + (d.kind || '')) : d.kind);
  if (d.index) setIndex(d.index);
  // scoreboard
  const findings = d.findings || [];
  const regex = findings.filter(f => f.caught_by_regex_baseline).length;
  const total = findings.length;
  $('#regexLine').textContent = `Regex Baseline (Gitleaks): ${regex} Caught (0 Logical Bugs, 0 Contextual/Image Leaks)`;
  $('#gemmaLine').textContent = `Plutonium (Gemma 4): ${total} Caught (Leaks + PII + Cross-File Logical Bugs)`;
  $('#regexNum').textContent = regex; $('#gemmaNum').textContent = total;
  const max = Math.max(total, regex, 1);
  requestAnimationFrame(() => { $('#regexBar').style.setProperty('--w', regex / max); $('#gemmaBar').style.setProperty('--w', total / max); });
  const cnt = c => findings.filter(f => f.category === c).length;
  const xf = findings.filter(f => f.cross_file_context_used).length;
  const only = total - regex;
  $('#breakdown').innerHTML = [
    `<span class="chip chip-red"><span class="dot"></span>${cnt('security_leak')} secret leaks</span>`,
    `<span class="chip chip-red"><span class="dot"></span>${cnt('privacy_pii')} PII</span>`,
    `<span class="chip chip-bug"><span class="dot"></span>${cnt('logical_bug')} logical bugs</span>`,
    `<span class="chip chip-blue">${ICON.link}${xf} cross-file proofs</span>`,
    only > 0 ? `<span class="chip chip-green">+${only} only Gemma 4 caught</span>` : '',
  ].join('');
  setStamp($('#verdictBadge'), d.verdict || 'PASS');
  $('#scanMeta').textContent = `engine: ${d.engine_used} · preset: ${d.preset_used} · ${d.indexed_chunks_count || 0} chunks indexed · ${(d.context || []).length} retrieved · ${d.elapsed_s ?? '?'}s`;
  $('#scanSummary').textContent = d.summary || '';
  $('#scanWarnings').innerHTML = (d.warnings || []).map(warnBox).join('');
  // thinking
  const tt = d.thinking_trace || '';
  $('#thinkTrace').textContent = tt || 'No reasoning trace returned by this engine (offline heuristic / cache).';
  $('#thinkLen').textContent = tt ? `${tt.length.toLocaleString()} chars` : '';
  // context
  renderContext(d.context || []);
  renderFindings();
  $('#previewBtn').disabled = !total; $('#applyBtn').disabled = !total;
}

function renderContext(ctx) {
  $('#ctxCount').textContent = `${ctx.length} chunk${ctx.length === 1 ? '' : 's'}`;
  if (!ctx.length) { $('#ctxList').innerHTML = '<p class="text-[13px] text-muted">No cross-file chunks were retrieved for this target.</p>'; return; }
  $('#ctxList').innerHTML = ctx.map((c, i) => {
    const base = (c.file_path || '').split('/').pop();
    return `<details class="rounded-xl border border-line bg-white overflow-hidden" ${i < 2 ? 'open' : ''}>
      <summary class="flex items-center gap-2 px-3 py-2.5 text-[12px] font-mono hover:bg-[#FCFBF8]">
        ${ICON.chev}
        <span class="font-semibold text-ink">${esc(base)}<span class="text-accent">:</span>${esc(c.symbol_name)}</span>
        <span class="text-muted">L${esc(c.start_line)}–${esc(c.end_line)}</span>
        <span class="ml-auto chip chip-grey !text-[10px]">${esc(c.chunk_type || 'chunk')}</span>
      </summary>
      <div class="codebox overflow-auto max-h-64 py-2 border-t border-line hljs">${codeLines(c.code || '', c.file_path, c.start_line || 1)}</div></details>`;
  }).join('');
}

function renderFindings() {
  const d = SCAN.data; const wrap = $('#findings');
  let list = (d && d.findings) || [];
  const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  list = list.slice().sort((a, b) => (sevRank[a.severity] - sevRank[b.severity]) || ((a.line_start || 0) - (b.line_start || 0)));
  if (SCAN.filter !== 'all') list = list.filter(f => f.category === SCAN.filter);
  if (!list.length) {
    const clean = d && !d.findings.length;
    wrap.innerHTML = `<div class="py-12 text-center"><p class="font-display text-[16px] font-bold ${clean ? 'text-good' : ''}">${d ? (clean ? 'Clean. Nothing to fix.' : 'No findings in this filter.') : 'No scan yet.'}</p></div>`;
    return;
  }
  wrap.innerHTML = list.map(cardHtml).join('');
  $$('.finding', wrap).forEach(card => {
    const f = list.find(x => x.id === card.dataset.id);
    card.querySelector('.jump').onclick = () => jumpTo(f);
    $$('input[type=radio]', card).forEach(r => r.onchange = () => {
      SCAN.decisions[f.id] = r.value; card.classList.toggle('ignored', r.value === 'whitelist');
    });
  });
}

function cardHtml(f) {
  const bug = isBug(f);
  const cat = bug ? '<span class="chip chip-bug"><span class="dot"></span>Logical / security bug</span>' : '<span class="chip chip-red"><span class="dot"></span>Privacy / secret leak</span>';
  const sub = f.category === 'privacy_pii' ? '<span class="chip chip-grey">PII</span>' : (f.category === 'security_leak' ? '<span class="chip chip-grey">Secret</span>' : '');
  const file = fileOfFinding(f) || f.file_path;
  const loc = `${file}${f.line_start ? ':' + f.line_start + (f.line_end && f.line_end !== f.line_start ? '-' + f.line_end : '') : ''}`;
  const proof = f.cross_file_context_used ? `<span class="chip chip-blue" title="Indexed symbol that proved this finding">${ICON.link}Cross-file proof: ${esc(f.cross_file_context_used)}</span>` : '';
  const who = f.caught_by_regex_baseline ? '<span class="chip chip-grey">Regex also caught</span>' : '<span class="chip chip-green">Only Gemma 4 caught</span>';
  const off = f.offending_snippet ? f.offending_snippet.split('\n').map(l => `<div class="diff-line diff-del">- ${esc(l)}</div>`).join('') : '';
  let rep = '';
  if (f.replacement_snippet) rep = f.replacement_snippet.split('\n').map(l => `<div class="diff-line diff-add">+ ${esc(l)}</div>`).join('');
  const envNote = f.env_var_name ? `<div class="diff-line diff-meta"># .env ← ${esc(f.env_var_name)}=•••</div>` : '';
  const diff = (off || rep) ? `<div class="diffbox mt-3 py-1.5 overflow-auto max-h-48"><div class="diff-line diff-meta"># proposed fix</div>${off}${rep}${envNote}</div>` : '';
  const acts = actionsFor(f);
  const cur = SCAN.decisions[f.id] || defaultAction(f);
  const radios = acts.map(([v, label]) => `<label><input type="radio" name="dec-${esc(f.id)}" value="${v}" ${cur === v ? 'checked' : ''}><span class="${v === 'whitelist' ? 'keep' : ''}">${esc(label)}${v === f.recommended_action ? '<span class="ml-1.5 opacity-60 text-[10.5px]">rec</span>' : ''}</span></label>`).join('');
  return `<article class="finding ${bug ? 'bug' : 'leak'} ${cur === 'whitelist' ? 'ignored' : ''}" data-id="${esc(f.id)}">
    <div class="flex flex-wrap items-center gap-1.5">${cat}${sub}<span class="chip sev-${esc(f.severity)}">${esc(f.severity)}</span>
      <span class="text-[11.5px] text-muted ml-auto tabular-nums">${Math.round((f.confidence || 0) * 100)}% conf.</span></div>
    <h4 class="f-title mt-2.5">${esc(f.title)}</h4>
    <button class="jump mt-1" title="Show in code viewer">${esc(loc)} ↗</button>
    <div class="mt-2 flex flex-wrap gap-1.5">${proof}${who}<span class="chip chip-grey font-mono !font-medium">${esc(f.rule_id)}</span></div>
    <p class="mt-2.5 text-[13px] text-ink2 leading-relaxed">${esc(f.reason)}</p>
    ${diff}
    <div class="seg mt-3.5" role="radiogroup" aria-label="Decision">${radios}</div>
  </article>`;
}

/* preview & apply */
async function previewPatch() {
  if (!SCAN.data) return;
  const btn = $('#previewBtn'); setBusy(btn, true, 'Building preview…');
  try {
    const r = await api('/api/preview', { body: { scan_id: SCAN.data.scan_id, decisions: SCAN.decisions } });
    const files = r.files || {};
    if (!Object.keys(files).length) { toast('No patchable text changes for the selected decisions.', 'warn'); return; }
    openPreviewModal(files, r.warnings || []);
  } catch (e) { toast('Preview failed: ' + e.message, 'err'); }
  finally { setBusy(btn, false); }
}

function diffHtml(diff) {
  if (!diff) return '<div class="p-4 text-muted text-[13px]">No changes.</div>';
  return '<div class="py-2 codebox">' + diff.split('\n').map(l => {
    let cls = '';
    if (l.startsWith('+++') || l.startsWith('---')) cls = 'diff-meta';
    else if (l.startsWith('+')) cls = 'diff-add'; else if (l.startsWith('-')) cls = 'diff-del'; else if (l.startsWith('@@')) cls = 'diff-hunk';
    return `<div class="diff-line ${cls}">${esc(l) || ' '}</div>`;
  }).join('') + '</div>';
}
function sideBySide(orig, patched, file) {
  const col = (txt, title, cls) => `<div class="min-w-0 border border-line rounded-xl overflow-hidden"><div class="px-3 py-2 text-[11.5px] font-semibold eyebrow ${cls} bg-[#F5F3EE] border-b border-line">${title}</div>
    <div class="codebox overflow-auto max-h-[70vh] py-2 hljs">${codeLines(txt, file)}</div></div>`;
  return `<div class="grid grid-cols-1 lg:grid-cols-2 gap-3 p-4">${col(orig, 'Original', '!text-accent')}${col(patched, 'Patched', '!text-good')}</div>`;
}
function openPreviewModal(files, warnings) {
  const keys = Object.keys(files); let active = keys[0]; let view = 'unified';
  $('#modalTitle').textContent = 'Preview combined patched file';
  const draw = () => {
    $('#modalTabs').innerHTML = keys.map(k => `<button class="file-tab ${k === active ? 'on' : ''}" data-k="${esc(k)}">${esc(k)}</button>`).join('');
    $$('#modalTabs button').forEach(b => b.onclick = () => { active = b.dataset.k; draw(); });
    $('#modalViewToggle').innerHTML = ['unified', 'side-by-side'].map(v => `<button class="filter-chip ${v === view ? 'active' : ''}" data-v="${v}">${v}</button>`).join('');
    $$('#modalViewToggle button').forEach(b => b.onclick = () => { view = b.dataset.v; draw(); });
    const f = files[active];
    $('#modalBody').innerHTML = (warnings.length ? `<div class="px-4 pt-3">${warnings.map(warnBox).join('')}</div>` : '')
      + (view === 'unified' ? diffHtml(f.diff) : sideBySide(f.original, f.patched, active));
  };
  $('#modalFoot').innerHTML = '';
  const apply = document.createElement('button'); apply.className = 'btn btn-primary'; apply.textContent = ' Apply Selected Fixes to Disk';
  apply.onclick = () => { closeModal(); applyFixes(); };
  const close = document.createElement('button'); close.className = 'btn btn-secondary'; close.textContent = 'Close'; close.onclick = closeModal;
  $('#modalFoot').append(close, apply);
  draw(); openModal();
}
function openModal() { const m = $('#modal'); m.classList.remove('hidden'); m.classList.add('flex'); $('#modalClose').focus(); }
function closeModal() { const m = $('#modal'); m.classList.add('hidden'); m.classList.remove('flex'); }

async function applyFixes() {
  if (!SCAN.data) return;
  const btn = $('#applyBtn'); setBusy(btn, true, 'Writing…');
  try {
    const r = await api('/api/apply', { body: { scan_id: SCAN.data.scan_id, decisions: SCAN.decisions } });
    const w = r.written || [];
    if (!w.length) { toast('Nothing written (all findings kept / whitelisted).' + ((r.warnings || []).length ? ' ' + r.warnings.join('; ') : ''), 'warn'); return; }
    const box = document.createElement('div');
    box.innerHTML = `<div class="font-semibold mb-1">Patched ${w.length} file${w.length > 1 ? 's' : ''}${w.some(x => !x.in_place) ? ' (sample fixtures untouched, safe copy)' : ''}</div>` +
      w.map(x => `<div class="font-mono text-[11.5px] text-good break-all">→ ${esc(x.rel_path || x.path)}</div>${x.env_path ? `<div class="font-mono text-[11.5px] text-warnc break-all">.env → ${esc(x.env_path)}</div>` : ''}`).join('');
    toast(box, 'ok', 9000);
    (r.warnings || []).forEach(m => toast(m, 'warn'));
  } catch (e) { toast('Apply failed: ' + e.message, 'err'); }
  finally { setBusy(btn, false); }
}

/* ==================================================================== TAB 2 */
const IMG = { listLoaded: false, current: null, img: null, boxes: [], scale: 1, drag: null, scanId: null };
const BOX_COLORS = { security_leak: '#C8432B', privacy_pii: '#D9822B', logical_bug: '#4B3FA6', manual: '#1F6C9F' };

async function loadImages() {
  IMG.listLoaded = true;
  try {
    const items = await api('/api/images');
    const list = $('#imageList');
    if (!items.length) { list.innerHTML = '<p class="text-[13px] text-muted p-1">No sample images yet (samples/screenshots/). Drop one below.</p>'; return; }
    list.innerHTML = items.map((it, i) => `<button class="img-item" data-i="${i}">
      <img src="${esc(it.url)}" alt="${esc(it.label)}" class="w-16 h-11 object-cover rounded-md border border-line flex-none" loading="lazy">
      <div class="min-w-0"><div class="text-[12.5px] font-semibold leading-tight">${esc(it.label)}</div>
      <div class="text-[10.5px] text-muted font-mono truncate mt-0.5">${esc(it.name)} · ${esc(it.width)}×${esc(it.height)}</div></div></button>`).join('');
    $$('.img-item', list).forEach(b => b.onclick = () => selectImage(items[+b.dataset.i]));
    IMG.items = items;
    if (!IMG.current) selectImage(items[0]);
    else $$('.img-item').forEach(b => b.classList.toggle('is-active', items[+b.dataset.i] && items[+b.dataset.i].path === IMG.current.path));
  } catch (e) { toast('Could not list images: ' + e.message, 'err'); }
}

function selectImage(it) {
  IMG.current = it; IMG.boxes = []; IMG.scanId = null;
  $$('.img-item').forEach(b => b.classList.toggle('is-active', IMG.items && IMG.items[+b.dataset.i] === it));
  const im = new Image();
  im.onload = () => { IMG.img = im; $('#canvasEmpty').classList.add('hidden'); $('#imgCanvas').classList.remove('hidden'); drawCanvas(); renderBoxList(); };
  im.onerror = () => toast('Image failed to load', 'err');
  im.src = it.url;
  $('#visionScanBtn').disabled = false; $('#redactBtn').disabled = false;
  $('#imgMeta').textContent = `${it.path} · ${it.width}×${it.height}`;
  $('#imgVerdict').innerHTML = ''; $('#resultCard').classList.add('hidden');
}

function drawCanvas() {
  const im = IMG.img; if (!im) return;
  const cv = $('#imgCanvas'); const wrap = $('#canvasWrap');
  if (!wrap.clientWidth) return;
  const maxW = wrap.clientWidth - 2; const maxH = Math.max(360, window.innerHeight * 0.68);
  const scale = Math.min(maxW / im.naturalWidth, maxH / im.naturalHeight, 1.5);
  IMG.scale = scale;
  const dpr = window.devicePixelRatio || 1;
  cv.style.width = Math.round(im.naturalWidth * scale) + 'px'; cv.style.height = Math.round(im.naturalHeight * scale) + 'px';
  cv.width = Math.round(im.naturalWidth * scale * dpr); cv.height = Math.round(im.naturalHeight * scale * dpr);
  const ctx = cv.getContext('2d'); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const W = im.naturalWidth * scale, H = im.naturalHeight * scale;
  ctx.drawImage(im, 0, 0, W, H);
  const style = $('#blurStyle').value;
  IMG.boxes.forEach((b, i) => {
    const [ymin, xmin, ymax, xmax] = b.bbox; const x = xmin / 1000 * W, y = ymin / 1000 * H, w = (xmax - xmin) / 1000 * W, h = (ymax - ymin) / 1000 * H;
    const color = BOX_COLORS[b.manual ? 'manual' : b.category] || '#C8432B';
    if (b.redact) {
      ctx.save(); ctx.beginPath(); ctx.rect(x, y, w, h); ctx.clip();
      if (style === 'solid_mask') { ctx.fillStyle = '#16150F'; ctx.fillRect(x, y, w, h); ctx.fillStyle = '#FAF9F6'; ctx.font = '600 10px "Geist Mono", monospace'; ctx.fillText('REDACTED', x + 5, y + Math.min(h - 3, 13)); }
      else { try { ctx.filter = 'blur(7px)'; } catch (e) {} ctx.drawImage(im, 0, 0, W, H); ctx.filter = 'none'; ctx.fillStyle = color + '1f'; ctx.fillRect(x, y, w, h); }
      ctx.restore();
    }
    ctx.save(); ctx.lineWidth = 2; ctx.strokeStyle = color; ctx.setLineDash(b.redact ? [] : [6, 4]);
    ctx.strokeRect(x, y, w, h);
    const label = `${i + 1} ${b.label}${b.redact ? '' : ' (kept)'}`.slice(0, 48);
    ctx.font = '600 11px Geist, sans-serif'; const tw = ctx.measureText(label).width + 10;
    const ly = y - 18 < 0 ? y + h + 2 : y - 18;
    ctx.fillStyle = b.redact ? color : '#77756E'; ctx.fillRect(x, ly, tw, 16);
    ctx.fillStyle = '#fff'; ctx.fillText(label, x + 5, ly + 12); ctx.restore();
  });
  if (IMG.drag && IMG.drag.moved) {
    const d = IMG.drag; ctx.save(); ctx.strokeStyle = '#1F6C9F'; ctx.setLineDash([4, 3]); ctx.lineWidth = 2;
    ctx.strokeRect(Math.min(d.x0, d.x1), Math.min(d.y0, d.y1), Math.abs(d.x1 - d.x0), Math.abs(d.y1 - d.y0)); ctx.restore();
  }
}

function canvasPoint(ev) { const r = $('#imgCanvas').getBoundingClientRect(); return { x: ev.clientX - r.left, y: ev.clientY - r.top, W: r.width, H: r.height }; }
function boxAt(p) {
  for (let i = IMG.boxes.length - 1; i >= 0; i--) {
    const [ymin, xmin, ymax, xmax] = IMG.boxes[i].bbox;
    if (p.x >= xmin / 1000 * p.W && p.x <= xmax / 1000 * p.W && p.y >= ymin / 1000 * p.H && p.y <= ymax / 1000 * p.H) return i;
  }
  return -1;
}
function initCanvas() {
  const cv = $('#imgCanvas');
  cv.addEventListener('pointerdown', ev => { if (!IMG.img) return; cv.setPointerCapture(ev.pointerId); const p = canvasPoint(ev); IMG.drag = { x0: p.x, y0: p.y, x1: p.x, y1: p.y, moved: false }; });
  cv.addEventListener('pointermove', ev => { if (!IMG.drag) return; const p = canvasPoint(ev); IMG.drag.x1 = p.x; IMG.drag.y1 = p.y; if (Math.hypot(p.x - IMG.drag.x0, p.y - IMG.drag.y0) > 6) IMG.drag.moved = true; if (IMG.drag.moved) drawCanvas(); });
  cv.addEventListener('pointerup', ev => {
    const d = IMG.drag; IMG.drag = null; if (!d) return; const p = canvasPoint(ev);
    if (!d.moved) { const i = boxAt(p); if (i >= 0) { IMG.boxes[i].redact = !IMG.boxes[i].redact; drawCanvas(); renderBoxList(); } return; }
    const c = v => Math.max(0, Math.min(1000, Math.round(v)));
    const bbox = [c(Math.min(d.y0, p.y) / p.H * 1000), c(Math.min(d.x0, p.x) / p.W * 1000), c(Math.max(d.y0, p.y) / p.H * 1000), c(Math.max(d.x0, p.x) / p.W * 1000)];
    if (bbox[2] - bbox[0] < 4 || bbox[3] - bbox[1] < 4) { drawCanvas(); return; }
    IMG.boxes.push({ id: 'manual-' + Date.now(), bbox, label: 'Manual redaction', category: 'manual', severity: 'HIGH', redact: true, manual: true });
    drawCanvas(); renderBoxList();
  });
  window.addEventListener('resize', () => { clearTimeout(IMG._rt); IMG._rt = setTimeout(drawCanvas, 120); });
}

function renderBoxList() {
  const list = $('#boxList'); $('#boxCount').textContent = IMG.boxes.length;
  if (!IMG.boxes.length) { list.innerHTML = '<p class="text-[13px] text-muted p-1">No regions yet. Run a vision scan or drag on the image to draw one.</p>'; return; }
  list.innerHTML = IMG.boxes.map((b, i) => {
    const color = BOX_COLORS[b.manual ? 'manual' : b.category] || '#C8432B';
    return `<div class="region ${b.redact ? '' : 'opacity-55'}">
      <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-[3px] flex-none" style="background:${color}"></span>
        <span class="text-[12.5px] font-semibold truncate">${i + 1}. ${esc(b.label)}</span>
        <label class="ml-auto flex items-center gap-1.5 cursor-pointer" title="${b.redact ? 'Will be redacted' : 'Kept as is'}"><input type="checkbox" class="sr-only bx" data-i="${i}" ${b.redact ? 'checked' : ''} aria-label="Redact region ${i + 1}"><span class="toggle"></span></label></div>
      <div class="mt-1.5 flex flex-wrap gap-1.5 items-center">${b.manual ? '<span class="chip chip-blue">manual</span>' : `<span class="chip sev-${esc(b.severity)}">${esc(b.severity)}</span>`}
        <span class="text-[10.5px] font-mono text-muted">[${b.bbox.join(', ')}]</span>
        ${b.manual ? `<button class="rm ml-auto text-[11.5px] text-accent hover:underline" data-i="${i}">remove</button>` : ''}</div>
      ${b.reason ? `<p class="mt-1.5 text-[12px] text-ink2 leading-snug">${esc(b.reason)}</p>` : ''}</div>`;
  }).join('');
  $$('.bx', list).forEach(c => c.onchange = () => { IMG.boxes[+c.dataset.i].redact = c.checked; drawCanvas(); renderBoxList(); });
  $$('.rm', list).forEach(c => c.onclick = () => { IMG.boxes.splice(+c.dataset.i, 1); drawCanvas(); renderBoxList(); });
}

function applyImageResult(r) {
  IMG.scanId = r.scan_id;
  IMG.boxes = IMG.boxes.filter(b => b.manual).concat((r.findings || []).filter(f => Array.isArray(f.bbox_2d) && f.bbox_2d.length === 4).map(f => ({
    id: f.id, bbox: f.bbox_2d.map(Number), label: f.title, category: f.category, severity: f.severity, reason: f.reason, redact: f.recommended_action !== 'whitelist', manual: false,
  })));
  const v = r.verdict || 'PASS';
  $('#imgVerdict').innerHTML = `<div class="flex flex-wrap gap-2 items-center"><span class="chip ${v === 'BLOCK' ? 'sev-CRITICAL' : v === 'WARN' ? 'chip-yellow' : 'chip-green'}">${esc(v)}</span><span class="text-[11px] font-mono text-muted">${esc(r.engine_used)} · ${esc(r.elapsed_s)}s</span></div>
    ${r.summary ? `<p class="text-[12px] text-ink2 mt-1.5">${esc(r.summary)}</p>` : ''}${(r.warnings || []).map(warnBox).join('')}`;
  drawCanvas(); renderBoxList();
}

async function visionScan() {
  if (!IMG.current) return;
  const btn = $('#visionScanBtn'); setBusy(btn, true, 'Scanning…');
  const stop = thinking($('#canvasWrap'), thinkerName() + ' vision', 3);
  try {
    const r = await api('/api/image/scan', { body: { path: IMG.current.path, mode: engineMode(), preset: preset(), offline: offline() } });
    applyImageResult(r);
    toast(`Vision scan: ${(r.findings || []).length} region(s) via ${r.engine_used}`, (r.findings || []).length ? 'warn' : 'ok');
  } catch (e) { toast('Vision scan failed: ' + e.message, 'err'); }
  finally { stop(); setBusy(btn, false); }
}

async function uploadImage(file) {
  if (!file) return;
  if (!/^image\//.test(file.type)) { toast('Please drop an image file', 'warn'); return; }
  const fd = new FormData(); fd.append('file', file); fd.append('mode', engineMode()); fd.append('preset', preset()); fd.append('offline', String(offline()));
  const stop = thinking($('#canvasWrap'), thinkerName() + ' vision', 3);
  try {
    const r = await api('/api/image/scan', { body: fd });
    const it = { ...r.image, label: 'Uploaded: ' + r.image.name, source: 'upload' };
    IMG.items = [it, ...(IMG.items || [])];
    await new Promise(res => { selectImage(it); const t = setInterval(() => { if (IMG.img && IMG.img.src.includes(encodeURIComponent(it.path).slice(0, 10))) { clearInterval(t); res(); } }, 50); setTimeout(() => { clearInterval(t); res(); }, 3000); });
    applyImageResult(r);
    loadImagesQuiet();
  } catch (e) { toast('Upload failed: ' + e.message, 'err'); }
  finally { stop(); }
}
async function loadImagesQuiet() { const cur = IMG.current; IMG.listLoaded = false; await loadImages(); IMG.current = cur; }

async function redactDownload() {
  if (!IMG.current) return;
  const boxes = IMG.boxes.filter(b => b.redact).map(b => b.bbox);
  if (!boxes.length) { toast('No boxes selected for redaction. Toggle at least one region.', 'warn'); return; }
  const btn = $('#redactBtn'); setBusy(btn, true, 'Redacting…');
  try {
    const res = await api('/api/image/redact', { body: { path: IMG.current.path, boxes, style: $('#blurStyle').value }, raw: true });
    const blob = await res.blob(); const url = URL.createObjectURL(blob);
    const name = (IMG.current.name || 'image').replace(/\.[^.]+$/, '') + '.redacted.png';
    $('#afterImg').src = url; $('#beforeImg').src = IMG.current.url;
    $('#downloadLink').href = url; $('#downloadLink').download = name;
    $('#resultCard').classList.remove('hidden'); syncCompare();
    const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    toast(`Redacted ${boxes.length} region(s) → ${res.headers.get('X-Redacted-Path') || name}`, 'ok');
  } catch (e) { toast('Redaction failed: ' + e.message, 'err'); }
  finally { setBusy(btn, false); }
}
function syncCompare() {
  const v = +$('#compareRange').value; const clip = $('#beforeClip');
  clip.style.width = v + '%';
  const after = $('#afterImg'); $('#beforeImg').style.width = after.clientWidth + 'px'; $('#beforeImg').style.height = 'auto';
}

/* ==================================================================== TAB 3 */
const FW = { vault: {}, sanitized: '' };
const DEFAULT_PROMPT = `salam khouya, 3andi mochkil f checkout dyal Atlas Pay
Le client Youssef El Amrani (CIN BE847291, tel +212661234567) kaykhlles b RIB 230780123456789012345678
w la réconciliation katla3 b 1 centime de différence chaque soir. Le stagiaire (CNE R139482710) a testé
contre https://hpc-staging.internal.um6p.ma/api/v1 avec HPC_TOKEN = "hpc_tok_7f3a9b2c1d4e5f60718293a4"
et CMI_STORE_KEY = "cmi_live_sk_9988776655443322" — ça marche, mais le total TVA est faux.

Voilà le code, chno l'mochkil ? Kifach n9addo bla ma nbeddlo l'API ?

def compute_total(amount_mad: float, quantity: int) -> float:
    subtotal = amount_mad * quantity
    tva = round(subtotal * 0.20, 2)
    return subtotal + tva

Traceback (most recent call last):
  File "reconcile.py", line 42, in <module>
    assert ledger_total == bank_total, f"mismatch for BE847291: {ledger_total} != {bank_total}"
AssertionError: mismatch for BE847291: 1199.99 != 1200.0`;

const tokRe = /\[[A-Z][A-Z0-9_]*_\d+\]/g;
function tokenChips(text) { return esc(text).replace(/\[[A-Z][A-Z0-9_]*_\d+\]/g, t => `<span class="tok">${t}</span>`); }
function rehydrateHtml(text, vault) {
  // escape then swap tokens for highlighted restored values
  return esc(text).replace(/\[[A-Z][A-Z0-9_]*_\d+\]/g, t => vault[t] !== undefined ? `<span class="restored" title="${esc(t)}">${esc(vault[t])}</span>` : `<span class="tok">${t}</span>`);
}
function rehydrateText(text, vault) { return String(text || '').replace(tokRe, t => vault[t] !== undefined ? vault[t] : t); }

function renderVault() {
  const tb = $('#vaultTable'); const reveal = $('#revealVault').checked;
  const ents = Object.entries(FW.vault);
  $('#entCount').textContent = ents.length;
  if (!ents.length) { tb.innerHTML = '<tr><td colspan="2" class="px-2.5 py-3 text-muted text-center">empty</td></tr>'; return; }
  const mask = v => reveal ? v : (v.length <= 4 ? '••••' : v.slice(0, 2) + '•'.repeat(Math.min(v.length - 4, 18)) + v.slice(-2));
  tb.innerHTML = ents.map(([k, v]) => `<tr class="border-t border-line"><td class="px-2.5 py-1.5"><span class="tok">${esc(k)}</span></td><td class="px-2.5 py-1.5 font-mono text-ink2 break-all">${esc(mask(String(v)))}</td></tr>`).join('');
}

async function sanitizePrompt() {
  const btn = $('#sanitizeBtn'); setBusy(btn, true, 'Sanitizing on-device…');
  try {
    const r = await api('/api/sanitize', { body: { text: $('#rawPrompt').value, use_local_llm: !offline() } });
    FW.vault = r.vault || {}; FW.sanitized = r.sanitized || '';
    $('#sanitizedOut').innerHTML = tokenChips(FW.sanitized);
    $('#sanEngine').textContent = r.engine || '';
    renderVault();
    $('#askBtn').disabled = false;
    (r.warnings || []).forEach(w => toast(w, 'warn'));
    toast(`${Object.keys(FW.vault).length} sensitive entities tokenized locally`, 'ok');
  } catch (e) { toast('Sanitize failed: ' + e.message, 'err'); }
  finally { setBusy(btn, false); }
}

async function askCloud() {
  if (!FW.sanitized) return;
  // client-side defense in depth too
  const leaks = Object.entries(FW.vault).filter(([k, v]) => v && v.length >= 3 && FW.sanitized.includes(v));
  if (leaks.length) { toast('Blocked: sanitized prompt still contains raw values (' + leaks.map(x => x[0]).join(', ') + ')', 'err'); return; }
  const btn = $('#askBtn'); setBusy(btn, true, 'Asking cloud…');
  const out = $('#fwOut');
  const stop = thinking(out, offline() ? 'Offline template' : 'Gemma 4 31B Dense', 4);
  try {
    const r = await api('/api/firewall/ask', { body: { sanitized_prompt: FW.sanitized, vault: FW.vault, mode: 'cloud_deep', offline: offline() } });
    $('#piiBytes').textContent = r.pii_bytes_sent ?? 0;
    $('#sentBytes').textContent = (r.sent_bytes ?? 0).toLocaleString();
    $('#fwEngine').textContent = r.engine + ' · ' + r.elapsed_s + 's';
    const restoredCode = rehydrateText(r.raw_fixed_code || '', FW.vault);
    out.innerHTML = `
      ${(r.warnings || []).map(warnBox).join('')}
      <details class="rounded-xl border border-line bg-white"><summary class="px-3 py-2.5 text-[12.5px] font-medium flex items-center gap-2">${ICON.chev} What was sent to the cloud <span class="ml-auto chip chip-green">0 raw PII</span></summary>
        <div class="px-3 pb-3 font-mono text-[12px] text-ink2 pre-wrap max-h-56 overflow-auto">${tokenChips(r.sent_prompt || '')}</div></details>
      <div class="rounded-xl border border-line bg-[#FCFBF8] p-3.5">
        <div class="eyebrow mb-2">Cloud answer · tokens only</div>
        <div class="text-[13px] text-ink2 pre-wrap leading-relaxed">${tokenChips(r.raw_answer || '')}</div></div>
      <div class="rounded-xl border-[1.5px] border-ink bg-white p-3.5" style="box-shadow:2px 2px 0 #346538">
        <div class="eyebrow !text-good mb-2">Rehydrated locally</div>
        <div class="text-[13px] text-ink pre-wrap leading-relaxed">${rehydrateHtml(r.raw_answer || '', FW.vault)}</div></div>
      ${restoredCode ? `<div class="rounded-xl border border-line overflow-hidden"><div class="px-3 py-2 eyebrow bg-[#F5F3EE] border-b border-line">Suggested fix</div>
        <div class="codebox overflow-auto max-h-72 py-2 hljs">${codeLines(restoredCode, 'fix.py')}</div></div>` : ''}`;
    toast('Answer received and rehydrated locally', 'ok');
  } catch (e) {
    toast('Firewall: ' + e.message, 'err');
  } finally { stop(); setBusy(btn, false); }
}

/* ==================================================================== TAB 4 */
const POLICY = { loaded: false };
function syncGutter() {
  const ta = $('#yamlEditor'); const n = ta.value.split('\n').length;
  const g = $('#yamlGutter'); if (g.dataset.n != n) { g.textContent = Array.from({ length: n }, (_, i) => i + 1).join('\n'); g.dataset.n = n; }
  g.scrollTop = ta.scrollTop;
}
async function loadPolicy() {
  POLICY.loaded = true;
  try {
    const r = await api('/api/policy');
    $('#yamlEditor').value = r.yaml || ''; syncGutter(); policyStats();
  } catch (e) { toast('Could not load policy: ' + e.message, 'err'); }
}
function policyStats() {
  const t = $('#yamlEditor').value;
  const rr = (t.match(/^\s*-\s*id:/gm) || []).length; const nl = (t.match(/nl_rules:/g) || []).length;
  $('#policyStats').textContent = `${t.split('\n').length} lines · ${rr} regex rules · ${nl} NL packs`;
}
function policyMsg(html, kind) {
  const el = $('#policyMsg'); el.classList.remove('hidden');
  el.className = 'mx-4 mt-3 text-[12.5px] rounded-lg px-3 py-2 border ' + (kind === 'ok' ? 'border-[#CFE0CC] bg-[#EDF3EC] text-[#346538]' : 'border-[#F3C9C4] bg-[#FDEBEC] text-[#9F2F2D] font-mono pre-wrap');
  el.innerHTML = html;
}
async function savePolicy() {
  const btn = $('#savePolicyBtn'); setBusy(btn, true, 'Validating…');
  try {
    const r = await api('/api/policy', { method: 'PUT', body: { yaml: $('#yamlEditor').value } });
    policyMsg(`Saved to <span class="font-mono">${esc(r.path)}</span>: ${esc(r.presets.length)} presets, ${esc(r.regex_rules)} regex rules, ${esc(r.nl_rules)} NL rules. Scanner cache reset.`, 'ok');
    toast('Policy saved and validated', 'ok');
  } catch (e) { policyMsg(esc(e.message), 'err'); toast('Policy invalid, not saved', 'err'); }
  finally { setBusy(btn, false); }
}

function renderMarkdown(md) {
  if (!md) return '<p class="text-[13px] text-muted">No markdown returned.</p>';
  if (window.marked) {
    try {
      const html = marked.parse(md, { mangle: false, headerIds: false });
      const tpl = document.createElement('template'); tpl.innerHTML = html;
      tpl.content.querySelectorAll('script,iframe,object,embed,style').forEach(n => n.remove());
      tpl.content.querySelectorAll('*').forEach(n => [...n.attributes].forEach(a => { if (/^on/i.test(a.name) || /javascript:/i.test(a.value)) n.removeAttribute(a.name); }));
      return tpl.innerHTML;
    } catch (e) {}
  }
  return `<pre class="pre-wrap text-[12px]">${esc(md)}</pre>`;
}

/** Find recall per engine in the benchmark result / markdown. */
function extractRecall(payload) {
  const out = [];
  const r = payload.result;
  const pct = v => { if (v === null || v === undefined) return null; if (typeof v === 'number') return v <= 1 ? v * 100 : v; const m = String(v).match(/([\d.]+)\s*%?/); if (!m) return null; const n = parseFloat(m[1]); return String(v).includes('%') || n > 1 ? n : n * 100; };
  const visit = (obj, name) => {
    if (!obj || typeof obj !== 'object') return;
    for (const [k, v] of Object.entries(obj)) {
      if (/recall/i.test(k) && (typeof v === 'number' || typeof v === 'string') && name) out.push({ engine: name, recall: pct(v) });
      else if (v && typeof v === 'object' && !Array.isArray(v)) visit(v, Array.isArray(obj) ? name : k);
    }
  };
  if (r && r.engines && typeof r.engines === 'object') {
    for (const [k, e] of Object.entries(r.engines)) if (e && e.recall !== undefined) out.push({ engine: e.label || k, recall: pct(e.recall) });
  }
  if (!out.length && r && typeof r === 'object') {
    for (const key of ['engines', 'summary', 'per_engine', 'metrics', 'totals']) if (r[key]) visit(r[key], null);
    if (!out.length) visit(r, null);
  }
  if (!out.length && payload.markdown) {
    const lines = payload.markdown.split('\n').filter(l => l.trim().startsWith('|'));
    const rows = lines.map(l => l.trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim().replace(/\*\*/g, '')));
    for (let i = 0; i < rows.length; i++) {
      const hdr = rows[i]; const ci = hdr.findIndex(c => /recall/i.test(c));
      if (ci > 0) { for (let j = i + 2; j < rows.length && rows[j].length === hdr.length; j++) { const v = pct(rows[j][ci]); if (v !== null) out.push({ engine: rows[j][0], recall: v }); } if (out.length) break; }
      const rowRecall = rows.find(rw => /recall/i.test(rw[0]));
      if (rowRecall && i === 0) { hdr.slice(1).forEach((h, k) => { const v = pct(rowRecall[k + 1]); if (v !== null) out.push({ engine: h, recall: v }); }); if (out.length) break; }
    }
  }
  const seen = new Set();
  return out.filter(o => o.recall !== null && !isNaN(o.recall) && !seen.has(o.engine) && seen.add(o.engine));
}
function renderBench(payload) {
  $('#benchMd').innerHTML = renderMarkdown(payload.markdown);
  const rec = extractRecall(payload);
  const chart = $('#benchChart');
  if (!rec.length) chart.innerHTML = '<p class="text-[13px] text-muted">No recall metric found in result.</p>';
  else chart.innerHTML = rec.map(o => {
    const regex = /regex|gitleaks|baseline/i.test(o.engine);
    return `<div><div class="flex justify-between items-baseline text-[13px] mb-1.5"><span class="font-medium ${regex ? 'text-muted' : 'text-ink'}">${esc(o.engine)}</span><span class="font-display font-extrabold text-[18px] tabular-nums ${regex ? 'text-muted' : 'text-accent'}">${o.recall.toFixed(0)}%</span></div>
      <div class="track !h-[10px]"><div class="bar ${regex ? 'grey' : 'red'}" style="--w:0" data-w="${Math.max(0, Math.min(100, o.recall)) / 100}"></div></div></div>`;
  }).join('');
  requestAnimationFrame(() => $$('#benchChart .bar').forEach(b => b.style.setProperty('--w', b.dataset.w)));
  const meta = [];
  if (payload.elapsed_s !== undefined) meta.push(`ran in ${payload.elapsed_s}s`);
  if (payload.ts) meta.push(new Date(payload.ts * 1000).toLocaleString());
  (payload.warnings || []).forEach(w => meta.push('! ' + w));
  $('#benchMeta').textContent = meta.join(' · ');
}
async function runBench() {
  const btn = $('#benchBtn'); setBusy(btn, true, 'Running benchmark…');
  const card = $('#benchMd');
  const stop = thinking(card, $('#benchOffline').checked ? 'Benchmark (offline)' : 'Benchmark: Regex vs Gemma 4', 6);
  try {
    const r = await api('/api/benchmark', { body: { offline: $('#benchOffline').checked } });
    renderBench(r);
    if ((r.warnings || []).length) toast(r.warnings.join('; '), 'warn'); else toast('Benchmark complete', 'ok');
  } catch (e) { toast('Benchmark failed: ' + e.message, 'err'); }
  finally { stop(); setBusy(btn, false); }
}
async function loadLastBench() {
  try { const r = await api('/api/benchmark/last'); if (r && (r.markdown || r.result)) renderBench(r); } catch (e) {}
}

/* ======================================================================= init */
async function reindex() {
  const btn = $('#reindexBtn'); setBusy(btn, true, 'Indexing…');
  try {
    const scen = SCAN.data && SCAN.data.scenario;
    const r = await api('/api/index', { body: { force: true, scenario: scen || null } });
    setIndex(r);
    (r.warnings || []).forEach(w => toast(w, 'warn'));
    toast(`Indexed ${r.files_indexed ?? 0} files (${r.files_reused ?? 0} reused) → ${r.chunks} chunks / ${r.symbols} symbols${scen ? ' [' + scen + ']' : ''}`, 'ok');
  } catch (e) { toast('Re-index failed: ' + e.message, 'err'); }
  finally { setBusy(btn, false); }
}

function init() {
  // restore prefs
  const em = store.get('engine', null); if (em) $('#engineMode').value = em;
  const dp = store.get('preset', null); if (dp) $('#domainPreset').value = dp;
  const off = params.has('offline') ? params.get('offline') === '1' : store.get('offline', false);
  $('#offlineToggle').checked = !!off; syncOffline();
  $('#engineMode').onchange = () => store.set('engine', engineMode());
  $('#domainPreset').onchange = () => store.set('preset', preset());
  $('#offlineToggle').onchange = syncOffline;
  $$('.tab-btn').forEach(b => b.onclick = () => showTab(b.dataset.tab));
  $('#reindexBtn').onclick = reindex;
  // tab 1
  $$('.scenario-btn').forEach(b => b.onclick = () => runScenario(b.dataset.scenario));
  $$('#filterChips .filter-chip').forEach(c => c.onclick = () => { SCAN.filter = c.dataset.filter; $$('#filterChips .filter-chip').forEach(x => x.classList.toggle('active', x === c)); renderFindings(); });
  $('#previewBtn').onclick = previewPatch; $('#applyBtn').onclick = applyFixes;
  $('#modalClose').onclick = closeModal; $('#modal').onclick = e => { if (e.target.id === 'modal') closeModal(); };
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
  // tab 2
  initCanvas();
  $('#visionScanBtn').onclick = visionScan; $('#redactBtn').onclick = redactDownload;
  $('#blurStyle').onchange = drawCanvas;
  $('#compareRange').oninput = syncCompare; $('#afterImg').onload = syncCompare;
  const dz = $('#dropzone');
  ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('drag'); }));
  dz.addEventListener('drop', e => uploadImage(e.dataTransfer.files[0]));
  $('#fileInput').onchange = e => uploadImage(e.target.files[0]);
  // tab 3
  $('#rawPrompt').value = DEFAULT_PROMPT;
  $('#sanitizeBtn').onclick = sanitizePrompt; $('#askBtn').onclick = askCloud;
  $('#revealVault').onchange = renderVault;
  // tab 4
  const ta = $('#yamlEditor');
  ta.addEventListener('input', () => { syncGutter(); policyStats(); }); ta.addEventListener('scroll', syncGutter);
  ta.addEventListener('keydown', e => {
    if (e.key === 'Tab') { e.preventDefault(); const s = ta.selectionStart; ta.setRangeText('  ', s, ta.selectionEnd, 'end'); syncGutter(); }
    if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); savePolicy(); }
  });
  $('#savePolicyBtn').onclick = savePolicy; $('#reloadPolicyBtn').onclick = loadPolicy;
  $('#benchBtn').onclick = runBench;

  loadStatus();
  setInterval(loadStatus, 30000);
  // deep links: ?tab=image|firewall|policy|code&demo=<scenario>&scan=1&fw=1
  const tabMap = { code: 'tab-code', image: 'tab-image', firewall: 'tab-firewall', policy: 'tab-policy' };
  const t = tabMap[params.get('tab')] || store.get('tab', 'tab-code');
  showTab($('#' + t) ? t : 'tab-code');
  if (params.get('demo')) { showTab('tab-code'); runScenario(params.get('demo')); }
  if (params.get('scan') === '1') { showTab('tab-image'); const iv = setInterval(() => { if (IMG.img) { clearInterval(iv); visionScan(); } }, 200); }
  if (params.get('fw') === '1') { showTab('tab-firewall'); sanitizePrompt().then(() => askCloud()); }
  if (params.get('bench') === '1') { showTab('tab-benchmark'); runBench(); }
}
document.addEventListener('DOMContentLoaded', init);

// Keyboard navigation follows the visible workspace tabs.
document.addEventListener('DOMContentLoaded', () => {
 const tabs = [...document.querySelectorAll('.tab-btn')];
 tabs.forEach((tab, i) => tab.addEventListener('keydown', e => {
   if (!['ArrowDown','ArrowUp','ArrowRight','ArrowLeft','Home','End'].includes(e.key)) return;
   e.preventDefault(); const n = e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length-1 : (i + (['ArrowDown','ArrowRight'].includes(e.key) ? 1 : -1) + tabs.length) % tabs.length;
   tabs[n].focus(); tabs[n].click();
 }));
});
