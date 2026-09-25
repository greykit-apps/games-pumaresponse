// ═══════════════════════════════════════════════════
// PUMARESPONSE — Incident Response Simulator
// ═══════════════════════════════════════════════════

const $ = id => document.getElementById(id);

// ── BOOT SEQUENCE ──────────────────────────────────
const BOOT_LINES = [
  ['Initializing PumaResponse MSSP Platform...', 'ok', '[ OK ]'],
  ['Loading SIEM connectors...', 'ok', '[ OK ]'],
  ['Connecting to Sentinel / Splunk / Elastic...', 'ok', '[ OK ]'],
  ['Loading threat intelligence feeds...', 'ok', '[ OK ]'],
  ['Syncing MITRE ATT&CK framework v19.2...', 'ok', '[ OK ]'],
  ['Loading incident playbooks...', 'ok', '[ OK ]'],
  ['Checking analyst certifications...', 'warn', '[ WARN ]'],
  ['Establishing customer VPN tunnels...', 'ok', '[ OK ]'],
  ['Pulling EDR telemetry...', 'ok', '[ OK ]'],
  ['Loading forensic toolkit...', 'ok', '[ OK ]'],
  ['Verifying chain-of-custody protocols...', 'ok', '[ OK ]'],
  ['MSSP shift handoff received — 1 incident in queue', 'warn', '[ ALERT ]'],
];

let bootIdx = 0;
function runBoot() {
  if (bootIdx < BOOT_LINES.length) {
    const [text, cls, tag] = BOOT_LINES[bootIdx];
    const div = document.createElement('div');
    div.className = 'boot-line';
    div.innerHTML = `<span class="label">${escapeHtml(text)}</span><span class="${cls}">${escapeHtml(tag)}</span>`;
    $('boot-log').appendChild(div);
    bootIdx++;
    setTimeout(runBoot, 120 + Math.random() * 180);
  } else {
    $('boot-prompt').style.display = 'block';
  }
}

function skipBoot() {
  // Render remaining boot lines instantly
  while (bootIdx < BOOT_LINES.length) {
    const [text, cls, tag] = BOOT_LINES[bootIdx];
    const div = document.createElement('div');
    div.className = 'boot-line';
    div.style.animationDuration = '0s';
    div.innerHTML = `<span class="label">${escapeHtml(text)}</span><span class="${cls}">${escapeHtml(tag)}</span>`;
    $('boot-log').appendChild(div);
    bootIdx++;
  }
  $('boot-prompt').style.display = 'block';
}

let bootDone = false;
document.addEventListener('keydown', function bootKey(e) {
  if (bootIdx < BOOT_LINES.length) { skipBoot(); return; }
  if (bootDone) return;
  bootDone = true;
  document.removeEventListener('keydown', bootKey);
  $('boot-screen').style.display = 'none';
  openMenu(); // pick an incident; nothing starts until you do
});
$('boot-screen').addEventListener('click', function() {
  if (bootIdx < BOOT_LINES.length) { skipBoot(); return; }
  if (bootDone) return;
  bootDone = true;
  $('boot-screen').style.display = 'none';
  openMenu();
});

setTimeout(runBoot, 400);

// ── INCIDENT SCENARIOS ─────────────────────────────
// Scenarios register themselves from js/scenarios/*.js (loaded after this file,
// in menu order). Nothing below reads INCIDENTS until the player starts a game.
const INCIDENTS = [];

// ── REAL-DATE ANCHORING ─────────────────────────────
// Scenarios are written against a fixed in-world "today" (incident.baseDate,
// 'YYYY-MM-DD'). On registration every string in the scenario, and every string a
// scenario function returns, is shifted so that date becomes the real today:
// "Feb 17" written two days before a Feb 19 baseDate always reads as two days ago.
// Shifted: "Feb 17" dates, "Thu, 19 Feb 2024" / "19 Feb 2024" (weekday recomputed),
// years 2010-2029 (except CVE IDs, which are real), and quarters Q1-Q4.
// Times of day are untouched. Every scenario must declare a baseDate.
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const DATE_RE = new RegExp(
  `(?:\\b(${WEEKDAYS.join('|')}), )?\\b(\\d{1,2}) (${MONTHS.join('|')}) (\\d{4})\\b`   // [Thu, ]19 Feb 2024
  + `|\\b(${MONTHS.join('|')}) (\\d{1,2})\\b(?!,? ?\\d{4})`                              // Feb 17
  + `|(?<!CVE-)\\b(20[12]\\d)\\b`                                                      // 2024
  + `|\\bQ([1-4])\\b`, 'g');                                                        // Q4

function makeDateShifter(baseDate) {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const base = new Date(baseDate + 'T00:00:00');
  const dayMs = 86400000;
  const shift = d => new Date(d.getTime() + Math.round((today - base) / dayMs) * dayMs);
  const years = today.getFullYear() - base.getFullYear();
  const quarters = years * 4 + Math.floor(today.getMonth() / 3) - Math.floor(base.getMonth() / 3);
  // "Dec 28" in a scenario based in February means last December
  const inBaseYear = (mon, day) => {
    const d = new Date(base.getFullYear(), MONTHS.indexOf(mon), +day);
    if (d - base > 183 * dayMs) d.setFullYear(d.getFullYear() - 1);
    return d;
  };
  return str => str.replace(DATE_RE, (m, wd, dd, mon, yyyy, mon2, dd2, year, q) => {
    if (mon) {
      const d = shift(new Date(+yyyy, MONTHS.indexOf(mon), +dd));
      return `${wd ? WEEKDAYS[d.getDay()] + ', ' : ''}${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}`;
    }
    if (mon2) { const d = shift(inBaseYear(mon2, dd2)); return `${MONTHS[d.getMonth()]} ${d.getDate()}`; }
    if (year) return String(+year + years);
    return 'Q' + ((((+q - 1 + quarters) % 4) + 4) % 4 + 1);
  });
}

function anchorDeep(v, fix) {
  if (typeof v === 'string') return fix(v);
  if (typeof v === 'function') return (...args) => anchorDeep(v(...args), fix);
  if (Array.isArray(v)) return v.map(x => anchorDeep(x, fix));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, anchorDeep(x, fix)]));
  return v;
}

function registerIncident(incident) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(incident.baseDate || '')) throw new Error(`${incident.id}: baseDate 'YYYY-MM-DD' is required`);
  INCIDENTS.push(anchorDeep(incident, makeDateShifter(incident.baseDate)));
}

// ── GAME STATE ─────────────────────────────────────
const STATE = {
  incident: null,
  phaseIdx: 0,
  scores: { time: 0, containment: 0, evidence: 0, thoroughness: 0 },
  elapsed: 0,
  notes: [],
  choices: [],
  flags: {},
  carried: [],
  findings: [],        // { phase, id, text } — evidence lines correctly tagged
  findingText: {},     // id -> line text, for every finding the player was shown
  falseLeads: 0,
  evLines: null,       // this phase's finding id per evidence line (null = not taggable)
  evCursor: -1,
  choiceOrder: null,   // display order of this phase's choices (origIdx)
  clockMode: 'realtime', // or 'turn' — player setting, remembered per browser
  clockStarted: false, // this phase's decision clock has been started
  phaseClock: 0,       // game minutes spent deciding this phase
  fired: new Set(),    // this phase's timeline events that have happened
  clockLog: [],        // { phase, text } — attacker actions that fired while you decided
  decisionMinutes: 0,
  played: new Set(),   // incident ids started this session — random picks skip these
  siemTimers: [],      // pending staggered SIEM entries, cleared on restart
  started: false,
  awaitingContinue: false,
};

const PHASE_NAMES = ['TRIAGE', 'CONTAINMENT', 'INVESTIGATION', 'ERADICATION', 'RECOVERY', 'POST-INCIDENT'];

// ── UTILITY ────────────────────────────────────────
// Escape HTML entities in user-facing text to prevent XSS
// Note: evidence.content intentionally uses HTML spans for log formatting
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// Scenario fields may be a plain value or a function of the run's state:
// (flags, state) => value. That is how a scenario reacts to earlier choices.
// Choices set flags via `sets`, can be hidden with `when`, and each phase may
// list `carried` consequences, shown above the briefing and scored on entry.
function resolve(v) {
  return typeof v === 'function' ? v(STATE.flags, STATE) : v;
}

function fmtUSD(n) {
  return '$' + Math.round(n).toLocaleString('en-US');
}

function formatElapsed(mins) {
  const d = Math.floor(mins / 1440);
  const h = Math.floor(mins / 60) % 24;
  const m = mins % 60;
  return `${d ? d + 'd ' : ''}${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
}

function addSiemEntry(time, sev, text) {
  const body = $('siem-feed-col');
  const div = document.createElement('div');
  div.className = 'siem-entry';
  const sevClass = { info:'siem-info', warn:'siem-warn', crit:'siem-crit', success:'siem-success' }[sev] || 'siem-info';
  div.innerHTML = `<span class="siem-time">[${escapeHtml(time)}]</span> <span class="${sevClass}">${escapeHtml(text)}</span>`;
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
}

function addNote(phase, text) {
  STATE.notes.push({ phase, text });
  renderNotes();
}

function renderNotes() {
  const body = $('notes-col');
  body.innerHTML = '<div class="section-title" style="margin-top:0;">ANALYST NOTES</div>';
  STATE.notes.forEach((n, i) => {
    const div = document.createElement('div');
    div.className = 'note-entry';
    div.innerHTML = `<span class="note-phase">[${escapeHtml(n.phase)}]</span> ${escapeHtml(n.text)}`
      + `<button type="button" class="note-remove" data-i="${i}" aria-label="Remove note: ${escapeHtml(n.text)}">REMOVE</button>`;
    body.appendChild(div);
  });
}

// Removing a note only tidies the notebook: a finding stays tagged and scored.
function removeNote(i) {
  STATE.notes.splice(i, 1);
  renderNotes();
  // Keep keyboard focus in the list: the note that moved up, else the one above
  const btns = document.querySelectorAll('.note-remove');
  const next = btns[Math.min(i, btns.length - 1)];
  if (next) next.focus({ preventScroll: true });
}
$('notes-col').addEventListener('click', (e) => {
  const btn = e.target.closest('.note-remove');
  if (!btn) return;
  e.stopPropagation(); // the right panel toggles its expanded view on any click
  removeNote(+btn.dataset.i);
});
// Enter/Space on the button is its own click; don't let the global keys
// (start clock, advance phase) act on it too
$('notes-col').addEventListener('keydown', (e) => {
  if (e.target.closest('.note-remove') && (e.key === 'Enter' || e.key === ' ')) e.stopPropagation();
});

// ── RENDER INCIDENT BRIEF ──────────────────────────
// Offer natural break points inside long indicators: before "@" in addresses and
// after "/" in paths/URLs, so they split at a seam instead of mid-token.
function iocBreaks(html) {
  return html.replace(/(\S{12,})/g, tok => tok.replace(/@/g, '<wbr>@').replace(/\//g, '/<wbr>'));
}

function renderBrief() {
  const inc = STATE.incident;
  const brief = $('incident-brief');
  brief.innerHTML = `
    <div class="incident-meta">
      <div class="meta-row"><span class="meta-label">TICKET</span><span class="meta-val">${escapeHtml(inc.ticketId)}</span></div>
      <div class="meta-row"><span class="meta-label">CLIENT</span><span class="meta-val">${escapeHtml(inc.client)}</span></div>
      <div class="meta-row"><span class="meta-label">SEVERITY</span><span class="meta-val ${inc.sevClass}">${escapeHtml(inc.severity)}</span></div>
      <div class="meta-row"><span class="meta-label">ASSIGNED</span><span class="meta-val">${escapeHtml(inc.assignedTime)}</span></div>
      <div class="meta-row"><span class="meta-label">TYPE</span><span class="meta-val">${escapeHtml(inc.title.split('—')[0].trim())}</span></div>
    </div>
    <div class="section-title">SUMMARY</div>
    <div class="brief-summary">${escapeHtml(inc.summary)}</div>
    <div class="section-title">INDICATORS OF COMPROMISE</div>
    <div class="ioc-list">${inc.iocs.map(i => `<div class="ioc-item"><div class="ioc-type">${escapeHtml(i.type)}</div><div class="ioc-val">${iocBreaks(escapeHtml(i.val))}</div></div>`).join('')}</div>
    <div class="score-tracker" id="score-tracker"></div>
  `;
  renderScoreTracker();
}

function renderScoreTracker() {
  const tracker = $('score-tracker');
  if (!tracker) return;
  const s = STATE.scores;
  const scoreColor = v => v >= 10 ? '' : v >= 0 ? 'warn' : 'crit';
  tracker.innerHTML = `
    <div class="section-title">PERFORMANCE METRICS</div>
    <div class="score-row"><span class="score-label">RESPONSE TIME</span><span class="score-val ${scoreColor(s.time)}">${s.time > 0 ? '+' : ''}${s.time}</span></div>
    <div class="score-row"><span class="score-label">CONTAINMENT</span><span class="score-val ${scoreColor(s.containment)}">${s.containment > 0 ? '+' : ''}${s.containment}</span></div>
    <div class="score-row"><span class="score-label">EVIDENCE</span><span class="score-val ${scoreColor(s.evidence)}">${s.evidence > 0 ? '+' : ''}${s.evidence}</span></div>
    <div class="score-row"><span class="score-label">THOROUGHNESS</span><span class="score-val ${scoreColor(s.thoroughness)}">${s.thoroughness > 0 ? '+' : ''}${s.thoroughness}</span></div>
  `;
}

// ── EVIDENCE TAGGING ───────────────────────────────
// An evidence line may carry a hidden marker, <!--f:id-->. When a phase's evidence
// has any, every line becomes taggable. Tagging a marked line records a finding and
// sets flag saw_<id>, which choices and outcomes can read like any other flag.
// Tagging an unmarked line is a false lead and costs time. Several lines may share
// an id (one finding spread across a log entry). Evidence without markers renders
// exactly as before, so scenarios opt in line by line.
const FINDING_RE = /<!--f:(\w+)-->/;
const FINDING_REWARD = { evidence: 2 };
const FALSE_LEAD = { time: -2, minutes: 2 };

// Taggable evidence is coloured by what a token IS, never by whether it matters:
// the same rules run over every line, so colour can't point at the findings.
// Hand-placed red (log-highlight) is removed from taggable evidence first.
// Summary screens (no markers) keep their authored colouring.
const LEX_RULES = [
  // severity / status words, as a SIEM would colour them
  [/\b(CRITICAL|ALERT|FAIL(?:ED|URE)?|DENIED|BLOCKED|ERROR|SUCCESS|NOT CONFIGURED|DISABLED|NONE|MALICIOUS)\b/g, 'log-highlight'],
  // IPv4 addresses, with optional port
  [/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g, 'log-warn'],
];
// Section headers ("── EMAIL BODY ──") are structure, not evidence: not taggable
const EV_HEADER_RE = /^\s*─{2,}.*─{2,}\s*$/;
function isEvHeader(line) {
  return !FINDING_RE.test(line) && EV_HEADER_RE.test(line.replace(/<[^>]+>/g, ''));
}
function lexHighlight(line) {
  if (isEvHeader(line)) return line;
  const plain = line.replace(/<span class="log-(?:highlight|ok)">([\s\S]*?)<\/span>/g, '$1');
  // Only touch text between tags, never markup or entities' insides
  return plain.split(/(<[^>]+>)/).map(seg => seg.startsWith('<') ? seg
    : LEX_RULES.reduce((t, [re, cls]) => t.replace(re, m => `<span class="${cls}">${m}</span>`), seg)).join('');
}

function renderEvidence(content) {
  if (!FINDING_RE.test(content)) { STATE.evLines = null; return `<pre>${content}</pre>`; }
  const lines = content.split('\n').map(lexHighlight);
  STATE.evLines = lines.map(l => (l.match(FINDING_RE) || [])[1] || null);
  STATE.evCursor = -1;
  const rows = lines.map((l, i) => !l.trim() ? '<span class="ev-blank"> </span>'
    : isEvHeader(l) ? `<span class="ev-head">${l}</span>`
    : `<span class="ev-line" id="ev-line-${i}" role="option" aria-selected="false" data-i="${i}">${l.replace(FINDING_RE, '')}</span>`).join('');
  return `<pre class="ev-taggable" id="ev-taggable" tabindex="0" role="listbox" aria-multiselectable="true"
    aria-label="Evidence lines. Arrow keys move, Enter tags the line as a finding.">${rows}</pre>`;
}

// Called once the evidence is in the DOM: remember what each finding says (for the debrief)
function indexFindings() {
  if (!STATE.evLines) return;
  STATE.evLines.forEach((id, i) => {
    if (id && !(id in STATE.findingText)) STATE.findingText[id] = $('ev-line-' + i).textContent.trim();
  });
  updateTagCount();
}

function updateTagCount() {
  const el = $('ev-hint');
  if (!el) return;
  const phase = STATE.incident.phases[STATE.phaseIdx].name;
  const n = new Set(STATE.evLines.filter((id, i) => id && $('ev-line-' + i).classList.contains('finding'))).size;
  const k = document.querySelectorAll('.ev-line.noise').length;
  el.innerHTML = `CLICK LINES TO TAG · <b>${n}</b> finding${n === 1 ? '' : 's'}${k ? ` · ${k} false` : ''}`;
}

function tagLine(i) {
  const el = $('ev-line-' + i);
  if (STATE.awaitingContinue || !STATE.evLines || !el || el.classList.contains('tagged')) return;
  const phase = STATE.incident.phases[STATE.phaseIdx].name;
  const id = STATE.evLines[i];
  const text = el.textContent.trim();
  const short = text.length > 70 ? text.slice(0, 67) + '...' : text;
  if (id) {
    STATE.evLines.forEach((fid, j) => {
      if (fid !== id) return;
      $('ev-line-' + j).classList.add('tagged', 'finding');
      $('ev-line-' + j).setAttribute('aria-selected', 'true');
    });
    // The same indicator can surface in more than one phase; it counts (and pays) once
    if (!STATE.flags['saw_' + id]) {
      STATE.flags['saw_' + id] = true;
      STATE.findings.push({ phase, id, text });
      Object.entries(FINDING_REWARD).forEach(([k, v]) => { STATE.scores[k] += v; });
      addNote(phase, `Finding: ${short}`);
      renderChoices(); // a finding can unlock an option
    }
  } else {
    el.classList.add('tagged', 'noise');
    el.setAttribute('aria-selected', 'true');
    STATE.falseLeads++;
    STATE.scores.time += FALSE_LEAD.time;
    advanceClock(FALSE_LEAD.minutes); // a false lead burns incident time, clock running or not
    addNote(phase, `False lead: ${short} (${FALSE_LEAD.time} TIME)`);
  }
  renderScoreTracker();
  updateTagCount();
}

function moveEvCursor(delta) {
  const idxs = [...document.querySelectorAll('.ev-line')].map(e => +e.dataset.i);
  if (!idxs.length) return;
  const pos = idxs.indexOf(STATE.evCursor);
  const next = idxs[pos < 0 ? 0 : Math.max(0, Math.min(idxs.length - 1, pos + delta))];
  document.querySelectorAll('.ev-line.cursor').forEach(e => e.classList.remove('cursor'));
  const el = $('ev-line-' + next);
  el.classList.add('cursor');
  el.scrollIntoView({ block: 'nearest' });
  $('ev-taggable').setAttribute('aria-activedescendant', el.id);
  STATE.evCursor = next;
}

$('action-body').addEventListener('click', (e) => {
  const line = e.target.closest('.ev-line');
  if (line) tagLine(+line.dataset.i);
});
$('action-body').addEventListener('keydown', (e) => {
  if (e.target.id !== 'ev-taggable') return;
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault(); e.stopPropagation();
    moveEvCursor(e.key === 'ArrowDown' ? 1 : -1);
  } else if ((e.key === 'Enter' || e.key === ' ') && !STATE.awaitingContinue) {
    e.preventDefault(); e.stopPropagation();
    if (STATE.evCursor < 0) moveEvCursor(0); else tagLine(STATE.evCursor);
  }
});

// Choices keep their shuffled order for the whole phase; an option unlocked
// mid-phase is appended rather than reshuffled, so letters don't move under you.
const CHOICE_KEYS = ['A', 'B', 'C', 'D', 'E'];
function renderChoices() {
  const container = $('choices-container');
  if (!container || !STATE.clockStarted) return;
  const phase = STATE.incident.phases[STATE.phaseIdx];
  const visible = phase.choices.map((c, i) => i).filter(i => !phase.choices[i].when || phase.choices[i].when(STATE.flags, STATE));
  const unlocked = [];
  if (!STATE.choiceOrder) { STATE.choiceOrder = shuffle(visible); STATE.unlockedChoices = new Set(); }
  else visible.forEach(i => {
    if (STATE.choiceOrder.includes(i)) return;
    STATE.choiceOrder.push(i); STATE.unlockedChoices.add(i); unlocked.push(i);
  });
  const order = STATE.choiceOrder.filter(i => visible.includes(i));
  container.innerHTML = order.map((i, d) => {
    const c = phase.choices[i];
    const isNew = STATE.unlockedChoices.has(i);
    return `<button class="choice-btn${isNew ? ' unlocked' : ''}" data-idx="${i}" onclick="selectChoice(${i})">
          <span class="choice-key">[${CHOICE_KEYS[d]}]</span>
          <span class="choice-label">${escapeHtml(resolve(c.label))}</span>
          <span class="choice-desc">${escapeHtml(resolve(c.desc))}</span>
          ${isNew ? `<span class="unlock-tag">◆ UNLOCKED BY YOUR FINDING</span>` : ''}
        </button>`;
  }).join('');
  if (unlocked.length) addNote(phase.name, 'New response option unlocked by your finding');
}

// ── DECISION CLOCK ─────────────────────────────────
// Opt-in per incident via `clock: { rate, par }` (game minutes per real second,
// and the default per-phase par in game minutes; a phase may set its own `par`).
// Each phase opens with the clock stopped: read, tag evidence, then start the clock
// to reveal the options. While it runs, the phase's `timeline` plays out —
// [{ at, when?, sev, text, sets?, score? }], `at` in minutes since the clock started.
// The clock also stops while the tab is hidden or a dialog is open.
try { if (localStorage.getItem('pumaresponse.clock') === 'turn') STATE.clockMode = 'turn'; } catch (e) {}

function clockActive() {
  return !!(STATE.incident && STATE.incident.clock) && STATE.clockMode === 'realtime';
}
function phasePar() {
  const phase = STATE.incident.phases[STATE.phaseIdx];
  return phase.par ?? STATE.incident.clock.par;
}
// ── INCIDENT WALL CLOCK ─────────────────────────────
// Every SIEM timestamp is wall-clock time on the incident's own timeline: the
// ticket is assigned at incident.assignedTime today, and time advances with the
// game (elapsed + this phase's clock). Past midnight a stamp carries the real date.
function hhmmToMin(t) {
  const m = /^(\d{1,2}):(\d{2})/.exec(t || '');
  return m ? +m[1] * 60 + +m[2] : null;
}
function wallStamp(minsSinceAssigned) {
  const t = (hhmmToMin(STATE.incident.assignedTime) ?? 0) + Math.floor(minsSinceAssigned);
  const day = Math.floor(t / 1440), m = ((t % 1440) + 1440) % 1440;
  const hhmm = `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
  if (day === 0) return hhmm;
  const d = new Date(); d.setDate(d.getDate() + day);
  return `${MONTHS[d.getMonth()]} ${d.getDate()} ${hhmm}`;
}
function clockStamp() {
  return wallStamp(STATE.elapsed + STATE.phaseClock);
}
function clockRunning() {
  return clockActive() && STATE.clockStarted && STATE.started && !STATE.awaitingContinue && !document.hidden
    && !$('menu-modal').classList.contains('visible') && !$('about-modal').classList.contains('visible')
    && !$('end-screen').classList.contains('visible') && $('help-overlay').hidden;
}

// Advance this phase's clock (live ticks, or minutes burned by a false lead) and fire due events
function advanceClock(minutes) {
  STATE.phaseClock += minutes;
  const phase = STATE.incident.phases[STATE.phaseIdx];
  (resolve(phase.timeline) || []).forEach((ev, i) => {
    if (STATE.fired.has(i) || ev.at > STATE.phaseClock || (ev.when && !ev.when(STATE.flags, STATE))) return;
    STATE.fired.add(i);
    Object.assign(STATE.flags, resolve(ev.sets) || {});
    Object.entries(ev.score || {}).forEach(([k, v]) => { STATE.scores[k] += v; });
    addSiemEntry(clockStamp(), ev.sev || 'crit', resolve(ev.text));
    STATE.clockLog.push({ phase: phase.name, text: resolve(ev.text) });
    renderScoreTracker();
  });
  updateClockUI();
}

function updateClockUI() {
  if (!STATE.incident || STATE.phaseIdx >= STATE.incident.phases.length) return; // finished: nothing live
  $('hdr-elapsed').textContent = formatElapsed(Math.floor(STATE.elapsed + STATE.phaseClock));
  const strip = $('live-strip');
  if (!strip) return;
  const phase = STATE.incident.phases[STATE.phaseIdx];
  const running = STATE.clockStarted && clockActive() && !STATE.awaitingContinue;
  const par = phasePar();
  strip.classList.toggle('running', running);
  strip.classList.toggle('over-par', running && STATE.phaseClock > par);
  const status = STATE.awaitingContinue ? 'CLOCK STOPPED — DECISION MADE'
    : running ? `CLOCK RUNNING — ${Math.floor(STATE.phaseClock)} MIN (PAR ${par})`
    : 'CLOCK STOPPED — READ THE BRIEFING';
  const live = STATE.awaitingContinue ? null : resolve(phase.live); // the outcome box says what happened
  strip.innerHTML = `<span class="ls-clock">${status}</span>${live ? `<span>${escapeHtml(live)}</span>` : ''}`;
}

function startClock() {
  if (STATE.clockStarted || STATE.awaitingContinue) return;
  STATE.clockStarted = true;
  const gate = $('start-clock-btn');
  if (gate) gate.remove();
  $('choices-title').hidden = false;
  renderChoices();
  if (clockActive()) addSiemEntry(clockStamp(), 'info', `${STATE.incident.phases[STATE.phaseIdx].name}: decision clock started`);
  updateClockUI();
  const first = document.querySelector('.choice-btn');
  if (first) first.focus({ preventScroll: true });
  $('choices-title').scrollIntoView({ block: 'start', behavior: 'smooth' });
}

let lastTick = performance.now();
setInterval(() => {
  const now = performance.now();
  const dt = (now - lastTick) / 1000;
  lastTick = now;
  if (clockRunning()) advanceClock(dt * STATE.incident.clock.rate);
}, 250);

function setClockMode(mode) {
  STATE.clockMode = mode;
  try { localStorage.setItem('pumaresponse.clock', mode); } catch (e) {}
  $('clock-realtime').setAttribute('aria-pressed', String(mode === 'realtime'));
  $('clock-turn').setAttribute('aria-pressed', String(mode === 'turn'));
  // Switching to turn-based mid-read shouldn't leave the options locked behind the gate
  if (mode === 'turn' && STATE.started && !STATE.clockStarted && $('start-clock-btn')) startClock();
  updateClockUI();
}

// ── RENDER PHASE ───────────────────────────────────
function renderPhase() {
  const phase = STATE.incident.phases[STATE.phaseIdx];
  const body = $('action-body');
  STATE.awaitingContinue = false; // before anything reads it while drawing the new phase

  // Update header
  $('phase-indicator').textContent = `PHASE: ${phase.name}`;
  const progressPct = Math.round((STATE.phaseIdx / PHASE_NAMES.length) * 100);
  $('phase-progress-fill').style.width = `${progressPct}%`;
  $('phase-progress-bar').setAttribute('aria-valuenow', progressPct);
  $('hdr-elapsed').textContent = formatElapsed(STATE.elapsed);

  // Consequences of earlier decisions that reach this phase — scored once, on entry
  const carried = (resolve(phase.carried) || []).map(c => ({ ...c, phase: phase.name }));
  carried.forEach(c => {
    Object.entries(c.score || {}).forEach(([k, v]) => { STATE.scores[k] += v; });
    STATE.carried.push(c);
  });
  const carriedHtml = carried.length ? `
    <div class="carried-box">
      <div class="carried-title">CARRIED FORWARD — CONSEQUENCES OF EARLIER DECISIONS</div>
      ${carried.map(c => {
        const pts = Object.entries(c.score || {}).filter(([, v]) => v)
          .map(([k, v]) => `<span class="${v > 0 ? 'pos' : 'neg'}">${k.toUpperCase()} ${v > 0 ? '+' : ''}${v}</span>`).join(' ');
        return `<div class="carried-item ${c.sev || 'bad'}">${escapeHtml(c.text)}${pts ? ` <span class="carried-score">${pts}</span>` : ''}</div>`;
      }).join('')}
    </div>` : '';

  // ── STORY ANCHOR ──
  // A phase begins no earlier than its story time, so the wall clock (SIEM stamps,
  // "time on incident") agrees with the narrative: `phase.at` (minutes since
  // assignment, value or function), or by default the phase's first authored
  // SIEM time. A player slower than the story keeps the later wall clock.
  const entries = resolve(phase.siemEntries);
  const authored = [];
  entries.forEach((e, i) => {
    let t = hhmmToMin(e.time);
    const prev = authored.slice().reverse().find(x => x != null);
    if (t != null && prev != null && t < prev - 720) t += 1440;
    authored.push(t);
  });
  const first = authored.find(x => x != null);
  const assigned = hhmmToMin(STATE.incident.assignedTime) ?? 0;
  const storyAt = phase.at != null ? resolve(phase.at)
    : first == null ? null : (((first - assigned) % 1440) + 1440) % 1440;
  if (storyAt != null && storyAt > STATE.elapsed) STATE.elapsed = storyAt;

  const evidence = resolve(phase.evidence);
  const evidenceHtml = renderEvidence(resolve(evidence.content));
  STATE.choiceOrder = null;
  STATE.phaseClock = 0;
  STATE.fired = new Set();
  STATE.clockStarted = !clockActive(); // clocked phases open stopped, behind the start button
  const gated = !STATE.clockStarted;

  body.innerHTML = `
    ${carriedHtml}
    <div class="narrative-box">
      <div class="narrator">SITUATION BRIEFING — ${escapeHtml(phase.name)}</div>
      ${escapeHtml(resolve(phase.narrative))}
    </div>
    <div class="evidence-box">
      <div class="ev-title">${escapeHtml(resolve(evidence.title))}${STATE.evLines ? '<span class="ev-hint" id="ev-hint" aria-live="polite"></span>' : ''}</div>
      ${evidenceHtml}
    </div>
    ${STATE.incident.clock ? '<div class="live-strip" id="live-strip" aria-live="off"></div>' : ''}
    ${gated ? `<button class="start-clock-btn" id="start-clock-btn" onclick="startClock()">▶ START CLOCK — SHOW RESPONSE OPTIONS
      <small>Take your time reading. Once the clock starts, the attacker keeps moving until you decide.</small></button>` : ''}
    <div class="section-title" id="choices-title" style="margin-top:12px;"${gated ? ' hidden' : ''}>SELECT YOUR RESPONSE</div>
    <div class="choices-container" id="choices-container" role="group" aria-label="Response choices"></div>
    <div id="outcome-area" aria-live="polite"></div>
  `;
  if (!gated) renderChoices();
  indexFindings();
  updateClockUI();
  body.scrollTop = 0; // new phase starts at the top, where carried consequences sit

  // Add SIEM entries for this phase
  // Authored entries keep their spacing but slide onto the incident's actual clock:
  // the phase's first entry lands on "now" (times wrapping past midnight unwrap first)
  const phaseStart = STATE.elapsed;
  entries.forEach((e, i) => {
    const stamp = authored[i] == null ? e.time : wallStamp(phaseStart + authored[i] - first);
    STATE.siemTimers.push(setTimeout(() => addSiemEntry(stamp, e.sev, resolve(e.text)), i * 400));
  });
  // Those events unfold while the player reads: the incident clock moves past them
  // (reading still costs no decision time), so everything logged next comes after
  const span = first == null ? 0 : Math.max(...authored.filter(x => x != null)) - first;
  STATE.elapsed += span;
  updateClockUI();

  renderScoreTracker();
  STATE.awaitingContinue = false;
}

// ── CHOICE HANDLING ────────────────────────────────
function selectChoice(idx) {
  if (STATE.awaitingContinue) return;
  STATE.awaitingContinue = true;

  const phase = STATE.incident.phases[STATE.phaseIdx];
  // Resolve every field against the flags as they stood when the choice was made
  const raw = phase.choices[idx];
  const choice = {
    key: raw.key,
    label: resolve(raw.label),
    quality: resolve(raw.quality),
    score: resolve(raw.score),
    outcome: resolve(raw.outcome),
  };
  Object.assign(STATE.flags, resolve(raw.sets) || {});

  // Apply scores
  Object.keys(choice.score).forEach(k => {
    STATE.scores[k] += choice.score[k];
  });

  // Time: minutes spent deciding (clock, or false leads when turn-based) plus the action itself.
  // Over par on a live clock costs Response Time: -1 per 2 minutes over, capped at -10.
  const clocked = clockActive();
  const deliberation = Math.floor(STATE.phaseClock);
  let parPenalty = 0;
  if (clocked) {
    const over = deliberation - phasePar();
    if (over > 0) parPenalty = -Math.min(10, Math.ceil(over / 2));
    STATE.scores.time += parPenalty;
    STATE.decisionMinutes += deliberation;
  }
  STATE.elapsed += deliberation + (clocked ? Math.max(5, 20 - choice.score.time) : Math.max(10, 30 - choice.score.time));
  STATE.phaseClock = 0;
  const clockLine = clocked
    ? `<div class="outcome-clock">DECIDED IN ${deliberation} MIN · PAR ${phasePar()}${parPenalty ? ` · <span class="neg">OVER PAR: TIME ${parPenalty}</span>` : ''}</div>`
    : '';

  STATE.choices.push({ phase: phase.name, choice: choice.key, quality: choice.quality });

  // Add note
  addNote(phase.name, `Action: ${choice.label} [${choice.quality.toUpperCase()}]`);

  // Replace choices with outcome
  const qualityClass = { good: 'good', partial: '', bad: 'bad' }[choice.quality];
  const titleClass = { good: 'good', partial: 'neutral', bad: 'bad' }[choice.quality];
  const titleText = { good: 'EFFECTIVE RESPONSE', partial: 'ACCEPTABLE — ROOM FOR IMPROVEMENT', bad: 'SUBOPTIMAL RESPONSE' }[choice.quality];

  const scoreLines = Object.entries(choice.score).map(([k, v]) => {
    if (v === 0) return '';
    return `<span class="${v > 0 ? 'pos' : 'neg'}">${k.toUpperCase()}: ${v > 0 ? '+' : ''}${v}</span>`;
  }).filter(Boolean).join('  ');

  // Remove choices section title, choices, and outcome-area — replace with outcome
  const taggable = $('ev-taggable');
  if (taggable) taggable.classList.add('locked');
  const choicesContainer = $('choices-container');
  const choicesTitle = choicesContainer.previousElementSibling; // "SELECT YOUR RESPONSE"
  const outcomeArea = $('outcome-area');
  if (choicesTitle && choicesTitle.classList.contains('section-title')) choicesTitle.remove();
  choicesContainer.remove();
  outcomeArea.innerHTML = `
    <div class="section-title" style="margin-top:12px;">YOUR ACTION: [${escapeHtml(choice.key)}] ${escapeHtml(choice.label)}</div>
    <div class="outcome-box ${qualityClass}">
      <div class="outcome-title ${titleClass}">${titleText}</div>
      <div class="outcome-text">${escapeHtml(choice.outcome)}</div>
      <div class="outcome-score">${scoreLines}</div>
      ${clockLine}
    </div>
    <button class="continue-btn" onclick="advancePhase()" id="continue-btn">
      ${STATE.phaseIdx < PHASE_NAMES.length - 1 ? 'PROCEED TO NEXT PHASE ▸' : 'COMPLETE INCIDENT ▸'}
    </button>
  `;

  // Add outcome SIEM entry
  const sevMap = { good: 'success', partial: 'warn', bad: 'crit' };
  addSiemEntry(wallStamp(STATE.elapsed), sevMap[choice.quality],
    `${phase.name}: ${titleText}`);

  renderScoreTracker();
  updateClockUI();

  // Scroll to outcome
  outcomeArea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── PHASE ADVANCEMENT ──────────────────────────────
function advancePhase() {
  STATE.phaseIdx++;
  if (STATE.phaseIdx >= PHASE_NAMES.length) {
    endGame();
  } else {
    renderPhase();
  }
}

// ── END GAME ───────────────────────────────────────
const GRADE_BANDS = { A: 85, B: 65, C: 45, D: 25 }; // % of the scenario's bestScore

// Best result per scenario, remembered in this browser only (a convenience —
// if storage is unavailable the game simply doesn't remember).
function loadBests() {
  try { return JSON.parse(localStorage.getItem('pumaresponse.best') || '{}') || {}; } catch (e) { return {}; }
}
function recordBest(id, grade, pct) {
  const bests = loadBests();
  const isNew = !bests[id] || pct > bests[id].pct;
  if (isNew) {
    bests[id] = { grade, pct };
    try { localStorage.setItem('pumaresponse.best', JSON.stringify(bests)); } catch (e) {}
  }
  return isNew;
}
function endGame() {
  $('game-screen').classList.remove('visible');

  const s = STATE.scores;
  const total = s.time + s.containment + s.evidence + s.thoroughness;
  // Graded against this scenario's best achievable score, so a grade means the same
  // thing in every scenario. With these bands: A needs the right calls AND the
  // evidence documented; the right calls alone land a B; random play lands D/F.
  const pct = Math.round((total / (STATE.incident.bestScore || 300)) * 100);

  let grade, gradeClass, titleText, titleClass, subtitle;
  if (pct >= GRADE_BANDS.A) {
    grade = 'A'; gradeClass = 'green'; titleText = 'INCIDENT RESOLVED'; titleClass = 'success';
    subtitle = 'Outstanding response. Your methodical approach minimized damage, preserved evidence, and set the client up for long-term improvement. The MSSP is proud to have you on the team.';
  } else if (pct >= GRADE_BANDS.B) {
    grade = 'B'; gradeClass = 'green'; titleText = 'INCIDENT RESOLVED'; titleClass = 'success';
    subtitle = 'Solid response overall. You contained the threat and recovered operations, though some opportunities for improvement were missed. Good work, analyst.';
  } else if (pct >= GRADE_BANDS.C) {
    grade = 'C'; gradeClass = 'amber'; titleText = 'INCIDENT CONTAINED'; titleClass = 'partial';
    subtitle = 'The incident was eventually contained, but delays and missed steps increased the blast radius. Review your approach and consider what could be done differently next time.';
  } else if (pct >= GRADE_BANDS.D) {
    grade = 'D'; gradeClass = 'amber'; titleText = 'INCIDENT CONTAINED — BARELY'; titleClass = 'partial';
    subtitle = 'Significant gaps in your response led to unnecessary damage, lost evidence, and client dissatisfaction. A post-mortem on your own process is recommended.';
  } else {
    grade = 'F'; gradeClass = 'red'; titleText = 'RESPONSE FAILURE'; titleClass = 'failure';
    subtitle = 'Critical errors throughout the response resulted in maximum damage, destroyed evidence, and a very unhappy client. Your MSSP manager would like a word.';
  }

  // Shareable, spoiler-free summary: one square per phase, no choice text
  const squares = STATE.choices.map(c => ({ good: '🟩', partial: '🟨', bad: '🟥' }[c.quality])).join('');
  const nFindings = Object.keys(STATE.findingText).length;
  STATE.resultText = [
    `PumaResponse — ${STATE.incident.title.split('—')[0].trim()} (${STATE.incident.ticketId})`,
    `Grade ${grade} · ${pct}% of best · ${STATE.incident.clock && STATE.clockMode === 'realtime' ? 'real-time' : 'turn-based'}`,
    squares,
    nFindings ? `Findings ${STATE.findings.length}/${nFindings} · false leads ${STATE.falseLeads}` : '',
    'https://pumaresponse.greykit.com/',
  ].filter(Boolean).join('\n');

  const prevBest = loadBests()[STATE.incident.id];
  const newBest = recordBest(STATE.incident.id, grade, pct);

  $('end-title').textContent = titleText;
  $('end-title').className = `end-title ${titleClass}`;
  $('end-subtitle').textContent = subtitle;

  const goodCount = STATE.choices.filter(c => c.quality === 'good').length;
  const partialCount = STATE.choices.filter(c => c.quality === 'partial').length;
  const badCount = STATE.choices.filter(c => c.quality === 'bad').length;

  const scoreColor = v => v >= 20 ? 'sc-val' : v >= 0 ? 'sc-val warn' : 'sc-val crit';

  $('end-scorecard').innerHTML = `
    <div class="scorecard-title">PERFORMANCE SCORECARD</div>
    <div class="sc-row"><span>Incident</span><span class="sc-val">${escapeHtml(STATE.incident.title)}</span></div>
    <div class="sc-row"><span>Client</span><span class="sc-val">${escapeHtml(STATE.incident.client)}</span></div>
    <div class="sc-row"><span>Total Elapsed</span><span class="sc-val">${formatElapsed(STATE.elapsed)}</span></div>
    ${STATE.incident.clock ? `
    <div class="sc-row"><span>Decision Clock</span><span class="sc-val">${STATE.clockMode === 'realtime' ? `Real-time · ${STATE.decisionMinutes} min deciding` : 'Turn-based'}</span></div>` : ''}
    ${Object.keys(STATE.findingText).length ? `
    <div class="sc-row"><span>Findings Tagged</span><span class="sc-val">${STATE.findings.length} of ${Object.keys(STATE.findingText).length}</span></div>
    <div class="sc-row"><span>False Leads</span><span class="sc-val">${STATE.falseLeads}</span></div>` : ''}
    ${(resolve(STATE.incident.debrief) || []).map(([k, v]) => `<div class="sc-row"><span>${escapeHtml(k)}</span><span class="sc-val">${escapeHtml(v)}</span></div>`).join('')}
    <div class="sc-section">SCORING BREAKDOWN</div>
    <div class="sc-row"><span>Response Time</span><span class="${scoreColor(s.time)}">${s.time > 0 ? '+' : ''}${s.time}</span></div>
    <div class="sc-row"><span>Containment</span><span class="${scoreColor(s.containment)}">${s.containment > 0 ? '+' : ''}${s.containment}</span></div>
    <div class="sc-row"><span>Evidence Preservation</span><span class="${scoreColor(s.evidence)}">${s.evidence > 0 ? '+' : ''}${s.evidence}</span></div>
    <div class="sc-row"><span>Thoroughness</span><span class="${scoreColor(s.thoroughness)}">${s.thoroughness > 0 ? '+' : ''}${s.thoroughness}</span></div>
    <div class="sc-section">DECISION QUALITY</div>
    <div class="sc-row"><span>Optimal Decisions</span><span class="sc-val" style="color:var(--green)">${goodCount}/6</span></div>
    <div class="sc-row"><span>Acceptable Decisions</span><span class="sc-val" style="color:var(--amber)">${partialCount}/6</span></div>
    <div class="sc-row"><span>Poor Decisions</span><span class="sc-val" style="color:var(--red)">${badCount}/6</span></div>
    <div class="sc-total">
      <div class="sc-grade ${gradeClass}">${grade}</div>
      <div>
        <div class="sc-grade-label">OVERALL GRADE</div>
        <div style="font-size:12px;color:var(--green-dim);">${total} points · ${pct}% of best possible</div>
        <div style="font-size:11px;color:var(--amber);">${newBest ? (prevBest ? `NEW PERSONAL BEST — was ${prevBest.grade} (${prevBest.pct}%)` : 'FIRST CLEAR — PERSONAL BEST RECORDED') : `PERSONAL BEST: ${prevBest.grade} (${prevBest.pct}%)`}</div>
      </div>
    </div>
  `;

  // Debrief
  const debrief = $('end-debrief');
  const phases = STATE.choices.map((c, i) => {
    const icon = { good: '✓', partial: '~', bad: '✗' }[c.quality];
    const color = { good: 'var(--green)', partial: 'var(--amber)', bad: 'var(--red)' }[c.quality];
    return `<span style="color:${color}">${icon} ${c.phase}</span>`;
  }).join(' → ');
  const consequences = STATE.carried.length ? `
    <div class="end-debrief-header" style="margin-top:12px;">CONSEQUENCES THAT CARRIED FORWARD</div>
    <div class="end-carried">${STATE.carried.map(c => `<div class="carried-item ${c.sev || 'bad'}"><span class="note-phase">[${escapeHtml(c.phase)}]</span> ${escapeHtml(c.text)}</div>`).join('')}</div>` : '';
  const clockHtml = STATE.clockLog.length ? `
    <div class="end-debrief-header" style="margin-top:12px;">WHILE THE CLOCK RAN</div>
    <div class="end-carried">${STATE.clockLog.map(c => `<div class="carried-item bad"><span class="note-phase">[${escapeHtml(c.phase)}]</span> ${escapeHtml(c.text)}</div>`).join('')}</div>` : '';
  // Every finding the player was shown: tagged first, then missed, each with its
  // ATT&CK technique where the finding is adversary behavior (incident.attack)
  const attack = STATE.incident.attack || {};
  const findingRow = ([id, t]) => {
    const tech = attack[id];
    const m = tech && tech.match(/^(T\d{4})(?:\.(\d{3}))?\s+(.*)$/);
    const tag = m ? ` <a class="attack-tag" href="https://attack.mitre.org/techniques/${m[1]}${m[2] ? '/' + m[2] : ''}/" target="_blank" rel="noopener">${escapeHtml(m[1] + (m[2] ? '.' + m[2] : ''))} ${escapeHtml(m[3])}</a>` : '';
    return `<div class="carried-item ${STATE.flags['saw_' + id] ? 'good' : 'info'}">${escapeHtml(t)}${tag}</div>`;
  };
  const shown = Object.entries(STATE.findingText);
  const tagged = shown.filter(([id]) => STATE.flags['saw_' + id]);
  const missed = shown.filter(([id]) => !STATE.flags['saw_' + id]);
  const missedHtml = shown.length ? `
    ${tagged.length ? `<div class="end-debrief-header" style="margin-top:12px;">EVIDENCE YOU TAGGED</div>
    <div class="end-carried">${tagged.map(findingRow).join('')}</div>` : ''}
    ${missed.length ? `<div class="end-debrief-header" style="margin-top:12px;">EVIDENCE YOU DIDN'T TAG</div>
    <div class="end-carried">${missed.map(findingRow).join('')}</div>` : ''}` : '';
  debrief.innerHTML = `<div class="end-debrief-header">PHASE DECISIONS</div>${phases}${clockHtml}${consequences}${missedHtml}`;

  $('end-screen').classList.add('visible');
  // Focus management: move focus to the end screen for accessibility
  // Focus the first action without scrolling to it: the player should land on their grade
  $('replay-incident-btn').focus({ preventScroll: true });
  $('end-screen').scrollTop = 0;
}

// ── KEYBOARD CONTROLS ──────────────────────────────
document.addEventListener('keydown', (e) => {
  if (!STATE.started) return;
  if ($('menu-modal').classList.contains('visible') || $('about-modal').classList.contains('visible')) return;
  if (!$('help-overlay').hidden) return; // the tour has its own keys

  const key = e.key.toUpperCase();
  // A-E and 1-5 select by display position (nth button on screen)
  if (CHOICE_KEYS.includes(key) && !STATE.awaitingContinue) {
    const displayIdx = CHOICE_KEYS.indexOf(key);
    const btns = document.querySelectorAll('.choice-btn');
    if (displayIdx < btns.length) {
      selectChoice(parseInt(btns[displayIdx].dataset.idx));
    }
  }
  if ((key === 'ENTER' || key === ' ') && !STATE.awaitingContinue && $('start-clock-btn')
      && !e.target.closest('button, #ev-taggable')) {
    e.preventDefault();
    startClock();
    return;
  }
  if ((key === 'ENTER' || key === ' ') && STATE.awaitingContinue) {
    const btn = $('continue-btn');
    if (btn) {
      e.preventDefault();
      advancePhase();
    }
  }
  if (key >= '1' && key <= String(CHOICE_KEYS.length) && key.length === 1 && !STATE.awaitingContinue) {
    const displayIdx = parseInt(key) - 1;
    const btns = document.querySelectorAll('.choice-btn');
    if (displayIdx < btns.length) {
      selectChoice(parseInt(btns[displayIdx].dataset.idx));
    }
  }
});

// ── START GAME ─────────────────────────────────────
// Random pick from incidents not yet played this session; once all have been
// seen the pool refills, minus the one just played so it never repeats back to back.
function pickIncident() {
  let pool = INCIDENTS.filter(i => !STATE.played.has(i.id));
  if (!pool.length) {
    STATE.played.clear();
    pool = INCIDENTS.filter(i => i !== STATE.incident);
  }
  return pool[Math.floor(Math.random() * pool.length)];
}

// An incident is "in progress" once it has started and the end screen isn't up
function incidentInProgress() {
  return STATE.started && !$('end-screen').classList.contains('visible');
}

function startGame(incident) {
  STATE.incident = incident || pickIncident();
  STATE.played.add(STATE.incident.id);
  STATE.phaseIdx = 0;
  STATE.scores = { time: 0, containment: 0, evidence: 0, thoroughness: 0 };
  STATE.elapsed = 0;
  STATE.notes = [];
  STATE.choices = [];
  STATE.flags = { ...(STATE.incident.initialFlags || {}) };
  STATE.carried = [];
  STATE.findings = [];
  STATE.findingText = {};
  STATE.falseLeads = 0;
  STATE.clockLog = [];
  STATE.decisionMinutes = 0;
  STATE.phaseClock = 0;
  STATE.started = true;

  // Update header
  $('hdr-ticket').textContent = STATE.incident.ticketId;
  const sevSpan = $('hdr-severity');
  sevSpan.textContent = STATE.incident.severity;
  sevSpan.className = STATE.incident.sevClass === 'high' ? 'crit' : '';

  // Clear anything left over from a previous incident
  STATE.siemTimers.forEach(clearTimeout);
  STATE.siemTimers = [];
  $('siem-feed-col').innerHTML = '';
  renderNotes();
  $('main').classList.remove('siem-expanded');
  const actionTab = document.querySelector('#mobile-tabs button[data-panel="action"]');
  if (actionTab) actionTab.click();
  $('end-screen').classList.remove('visible');

  // Show game screen
  $('game-screen').classList.add('visible');

  // Render
  renderBrief();
  renderPhase();

  // Initial SIEM entries
  addSiemEntry('--:--', 'info', 'PumaResponse MSSP Platform initialized');
  addSiemEntry('--:--', 'info', `Analyst on shift — incident queue: 1`);
}

// ── SIEM PANEL EXPAND/COLLAPSE ─────────────────────
$('right-panel').addEventListener('click', (e) => {
  e.stopPropagation();
  $('main').classList.toggle('siem-expanded');
});

$('siem-overlay').addEventListener('click', (e) => {
  e.stopPropagation();
  $('main').classList.remove('siem-expanded');
});

// ── ABOUT MODAL (with focus trap + Escape key) ───
let previousFocus = null;
function openAboutModal() {
  previousFocus = document.activeElement;
  $('about-modal').classList.add('visible');
  $('about-close-btn').focus();
}
function closeAboutModal() {
  $('about-modal').classList.remove('visible');
  if (previousFocus) previousFocus.focus();
}
$('about-btn').addEventListener('click', (e) => {
  e.stopPropagation();
  openAboutModal();
});
$('about-close-btn').addEventListener('click', closeAboutModal);
$('about-modal').addEventListener('click', (e) => {
  if (e.target === $('about-modal')) closeAboutModal();
});
// Focus trap and Escape key for modal
$('about-modal').addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { closeAboutModal(); return; }
  if (e.key === 'Tab') {
    const focusable = $('about-modal-inner').querySelectorAll('button, [href], [tabindex]:not([tabindex="-1"])');
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
});

// ── HELP TOUR ─────────────────────────────────────
// Dims the game screen and lights up one area at a time, with a callout
// pointing at it. Steps whose area isn't on screen right now are skipped. On
// phones the tour switches to the panel it is describing. The clock is stopped
// while the tour is open (clockRunning), and game keys are ignored.
const HELP_STEPS = [
  { el: () => $('header'), title: 'INCIDENT HEADER',
    body: 'The ticket, its severity, and the time elapsed on the incident — the wall clock, which moves with the story as well as with your decisions. The phase on the right and the bar underneath show how far through the six phases you are.' },
  { el: () => document.querySelector('.incident-meta'), panel: 'brief', title: 'INCIDENT BRIEF',
    body: 'Who the client is, how severe this is, and when it was handed to you. The summary below it is what the SOC knew at handoff.' },
  { el: () => document.querySelector('.ioc-list'), panel: 'brief', title: 'INDICATORS OF COMPROMISE',
    body: 'What was known at handoff: hashes, IPs, domains, accounts. They are where the investigation starts, not the whole story — each phase\'s evidence turns up more.' },
  { el: () => $('score-tracker'), panel: 'brief', title: 'PERFORMANCE METRICS',
    body: 'Your running score in four dimensions: response time, containment, evidence preservation and thoroughness. Decisions, tagged findings, false leads, time over par and consequences of earlier choices all move them. Your grade is the total as a percentage of the best possible for this incident.' },
  { el: () => document.querySelector('#action-body .carried-box'), panel: 'action', title: 'CARRIED FORWARD',
    body: 'Consequences of your earlier decisions that caught up with you in this phase, with the points each one cost or earned.' },
  { el: () => document.querySelector('#action-body .narrative-box'), panel: 'action', title: 'SITUATION BRIEFING',
    body: 'What has happened and what this phase asks of you. It is written for the path you are on, so it changes with the choices you made earlier.' },
  { el: () => document.querySelector('#action-body .evidence-box'), panel: 'action', title: 'EVIDENCE',
    body: 'Logs and artefacts for this phase. Click a line, or use ↑ ↓ and Enter, to tag it as a finding. A real finding earns evidence points, can unlock a better response option, and strengthens your report; tagging noise is a false lead that costs time. Colour shows what a token is — severity words, IP addresses — never whether it matters.' },
  { el: () => STATE.incident && STATE.incident.clock ? ($('start-clock-btn') || $('live-strip')) : null, panel: 'action', title: 'DECISION CLOCK',
    body: () => STATE.clockMode === 'turn'
      ? 'You are playing turn-based, so there is no clock: take as long as you like. Real-time mode, in the ↺ menu, has the attacker keep moving while you decide.'
      : 'Reading is free: each phase opens with the clock stopped. Starting it shows your response options, and from then on the attacker keeps moving — this strip shows what is getting worse. Deciding over par costs response time. Turn-based mode, in the ↺ menu, has no clock.' },
  { el: () => { const c = $('choices-container'); if (c && c.children.length) return c; const o = $('outcome-area'); return o && o.children.length ? o : null; },
    panel: 'action', title: 'RESPONSE OPTIONS',
    body: () => STATE.awaitingContinue
      ? 'The outcome of your decision: what happened, and what it scored. Proceed when you are ready — the consequences may follow you into later phases.'
      : 'Three options each phase, sometimes a fourth unlocked by a finding you tagged. Choose with A–D, 1–4, or a click. There is no undo.' },
  { el: () => $('siem-feed-col'), panel: 'siem', title: 'SIEM FEED',
    body: 'Events as they happen, stamped on the incident\'s clock: each phase\'s alerts, what the attacker does while your clock runs, and the result of every decision. Click the panel to widen it.' },
  { el: () => $('notes-col'), panel: 'siem', title: 'ANALYST NOTES',
    body: 'Your running log of findings, false leads and actions. Hover a note to remove it. That only tidies the log: a finding stays tagged and scored.' },
  { el: () => $('menu-btn'), title: 'INCIDENT MENU',
    body: 'Replay this incident, start another or choose a scenario, switch between real-time and turn-based, or delete all game data. The clock stops while it is open.' },
  { el: () => $('help-btn'), title: 'HELP',
    body: 'Open this tour whenever you like; the clock is stopped while it is open. ← and → step through it, Esc leaves.' },
];
let helpSteps = [], helpIdx = 0, helpReturnFocus = null, helpTab = null;

function helpMobile() { return getComputedStyle($('mobile-tabs')).display !== 'none'; }
function helpShowPanel(panel) {
  if (!panel || !helpMobile()) return;
  const btn = document.querySelector(`#mobile-tabs button[data-panel="${panel}"]`);
  if (btn && !btn.classList.contains('active')) btn.click();
}
// The part of an element actually on screen: clipped by every scrolling or clipping ancestor
function helpRect(el) {
  const r = el.getBoundingClientRect();
  let { top, left, right, bottom } = r;
  for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
    const cs = getComputedStyle(p);
    if (!/(auto|scroll|hidden)/.test(cs.overflowX + cs.overflowY)) continue;
    const pr = p.getBoundingClientRect();
    top = Math.max(top, pr.top); bottom = Math.min(bottom, pr.bottom);
    left = Math.max(left, pr.left); right = Math.min(right, pr.right);
  }
  const pad = 4;
  top = Math.max(top, 0) - pad; left = Math.max(left, 0) - pad;
  right = Math.min(right, innerWidth) + pad; bottom = Math.min(bottom, innerHeight) + pad;
  return { top, left, right, bottom, width: right - left, height: bottom - top };
}
function setSpot(r) {
  Object.assign($('help-spot').style, { top: r.top + 'px', left: r.left + 'px', width: r.width + 'px', height: r.height + 'px' });
}
// Put the callout beside the target, never over it if any side has room (narrowing
// it to fit beside a large area), with its arrow aimed at the target's centre
const HELP_POP_W = 340, HELP_POP_MIN_W = 240;
function placeHelpPop(r) {
  const pop = $('help-pop'), arrow = $('help-arrow');
  const vw = innerWidth, vh = innerHeight, gap = 14, m = 8;
  const room = { right: vw - r.right - gap - m, left: r.left - gap - m, bottom: vh - r.bottom - gap - m, top: r.top - gap - m };
  let side = null;
  for (const s of ['right', 'left', 'bottom', 'top']) {
    if (s === 'right' || s === 'left') {
      const w = Math.min(HELP_POP_W, room[s]);
      if (w < HELP_POP_MIN_W) continue;
      pop.style.width = w + 'px';
      if (pop.offsetHeight <= vh - 2 * m) { side = s; break; }
    } else {
      pop.style.width = '';
      if (pop.offsetHeight <= room[s]) { side = s; break; }
    }
  }
  if (!side) { // nothing fits cleanly: the side with the most room, overlapping
    pop.style.width = '';
    side = Object.keys(room).sort((a, b) => room[b] - room[a])[0];
  }
  const pw = pop.offsetWidth, ph = pop.offsetHeight;
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
  let top, left;
  if (side === 'right' || side === 'left') {
    left = side === 'right' ? r.right + gap : r.left - gap - pw;
    top = clamp(cy - ph / 2, m, vh - ph - m);
    arrow.style.top = clamp(cy - top - 6, 12, ph - 24) + 'px'; arrow.style.left = side === 'right' ? '-7px' : '';
  } else {
    top = side === 'bottom' ? r.bottom + gap : r.top - gap - ph;
    left = clamp(cx - pw / 2, m, vw - pw - m);
    arrow.style.left = clamp(cx - left - 6, 12, pw - 24) + 'px'; arrow.style.top = side === 'bottom' ? '-7px' : '';
  }
  pop.style.left = clamp(left, m, vw - pw - m) + 'px';
  pop.style.top = clamp(top, m, vh - ph - m) + 'px';
  pop.dataset.side = side;
}
function showHelpStep(i) {
  helpIdx = i;
  const step = helpSteps[i];
  helpShowPanel(step.panel);
  const el = step.el();
  if (el) el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  $('help-count').textContent = `HELP · ${i + 1} OF ${helpSteps.length}`;
  $('help-title').textContent = step.title;
  $('help-body').textContent = resolve(step.body);
  $('help-prev').disabled = i === 0;
  $('help-next').textContent = i === helpSteps.length - 1 ? 'DONE' : 'NEXT ▸';
  const r = helpRect(el);
  setSpot(r);
  placeHelpPop(r);
}
function openHelp() {
  if (!STATE.started || !$('game-screen').classList.contains('visible') || $('end-screen').classList.contains('visible')) return;
  // Only the steps whose area exists right now (no carried box, no options yet, ...)
  helpSteps = HELP_STEPS.filter(s => s.el());
  if (!helpSteps.length) return;
  helpReturnFocus = document.activeElement;
  helpTab = helpMobile() ? (document.querySelector('#mobile-tabs button.active') || {}).dataset?.panel : null;
  $('main').classList.remove('siem-expanded');
  const overlay = $('help-overlay'), spot = $('help-spot');
  overlay.hidden = false;
  // Dim first: the spotlight starts as a point at the first area's centre, then opens onto it
  helpShowPanel(helpSteps[0].panel);
  const r = helpRect(helpSteps[0].el());
  spot.classList.add('instant');
  setSpot({ top: r.top + r.height / 2, left: r.left + r.width / 2, width: 0, height: 0 });
  $('help-pop').classList.add('hidden');
  void spot.offsetWidth;
  spot.classList.remove('instant');
  overlay.classList.add('open');
  setTimeout(() => {
    if (overlay.hidden) return;
    showHelpStep(0);
    $('help-pop').classList.remove('hidden');
    $('help-next').focus({ preventScroll: true });
  }, 220);
}
function closeHelp() {
  const overlay = $('help-overlay');
  if (overlay.hidden) return;
  overlay.classList.remove('open');
  overlay.hidden = true;
  if (helpTab) helpShowPanel(helpTab);
  lastTick = performance.now(); // the tour's time is not decision time
  if (helpReturnFocus && document.contains(helpReturnFocus)) helpReturnFocus.focus({ preventScroll: true });
}
function helpStep(delta) {
  const i = helpIdx + delta;
  if (i < 0) return;
  if (i >= helpSteps.length) { closeHelp(); return; }
  showHelpStep(i);
}
$('help-btn').addEventListener('click', (e) => { e.stopPropagation(); openHelp(); });
$('help-prev').addEventListener('click', () => helpStep(-1));
$('help-next').addEventListener('click', () => helpStep(1));
$('help-exit').addEventListener('click', closeHelp);
$('help-overlay').addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { e.preventDefault(); closeHelp(); }
  else if (e.key === 'ArrowRight') { e.preventDefault(); helpStep(1); }
  else if (e.key === 'ArrowLeft') { e.preventDefault(); helpStep(-1); }
  else if (e.key === 'Tab') {
    const f = [...$('help-pop').querySelectorAll('button')].filter(b => !b.disabled);
    const i = f.indexOf(document.activeElement);
    e.preventDefault();
    f[(i + (e.shiftKey ? -1 : 1) + f.length) % f.length].focus();
  }
});
window.addEventListener('resize', () => { if (!$('help-overlay').hidden) showHelpStep(helpIdx); });

// ── MOBILE TAB SWITCHING ─────────────────────────
document.querySelectorAll('#mobile-tabs button').forEach(btn => {
  btn.addEventListener('click', () => {
    const panel = btn.dataset.panel;
    // Update tab active state
    document.querySelectorAll('#mobile-tabs button').forEach(b => {
      b.classList.remove('active');
      b.setAttribute('aria-pressed', 'false');
    });
    btn.classList.add('active');
    btn.setAttribute('aria-pressed', 'true');
    // Toggle panel visibility
    const panels = { action: 'action-panel', brief: 'left-panel', siem: 'right-panel' };
    Object.values(panels).forEach(id => {
      $(id).classList.remove('mobile-visible', 'mobile-hidden');
    });
    $(panels[panel]).classList.add('mobile-visible');
    Object.entries(panels).forEach(([key, id]) => {
      if (key !== panel) $(id).classList.add('mobile-hidden');
    });
  });
});

// ── INCIDENT MENU / RESTART ─────────────────────
// Restarting never reloads the page, so the boot sequence only plays once.
let menuReturnFocus = null;
function openMenu() {
  menuReturnFocus = document.activeElement;
  const inc = STATE.incident;
  $('menu-warning').textContent = incidentInProgress()
    ? `${inc.ticketId} is still open (phase ${STATE.phaseIdx + 1} of ${PHASE_NAMES.length}). Starting another incident abandons it — progress is lost.`
    : '';
  // Before the first incident there is nothing to replay or go back to
  $('menu-replay').hidden = !inc;
  $('menu-close-btn').hidden = !inc;
  if (inc) $('menu-replay').textContent = `↺ REPLAY ${inc.ticketId}`;
  disarmReset();
  const bests = loadBests();
  $('scenario-list').innerHTML = INCIDENTS.map((i, idx) => `
    <button class="scenario-row${i === inc ? ' current' : ''}" data-idx="${idx}">
      <span class="sr-title">${escapeHtml(i.title)}</span>
      <span class="sr-sev${i.severity === 'CRITICAL' ? ' crit' : ''}">${escapeHtml(i.severity)}</span>
      <span class="sr-client">${escapeHtml(i.client)}</span>
      <span class="sr-played">${[i === inc ? 'CURRENT' : '', bests[i.id] ? `BEST ${bests[i.id].grade} · ${bests[i.id].pct}%` : STATE.played.has(i.id) ? 'PLAYED' : ''].filter(Boolean).join(' · ')}</span>
    </button>`).join('');
  $('clock-realtime').setAttribute('aria-pressed', String(STATE.clockMode === 'realtime'));
  $('clock-turn').setAttribute('aria-pressed', String(STATE.clockMode === 'turn'));
  $('menu-modal').classList.add('visible');
  // With nothing loaded, focus the dialog rather than a button: the key that dismissed
  // the boot screen would otherwise land on it and start an incident
  (inc ? $('menu-close-btn') : $('menu-modal-inner')).focus({ preventScroll: true });
  $('menu-modal-inner').scrollTop = 0; // on phones the list scrolls; keep the warning in view
}
function closeMenu() {
  if (!STATE.incident) return; // nothing behind the menu yet: pick an incident
  $('menu-modal').classList.remove('visible');
  disarmReset();
  if (menuReturnFocus && document.contains(menuReturnFocus)) menuReturnFocus.focus();
}

// ── DELETE GAME DATA ───────────────────────────────
// Everything this game keeps in the browser (personal bests, clock setting) is
// under 'pumaresponse.'. Deleting takes two presses: the first arms the button
// for a few seconds. An incident in progress is abandoned and the menu starts fresh.
let resetTimer = null;
function disarmReset() {
  clearTimeout(resetTimer);
  $('menu-reset').classList.remove('armed');
  $('menu-reset').textContent = 'DELETE ALL GAME DATA';
  $('menu-reset-note').textContent = '';
}
function resetAllData() {
  for (const store of [localStorage, sessionStorage]) {
    try { Object.keys(store).filter(k => k.startsWith('pumaresponse.')).forEach(k => store.removeItem(k)); } catch (e) {}
  }
  STATE.siemTimers.forEach(clearTimeout);
  STATE.siemTimers = [];
  STATE.played.clear();
  STATE.clockMode = 'realtime';
  STATE.started = false;
  STATE.incident = null;
  $('game-screen').classList.remove('visible');
  $('end-screen').classList.remove('visible');
  openMenu();
  $('menu-warning').textContent = 'All game data deleted from this browser: personal bests and settings.';
}
$('menu-reset').addEventListener('click', () => {
  const btn = $('menu-reset');
  if (!btn.classList.contains('armed')) {
    btn.classList.add('armed');
    btn.textContent = 'PRESS AGAIN TO DELETE';
    $('menu-reset-note').textContent = 'This deletes your personal bests and clock setting, and abandons any incident in progress. It can\'t be undone.';
    clearTimeout(resetTimer);
    resetTimer = setTimeout(disarmReset, 6000);
    return;
  }
  resetAllData();
});
function restartWith(incident) {
  $('menu-modal').classList.remove('visible');
  startGame(incident);
  const first = document.querySelector('.choice-btn');
  if (first) first.focus();
}

$('menu-btn').addEventListener('click', (e) => { e.stopPropagation(); openMenu(); });
$('menu-close-btn').addEventListener('click', closeMenu);
$('menu-replay').addEventListener('click', () => restartWith(STATE.incident));
$('menu-random').addEventListener('click', () => restartWith());
$('clock-realtime').addEventListener('click', () => setClockMode('realtime'));
$('clock-turn').addEventListener('click', () => setClockMode('turn'));
$('scenario-list').addEventListener('click', (e) => {
  const row = e.target.closest('.scenario-row');
  if (row) restartWith(INCIDENTS[+row.dataset.idx]);
});
$('menu-modal').addEventListener('click', (e) => {
  if (e.target === $('menu-modal')) closeMenu();
});
$('menu-modal').addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { closeMenu(); return; }
  if (e.key === 'Tab') {
    const focusable = $('menu-modal-inner').querySelectorAll('button:not([hidden])');
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
});

$('replay-incident-btn').addEventListener('click', () => restartWith(STATE.incident));
$('new-incident-btn').addEventListener('click', () => restartWith());
$('choose-incident-btn').addEventListener('click', openMenu);
$('copy-result-btn').addEventListener('click', async () => {
  const btn = $('copy-result-btn');
  const text = STATE.resultText || '';
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch (e) {
    // Fallback for contexts without the async clipboard API
    const ta = document.createElement('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { ok = document.execCommand('copy'); } catch (e2) {}
    ta.remove();
  }
  btn.textContent = ok ? 'COPIED ✓' : 'COPY FAILED';
  setTimeout(() => { btn.textContent = 'COPY RESULT'; }, 2000);
});

// Console easter egg (guarded against duplicate execution)
if (!window.__pumaConsoleLogged) {
  window.__pumaConsoleLogged = true;
  console.log('%c╔══════════════════════════════════════════╗', 'color: #00ff41');
  console.log('%c║  PUMARESPONSE — INCIDENT RESPONSE SIM   ║', 'color: #00ff41');
  console.log('%c║  if you\'re reading this, good instincts. ║', 'color: #00ff41');
  console.log('%c║  check the SIEM logs. always check logs. ║', 'color: #00ff41');
  console.log('%c╚══════════════════════════════════════════╝', 'color: #00ff41');
}
