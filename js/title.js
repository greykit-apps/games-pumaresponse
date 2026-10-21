// ═══════════════════════════════════════════════════
// TITLE — the terminal (games-meta STANDARD.md §16)
// ═══════════════════════════════════════════════════
// Canon's boot and the hold (§14), then the tube comes on: the logo types
// itself in and the main menu prints as a terminal pane, over the game
// screen set on the desk as a monitor, an incident being worked in it on
// autopilot (the backdrop, below). It replaces the old boot and its "press
// any key"; the ↺ menu's scenario list is Choose incident. Loaded after
// game.js and the scenarios, and after js/gk-title.js, gk-intro.js and
// gk-terminal.js, the shared code from games-meta's canon/.

const TITLE_LOGO = [
  ' ____  _   _ __  __    _    ____  _____ ____  ____   ___  _   _ ____  _____',
  '|  _ \\| | | |  \\/  |  / \\  |  _ \\| ____/ ___||  _ \\ / _ \\| \\ | / ___|| ____|',
  '| |_) | | | | |\\/| | / _ \\ | |_) |  _| \\___ \\| |_) | | | |  \\| \\___ \\|  _|',
  '|  __/| |_| | |  | |/ ___ \\|  _ <| |___ ___) |  __/| |_| | |\\  |___) | |___',
  '|_|    \\___/|_|  |_/_/   \\_\\_| \\_\\_____|____/|_|    \\___/|_| \\_|____/|_____|',
];
const TITLE_SUB = 'MANAGED SECURITY SERVICES  //  INCIDENT RESPONSE PLATFORM v1.0.0';

let introDone = false, titleSwitches = null;

// ── SOUND ──────────────────────────────────────────
// The title brought the game its first sounds (the boot, the terminal's keys,
// the tube coming on), and with them a Sound switch: on unless switched off,
// kept under pumaresponse.sound. M switches it anywhere.
const SOUND_KEY = 'pumaresponse.sound';
let soundOn = (() => { try { return localStorage.getItem(SOUND_KEY) !== '0'; } catch (e) { return true; } })();
let audioCtx = null;
// The AudioContext, made if need be but not woken: the intro's continue press is what lets it play
function titleAudio() {
  if (!audioCtx) try { audioCtx = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) { return null; }
  return audioCtx;
}
function titleSfx(fn) {
  if (!soundOn) return null;
  const ac = titleAudio();
  if (ac) try { return fn(ac, ac.destination); } catch (e) { /* audio is a nicety, never a failure */ }
  return null;
}
function setSound(on) {
  soundOn = !!on;
  try { localStorage.setItem(SOUND_KEY, soundOn ? '1' : '0'); } catch (e) {}
  if (titleSwitches) titleSwitches.refresh();
  if ($('settings-modal').classList.contains('visible')) renderSettings();
}
function titleToggles() { return { sound: { get: () => soundOn, set: setSound } }; }

// ── THE TITLE ──────────────────────────────────────
function titleCfg() {
  const bests = loadBests(), done = INCIDENTS.filter(i => bests[i.id]).length;
  return {
    name: 'PumaResponse',
    sub: TITLE_SUB,
    scene: true,
    primary: 'random',
    items: [
      { act: 'random', label: 'New random incident', key: 'N', meta: `any of ${INCIDENTS.length}` },
      { act: 'choose', label: 'Choose incident', key: 'C', meta: done ? `${done} of ${INCIDENTS.length} graded` : `${INCIDENTS.length} scenarios` },
      { act: 'demo', label: 'Watch a demo', key: 'D', meta: 'autopilot' },
      'gap',
      { act: 'settings', label: 'Settings', key: 'S' },
      { act: 'help', label: 'Help', key: '?' },
      { act: 'about', label: 'About', key: 'A' },
    ],
  };
}
// Draw the title into #title. On the first load the intro's finish() lays
// out the credit and the Sound switch; every title after that does it here.
function openTitle() {
  const el = $('title');
  el.innerHTML = titleHTML(titleCfg());
  el.hidden = false;
  titleOpen = true;
  document.body.classList.add('on-title');
  const t = el.querySelector('.gk-title');
  if (introDone) titleSwitches = gkIntegrate(t, { toggles: titleToggles(), tick: () => titleSfx(gkxKey) });
  startBackdrop();
  const term = gkTerminal(t, {
    logo: TITLE_LOGO,
    prompt: 'responder@pumaresponse:~$',
    type: ms => titleSfx((ac, out) => gkxChatter(ac, out, { ms })),
    power: () => titleSfx(gkxPower),
  });
  sizeMonitor();
  return { t, timing: term.timing };
}
function closeTitle() {
  if (!titleOpen) return;
  titleOpen = false;
  $('title').hidden = true;
  $('title').innerHTML = '';
  titleSwitches = null;
  document.body.classList.remove('on-title');
}
// Back to the title from an incident: the logo whole, the menu printing in again.
// An incident in progress is abandoned, as starting another one would.
function toTitle() {
  ['menu-modal', 'about-modal', 'settings-modal', 'howto-modal', 'end-screen'].forEach(id => $(id).classList.remove('visible'));
  if (!$('help-overlay').hidden) closeHelp(); // the tour belongs to the incident being left
  stopIncident();
  const { t } = openTitle();
  gkxReveal(t);
}
function focusTitle() {
  const b = document.querySelector('#title .gk-primary') || document.querySelector('#title .gk-menu button');
  if (b) b.focus({ preventScroll: true });
}

function titleAct(a) {
  if (a === 'random') { restartWith(); return; }
  if (a === 'choose') { openMenu(); return; }
  if (a === 'demo') { watchDemo(); return; }
  if (a === 'settings') { openSettings(); return; }
  if (a === 'help') { openHowTo(); return; }
  if (a === 'about') { openAboutModal(); return; }
}
$('end-main-btn').addEventListener('click', toTitle);
$('title').addEventListener('click', e => {
  const b = e.target.closest('[data-act]');
  if (b) titleAct(b.dataset.act);
});

// A dialog or a sheet over the title has the keys to itself
function titleBusy() {
  return ['menu-modal', 'about-modal', 'settings-modal', 'howto-modal'].some(id => $(id).classList.contains('visible'))
    || !!document.querySelector('.gk-sheet');
}
// The title's keys, ahead of the game's (which would otherwise answer the
// backdrop's choices): true when the key is spent
function titleKey(e) {
  if (!titleOpen || titleBusy()) return false;
  if (e.ctrlKey || e.metaKey || e.altKey) return false;
  const k = e.key.length === 1 ? e.key.toLowerCase() : e.key;
  if (k === 'Enter' || k === ' ' || k === 'Tab' || k === 'Shift' || k === 'Escape') return false;
  if (k === 'm') { e.preventDefault(); setSound(!soundOn); return true; }
  const menu = document.querySelector('#title .gk-menu'), hit = menu && titleKeyButton(menu, e.key);
  if (hit) { e.preventDefault(); titleAct(hit.dataset.act); return true; }
  if (menu) titleArrow(menu, e);
  return true;
}
window.addEventListener('keydown', e => {
  if (titleKey(e)) { e.stopImmediatePropagation(); return; }
  // M switches sound anywhere else too, but never while typing into a field
  if (!titleOpen && (e.key === 'm' || e.key === 'M') && !e.ctrlKey && !e.metaKey && !e.altKey
      && !(e.target.closest && e.target.closest('input, select, textarea'))) setSound(!soundOn);
}, true);

// Every load opens on the title, under canon's boot
function startTitle() {
  injectTitleCSS();
  const intro = startIntro({ lines: [bootReloadLine(), 'scenarios: ' + INCIDENTS.length + ' loaded'], audio: titleAudio, bootSound: soundOn ? gkBootSound : false });
  const { t, timing } = openTitle();
  intro.finish({
    more: ['MSSP shift handoff received'],
    title: t,
    name: 'lines',
    timing,
    toggles: titleToggles(),
    tick: () => titleSfx(gkxKey),
    onContinue: () => { const ac = titleAudio(); if (ac && ac.state !== 'running') ac.resume().catch(() => {}); },
  }).then(r => { titleSwitches = r.toggles; introDone = true; });
}

// ── THE BACKDROP ───────────────────────────────────
// An incident being worked on autopilot, the whole game screen, running on the
// monitor behind the menu as the board games' tables do. It opens a phase or
// two in; nothing of it is graded, recorded or counted as played, and one that
// finishes just starts another.
function startBackdrop() {
  if (STATE.started) return; // an incident is already on screen
  _autopilot = true;
  _backdrop = true;
  const played = new Set(STATE.played);
  startGame(INCIDENTS[Math.floor(Math.random() * INCIDENTS.length)]);
  STATE.played = played; // the player's random picks are theirs
  fastForward(1 + Math.floor(Math.random() * 3));
  pilotNext = performance.now() + 1500;
}
// Play the incident on, unseen, through `phases` phases
function fastForward(phases) {
  for (let p = 0; p < phases && STATE.phaseIdx < PHASE_NAMES.length - 1; p++) {
    pilotTag(); pilotTag(); // a finding or two, as the analyst read this phase
    for (let n = 0; n < 12 && STATE.started && !STATE.awaitingContinue; n++) pilotStep(true);
    if (STATE.awaitingContinue) advancePhase();
  }
  if (STATE.incident && STATE.phaseIdx < PHASE_NAMES.length) {
    // into this phase's reading, with a finding or two already tagged
    pilotTag(); pilotTag();
  }
}
// End whatever incident is on screen, ungraded
function stopIncident() {
  STATE.siemTimers.forEach(clearTimeout);
  STATE.siemTimers = [];
  STATE.started = false;
  STATE.incident = null;
  _autopilot = false;
  _backdrop = false;
  $('game-screen').classList.remove('visible');
  $('end-screen').classList.remove('visible');
}
function stopBackdrop() { if (_autopilot) stopIncident(); }
// The backdrop's incident finished: another one, out of the step that finished it
function backdropAgain() {
  setTimeout(() => {
    if (!_autopilot) return;
    const watching = !_backdrop;
    stopIncident();
    startBackdrop();
    if (watching) { _backdrop = false; } else sizeMonitor();
  }, 0);
}

// The analyst the backdrop plays with: read and tag what matters, start the
// clock, take a response (usually a good one), carry on
function pilotTag() {
  if (!STATE.evLines || STATE.awaitingContinue) return false;
  const open = STATE.evLines.map((id, i) => id && !$('ev-line-' + i)?.classList.contains('tagged') ? i : -1).filter(i => i >= 0);
  if (!open.length) return false;
  tagLine(open[Math.floor(Math.random() * open.length)]);
  return true;
}
function pilotStep(fast) {
  if (!_autopilot || !STATE.started || !STATE.incident) return;
  if (STATE.awaitingContinue) { if ($('continue-btn')) advancePhase(); return; }
  if (!fast && Math.random() < 0.45 && pilotTag()) return;
  if ($('start-clock-btn')) { startClock(); return; }
  const btns = [...document.querySelectorAll('.choice-btn')];
  if (!btns.length) return;
  const phase = STATE.incident.phases[STATE.phaseIdx];
  const good = btns.filter(b => resolve(phase.choices[+b.dataset.idx].quality) === 'good');
  const pool = good.length && Math.random() < 0.7 ? good : btns;
  selectChoice(+pool[Math.floor(Math.random() * pool.length)].dataset.idx);
}
let pilotNext = 0;
setInterval(() => {
  if (!_autopilot || performance.now() < pilotNext) return;
  pilotStep(false);
  // a phase is read for a while; a decision made is carried on from sooner
  pilotNext = performance.now() + (STATE.awaitingContinue ? 2500 : 2800 + Math.random() * 2600);
}, 250);

// Watch a demo: the backdrop's incident, out from behind the menu. Any key or
// click goes back to the title.
function watchDemo() {
  if (!STATE.started) startBackdrop();
  closeTitle();
  _backdrop = false;
  addSiemEntry('--:--', 'info', 'DEMO — press any key or click to return to the menu');
  setTimeout(() => {
    const leave = e => {
      if (e.type === 'keydown' && ['Shift', 'Control', 'Alt', 'Meta', 'Tab'].includes(e.key)) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      window.removeEventListener('keydown', leave, true);
      window.removeEventListener('pointerdown', leave, true);
      if (_autopilot && !titleOpen) toTitle();
    };
    window.addEventListener('keydown', leave, true);
    window.addEventListener('pointerdown', leave, true);
  }, 300);
}

// The monitor's place and size. Its left edge stands off the menu and logo; it is as
// big as it can be while it fits the page's height and at least half of its
// right-hand column (the SIEM feed) is still on the page: past that it may run
// off the edge. Measured, not worked out, since the perspective brings the
// near edge forward by an amount that depends on the size. A phone has no room
// beside the menu, so there the monitor sits behind it, straight on.
function sizeMonitor() {
  const root = document.documentElement.style, scr = $('game-screen');
  if (innerWidth <= 640) {
    root.setProperty('--mon-x', '0px');
    root.setProperty('--mon-s', Math.min(innerWidth * 0.94 / 1280, innerHeight * 0.9 / 800).toFixed(4));
    return;
  }
  // clear of the whole left column -- the menu, and the logo and its line,
  // which here run wider than the menu -- so nothing of the screen sits behind
  // them. The logo is measured by its letters: its box is the column's width.
  const ink = el => {
    let right = 0;
    const tw = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    for (let n; (n = tw.nextNode());) {
      if (!n.textContent.trim()) continue;
      const rg = document.createRange();
      rg.selectNodeContents(n);
      for (const r of rg.getClientRects()) right = Math.max(right, r.right);
    }
    return right;
  };
  const menu = document.querySelector('#title .gk-menu');
  const from = Math.max(menu ? menu.getBoundingClientRect().right : innerWidth * 0.4,
    ...[...document.querySelectorAll('#title main > h1, #title main > .gk-sub')].map(ink)) + 40;
  root.setProperty('--mon-l', Math.round(from) + 'px');
  const col = $('right-panel');
  if (!scr.classList.contains('visible') || !col) { root.setProperty('--mon-s', '0.5'); return; }
  scr.style.animation = 'none'; // measured at the drift's start, where the near edge is nearest
  const fits = s => {
    root.setProperty('--mon-s', s.toFixed(4));
    const r = scr.getBoundingClientRect(), o = col.getBoundingClientRect();
    return o.left + o.width / 2 <= innerWidth - 4 && r.top >= 6 && r.bottom <= innerHeight - 6;
  };
  let lo = 0.15, hi = 1.5;
  for (let i = 0; i < 14; i++) { const m = (lo + hi) / 2; if (fits(m)) lo = m; else hi = m; }
  fits(lo);
  const r = scr.getBoundingClientRect();
  root.setProperty('--mon-x', Math.round((r.left + Math.min(r.right, innerWidth)) / 2 - innerWidth / 2) + 'px');
  scr.style.animation = '';
}
addEventListener('resize', () => { if (titleOpen) sizeMonitor(); });

// ── SETTINGS ───────────────────────────────────────
// Sound, the decision clock (it was in the ↺ menu), and Forget everything
// (it was the menu's Reset progress), on the title and in the ↺ menu
let settingsReturn = null, forgetArmed = false;
function openSettings() {
  settingsReturn = document.activeElement;
  forgetArmed = false;
  renderSettings();
  $('settings-modal').classList.add('visible');
  $('settings-close-btn').focus();
}
function closeSettings() {
  $('settings-modal').classList.remove('visible');
  if (titleOpen) focusTitle();
  else if (settingsReturn && document.contains(settingsReturn)) settingsReturn.focus();
}
function renderSettings() {
  const pill = (on, label, act) => `<button class="menu-action" data-set="${act}" aria-pressed="${on}">${label}</button>`;
  $('settings-body').innerHTML = `
    <div class="menu-section">SOUND</div>
    <div class="menu-actions">${pill(soundOn, 'ON', 'sound-on')}${pill(!soundOn, 'OFF', 'sound-off')}</div>
    <p class="menu-note">The boot, the terminal's keys and the title. [M] switches it anywhere, and so does the switch on the title.</p>
    <div class="menu-section">DECISION CLOCK</div>
    <div class="menu-actions">${pill(STATE.clockMode === 'realtime', 'REAL-TIME', 'clock-realtime')}${pill(STATE.clockMode === 'turn', 'TURN-BASED', 'clock-turn')}</div>
    <p class="menu-note">Real-time: each phase opens with the clock stopped so you can read. Starting the clock shows your options, and the attacker keeps moving until you decide. Turn-based: no clock.</p>
    <div class="menu-section">THIS BROWSER</div>
    <div class="menu-actions"><button class="menu-action menu-reset${forgetArmed ? ' armed' : ''}" data-set="forget">${forgetArmed ? 'PRESS AGAIN TO FORGET EVERYTHING' : 'FORGET EVERYTHING'}</button></div>
    <p class="menu-note">${forgetArmed
      ? 'This deletes your personal bests and settings, and abandons any incident in progress. It can\'t be undone.'
      : 'Personal bests, the clock and sound settings, and whether the help tour has run, are kept in this browser only.'}</p>`;
}
$('settings-body').addEventListener('click', e => {
  const b = e.target.closest('[data-set]');
  if (!b) return;
  const a = b.dataset.set;
  if (a === 'sound-on') setSound(true);
  if (a === 'sound-off') setSound(false);
  if (a === 'clock-realtime' || a === 'clock-turn') { setClockMode(a.slice(6)); renderSettings(); }
  if (a === 'forget') {
    if (forgetArmed) {
      for (const store of [localStorage, sessionStorage]) {
        try { Object.keys(store).filter(k => k.startsWith('pumaresponse')).forEach(k => store.removeItem(k)); } catch (e) {}
      }
      location.reload();
      return;
    }
    forgetArmed = true;
    renderSettings();
    setTimeout(() => { if (forgetArmed) { forgetArmed = false; if ($('settings-modal').classList.contains('visible')) renderSettings(); } }, 6000);
  }
  const again = $('settings-body').querySelector(`[data-set="${a}"]`);
  if (again) again.focus();
});
$('settings-close-btn').addEventListener('click', closeSettings);
$('settings-modal').addEventListener('click', e => { if (e.target === $('settings-modal')) closeSettings(); });
$('settings-modal').addEventListener('keydown', e => { if (e.key === 'Escape') { e.stopPropagation(); closeSettings(); } });

// ── HELP (from the title) ──────────────────────────
// How to play, in brief: the tour that HELP gives in an incident needs the
// incident's screen to point at
let howtoReturn = null;
function openHowTo() {
  howtoReturn = document.activeElement;
  $('howto-modal').classList.add('visible');
  $('howto-close-btn').focus();
}
function closeHowTo() {
  $('howto-modal').classList.remove('visible');
  if (titleOpen) focusTitle();
  else if (howtoReturn && document.contains(howtoReturn)) howtoReturn.focus();
}
$('howto-close-btn').addEventListener('click', closeHowTo);
$('howto-modal').addEventListener('click', e => { if (e.target === $('howto-modal')) closeHowTo(); });
$('howto-modal').addEventListener('keydown', e => { if (e.key === 'Escape') { e.stopPropagation(); closeHowTo(); } });

startTitle();
