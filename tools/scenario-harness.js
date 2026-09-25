// Scenario harness for PumaResponse — a development tool, not loaded by the game.
//
// Serve the repo (python3 -m http.server 8000), open the game, then in the console:
//   await import('/tools/scenario-harness.js?' + Date.now())
//   harness('RANSOMWARE')      // walks the decision tree under six play styles and
//                              // reports rule violations (a wrong choice count,
//                              // undefined/NaN in rendered text) plus outcome spread
//   calibrate('RANSOMWARE')    // best achievable score vs. the scenario's bestScore
// Run one scenario per call; a full calibrate takes ~20-40 s. Reload between runs.
(function () {
  const RE = /undefined|NaN|\[object|=>/;
  const snip = t => (t.match(/.{0,50}(undefined|NaN|\[object|=>).{0,30}/) || [''])[0];

  function run(inc, n, { tag, preferD, dither, mode }) {
    const bad = [];
    setClockMode(mode);
    startGame(inc);
    for (let p = 0; p < 6; p++) {
      const phase = inc.phases[p];
      if (mode === 'realtime' && !$('start-clock-btn')) bad.push(`p${p} not gated`);
      if (STATE.evLines) STATE.evLines.forEach((id, i) => { if (tag === 'all' || (tag === 'findings' && id)) tagLine(i); });
      startClock();
      if (dither) advanceClock(dither);
      const vis = [...document.querySelectorAll('.choice-btn')].map(b => +b.dataset.idx);
      const base = vis.filter(i => phase.choices[i].key !== 'D').sort((a, b) => a - b);
      const extra = vis.filter(i => phase.choices[i].key === 'D');
      if (base.length !== 3) bad.push(`p${p} base choices=${base.length}`);
      if (tag === 'none' && vis.length !== 3) bad.push(`p${p} ${vis.length} choices with nothing tagged`);
      if (extra.length > 1) bad.push(`p${p} ${extra.length} D options`);
      const pre = $('action-body').innerText; if (RE.test(pre)) bad.push(`p${p} pre: ${snip(pre)}`);
      const pick = preferD && extra.length ? extra[0] : base[Math.floor(n / 3 ** p) % 3];
      selectChoice(pick);
      const post = $('action-body').innerText; if (RE.test(post)) bad.push(`p${p} post: ${snip(post)}`);
      advancePhase();
    }
    const end = $('end-screen').innerText;
    if (RE.test(end)) bad.push(`end: ${snip(end)}`);
    const s = STATE.scores;
    const res = {
      total: s.time + s.containment + s.evidence + s.thoroughness,
      grade: document.querySelector('.sc-grade').textContent,
      rows: (resolve(inc.debrief) || []).map(r => r.join(': ')).join(' | '),
      findings: `${STATE.findings.length}/${Object.keys(STATE.findingText).length}`,
      events: STATE.clockLog.length, carried: STATE.carried.length,
    };
    STATE.siemTimers.forEach(clearTimeout); STATE.siemTimers = [];
    return { bad, res };
  }

  // Thousands of simulated games must not overwrite the player's remembered bests
  const withBestsPreserved = fn => function (...args) {
    let saved = null;
    try { saved = localStorage.getItem('pumaresponse.best'); } catch (e) {}
    try { return fn.apply(this, args); } finally {
      try { saved === null ? localStorage.removeItem('pumaresponse.best') : localStorage.setItem('pumaresponse.best', saved); } catch (e) {}
    }
  };

  window.harness = withBestsPreserved(function (id, { step = 1, configs } = {}) {
    const inc = INCIDENTS.find(i => i.id === id);
    configs = configs || [
      { name: 'rt-none', tag: 'none', mode: 'realtime', dither: 0, sparse: 2 },
      { name: 'rt-findings', tag: 'findings', mode: 'realtime', dither: 0 },
      { name: 'rt-findings-D', tag: 'findings', mode: 'realtime', dither: 0, preferD: true, sparse: 5 },
      { name: 'rt-slow20', tag: 'findings', mode: 'realtime', dither: 20, sparse: 7 },
      { name: 'turn-none', tag: 'none', mode: 'turn', dither: 0, sparse: 7 },
      { name: 'rt-spam', tag: 'all', mode: 'realtime', dither: 0, sparse: 29 },
    ];
    const out = { id, configs: {} };
    const allBad = [], errs = [];
    for (const c of configs) {
      const agg = { runs: 0, grades: {}, min: 1e9, max: -1e9, avg: 0, rows: {}, findings: {}, maxEvents: 0, maxCarried: 0 };
      for (let n = 0; n < 729; n += (c.sparse || step)) {
        try {
          const { bad, res } = run(inc, n, c);
          bad.forEach(b => allBad.push(`${c.name} n${n} ${b}`));
          agg.runs++; agg.avg += res.total;
          agg.grades[res.grade] = (agg.grades[res.grade] || 0) + 1;
          agg.min = Math.min(agg.min, res.total); agg.max = Math.max(agg.max, res.total);
          agg.rows[res.rows] = (agg.rows[res.rows] || 0) + 1;
          agg.findings[res.findings] = (agg.findings[res.findings] || 0) + 1;
          agg.maxEvents = Math.max(agg.maxEvents, res.events); agg.maxCarried = Math.max(agg.maxCarried, res.carried);
        } catch (e) { errs.push(`${c.name} n${n}: ${e.message} ${(e.stack || '').split('\n')[1] || ''}`); if (errs.length > 5) break; }
      }
      agg.avg = Math.round(agg.avg / Math.max(1, agg.runs));
      const rows = Object.entries(agg.rows).sort((a, b) => b[1] - a[1]);
      agg.distinctOutcomes = rows.length; agg.rows = rows.slice(0, 3).map(([r, k]) => `${k}× ${r}`);
      out.configs[c.name] = agg;
    }
    $('end-screen').classList.remove('visible');
    setClockMode('realtime');
    out.errs = errs.slice(0, 6); out.badCount = allBad.length; out.bad = allBad.slice(0, 8);
    return JSON.stringify(out);
  });
  window.withBestsPreserved = withBestsPreserved;
})();

// Best achievable total per scenario: every finding tagged, instant decisions,
// all 729 base paths, with and without taking unlocked D options. Also the
// "all good choices, nothing tagged" reference and random-play percentiles.
window.calibrate = window.withBestsPreserved(function (id) {
  const inc = INCIDENTS.find(i => i.id === id);
  const totals = []; let best = -1e9, bestPath = '';
  const one = (n, tag, preferD, pickGood) => {
    setClockMode('realtime'); startGame(inc);
    const path = [];
    for (let p = 0; p < 6; p++) {
      const phase = inc.phases[p];
      if (tag && STATE.evLines) STATE.evLines.forEach((fid, i) => { if (fid) tagLine(i); });
      startClock();
      const vis = [...document.querySelectorAll('.choice-btn')].map(b => +b.dataset.idx);
      const base = vis.filter(i => phase.choices[i].key !== 'D').sort((a, b) => a - b);
      const extra = vis.filter(i => phase.choices[i].key === 'D');
      let pick = preferD && extra.length ? extra[0] : base[Math.floor(n / 3 ** p) % 3];
      if (pickGood) pick = base.find(i => resolve(phase.choices[i].quality) === 'good') ?? base[0];
      path.push(phase.choices[pick].key);
      selectChoice(pick); advancePhase();
    }
    const s = STATE.scores; STATE.siemTimers.forEach(clearTimeout); STATE.siemTimers = [];
    return { total: s.time + s.containment + s.evidence + s.thoroughness, path: path.join('') };
  };
  for (let n = 0; n < 729; n++) for (const d of [false, true]) {
    const r = one(n, true, d, false); if (r.total > best) { best = r.total; bestPath = r.path; }
    if (!d) totals.push(r.total);
  }
  const goodNoTag = one(0, false, false, true).total, goodTag = one(0, true, false, true).total;
  totals.sort((a, b) => a - b);
  const pc = q => totals[Math.floor(q * (totals.length - 1))];
  $('end-screen').classList.remove('visible');
  const pct = v => Math.round(100 * v / best);
  return {
    id, best, stored: inc.bestScore, drift: best !== inc.bestScore ? `update bestScore to ${best}` : 'ok', bestPath,
    goodNoTag: `${goodNoTag} (${pct(goodNoTag)}%)`, goodTag: `${goodTag} (${pct(goodTag)}%)`,
    random: { p10: pct(pc(0.1)) + '%', p50: pct(pc(0.5)) + '%', p90: pct(pc(0.9)) + '%' },
  };
});
