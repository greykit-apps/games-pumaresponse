// Insider Threat — Data Exfiltration by Departing Employee
// Scenario data for PumaResponse — format documented in README → Development.

// INSIDER: ITAR-marked files Marcus Reeves has copied out of Pinnacle's control.
// 1,204 were already gone at handoff (the 21-day history); 1,643 proprietary,
// non-ITAR files went with them. While nothing stops him he keeps copying, and
// INSIDER_COPY_STEPS is how many more leave t minutes into a decision.
const INSIDER_ITAR_AT_HANDOFF = 1204;
const INSIDER_PROPRIETARY = 1643;
const INSIDER_COPY_STEPS = [[0, 0], [5, 58], [11, 131], [20, 212], [35, 330], [60, 470]];
function insiderCopied(t) {
  return INSIDER_COPY_STEPS.filter(([at]) => t >= at).pop()[1];
}
// Files leaving during this decision: none once he's locked out or the channels are
// closed; twice the pace once he knows he's being watched.
function insiderLeak(f, t) {
  if (f.accessCut || f.exfilBlocked) return 0;
  return insiderCopied(t) * (f.subjectAlerted ? 2 : 1);
}
function insiderNum(n) {
  return Math.round(n).toLocaleString('en-US');
}
// Wall-clock stamp m minutes after the 11:30 handoff; carries the date past midnight (Mar 1)
function insStamp(m) {
  const t = 11 * 60 + 30 + Math.floor(m);
  const day = Math.floor(t / 1440);
  const hhmm = `${String(Math.floor(t / 60) % 24).padStart(2, '0')}:${String(t % 60).padStart(2, '0')}`;
  return day ? `Mar ${1 + day} ${hhmm}` : hhmm;
}
// A DDTC disclosure is complete only if it can say which files and who received them
function insiderDdtcFull(f) {
  return f.scope >= 1 && !!f.saw_foreignRecipient;
}
function insiderEvidenceStatus(f) {
  if (!f.custody) return 'Contested — no chain of custody on ENGR-WS-12';
  const base = f.custodyLate ? 'Partly — workstation imaged late' : 'Yes — workstation and DLP logs under chain of custody';
  if (!f.evidenceDestroyed) return base;
  return base + (f.cloudPreserved ? '; his copies wiped, provider records preserved' : '; his own copies destroyed');
}
function insiderReferral(f) {
  if (f.scope < 1) return 'Stalled — FBI has DLP alerts, no images or inventory';
  let s = 0;
  if (f.custody) s += f.custodyLate ? 1 : 2;
  if (!f.evidenceDestroyed || f.cloudPreserved) s += 1;
  if (f.warrantSeized || f.deviceExam) s += 1;
  if (f.saw_afterHours || f.saw_homeIp) s += 1;        // attribution: it was him at the keyboard
  if (f.evidenceDestroyed && f.saw_antiForensics) s += 1; // the wiping itself, documented
  if (s >= 4) return f.saw_foreignRecipient
    ? 'Accepted — AECA export and trade-secret charges being drafted'
    : 'Accepted — trade-secret charges only (recipient never identified)';
  if (s >= 2) return 'Accepted — prosecution uncertain; civil suit carries the case';
  return 'Declined for prosecution — civil action only';
}
function insiderDdtcStatus(f) {
  if (f.ddtc === 'full') return f.recipientMapped
    ? 'Filed — complete (files, USML paragraphs, foreign recipient)'
    : 'Filed — files and foreign recipient identified';
  if (f.ddtc === 'initial') {
    const missing = [f.scope < 1 && 'which files', !f.saw_foreignRecipient && 'who received them'].filter(Boolean).join(' or ');
    return `Initial notification only — can't say ${missing || 'the full scope'}`;
  }
  if (f.ddtc === 'late') return 'Deferred — DFARS filed, DDTC not yet notified';
  if (f.ddtc === 'directed') return 'Not filed — DDTC learned of it from the FBI';
  return 'Not filed';
}

registerIncident(
  {
    id: 'INSIDER',
    title: 'Insider Threat — Data Exfiltration by Departing Employee',
    client: 'Pinnacle Aerospace',
    severity: 'HIGH',
    sevClass: 'high',
    ticketId: 'IR-2024-0956',
    // In-world "today": dates in this file are written relative to it and
    // shown shifted to the real date (see REAL-DATE ANCHORING in js/game.js)
    baseDate: '2024-03-01',
    assignedTime: '11:30 ET',
    summary: 'DLP alert triggered by departing senior engineer uploading proprietary avionics designs to personal cloud storage. Employee gave 2-week notice yesterday. Bulk access to ITAR-controlled technical data detected.',
    iocs: [
      { type: 'USER', val: 'mreeves — Senior Avionics Engineer (notice period)' },
      { type: 'DOMAIN', val: 'drive.google.com — personal Google Drive uploads' },
      { type: 'DOMAIN', val: 'mega.nz — encrypted file transfers detected' },
      { type: 'USB', val: 'SanDisk Ultra 256GB — connected to ENGR-WS-12' },
      { type: 'FILE', val: 'ITAR-marked drawings and CDRL deliverables (.pdf, .step, .dwg)' },
    ],
    // Run state. Every later phase reads these; choices change them via `sets`.
    initialFlags: {
      itarFiles: INSIDER_ITAR_AT_HANDOFF, // ITAR-marked files out of Pinnacle's control; grows while he copies
      subjectAlerted: false,  // Marcus knows or suspects he is being watched
      alertedAt: '',          // phase in which he found out
      evidenceDestroyed: false, // he wiped/deleted his own copies (USB, cloud, home laptop)
      custody: false,         // ENGR-WS-12 imaged and DLP logs preserved under chain of custody
      custodyLate: false,     // ...but only after the workstation had been handled
      hrLegal: false,         // employment actions run through HR and counsel, documented
      accessCut: false,       // all of his logical access revoked
      exfilBlocked: false,    // covert restrictions: ITAR re-ACL, proxy blocks, print hold
      escorted: false,        // fired / walked out with no HR-counsel process behind it
      vpnCut: false,          // VPN killed but on-site access left alone
      cloudPreserved: false,  // FBI preservation requests to Google / MEGA
      fbiEarly: false,        // FBI engaged during containment, while he was still unaware
      warrantSeized: false,   // FBI search warrant executed at his home before he knew
      fwdActive: true,        // his 30-day-old mailbox forward to personal Gmail
      credsRotated: false,    // shared lab accounts, PINs and Wi-Fi PSK rotated
      parkingLot: false,      // he got back in over the shared engineering Wi-Fi key
      scope: 0,               // 0 = DLP alerts only, 1 = ITAR files catalogued, 2 = full inventory
      recipientMapped: false, // every ITAR file mapped to USML paragraph and to its foreign recipient
      ddtc: '',               // '' | 'full' | 'initial' | 'late' | 'directed'
      deviceExam: false,      // his devices produced to a neutral forensic examiner (civil)
      triagedAt: 0,           // wall-clock minute (since handoff) the Triage action landed
    },
    // 2 real seconds per game minute once the decision clock starts; 10-minute par
    clock: { rate: 0.5, par: 10 },
    // Best achievable total (every finding tagged, instant decisions, best path).
    // Grades are a percentage of this. Recompute with tools/scenario-harness.js after
    // changing this scenario's scores, carried penalties or findings.
    bestScore: 357,
    // MITRE ATT&CK (Enterprise v19) technique per finding, shown in the debrief.
    // Findings that aren't adversary behavior (missing controls, business facts) are omitted.
    attack: {
      usb: "T1052.001 Exfiltration Over Physical Medium: Exfiltration over USB",
      gdrive: "T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage",
      mega: "T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage",
      bulkRead: "T1039 Data from Network Shared Drive",
      homeIp: "T1078.004 Valid Accounts: Cloud Accounts",
      fwdRule: "T1114.003 Email Collection: Email Forwarding Rule",
      uavGuidance: "T1039 Data from Network Shared Drive",
      gmailAttach: "T1048 Exfiltration Over Alternative Protocol",
      antiForensics: "T1070.004 Indicator Removal: File Deletion",
      scopeCreep: "T1039 Data from Network Shared Drive",
      dlpMonitor: "T1052.001 Exfiltration Over Physical Medium: Exfiltration over USB",
      foreignRecipient: "T1048 Exfiltration Over Alternative Protocol",
    },
    debrief: f => [
      ['ITAR Files Exfiltrated', `${insiderNum(f.itarFiles)} (${insiderNum(f.itarFiles - INSIDER_ITAR_AT_HANDOFF)} after the MSSP took the case)`],
      ['Subject Tipped Off', f.alertedAt ? `Yes — during ${f.alertedAt}` : 'Not until the termination meeting'],
      ['Evidence Admissible', insiderEvidenceStatus(f)],
      ['DDTC Disclosure', insiderDdtcStatus(f)],
      ['Referral Outcome', insiderReferral(f)],
      ['Copies Recovered', f.warrantSeized ? 'Seized under FBI search warrant'
        : f.deviceExam ? (f.evidenceDestroyed ? 'Devices produced wiped — spoliation finding' : 'Produced to neutral examiner, sequestered')
        : f.evidenceDestroyed ? 'None — whatever he kept is beyond reach' : 'None — he still holds them'],
    ],
    phases: [
      { // TRIAGE
        name: 'TRIAGE',
        narrative: 'Pinnacle Aerospace\'s DLP system flagged bulk uploads from senior engineer Marcus Reeves\'s workstation. He submitted his resignation yesterday and his last day is in two weeks. He\'s a 9-year employee with access to ITAR-controlled avionics designs for a major DoD contract. HR says he\'s going to a competitor. He is at his desk right now.',
        evidence: {
          title: 'DLP ALERTS — LAST 24 HOURS',
          content: `<span class="log-warn">[Yesterday 17:45]</span> HR: mreeves — resignation submitted (last day in 2 weeks)
<span class="log-warn">[Yesterday 18:02]</span> Proxy: mreeves → linkedin.com (profile edited)
<span class="log-warn">[Yesterday 19:30]</span> Print: jpatel — 4 pages, BLDG-A-PRINTER-01
<span class="log-warn">[Yesterday 21:52]</span> Badge-in: mreeves — Building C, after hours<!--f:afterHours-->
<span class="log-warn">[Yesterday 22:14]</span> <span class="log-highlight">DLP ALERT</span> USB device connected: ENGR-WS-12<!--f:usb-->
  Device: SanDisk Ultra 256GB (not company-issued)<!--f:usb-->
  Serial: 4C530001240615117421<!--f:usb-->
  Files copied: 47 files, 3.2 GB<!--f:usb-->
<span class="log-warn">[Yesterday 22:40]</span> AV: ENGR-WS-12 — definitions updated, scan clean
<span class="log-warn">[Yesterday 23:01]</span> <span class="log-highlight">DLP ALERT</span> Cloud upload: drive.google.com
  Account: mreeves@gmail.com — 28 files, 890 MB<!--f:gdrive-->
  File types: .pdf, .step, .dwg<!--f:gdrive-->
<span class="log-warn">[Yesterday 23:18]</span> Badge-out: mreeves — Building C<!--f:afterHours-->
<span class="log-warn">[Today 02:30]</span> <span class="log-highlight">DLP ALERT</span> Cloud upload: mega.nz (via VPN, home)
  Account: m.reeves.avx@proton.me<!--f:mega-->
  Encrypted upload — 1.4 GB<!--f:mega-->
<span class="log-warn">[Today 06:55]</span> Windows Update: ENGR-WS-12 — KB5034441 installed, reboot pending
<span class="log-warn">[Today 07:12]</span> DLP: jpatel — .step file to approved supplier portal (policy exception #44)
<span class="log-warn">[Today 08:00]</span> Badge-in: mreeves entered Building C (engineering lab)
<span class="log-warn">[Today 09:15]</span> File access: \\\\pinnacle-fs\\ITAR\\F-35_Avionics\\<!--f:bulkRead-->
  217 files accessed — bulk read pattern<!--f:bulkRead-->`
        },
        choices: [
          {
            key: 'A',
            label: 'Preserve evidence quietly: mirror DLP logs, image workstation after hours, coordinate with legal and HR',
            desc: 'Covert evidence preservation. Don\'t tip off the employee. Work with legal to establish proper chain of custody for potential prosecution.',
            quality: 'good',
            score: { time: 10, containment: 10, evidence: 25, thoroughness: 15 },
            sets: (f, st) => ({ triagedAt: st.elapsed, custody: true, hrLegal: true, itarFiles: f.itarFiles + insiderLeak(f, st.phaseClock) }),
            outcome: (f, st) => {
              const n = insiderLeak(f, st.phaseClock);
              return 'DLP logs preserved with timestamps. Legal counsel engaged for ITAR violation assessment and approves covert monitoring under the consent banner in Pinnacle\'s acceptable-use policy. HR confirms the employee is joining Zhentian Dynamics, a known competitor with foreign ownership. You coordinate with Pinnacle\'s Insider Threat Program Senior Official — a role the facility clearance requires, with no analytics behind it — to begin covert monitoring. Evidence chain of custody established per federal litigation requirements.'
                + (n ? ` While the plan came together he kept working: ${insiderNum(n)} more ITAR-marked files left his workstation.` : '');
            },
          },
          {
            key: 'B',
            label: 'Immediately disable the employee\'s access to all systems',
            desc: 'Lock out mreeves from network, email, building access, and file shares.',
            quality: 'partial',
            score: { time: 15, containment: 15, evidence: -10, thoroughness: 0 },
            sets: (f, st) => ({
              triagedAt: st.elapsed,
              accessCut: true, subjectAlerted: true, alertedAt: f.alertedAt || 'TRIAGE', evidenceDestroyed: true,
              itarFiles: f.itarFiles + insiderLeak(f, st.phaseClock),
            }),
            outcome: (f, st) => {
              const n = insiderLeak(f, st.phaseClock);
              return (n ? `By the time the lockout lands, ${insiderNum(n)} more ITAR-marked files have gone. ` : '')
                + 'Access revoked — no more data can leave through Pinnacle\'s systems. But the sudden lockout alerts the employee, who deletes his personal cloud uploads and wipes the USB drive before you can obtain them. Legal counsel says the abrupt, undocumented lockout may complicate civil litigation and the ITAR violation referral.';
            },
          },
          {
            key: 'C',
            label: 'Talk to the employee directly to understand what he\'s doing',
            desc: 'Have a conversation with Marcus to ask why he\'s copying files.',
            quality: 'bad',
            score: { time: -15, containment: -20, evidence: -15, thoroughness: -10 },
            sets: (f, st) => ({
              triagedAt: st.elapsed,
              subjectAlerted: true, alertedAt: f.alertedAt || 'TRIAGE', evidenceDestroyed: true,
              itarFiles: f.itarFiles + insiderLeak(f, st.phaseClock),
            }),
            outcome: 'Marcus claims he was backing up personal notes and code samples for his portfolio. Tipped off, he spends his lunch break deleting cloud uploads, wiping browser history, and physically destroying the USB drive. He claims everything is deleted. He still has every access he had this morning. You\'ve lost most of the evidence and given him a heads-up to cover his tracks.',
          },
        ],
        live: (f, st) => `ITAR FILES OUT OF PINNACLE'S CONTROL: ${insiderNum(f.itarFiles + insiderLeak(f, st.phaseClock))} · STILL COPYING`,
        timeline: [
          { at: 5, sev: 'crit', text: 'ENGR-WS-12: 58 more files read from \\\\pinnacle-fs\\ITAR\\F-35_Avionics\\', score: { containment: -3 } },
          { at: 11, sev: 'crit', text: 'DLP: SanDisk Ultra 256GB re-connected to ENGR-WS-12 — 1.1 GB copied', score: { containment: -3 } },
          { at: 20, sev: 'crit', text: 'Proxy: mega.nz upload session opened from ENGR-WS-12 — 212 ITAR files now gone since handoff', score: { containment: -3 } },
          { at: 35, sev: 'crit', text: 'DLP: mreeves → personal Gmail — ITAR-marked attachment', score: { containment: -3, evidence: -2 } },
        ],
        siemEntries: [
          { time: '11:30', sev: 'crit', text: 'INCIDENT ASSIGNED — Insider Threat — Pinnacle Aerospace' },
          { time: '11:31', sev: 'warn', text: 'ITAR-controlled data access detected — departing employee' },
          { time: '11:32', sev: 'crit', text: '3.2 GB copied to personal USB + cloud uploads to mega.nz' },
          { time: '11:33', sev: 'warn', text: 'Employee joining competitor with foreign ownership' },
        ],
      },
      { // CONTAINMENT
        name: 'CONTAINMENT',
        // The monitoring below has to happen before you read it
        at: f => f.triagedAt + (f.accessCut ? 50 : 65),
        narrative: f => {
          if (f.accessCut) return 'Marcus is locked out, and he knows it. Within twenty minutes of the lockout his Google Drive uploads were gone, and he told HR the USB drive held "personal photos, already reformatted." Legal counsel confirms this is potentially an ITAR violation (federal crime) and recommends involving the FBI. What already left is beyond your systems; what is left to contain are the gaps in the lockout — and his status as an employee, which runs through HR, not the MSSP.';
          if (f.subjectAlerted) return 'After the conversation Marcus went back to his desk. He still has every access he had this morning, and he now knows he is being watched. Legal counsel confirms this is potentially an ITAR violation (federal crime) and recommends involving the FBI. You need to contain the data loss without destroying what is left of the legal case.';
          return 'Evidence preservation is underway. Legal counsel has confirmed this is potentially an ITAR violation (federal crime) and recommends involving the FBI. The employee is still on-site and actively accessing ITAR-controlled files. You need to contain the data loss without destroying the legal case.';
        },
        evidence: f => f.accessCut ? {
          title: 'POST-LOCKOUT TELEMETRY',
          content: `<span class="log-warn">[${insStamp(f.triagedAt)}]</span> Print release: mreeves at BLDG-C-PRINTER-02<!--f:printJob-->
  Document: UAV_nav_architecture.pdf (38 pages, ITAR)<!--f:printJob-->
<span class="log-ok">[${insStamp(f.triagedAt + 5)}]</span> AD: mreeves — account disabled, sessions revoked
<span class="log-warn">[${insStamp(f.triagedAt + 8)}]</span> Badge: mreeves — DENIED at Building C turnstile
<span class="log-warn">[${insStamp(f.triagedAt + 13)}]</span> Facilities: mreeves escorted to lobby — backpack not inspected
<span class="log-warn">[${insStamp(f.triagedAt + 16)}]</span> Entra ID: sign-in blocked — mreeves from 73.162.48.19 (residential)<!--f:homeIp-->
<span class="log-warn">[${insStamp(f.triagedAt + 22)}]</span> Teams: jpatel → eng-leads "anyone know why Marcus left?"
<span class="log-warn">[${insStamp(f.triagedAt + 30)}]</span> Exchange: message for mreeves delivered<!--f:fwdRule-->
  Inbox rule "ref" — forwarded to mreeves@gmail.com<!--f:fwdRule-->
<span class="log-warn">[${insStamp(f.triagedAt + 35)}]</span> Proxy: jpatel → confluence.pinnacle.local (AVX handover page)
<span class="log-warn">[${insStamp(f.triagedAt + 39)}]</span> ENGR-WS-12: screen locked, idle — no logon since ${insStamp(f.triagedAt + 5)}
<span class="log-warn">[${insStamp(f.triagedAt + 42)}]</span> Entra ID: sign-in blocked — mreeves from 73.162.48.19<!--f:homeIp-->

<span class="log-ok">── LEGAL GUIDANCE ──</span>
  - ITAR violations: penalties up to $1M per violation + 20 years
  - Need to preserve evidence for federal referral
  - Employment action must be documented and reviewed by counsel
  - Employee retains some rights during notice period`
        } : {
          title: 'CONTINUED ACTIVITY MONITORING',
          content: `<span class="log-warn">[${insStamp(f.triagedAt + 15)}]</span> mreeves accessing \\\\pinnacle-fs\\ITAR\\UAV_Guidance\\<!--f:uavGuidance-->
  54 additional files — 780 MB<!--f:uavGuidance-->
<span class="log-warn">[${insStamp(f.triagedAt + 17)}]</span> Jira: mreeves — AVX-2231 moved to "Handover"
<span class="log-warn">[${insStamp(f.triagedAt + 22)}]</span> <span class="log-highlight">EMAIL</span> mreeves → personal Gmail<!--f:gmailAttach-->
  Subject: "Reference Materials"<!--f:gmailAttach-->
  Attachment: guidance_specs_v3.pdf (ITAR-marked)<!--f:gmailAttach-->
<span class="log-warn">[${insStamp(f.triagedAt + 25)}]</span> Teams: mreeves → jpatel "can you cover the 2pm review?"
<span class="log-warn">[${insStamp(f.triagedAt + 31)}]</span> Print job: ENGR-WS-12 → BLDG-C-PRINTER-02<!--f:printJob-->
  Document: UAV_nav_architecture.pdf (38 pages, ITAR)<!--f:printJob-->
<span class="log-warn">[${insStamp(f.triagedAt + 36)}]</span> Proxy: mreeves → weather.com
<span class="log-warn">[${insStamp(f.triagedAt + 40)}]</span> Webmail access: mreeves@gmail.com from ENGR-WS-12<!--f:gdrive-->
  Uploading additional files to Google Drive<!--f:gdrive-->${f.subjectAlerted ? `
<span class="log-warn">[${insStamp(f.triagedAt + 50)}]</span> Process: sdelete64.exe -p 3 E:\\ (USB volume)<!--f:antiForensics-->
<span class="log-warn">[${insStamp(f.triagedAt + 52)}]</span> Chrome: history, cookies and cache cleared
<span class="log-warn">[${insStamp(f.triagedAt + 61)}]</span> Proxy (TLS-inspected): drive.google.com — 28 DELETE requests<!--f:antiForensics-->` : ''}

<span class="log-ok">── LEGAL GUIDANCE ──</span>
  - ITAR violations: penalties up to $1M per violation + 20 years
  - Need to preserve evidence for federal referral
  - Premature confrontation may trigger spoliation
  - Employee retains some rights during notice period`
        },
        choices: [
          {
            key: 'A',
            when: f => !f.accessCut,
            label: 'Silently restrict ITAR file access via ACLs, block personal cloud domains, continue monitoring',
            desc: 'Reduce access without alerting the employee. Block exfil channels at the proxy. Maintain the covert investigation.',
            quality: 'good',
            score: { time: 10, containment: 20, evidence: 15, thoroughness: 15 },
            sets: (f, st) => ({ exfilBlocked: true, itarFiles: f.itarFiles + insiderLeak(f, st.phaseClock) }),
            outcome: (f, st) => {
              const n = insiderLeak(f, st.phaseClock);
              return (n ? `${insiderNum(n)} more ITAR files left while you decided. ` : '')
                + (f.subjectAlerted
                  ? 'ITAR file shares re-ACL\'d, personal cloud and webmail domains blocked at the web proxy, print jobs routed to a hold queue. It stops the bulk copying — but there is nothing covert left to protect. He already knows, and he spent lunch deleting what he could.'
                  : 'ITAR file shares quietly re-ACL\'d — mreeves can still access his normal project files but not bulk-download controlled data. Personal cloud and webmail domains blocked at the web proxy (applied org-wide to avoid suspicion). Print jobs routed to a hold queue. The employee doesn\'t notice the restrictions for several hours. Evidence continues accumulating.');
            },
          },
          {
            key: 'A',
            when: f => f.accessCut,
            label: 'Have HR place him on paid administrative leave, counsel send a preservation and return demand, image ENGR-WS-12',
            desc: 'Turn the lockout into a documented employment action and preserve what is still on Pinnacle\'s side.',
            quality: 'good',
            score: { time: 10, containment: 20, evidence: 15, thoroughness: 15 },
            sets: f => ({ hrLegal: true, custody: true, fwdActive: f.fwdActive && !f.saw_fwdRule }),
            outcome: f => 'HR places Marcus on paid administrative leave pending investigation — documented, reviewed by counsel, and far easier to defend than an unexplained lockout. Counsel\'s letter directs him to preserve and return all Pinnacle information and devices. ENGR-WS-12 is imaged under chain of custody; nobody has touched it since the lockout, so it is a clean capture. What he took home is another matter.'
              + (f.saw_fwdRule ? ' You also have Exchange delete the forwarding rule the lockout missed — disabling a sign-in never stops server-side mail rules.' : ''),
          },
          {
            key: 'B',
            when: f => !f.accessCut,
            label: 'Disable the employee\'s VPN and remote access, restrict to on-site only',
            desc: 'Prevent any after-hours access. He can still work on-site but can\'t connect remotely.',
            quality: 'partial',
            score: { time: 5, containment: 10, evidence: 5, thoroughness: 5 },
            sets: (f, st) => ({
              subjectAlerted: true, alertedAt: f.alertedAt || 'CONTAINMENT', evidenceDestroyed: true, vpnCut: true,
              itarFiles: f.itarFiles + insiderLeak(f, st.phaseClock) + 240,
            }),
            outcome: 'VPN and remote access disabled. This prevents after-hours exfiltration but he\'s still copying data on-site. He notices his VPN is down and asks IT — the help desk tells him it\'s a "system issue" but he grows suspicious. He accelerates his exfiltration efforts during business hours.',
          },
          {
            key: 'B',
            when: f => f.accessCut,
            label: 'Block personal cloud and webmail org-wide and wait for HR to decide his status',
            desc: 'Close the channels at the proxy. Employment status is HR\'s call; let them make it in their own time.',
            quality: 'partial',
            score: { time: 5, containment: 10, evidence: 5, thoroughness: 5 },
            sets: { exfilBlocked: true },
            outcome: 'The proxy blocks are sound hygiene, aimed at a man who no longer has a login. HR spends the afternoon debating whether he is suspended, on leave or fired. Nobody documents the lockout, nobody images ENGR-WS-12, and nobody writes to him about the drive.',
          },
          {
            key: 'C',
            when: f => !f.accessCut,
            label: 'Have security escort the employee out of the building immediately',
            desc: 'Remove the threat. Walk him out and collect his badge and equipment.',
            quality: 'bad',
            score: { time: 10, containment: 15, evidence: -20, thoroughness: -10 },
            sets: (f, st) => ({
              accessCut: true, escorted: true, subjectAlerted: true, alertedAt: f.alertedAt || 'CONTAINMENT', evidenceDestroyed: true,
              itarFiles: f.itarFiles + insiderLeak(f, st.phaseClock),
            }),
            outcome: f => 'Marcus is escorted out, creating a scene in the engineering lab. '
              + (f.custody ? 'His workstation was already imaged, ' : 'His workstation is seized with no forensic procedure, ')
              + 'but he already transferred key files. Without HR and counsel deciding the timing, the abrupt removal during his notice period invites a wrongful termination claim. His personal devices (phone, home computer) where he likely has copies are beyond your reach without a federal warrant — and the abrupt action does not give the FBI time to prepare one.',
          },
          {
            key: 'C',
            when: f => f.accessCut,
            label: 'Terminate him for cause today, by phone, and bar him from the site',
            desc: 'He stole export-controlled data. Fire him now and be done with it.',
            quality: 'bad',
            score: { time: 10, containment: 15, evidence: -20, thoroughness: -10 },
            sets: { escorted: true },
            outcome: 'HR fires him for cause over the phone before counsel has reviewed a single log. His new lawyer calls it retaliation for resigning to join a competitor, and a man with nothing left to lose from Pinnacle has no reason to answer a return demand. ENGR-WS-12 sits un-imaged under a desk.',
          },
          {
            key: 'D',
            when: f => f.saw_gdrive || f.saw_mega,
            label: f => f.accessCut
              ? 'Documented leave and imaging via HR and counsel — and have counsel bring the FBI in now to preserve his cloud accounts'
              : 'Silently restrict and block — and have counsel bring the FBI in now to preserve his cloud accounts',
            desc: f => `You logged ${[f.saw_gdrive && 'the Google account', f.saw_mega && 'the MEGA account'].filter(Boolean).join(' and ')}. Agents can ask the provider to freeze it before he thinks to empty it.`,
            quality: 'good',
            score: { time: 10, containment: 20, evidence: 20, thoroughness: 20 },
            sets: (f, st) => ({
              cloudPreserved: true, fbiEarly: true, hrLegal: true,
              ...(f.accessCut
                ? { custody: true, fwdActive: f.fwdActive && !f.saw_fwdRule }
                : { exfilBlocked: true, itarFiles: f.itarFiles + insiderLeak(f, st.phaseClock) }),
            }),
            outcome: (f, st) => {
              const n = insiderLeak(f, st.phaseClock);
              const google = f.saw_gdrive
                ? (f.evidenceDestroyed
                  ? 'Google preserves what is left of mreeves@gmail.com under an 18 U.S.C. § 2703(f) request within hours: the files are gone, but subscriber records and the upload-and-delete activity log survive — proof of both the theft and the clean-up. '
                  : 'Google freezes mreeves@gmail.com under an 18 U.S.C. § 2703(f) request within hours, contents intact. ')
                : '';
              const mega = f.saw_mega
                ? 'MEGA is a New Zealand company, so that request goes through NZ Police liaison and takes days; the content is end-to-end encrypted even to MEGA, but account records and share-link access logs are held. '
                : '';
              return (f.accessCut
                ? 'HR places him on documented paid leave, counsel sends a preservation and return demand, and ENGR-WS-12 is imaged under chain of custody. '
                : 'ITAR shares quietly re-ACL\'d, personal cloud and webmail blocked org-wide, print jobs held. ')
                + 'Counsel calls the FBI field office\'s counterintelligence squad the same hour. ' + google + mega
                + (f.subjectAlerted ? 'He already knows he is watched, so this is salvage, not surprise.' : 'He has no idea. Agents start drafting a search-warrant affidavit for his home.')
                + (n ? ` (${insiderNum(n)} more ITAR files left while you decided.)` : '');
            },
          },
        ],
        live: (f, st) => f.accessCut
          ? (f.fwdActive ? 'SUBJECT LOCKED OUT · HIS MAIL STILL FORWARDING TO GMAIL' : 'SUBJECT LOCKED OUT')
          : `ITAR FILES OUT: ${insiderNum(f.itarFiles + insiderLeak(f, st.phaseClock))} · ${f.subjectAlerted ? 'COPYING FAST — HE KNOWS' : 'STILL COPYING'}`,
        timeline: [
          { at: 5, when: f => !f.accessCut, sev: 'crit', text: f => `ENGR-WS-12: ${f.subjectAlerted ? 116 : 58} more files read from \\\\pinnacle-fs\\ITAR\\UAV_Guidance\\`, score: { containment: -3 } },
          { at: 6, when: f => !f.accessCut && f.subjectAlerted, sev: 'crit', text: 'ENGR-WS-12: sdelete64.exe run against USB volume E: and Downloads', score: { evidence: -4 } },
          { at: 11, when: f => !f.accessCut, sev: 'crit', text: 'Proxy: drive.google.com upload session — 220 MB from ENGR-WS-12', score: { containment: -3 } },
          { at: 20, when: f => !f.accessCut, sev: 'crit', text: 'BLDG-C-PRINTER-02: UAV_guidance_loops.pdf — 22 pages (ITAR) released to mreeves', score: { containment: -3 } },
          { at: 6, when: f => f.accessCut, sev: 'warn', text: 'Entra ID: 4 more blocked sign-ins for mreeves from 73.162.48.19' },
          { at: 12, when: f => f.accessCut && f.fwdActive, sev: 'crit', text: 'Exchange: rule "ref" forwards "UAV guidance design review" thread to mreeves@gmail.com', score: { containment: -3 } },
        ],
        siemEntries: f => f.accessCut ? [
          { time: '11:41', sev: 'success', text: 'mreeves locked out — AD disabled, sessions revoked' },
          { time: '11:52', sev: 'warn', text: 'Blocked sign-ins for mreeves from residential IP' },
          { time: '12:06', sev: 'warn', text: 'Mail to mreeves still delivered — inbox rule processing' },
        ] : [
          { time: '11:50', sev: 'crit', text: 'Continued ITAR file access — 54 additional files' },
          { time: '11:55', sev: 'warn', text: 'Email exfiltration: ITAR document sent to personal Gmail' },
          { time: '12:05', sev: 'warn', text: 'Physical exfil: ITAR document sent to printer' },
          ...(f.subjectAlerted ? [{ time: '12:20', sev: 'crit', text: 'Anti-forensics: secure-delete run on ENGR-WS-12' }] : []),
        ],
      },
      { // INVESTIGATION
        name: 'INVESTIGATION',
        carried: f => {
          const out = [];
          if (f.vpnCut) out.push({
            text: f.alertedAt === 'TRIAGE'
              ? 'With his VPN gone as well, Marcus stopped pretending. He copied hard all afternoon — 240 more ITAR files onto a second USB drive — and last night ran a disk-wipe utility on his home laptop.'
              : 'Suspicious since his VPN died, Marcus copied hard all afternoon — 240 more ITAR files onto a second USB drive. Last night he ran a disk-wipe utility on his home laptop.',
            score: { containment: -8, evidence: -5 },
          });
          if (f.escorted) out.push({
            text: f.hrLegal
              ? 'Marcus\'s attorney writes: the removal was retaliation for resigning to join a competitor. Counsel was engaged, but nobody asked them before he was walked out.'
              : 'Marcus\'s attorney writes: he was fired during his notice period with no process and no stated cause, in retaliation for resigning. Pinnacle has nothing on paper to answer with.',
            score: { thoroughness: f.hrLegal ? -3 : -6 },
          });
          if (!f.custody) out.push({
            text: f.escorted
              ? 'Security carried ENGR-WS-12 to IT, where a technician logged in "to see what he had been doing." Last-access times on every file he touched are now overwritten.'
              : 'Nobody has imaged ENGR-WS-12. It has sat on the network since this morning while its event logs roll over.',
            score: { evidence: -8 },
          });
          if (f.evidenceDestroyed && !f.cloudPreserved) out.push({
            text: 'His Google Drive and MEGA copies are deleted and nobody asked either provider to preserve anything. What he uploaded now rests on your DLP logs alone.',
            score: { evidence: -5 },
          });
          if (f.evidenceDestroyed && f.cloudPreserved) out.push({
            sev: 'info',
            text: 'The provider records the FBI preserved log every upload — and every deletion. The clean-up is evidence too.',
          });
          if (f.fbiEarly && !f.subjectAlerted) out.push({
            sev: 'good',
            text: 'FBI agents have enough for a search-warrant affidavit on his home. They want this phase\'s package to finish it — and they need him not to know.',
          });
          return out;
        },
        narrative: f => [
          !f.accessCut && !f.exfilBlocked
            ? 'Marcus is still at his desk and still copying — blocking his VPN did nothing about the workstation in front of him.'
            : f.accessCut ? 'Marcus is off Pinnacle\'s network.' : 'Containment measures are limiting further data loss.',
          'Now determine the full scope: exactly what was taken, over what timeframe, and whether this is opportunistic or coordinated.',
          f.fbiEarly
            ? 'The FBI has been in since containment and wants a complete evidence package.'
            : 'Pinnacle\'s counsel has now contacted the FBI, which wants a complete evidence package.',
        ].join(' '),
        evidence: {
          title: 'HISTORICAL ACCESS ANALYSIS — 90-DAY LOOKBACK',
          content: f => `<span class="log-ok">── ACCESS PATTERN ANALYSIS ──</span>
<span class="log-warn">[90 days ago]</span> Baseline: mreeves 15-25 files/day, VPN weekdays only
<span class="log-warn">[30 days ago]</span> mreeves access pattern changed:
  New: 80-150 files/day across multiple ITAR directories<!--f:scopeCreep-->
  <span class="log-highlight">Accessed 12 projects outside his assigned scope</span><!--f:scopeCreep-->
<span class="log-warn">[30 days ago]</span> Exchange: inbox rule "ref" created on mreeves<!--f:fwdRule-->
  Action: forward all mail to mreeves@gmail.com<!--f:fwdRule-->
<span class="log-warn">[26 days ago]</span> VPN: mreeves — 38 sessions, normal hours
<span class="log-warn">[21 days ago]</span> First personal USB connection detected<!--f:dlpMonitor-->
  DLP policy USB-01: MONITOR ONLY — action log, no block<!--f:dlpMonitor-->
<span class="log-warn">[18 days ago]</span> Training: mreeves — annual ITAR awareness module completed
<span class="log-warn">[14 days ago]</span> Personal email used from work device (first time)
<span class="log-warn">[9 days ago]</span> Corporate mail: mreeves → h.zhao@zd-aerospace.com<!--f:foreignRecipient-->
  Subject: "Onboarding — reference package"<!--f:foreignRecipient-->
  Attachment: nav_filter_trade_study.pdf (ITAR-marked)<!--f:foreignRecipient-->
<span class="log-warn">[6 days ago]</span> HR: reference-check call from ZD Aerospace Solutions
<span class="log-warn">[Yesterday]</span> Resignation submitted — exfil volume spiked

<span class="log-ok">── TOTAL EXFILTRATION ESTIMATE (TO DETECTION) ──</span>
  USB transfers: ~12 GB over 21 days (7 sessions)
  Cloud uploads: ~4.3 GB (Google Drive + Mega.nz)
  Email attachments: ~340 MB (18 emails)
  Printed documents: ~280 pages
  <span class="log-highlight">Total: ~16.6 GB of proprietary/ITAR data</span>${f.itarFiles > INSIDER_ITAR_AT_HANDOFF ? `
  Since MSSP assignment: <span class="log-highlight">+${insiderNum(f.itarFiles - INSIDER_ITAR_AT_HANDOFF)} ITAR-marked files</span>` : ''}

<span class="log-ok">── COMPETITOR INTELLIGENCE ──</span>
  Destination: Zhentian Dynamics (HQ: Shenzhen, China)
  US subsidiary: ZD Aerospace Solutions, Arlington VA
  h.zhao: Director of Engineering, seconded from Shenzhen HQ<!--f:foreignRecipient-->
  Active contracts: Competing DoD UAV program`
        },
        choices: [
          {
            key: 'A',
            label: 'Full forensic investigation: complete file inventory, timeline reconstruction, competitor analysis for FBI',
            desc: 'Build the complete evidence package: every file accessed, every transfer, full timeline. Assess competitive damage. Prepare FBI referral.',
            quality: 'good',
            score: { time: -5, containment: 5, evidence: 25, thoroughness: 20 },
            sets: (f, st) => ({
              scope: 2, custody: true, custodyLate: f.custodyLate || !f.custody,
              itarFiles: f.itarFiles + insiderLeak(f, st.phaseClock),
              warrantSeized: f.fbiEarly && !f.subjectAlerted,
              fwdActive: f.fwdActive && !f.saw_fwdRule,
            }),
            outcome: (f, st) => {
              const itar = f.itarFiles + insiderLeak(f, st.phaseClock);
              return `Complete inventory: ${insiderNum(itar + INSIDER_PROPRIETARY)} files taken outside his normal duties across 4 channels over 21 days — ${insiderNum(itar)} ITAR-controlled, ${insiderNum(INSIDER_PROPRIETARY)} proprietary. `
                + (!f.custody ? (f.escorted
                  ? 'ENGR-WS-12 is finally imaged; the defense will make much of the IT technician\'s login, but the image is sound from here on. '
                  : 'ENGR-WS-12 is finally imaged — late, but under chain of custody from here on. ') : '')
                + (f.saw_gmailAttach ? 'The Exchange copy of "Reference Materials" is the one exhibit he could never delete. ' : '')
                + 'Competitive damage assessment shows the stolen designs directly relate to Zhentian\'s competing DoD bid. '
                + (f.saw_foreignRecipient ? 'The email to h.zhao@zd-aerospace.com put ITAR data in a foreign national\'s hands — that is an unlicensed export, not just a theft. ' : '')
                + (f.saw_fwdRule && f.fwdActive ? 'You have Exchange quietly delete the forwarding rule you found; his Gmail simply stops getting Pinnacle mail. ' : '')
                + 'FBI accepts referral. DCSA (Defense Counterintelligence) opens investigation.';
            },
          },
          {
            key: 'B',
            label: 'Focus on the ITAR-controlled files only — catalog what\'s export-controlled',
            desc: 'Prioritize the files that trigger federal jurisdiction. Skip the proprietary-but-uncontrolled files.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 10, thoroughness: 5 },
            sets: (f, st) => ({
              scope: 1,
              itarFiles: f.itarFiles + insiderLeak(f, st.phaseClock),
              warrantSeized: f.fbiEarly && f.custody && !f.subjectAlerted,
            }),
            outcome: (f, st) => `ITAR file inventory completed: ${insiderNum(f.itarFiles + insiderLeak(f, st.phaseClock))} controlled files confirmed exfiltrated. Sufficient for FBI referral. But you miss ${insiderNum(INSIDER_PROPRIETARY)} proprietary files that, while not ITAR, represent significant trade secret theft. Pinnacle's civil litigation case against Zhentian is weaker without the full picture. The competitive damage goes beyond just the controlled files.`
              + (f.custody ? '' : ' And nobody images ENGR-WS-12 — the catalogue is built from DLP logs and file-server audit trails alone.'),
          },
          {
            key: 'C',
            label: 'Just document the DLP alerts and let the FBI handle the investigation',
            desc: 'Hand over the DLP logs and let law enforcement do the forensics.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: -15, thoroughness: -15 },
            sets: (f, st) => ({ scope: 0, evidenceDestroyed: true, itarFiles: f.itarFiles + insiderLeak(f, st.phaseClock) }),
            outcome: 'DLP logs alone don\'t tell the complete story — they show alerts but not the full file inventory or historical access pattern. The FBI asks for forensic images and a complete timeline you don\'t have. By the time a warrant is obtained for the employee\'s personal devices, data has been wiped. The criminal case is weakened. Pinnacle is frustrated by the incomplete evidence.',
          },
          {
            key: 'D',
            when: f => f.saw_foreignRecipient,
            label: 'Full forensic package, and map every ITAR file to its USML paragraph and to each foreign person who received it',
            desc: 'Everything in the full investigation, plus the export-control scoping a DDTC disclosure has to contain: what, under which category, to whom.',
            quality: 'good',
            score: { time: -5, containment: 5, evidence: 30, thoroughness: 25 },
            sets: (f, st) => ({
              scope: 2, recipientMapped: true, custody: true, custodyLate: f.custodyLate || !f.custody,
              itarFiles: f.itarFiles + insiderLeak(f, st.phaseClock),
              warrantSeized: f.fbiEarly && !f.subjectAlerted,
              fwdActive: f.fwdActive && !f.saw_fwdRule,
            }),
            outcome: (f, st) => {
              const itar = f.itarFiles + insiderLeak(f, st.phaseClock);
              return `Complete inventory: ${insiderNum(itar + INSIDER_PROPRIETARY)} files over 21 days, ${insiderNum(itar)} of them ITAR-controlled — and each controlled file mapped to its USML category and paragraph and to where it went. One recipient matters above all: h.zhao, seconded from Zhentian's Shenzhen HQ, a PRC national. Releasing ITAR data to him in Arlington is an export to China, a §126.1 proscribed country. `
                + (!f.custody ? 'ENGR-WS-12 is finally imaged — late, but under chain of custody from here on. ' : '')
                + (f.saw_fwdRule && f.fwdActive ? 'Exchange quietly deletes the forwarding rule you found. ' : '')
                + 'FBI accepts referral with an export count on the table. DCSA opens investigation.';
            },
          },
        ],
        live: (f, st) => (!f.accessCut && !f.exfilBlocked)
          ? `ITAR FILES OUT: ${insiderNum(f.itarFiles + insiderLeak(f, st.phaseClock))} · STILL COPYING`
          : (!f.subjectAlerted && f.fwdActive ? 'HIS MAIL STILL FORWARDS TO GMAIL · SUBJECT UNAWARE' : `ITAR FILES OUT: ${insiderNum(f.itarFiles)}`),
        timeline: [
          { at: 6, when: f => !f.accessCut && !f.exfilBlocked, sev: 'crit', text: 'ENGR-WS-12: 116 more ITAR files to USB volume F:', score: { containment: -3 } },
          { at: 12, when: f => !f.subjectAlerted && f.fwdActive, sev: 'crit',
            text: f => f.exfilBlocked
              ? 'Exchange: rule "ref" forwards IT notice "ITAR share permissions changed — access review" to mreeves@gmail.com'
              : 'Exchange: rule "ref" forwards "Security stand-down Friday — ITAR handling" to mreeves@gmail.com',
            sets: f => ({ subjectAlerted: true, alertedAt: f.alertedAt || 'INVESTIGATION', evidenceDestroyed: true }),
            score: { evidence: -5 } },
        ],
        siemEntries: [
          { time: '14:00', sev: 'info', text: 'Investigation: 90-day historical access analysis' },
          { time: '14:15', sev: 'crit', text: '16.6 GB total exfiltration over 21 days — 4 channels' },
          { time: '14:20', sev: 'warn', text: 'Competitor: Zhentian Dynamics — foreign-owned, competing DoD bid' },
          { time: '14:25', sev: 'crit', text: 'ITAR violation confirmed — FBI referral recommended' },
        ],
      },
      { // ERADICATION
        name: 'ERADICATION',
        // The warrant runs at 06:10 the next morning; two days later if the forward tipped him first
        at: f => f.warrantSeized ? 1440 - 150 : f.alertedAt === 'INVESTIGATION' && f.fbiEarly ? 3 * 1440 - 150 : 0,
        carried: f => {
          const out = [];
          if (f.warrantSeized) out.push({
            sev: 'good',
            text: f.saw_usb
              ? '06:10 — FBI agents execute a search warrant at his home. Seized: a laptop, a NAS, and the SanDisk Ultra 256GB, serial 4C530001240615117421, named in the warrant.'
              : '06:10 — FBI agents execute a search warrant at his home. Seized: a laptop, a NAS and three USB drives. Nobody recorded the SanDisk\'s serial, so agents are still working out which one was in ENGR-WS-12.',
            score: { evidence: f.saw_usb ? 8 : 5 },
          });
          if (f.alertedAt === 'INVESTIGATION') out.push({
            text: f.fbiEarly
              ? 'His forwarding rule put a Pinnacle-wide notice in his Gmail, and he read it for what it was. When agents executed their warrant two days later they found a freshly reimaged laptop and no USB drives.'
              : 'His forwarding rule put a Pinnacle-wide notice in his Gmail, and he read it for what it was. That night his home laptop was reimaged.',
            score: { evidence: -5 },
          });
          if (f.scope < 1) out.push({
            text: 'The FBI case agent asks for forensic images and a file inventory. There are none; the referral goes into a queue.',
            score: { evidence: -5 },
          });
          return out;
        },
        narrative: f => (f.warrantSeized
          ? 'The FBI has executed its warrant and the investigation package is complete. '
          : 'The investigation is complete and the FBI has been briefed. ')
          + 'Now ensure all unauthorized access is fully revoked and the insider\'s footprint is cleaned from all systems. '
          + (f.escorted
            ? 'He is already off the site; HR is papering the termination with counsel after the fact.'
            : 'Legal has approved terminating the employee effective immediately — HR and counsel will run the termination meeting; your job is to make the access cut-over land the minute it starts.'),
        evidence: {
          title: 'ACCESS & ARTIFACT INVENTORY',
          content: f => `<span class="log-highlight">ACCOUNTS & ACCESS:</span>
  - AD account: mreeves (${f.accessCut ? 'disabled' : 'active, notice period'})
  - Badge access: Buildings A, B, C, Engineering Lab, Server Room${f.accessCut ? ' (building entry suspended; lab and server-room grants still provisioned)' : ''}
  - VPN: Full tunnel access to engineering network
  - Cloud: Confluence, Jira, SharePoint, OneDrive (corporate)
  - Source control: GitLab — 14 repositories (3 holding ITAR technical data), personal access token valid
  - AWS: IAM user (not federated to AD) — dev environment, access keys active

<span class="log-highlight">SHARED CREDENTIALS:</span>
  - mreeves had access to 3 shared engineering accounts
  - Lab equipment with shared PINs (not rotated)
  - Wi-Fi PSK for engineering VLAN (shared key)

<span class="log-highlight">PERSONAL ARTIFACTS ON CORPORATE SYSTEMS:</span>
  - Browser: saved passwords to personal accounts
  - OneDrive: personal files mixed with corporate
  - Email: forwarding rule to personal Gmail (set up 30 days ago) — ${f.fwdActive ? '<span class="log-highlight">ACTIVE</span>' : 'removed'}`
        },
        choices: [
          {
            key: 'A',
            label: 'Full deprovisioning: disable all accounts, revoke badges, rotate shared creds, remove forwarding rules',
            desc: 'Complete access revocation across every system. Rotate any shared credentials the employee knew. Remove all persistence (email forwarding, saved sessions).',
            quality: 'good',
            score: { time: 5, containment: 15, evidence: 5, thoroughness: 20 },
            sets: { accessCut: true, fwdActive: false, credsRotated: true },
            outcome: f => (f.escorted
              ? 'HR sends the termination letter and a property-return demand by courier. '
              : 'HR and counsel hold the termination meeting; he is asked to return company property and certify he holds no Pinnacle data, and on his lawyer\'s advice he declines to sign. The MSSP\'s part is the cut-over, timed to the minute the meeting starts. ')
              + 'AD account disabled, all cloud sessions revoked, badge access terminated across all buildings. Shared engineering accounts rotated. Lab PINs changed. Engineering VLAN Wi-Fi key rotated. '
              + (f.fwdActive ? 'Email forwarding rule removed. ' : '')
              + 'GitLab access revoked and personal access tokens rotated; the AWS IAM user, which never touched AD, is deleted and its keys revoked. '
              + (f.saw_printJob ? 'The return demand lists the 38-page UAV_nav_architecture.pdf printout you logged. ' : '')
              + 'Complete offboarding in 45 minutes — no residual access.',
          },
          {
            key: 'B',
            label: 'Disable AD account and revoke badge access, handle the rest later',
            desc: 'Quick lockout from the primary systems. Clean up shared creds during the next maintenance window.',
            quality: 'partial',
            score: { time: 10, containment: 5, evidence: 0, thoroughness: -5 },
            sets: f => ({ accessCut: true, fwdActive: f.fwdActive && !f.saw_fwdRule }),
            outcome: f => 'Primary access disabled. '
              + (f.fwdActive && !f.saw_fwdRule
                ? 'But the email forwarding rule continues sending copies of engineering team emails to his personal Gmail until someone notices. '
                : f.fwdActive ? 'The forwarding rule you documented goes on the same change ticket and is deleted. ' : '')
              + 'Shared credentials aren\'t rotated — if the employee memorized them, he could still access lab equipment or the engineering VLAN from the parking lot.',
          },
          {
            key: 'C',
            label: 'Just disable the AD account — standard offboarding will handle the rest on his last day',
            desc: 'Let the normal HR offboarding process run its course.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: -5, thoroughness: -20 },
            sets: f => ({ accessCut: true, fwdActive: f.fwdActive && !f.saw_fwdRule, parkingLot: true, itarFiles: f.itarFiles + 85 }),
            outcome: f => 'AD disabled but everything else stays active. '
              + (f.fwdActive && !f.saw_fwdRule
                ? 'The email forwarding rule keeps sending engineering team communications to his personal Gmail — including discussions about the incident investigation itself. '
                : '')
              + 'He connects to the engineering Wi-Fi from the parking lot using the shared key and accesses a lab workstation with a shared PIN. 85 more ITAR files are exfiltrated before anyone notices.',
          },
        ],
        live: f => f.fwdActive ? 'FORWARD RULE → mreeves@gmail.com: ACTIVE' : 'SHARED LAB CREDENTIALS & WI-FI KEY: UNROTATED',
        timeline: [
          { at: 10, when: f => f.fwdActive, sev: 'crit', text: 'Exchange: rule "ref" forwards "Who has the UAV guidance baseline?" thread to mreeves@gmail.com', score: { containment: -3 } },
        ],
        siemEntries: f => [
          { time: '15:30', sev: 'info', text: 'Eradication: full access revocation for mreeves' },
          { time: '15:35', sev: f.accessCut ? 'info' : 'success', text: f.accessCut ? 'AD account already disabled — auditing non-AD access' : 'AD account disabled, all sessions revoked' },
          { time: '15:40', sev: 'warn', text: f.fwdActive ? 'Email forwarding rule to personal Gmail still active — 30 days old' : 'Email forwarding rule to personal Gmail — already removed' },
        ],
      },
      { // RECOVERY
        name: 'RECOVERY',
        // What eradication left running gets a day to do its damage
        at: (f, st) => (f.fwdActive || f.parkingLot) ? st.elapsed + 1440 : 0,
        carried: f => {
          const out = [];
          if (f.fwdActive) out.push({
            text: 'The forwarding rule has run for a full day since eradication, delivering engineering-team mail to his Gmail — including a thread about the investigation itself.',
            score: { containment: -10 },
          });
          if (f.parkingLot) out.push({
            text: 'Overnight the Wi-Fi controller logged his personal laptop on the engineering VLAN from the parking lot, using the shared key. 85 more ITAR files went out through a lab workstation with a shared PIN.',
            score: { containment: -10 },
          });
          if (!f.credsRotated && !f.parkingLot) out.push({
            sev: 'info',
            text: 'Shared lab accounts, PINs and the engineering Wi-Fi key are still the ones he knew.',
          });
          return out;
        },
        narrative: f => (f.fwdActive || f.parkingLot || !f.credsRotated
          ? 'The insider\'s primary access is revoked, though not every door is shut. '
          : 'The insider\'s access is fully revoked. ')
          + 'Now Pinnacle needs to assess the damage, protect their competitive position, and ensure their DoD contract compliance. HSI (Homeland Security Investigations), which leads most ITAR criminal cases, has joined the FBI; DCSA is watching the facility clearance.',
        evidence: {
          title: 'RECOVERY & COMPLIANCE STATUS',
          content: f => `<span class="log-ok">ACCESS STATUS:</span>
  - All insider accounts disabled ✓
  - Shared credentials rotated: ${f.credsRotated ? '✓' : '<span class="log-highlight">NO ✗</span>'}
  - Mail forwarding to personal Gmail: ${f.fwdActive ? '<span class="log-highlight">STILL RUNNING ✗</span>' : 'removed ✓'}

<span class="log-warn">COMPETITIVE DAMAGE:</span>
  - ITAR-controlled files exfiltrated: ${insiderNum(f.itarFiles)}
  - Proprietary files: ${f.scope >= 2 ? `${insiderNum(INSIDER_PROPRIETARY)} (inventoried)` : '<span class="log-highlight">not inventoried</span>'}
  - Zhentian competing for same DoD UAV contract
  - Bid submission deadline: 45 days
  - Stolen designs overlap 60% with bid technical approach

<span class="log-warn">SCOPE AVAILABLE FOR DISCLOSURE:</span>
  - Files: ${f.scope >= 2 ? 'file-level inventory' : f.scope === 1 ? 'ITAR files catalogued' : '<span class="log-highlight">DLP alerts only</span>'}${f.recipientMapped ? ', mapped to USML paragraphs' : ''}
  - Programs: ${[f.saw_bulkRead && 'F-35 avionics', f.saw_uavGuidance && 'UAV guidance'].filter(Boolean).join(', ') || '<span class="log-highlight">not documented</span>'}
  - Foreign recipient: ${f.saw_foreignRecipient ? 'h.zhao@zd-aerospace.com (PRC national)' : '<span class="log-highlight">not identified</span>'}

<span class="log-warn">EVIDENCE:</span>
  - Workstation: ${f.custody ? (f.custodyLate ? 'imaged late' : 'imaged, chain of custody intact') : '<span class="log-highlight">never imaged</span>'}
  - His copies: ${f.warrantSeized ? 'seized under FBI warrant' : f.evidenceDestroyed ? (f.cloudPreserved ? 'wiped; provider records preserved' : '<span class="log-highlight">wiped / deleted</span>') : 'in his possession'}

<span class="log-warn">COMPLIANCE:</span>
  - ITAR violation: Voluntary disclosure to DDTC (§127.12) recommended
  - DoD contract: DFARS 252.204-7012 cyber incident report (72 hours)
  - Must demonstrate adequate security controls were in place
  - DLP was in monitor-only mode (not blocking)`
        },
        choices: [
          {
            key: 'A',
            label: 'Self-disclose to DDTC, file DFARS report, brief the DoD program office, engage trade secret counsel',
            desc: 'Full compliance response: voluntary disclosure to State Dept, mandatory DoD notification, program office briefing, and initiate trade secret litigation prep.',
            quality: 'good',
            score: { time: 5, containment: 5, evidence: 10, thoroughness: 20 },
            sets: f => ({ ddtc: insiderDdtcFull(f) ? 'full' : 'initial' }),
            outcome: f => (insiderDdtcFull(f)
              ? `DDTC voluntary disclosure filed: ${insiderNum(f.itarFiles)} files${f.recipientMapped ? ' mapped to USML paragraphs' : ''}, the programs they came from, and the foreign person who received them. Complete and accurate, it demonstrates good faith — the strongest mitigation DDTC recognizes. `
              : `DDTC receives an initial notification inside the window, but it cannot say ${[f.scope < 1 && 'which files left', !f.saw_foreignRecipient && 'who received them'].filter(Boolean).join(' or ')}. The full disclosure is due within 60 days and must be rebuilt, and one DDTC later finds incomplete loses much of its mitigating weight. `)
              + 'DFARS cyber incident report submitted within 72 hours. DoD program office briefed on potential compromise of bid-relevant designs. '
              + (f.scope >= 2
                ? 'Trade secret counsel begins emergency TRO preparation against Zhentian with the full file inventory behind it. '
                : `Trade secret counsel begins TRO preparation, but without an inventory of the ${insiderNum(INSIDER_PROPRIETARY)} proprietary files the motion leans on the ITAR material alone. `)
              + 'Pinnacle\'s proactive response preserves their contract eligibility.',
          },
          {
            key: 'B',
            label: 'File the mandatory DFARS report and handle ITAR disclosure later',
            desc: 'Meet the 72-hour DoD requirement. Deal with State Dept on a longer timeline.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 5, thoroughness: 5 },
            sets: { ddtc: 'late' },
            outcome: 'DFARS report filed on time. But delaying the ITAR disclosure to DDTC increases regulatory risk — a prompt, complete voluntary disclosure is the single biggest mitigating factor in how DDTC sets civil penalties of up to $1.3M per violation, and every week of delay makes it look less voluntary. Without the trade secret TRO, Zhentian may have time to integrate the stolen designs into their competing bid.',
          },
          {
            key: 'C',
            label: 'Let legal handle all the regulatory stuff — focus on hardening DLP to blocking mode',
            desc: 'Technical hardening is the priority. Legal and compliance teams can handle notifications.',
            quality: 'bad',
            score: { time: 15, containment: -10, evidence: -5, thoroughness: -15 },
            sets: { ddtc: 'directed' },
            outcome: 'DLP set to blocking — good, but the horse has already left the barn. Without your technical findings driving the regulatory response, legal files incomplete reports. The DFARS report misses the 72-hour window. DDTC learns about the ITAR violation from the FBI investigation rather than voluntary disclosure — maximum penalties apply. Pinnacle\'s contracting officer questions their security program.',
          },
          {
            key: 'D',
            when: f => f.saw_usb && !f.warrantSeized,
            label: 'Full compliance response — and have counsel demand the SanDisk and his personal devices for a neutral forensic examiner',
            desc: 'You have the drive\'s serial number. Counsel can demand that exact device, and his laptop, under a stipulated inspection protocol.',
            quality: 'good',
            score: { time: 5, containment: 10, evidence: 15, thoroughness: 20 },
            sets: f => ({ ddtc: insiderDdtcFull(f) ? 'full' : 'initial', deviceExam: true }),
            outcome: f => (insiderDdtcFull(f)
              ? 'DDTC voluntary disclosure filed, complete as to files and recipient. '
              : 'DDTC gets an initial notification; the full disclosure still has gaps to fill within 60 days. ')
              + 'DFARS report in on time, program office briefed, TRO preparation under way. Counsel\'s demand names the SanDisk by serial number; under a stipulated protocol his lawyer produces it and his laptop to a neutral examiner. '
              + (f.evidenceDestroyed
                ? 'Both were wiped or destroyed after he was tipped off, and the examiner documents exactly that. In the civil case it is spoliation: the court can instruct the jury to presume the destroyed data was what Pinnacle says it was.'
                : 'The examiner finds the ITAR files on the SanDisk and a synced MEGA client on the laptop. Both are sequestered, and his lawyer starts talking about cooperation.'),
          },
        ],
        live: 'DFARS 72-HOUR REPORTING WINDOW: OPEN',
        timeline: [
          { at: 10, sev: 'warn', text: 'HR: ZD Aerospace reference-check call — his start date moved up to Monday', score: { containment: -3 } },
        ],
        siemEntries: [
          { time: '16:30', sev: 'info', text: 'Recovery: regulatory compliance and competitive damage assessment' },
          { time: '16:35', sev: 'warn', text: 'DFARS 72-hour reporting deadline approaching' },
          { time: '16:40', sev: 'crit', text: 'ITAR voluntary disclosure to DDTC recommended — major penalty mitigation' },
        ],
      },
      { // POST-INCIDENT
        name: 'POST-INCIDENT',
        carried: f => {
          const out = [];
          if (f.ddtc === 'directed') out.push({
            text: 'DDTC heard about the export from the FBI, not from Pinnacle. It has opened its own inquiry, and no voluntary-disclosure mitigation applies.',
            score: { thoroughness: -10 },
          });
          if (f.ddtc === 'late') out.push({
            text: 'The DDTC disclosure still has not been filed. Counsel warns that the longer it waits, the less voluntary it looks.',
            score: { thoroughness: -5 },
          });
          if (!f.warrantSeized && !f.deviceExam) out.push({
            text: f.evidenceDestroyed
              ? 'No copy of the stolen data has been recovered. He wiped what could be examined; whatever he kept is beyond Pinnacle\'s reach.'
              : 'No copy of the stolen data has been recovered. Whatever he took, he still holds.',
            score: { containment: -5 },
          });
          return out;
        },
        narrative: 'The immediate crisis is managed — access revoked, FBI engaged, regulatory notifications in progress. Pinnacle\'s CISO wants a comprehensive review of how this happened and what needs to change. The board is rattled.',
        evidence: {
          title: 'INCIDENT METRICS',
          content: (f, st) => `<span class="log-ok">TIMELINE:</span>
  Exfil started:     21 days before detection
  Resignation:       Day 0 (yesterday)
  DLP alerts:        Day 0 (escalated to MSSP)
  Containment:       Day 1 (today)
  FBI referral:      Day 1
  Subject tipped:    ${f.alertedAt ? `during ${f.alertedAt}` : 'not before termination'}
  Time on incident:  ${formatElapsed(st.elapsed)}

<span class="log-warn">DATA LOSS:</span>
  ITAR files exfiltrated:   ${insiderNum(f.itarFiles)} (${insiderNum(f.itarFiles - INSIDER_ITAR_AT_HANDOFF)} after MSSP assignment)
  Proprietary files:        ${f.scope >= 2 ? insiderNum(INSIDER_PROPRIETARY) : 'not inventoried'}
  Copies recovered:         ${f.warrantSeized ? 'seized under warrant' : f.deviceExam ? 'produced to neutral examiner' : 'none'}

<span class="log-warn">ROOT CAUSES:</span>
  1. DLP in monitor-only mode — never switched to blocking
  2. No automated departure risk flagging (HR → Security)
  3. Excessive access scope — files outside assigned projects accessible
  4. No USB device control policy
  5. Shared credentials for lab equipment and Wi-Fi
  6. Insider threat program on paper only — no user activity monitoring or behavioral analytics
  7. Personal cloud/webmail accessible from engineering workstations
  8. No alerting on mailbox rules that forward externally

<span class="log-warn">FINANCIAL EXPOSURE:</span>
  - ITAR penalties: Up to $1.3M per violation — ${f.ddtc === 'full' ? 'voluntary disclosure filed' : f.ddtc === 'initial' ? 'initial notification filed, full disclosure due in 60 days' : f.ddtc === 'late' ? 'disclosure not yet filed' : '<span class="log-highlight">no voluntary-disclosure mitigation</span>'}
  - Trade secret damages: Estimated $45M competitive value
  - Investigation costs: ~$180K (MSSP + legal + forensics)
  - Contract risk: DoD may reassess contractor eligibility`
        },
        choices: [
          {
            key: 'A',
            label: 'Full report with insider threat program design, DLP remediation plan, and compliance roadmap',
            desc: 'Comprehensive post-incident: root cause analysis, insider threat program recommendations, DLP overhaul, access governance model, and regulatory compliance roadmap.',
            quality: 'good',
            // Recommendations tied to documented artefacts carry more weight
            score: (f, st) => ({
              time: 5, containment: 5,
              evidence: 10 + Math.min(5, st.findings.length),
              thoroughness: 25 + Math.min(5, 2 * [f.saw_scopeCreep, f.saw_dlpMonitor, f.saw_afterHours || f.saw_homeIp, f.saw_fwdRule].filter(Boolean).length),
            }),
            outcome: f => {
              const tied = [
                f.saw_scopeCreep && 'need-to-know ACLs on ITAR shares (he read 12 projects he was never on)',
                f.saw_dlpMonitor && 'DLP moved to blocking, with 21 days of logged-but-allowed USB copies as the business case',
                (f.saw_afterHours || f.saw_homeIp) && 'user activity monitoring that correlates badge and logon records',
                f.saw_fwdRule && 'alerting on any mailbox rule that forwards outside the company',
              ].filter(Boolean);
              return 'Report drives creation of a real insider threat program under the existing ITPSO — user activity monitoring and behavioral analytics, automated HR-to-Security triggers on resignation, DLP in blocking mode, USB device control, network segmentation for ITAR systems, and elimination of shared credentials. '
                + (tied.length >= 2
                  ? `Each recommendation is tied to an artefact from this case: ${tied.join('; ')}. `
                  : 'The recommendations are sound but generic — few are tied to anything documented in this case, and the CISO has to argue each one from first principles. ')
                + 'Board approves $1.2M security investment. DoD contracting officer is satisfied with the remediation plan. '
                + (f.ddtc === 'directed' || f.ddtc === 'late'
                  ? 'DCSA\'s review is less forgiving: with the DDTC disclosure missing, the program reads as something written after the fact.'
                  : 'DCSA review concludes favorably.');
            },
          },
          {
            key: 'B',
            label: 'Standard report with DLP recommendations and access control improvements',
            desc: 'Focus on the technical gaps. Cover DLP, USB controls, and access management.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 5, thoroughness: 5 },
            outcome: 'Technical recommendations implemented: DLP blocking, USB control, tighter ACLs. But without the insider threat program and HR integration, Pinnacle remains vulnerable to the same pattern — they\'ll catch the next insider faster but won\'t prevent the behavior. The DoD wants to see a more comprehensive program.',
          },
          {
            key: 'C',
            label: 'Close the incident — the FBI is handling it from here',
            desc: 'Law enforcement has the case. Pinnacle just needs to cooperate with the investigation.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: -10, thoroughness: -25 },
            outcome: 'No lessons learned, no program improvements. Three months later, another engineer downloads proprietary data before joining a competitor — this time it\'s caught earlier by DLP but the same systemic gaps exist. DCSA\'s next review rates Pinnacle\'s insider threat program inadequate and puts its facility clearance under scrutiny.',
          },
        ],
        siemEntries: [
          { time: '18:00', sev: 'info', text: 'Post-incident: program review and recommendations' },
          { time: '18:05', sev: 'warn', text: 'Root cause: insider threat program on paper only, DLP monitor-only' },
          { time: '18:10', sev: 'info', text: 'Board briefing scheduled — CISO requesting full report' },
        ],
      },
    ],
  }
);
