// Supply Chain Compromise — Backdoored Software Update
// Scenario data for PumaResponse — format documented in README → Development.

// SUPPLY_CHAIN: how far npext.dll's second stage has spread, t minutes into the
// Triage decision — [at, hosts carrying Cobalt Strike, patient records reached].
// Three hosts (DB-PROD-01, DC-01, EXEC-WS-04) and the EMR's 180,000 patients were
// already hit at handoff; the stager keeps pulling tooling onto *PROD*/*DC*/*EXEC*
// hosts, and each new PHI system it reaches adds patients the EMR doesn't hold.
const SC_STAGE = [[0, 3, 180000], [6, 7, 180000], [12, 12, 180000], [20, 18, 218000], [35, 26, 218000], [60, 33, 251000], [120, 47, 251000]];
function scStage(t) {
  const [, hosts, records] = SC_STAGE.filter(([at]) => t >= at).pop();
  return { hosts, records };
}
function scN(n) {
  return Math.round(n).toLocaleString('en-US');
}
// Would an update signed with NetPulse's stolen key install on Vertex endpoints?
function scFakeUpdateLands(f) {
  return !f.agentUninstalled && f.updateTrusted && !f.hashPinned && !f.certRevoked;
}
// Is there still a way back in for the attacker?
function scFoothold(f) {
  return (f.lateral > 0 && !f.lateralFound) || (f.krbtgtStolen && !f.krbtgtReset)
    || (f.reinfected > 0 && !f.reinfectContained);
}
// HIPAA notification as filed. how: 'mssp' (your findings feed it) or 'client' (compliance alone)
function scNotifyStatus(f, how) {
  const exposed = f.recordsExposed;
  const told = how === 'client' ? 180000 : (f.scopedRecords || 180000);
  const timing = f.notifyPrepped ? 'filed day 41 of 60' : 'filed day 58 of 60';
  if (told < exposed) return `UNDER-REPORTED — ${scN(told)} notified of ${scN(exposed)} exposed · ${timing}`;
  if (how === 'client') return `${scN(told)} notified by client compliance — data types and dates incomplete · ${timing}`;
  if (!f.scopePrecise) return `${scN(told)} notified on a presumptive scope · HHS/OCR + media · ${timing}`;
  return `Accurate — ${scN(told)} notified · HHS/OCR + media · ${timing}`;
}

registerIncident(
  {
    id: 'SUPPLY_CHAIN',
    title: 'Supply Chain Compromise — Backdoored Software Update',
    client: 'Vertex Healthcare Systems',
    severity: 'CRITICAL',
    sevClass: 'high',
    ticketId: 'IR-2024-1102',
    // In-world "today": every date in this file is written relative to it and
    // shown shifted to the real date (see REAL-DATE ANCHORING in js/game.js)
    baseDate: '2024-03-15',
    assignedTime: '09:15 UTC',
    summary: 'Trusted IT monitoring agent (NetPulse RMM) pushed backdoored update to 340+ endpoints. Beacon traffic detected to unknown C2. Patient data systems potentially accessed.',
    iocs: [
      { type: 'FILE HASH', val: 'e4f7a1b2c3d5...9f0e (SHA256) — trojanized NetPulse update' },
      { type: 'IP', val: '198.51.100.47 — C2 beacon (HTTPS)' },
      { type: 'IP', val: '203.0.113.88 — secondary staging server' },
      { type: 'DOMAIN', val: 'update-netpulse[.]com — spoofed update domain' },
      { type: 'PROCESS', val: 'netpulse-svc.exe — legitimate name, illegitimate payload' },
      { type: 'CERT', val: 'Signed with stolen NetPulse code-signing certificate' },
    ],
    // Run state. Every later phase reads these; choices change them via `sets`.
    initialFlags: {
      hostsStaged: 3,          // hosts carrying second-stage tooling (Cobalt Strike) — 3 at handoff
      recordsExposed: 180000,  // distinct patients whose PHI the attacker reached
      c2Blocked: false,        // 198.51.100.47 and 203.0.113.88 blocked at the firewall
      attackerTipped: false,   // the attacker read our vendor ticket and ran anti-forensics
      agentUninstalled: false, // NetPulse removed with its uninstaller (install dir wiped)
      evidenceLost: false,     // npext.dll samples / install-dir artefacts destroyed
      memoryCaptured: false,   // RAM from DC-01 and DB-PROD-01 imaged before isolation
      dcContained: false,      // DC-01 isolated, cutting its Cobalt Strike implant off
      krbtgtStolen: false,     // DCSync ran on DC-01 — the attacker holds the krbtgt hash
      krbtgtReset: false,      // krbtgt double-reset done
      lateral: 0,              // hosts Cobalt Strike reached over SMB, outside the npext beacon list
      lateralFound: false,     // those hosts were identified (hunt or forensics)
      hashPinned: false,       // app control moved NetPulse from publisher trust to a hash pin
      certRevoked: false,      // the CA revoked NetPulse's stolen code-signing certificate
      updateTrusted: true,     // endpoints still take NetPulse updates on the publisher's word
      reinfected: 0,           // hosts that installed the fake "v4.2.3" signed with the stolen key
      reinfectContained: false,// ...and it was caught and removed
      ransomware: false,       // waited on the vendor; the attacker detonated on day 4
      emrHardDown: false,      // EMR crash-stopped across all three hospitals
      scopedRecords: 0,        // patients the investigation can put in the notification
      scopePrecise: false,     // scope rests on a record-level SQL audit trail
      vendorCoordinated: false,// NetPulse got our findings the same day
      cisaShared: false,       // CISA / HHS HC3 / Health-ISAC got the IOC package
      notifyPrepped: false,    // HIPAA notification work started in recovery
      notifyStatus: '',        // how the HIPAA notification actually went out
    },
    // 2 real seconds per game minute once the decision clock starts; 10-minute par
    clock: { rate: 0.5, par: 10 },
    // Best achievable total (every finding tagged, instant decisions, best path).
    // Grades are a percentage of this. Recompute with tools/scenario-harness.js after
    // changing this scenario's scores, carried penalties or findings.
    bestScore: 343,
    // MITRE ATT&CK (Enterprise v19) technique per finding, shown in the debrief.
    // Findings that aren't adversary behavior (missing controls, business facts) are omitted.
    attack: {
      npext: "T1195.002 Supply Chain Compromise: Compromise Software Supply Chain",
      signCert: "T1553.002 Subvert Trust Controls: Code Signing",
      staging: "T1071.001 Application Layer Protocol: Web Protocols",
      c2ip: "T1071.001 Application Layer Protocol: Web Protocols",
      dbprod: "T1071.001 Application Layer Protocol: Web Protocols",
      credTheft: "T1003.001 OS Credential Dumping: LSASS Memory",
      healthCheck: "T1543.003 Create or Modify System Process: Windows Service",
      dnsFallback: "T1008 Fallback Channels",
      patientsQuery: "T1213.006 Data from Information Repositories: Databases",
      exfil: "T1041 Exfiltration Over C2 Channel",
      antiForensics: "T1070.004 Indicator Removal: File Deletion",
      buildServer: "T1195.002 Supply Chain Compromise: Compromise Software Supply Chain",
      keyTheft: "T1552.004 Unsecured Credentials: Private Keys",
      lateralCS: "T1543.003 Create or Modify System Process: Windows Service",
      sqlAudit: "T1213.006 Data from Information Repositories: Databases",
      auditGap: "T1685 Disable or Modify Tools",
    },
    debrief: f => [
      ['Endpoints Compromised', `342 took the trojanized update · ${f.hostsStaged} carried second-stage tooling`
        + (f.reinfected > 0 ? ` · ${f.reinfected} reinfected` : '') + (f.ransomware ? ' · 64 encrypted' : '')],
      ['Patient Records Exposed', scN(f.recordsExposed)],
      ['Re-infection Risk', f.reinfected > 0 && !f.reinfectContained ? `REINFECTED — fake v4.2.3 live on ${f.reinfected} hosts`
        : f.reinfected > 0 ? 'Reinfection caught in recovery; update path now closed'
        : f.agentUninstalled ? 'None — agent uninstalled (with the evidence)'
        : f.certRevoked ? 'Closed — stolen certificate revoked by the CA'
        : f.hashPinned ? 'Closed — NetPulse pinned by hash, not publisher'
        : !f.updateTrusted ? 'Closed — NetPulse update channel disabled'
        : 'OPEN — endpoints trust anything the stolen key signs'],
      ['HIPAA Notification', f.notifyStatus || 'Not filed'],
      ['Attacker Access at Close', scFoothold(f) ? 'STILL PRESENT' : 'Removed'],
    ],
    phases: [
      { // TRIAGE
        name: 'TRIAGE',
        narrative: 'Your threat intelligence feed flagged anomalous beacon traffic from multiple Vertex Healthcare endpoints to an IP with no prior reputation. Investigation reveals all beaconing hosts received a NetPulse RMM agent update 6 hours ago. NetPulse is a trusted vendor — their updates are whitelisted. The update binary is signed with a valid NetPulse certificate but contains an embedded DLL that wasn\'t in previous versions.',
        evidence: {
          title: 'BEACON ANALYSIS — NETWORK TELEMETRY',
          content: `<span class="log-warn">[03:12:00]</span> NetPulse auto-update pushed: v4.2.1 → v4.2.2
<span class="log-warn">[03:12:02]</span> Package SHA256 e4f7a1b2c3d5...9f0e (v4.2.1: 7c21d0e9...a04d)<!--f:npext-->
<span class="log-warn">[03:14:33]</span> 342 endpoints received update (all managed hosts)
<span class="log-ok">[03:14:40]</span> App control: v4.2.2 allowed by publisher rule "NetPulse Software, Inc."<!--f:signCert-->
<span class="log-ok">[04:00:00]</span> WSUS sync complete — 12 Windows updates approved
<span class="log-warn">[05:44:02]</span> npext.dll GET hxxps://update-netpulse[.]com/cfg/7731 — 200 (18 KB)<!--f:staging-->
<span class="log-ok">[07:30:11]</span> Proxy: 1,204 hosts → login.microsoftonline.com (baseline)
<span class="log-warn">[09:01:44]</span> <span class="log-highlight">ALERT</span> TI match: 198.51.100.47 — no prior reputation<!--f:c2ip-->
<span class="log-warn">[09:02:01]</span> Beacon interval: 300s ± jitter, HTTPS port 443<!--f:c2ip-->
<span class="log-ok">[09:02:30]</span> DNS: 342 hosts → telemetry.netpulse.io (normal agent check-in)
<span class="log-warn">[09:03:15]</span> <span class="log-highlight">CRITICAL</span> 47 hosts beaconing to 198.51.100.47
<span class="log-warn">[09:04:00]</span> Binary analysis: netpulse-svc.exe loads embedded npext.dll<!--f:npext-->
<span class="log-warn">[09:05:22]</span> npext.dll — NOT present in v4.2.1, signed with same cert<!--f:signCert-->
<span class="log-warn">[09:05:23]</span>   Authenticode: "NetPulse Software, Inc." · serial 3A:0F:...:91 · valid<!--f:signCert-->
<span class="log-ok">[09:06:40]</span> EDR: 342/342 NetPulse hosts reporting healthy
<span class="log-warn">[09:08:12]</span> Firewall: DB-PROD-01 → 203.0.113.88:443 — 3 sessions since 06:15<!--f:staging-->
<span class="log-warn">[09:10:00]</span> <span class="log-highlight">ALERT</span> EMR database server DB-PROD-01 among beaconing hosts<!--f:dbprod-->`
        },
        choices: [
          {
            key: 'A',
            label: 'Quarantine the NetPulse update, block C2 IPs, and isolate beaconing hosts',
            desc: 'Kill the update process, push EDR quarantine on the malicious DLL, firewall-block C2, and network-isolate confirmed beaconing hosts.',
            quality: 'good',
            score: { time: 15, containment: 20, evidence: 10, thoroughness: 10 },
            sets: (f, st) => {
              const s = scStage(st.phaseClock);
              return { c2Blocked: true, hostsStaged: s.hosts, recordsExposed: s.records };
            },
            outcome: (f, st) => {
              const s = scStage(st.phaseClock);
              return 'EDR quarantines npext.dll across all 342 endpoints — the samples sit in the EDR vault, intact. Firewall rules block 198.51.100.47 and 203.0.113.88. The 47 actively beaconing hosts are network-isolated — all but DC-01 and DB-PROD-01, which sit on the EDR critical-asset exclusion list and need a change approval to cut off. C2 channel severed within 8 minutes. The legitimate NetPulse service continues running without the malicious component.'
                + (s.hosts > 3 ? ` But the stager had ${Math.round(st.phaseClock)} minutes to work while you weighed it: Cobalt Strike had already landed on ${s.hosts} hosts, not 3.` : '')
                + (s.records > 180000 ? ` And it reached beyond the EMR before the block — ${scN(s.records)} patients' records are now in play, not 180,000.` : '');
            },
          },
          {
            key: 'B',
            label: 'Uninstall NetPulse from all endpoints immediately',
            desc: 'Remove the entire NetPulse agent — malicious and legitimate components — from every managed host.',
            quality: 'partial',
            score: { time: 5, containment: 15, evidence: -10, thoroughness: 0 },
            sets: (f, st) => {
              const s = scStage(st.phaseClock);
              return { agentUninstalled: true, evidenceLost: true, updateTrusted: false, hostsStaged: s.hosts, recordsExposed: s.records };
            },
            outcome: (f, st) => 'NetPulse fully removed from all endpoints, which stops the beacon. However, you\'ve also removed the legitimate RMM agent — Vertex IT now has no remote management capability for 342 endpoints during an active incident. Forensic artifacts within the NetPulse install directory are lost on hosts where the uninstaller ran cleanup.'
              + ` And the uninstaller only knows about NetPulse: the Cobalt Strike beacon npext.dll already dropped on ${scStage(st.phaseClock).hosts} hosts is not part of the package, and nothing is blocking it from reaching 203.0.113.88.`,
          },
          {
            key: 'C',
            label: 'Contact NetPulse vendor support to ask if the update is legitimate',
            desc: 'Reach out to NetPulse\'s support team to verify whether v4.2.2 is an authorized release.',
            quality: 'bad',
            score: { time: -20, containment: -15, evidence: 5, thoroughness: -5 },
            // Three hours on hold before anyone acts
            sets: (f, st) => {
              const s = scStage(st.phaseClock + 180);
              return { attackerTipped: true, evidenceLost: true, hostsStaged: s.hosts, recordsExposed: s.records };
            },
            outcome: (f, st) => {
              const s = scStage(st.phaseClock + 180);
              return 'NetPulse support is slow to respond — it\'s a weekend. When the on-call engineer does answer, he checks the release manifest: v4.2.2 is an official, signed build, so as far as he can tell it\'s legitimate. It came out of their own pipeline. '
                + `Three hours later NetPulse security calls back: the build server was compromised and the update was never authorized. By then the stager has put Cobalt Strike on ${s.hosts} hosts, and the attacker has escalated on DB-PROD-01 and queried patient data for ${scN(s.records)} patients across the EMR, billing and clinic systems. `
                + 'Worse: your ticket, quoting the C2 IP, went into a support system the attacker had been reading from inside NetPulse. They know you\'re coming.';
            },
          },
          {
            key: 'D',
            when: f => f.saw_signCert,
            label: 'Contain as above, and pin NetPulse by hash — stop trusting the publisher',
            desc: 'Quarantine npext.dll, block C2, isolate the beaconing hosts; switch the app-control rule from "NetPulse Software, Inc." to the v4.2.1 hashes and freeze auto-update.',
            quality: 'good',
            score: { time: 15, containment: 25, evidence: 10, thoroughness: 15 },
            sets: (f, st) => {
              const s = scStage(st.phaseClock);
              return { c2Blocked: true, hashPinned: true, hostsStaged: s.hosts, recordsExposed: s.records };
            },
            outcome: (f, st) => {
              const s = scStage(st.phaseClock);
              return 'EDR quarantines npext.dll across all 342 endpoints; 198.51.100.47 and 203.0.113.88 blocked; the 47 beaconing hosts isolated, bar DC-01 and DB-PROD-01 on the critical-asset exclusion list. Because the malicious DLL carries NetPulse\'s real signature, you also replace the publisher rule with a hash allowlist for the known-good v4.2.1 binaries and freeze auto-update at the console. Whoever holds that signing key can no longer ship anything Vertex endpoints will run.'
                + (s.hosts > 3 ? ` Cobalt Strike had already reached ${s.hosts} hosts while you decided.` : '')
                + (s.records > 180000 ? ` ${scN(s.records)} patients' records were reached before the block.` : '');
            },
          },
        ],
        live: (f, st) => {
          const s = scStage(st.phaseClock);
          return `SECOND STAGE ON ${s.hosts} HOSTS · ${scN(s.records)} PATIENT RECORDS REACHED`;
        },
        timeline: [
          { at: 6, sev: 'crit', text: 'npext.dll: Cobalt Strike pulled onto 4 more *PROD* servers — 7 hosts staged', score: { containment: -3 } },
          { at: 12, sev: 'crit', text: 'LIS-PROD-01 (lab results) staged — 12 hosts carry second-stage tooling', score: { containment: -3 } },
          { at: 20, sev: 'crit', text: 'BILL-PROD-02: claims_archive queried — 38,000 former patients not in the EMR', score: { containment: -5 } },
          { at: 35, sev: 'crit', text: 'Second stage on 26 hosts — five *EXEC* workstations included' },
          { at: 60, sev: 'crit', text: 'OUTPT-DB-01 (outpatient clinics): 33,000 more patients queried' },
        ],
        siemEntries: [
          { time: '09:15', sev: 'crit', text: 'INCIDENT ASSIGNED — Supply Chain — Vertex Healthcare' },
          { time: '09:15', sev: 'warn', text: 'SLA CLOCK STARTED — P1 response: 15 min target' },
          { time: '09:16', sev: 'crit', text: '47 hosts beaconing to unknown C2 — NetPulse update vector' },
          { time: '09:17', sev: 'warn', text: 'EMR database server DB-PROD-01 in beaconing host list' },
        ],
      },
      { // CONTAINMENT
        name: 'CONTAINMENT',
        carried: f => {
          const out = [];
          if (f.attackerTipped) out.push({
            text: '10:52 — forty minutes after your ticket landed in NetPulse\'s queue, npext.dll scheduled its own deletion on 29 hosts and cleared their Security and System event logs.',
            score: { evidence: -10, containment: -5 },
          });
          if (f.agentUninstalled) out.push({
            text: 'Vertex IT has no remote management on 342 endpoints, and no npext.dll sample survived the uninstall. Every capture from here on is EDR or hands at the keyboard.',
            score: { evidence: -5, time: -5 },
          });
          if (!f.c2Blocked) out.push({
            text: `Nothing is blocking 198.51.100.47 or 203.0.113.88. Cobalt Strike on ${f.hostsStaged} hosts is still talking to its operator.`,
            score: { containment: -5 },
          });
          if (f.hostsStaged >= 12) out.push({
            text: `Second-stage tooling reached ${f.hostsStaged} hosts during triage. Each one is a rebuild, not a clean-up.`,
            score: { containment: -5 },
          });
          else if (f.hostsStaged > 3) out.push({
            sev: 'info',
            text: `Second-stage tooling reached ${f.hostsStaged} hosts during triage, not the 3 you started with.`,
          });
          return out;
        },
        narrative: f => [
          f.attackerTipped ? 'Three hours went to waiting on the vendor, and the attacker knows you are here.'
            : f.agentUninstalled ? 'NetPulse is gone from every endpoint and the npext.dll beacon has stopped — but what it installed has not.'
            : 'Initial triage is done and the HTTPS C2 channel is cut.',
          'The malicious update hit 342 endpoints but only 47 are actively beaconing — the backdoor appears to activate selectively based on hostname patterns matching servers and privileged workstations.',
          `The attacker has already moved laterally to the EMR database server and a domain controller${f.hostsStaged > 3 ? `, and second-stage tooling now sits on ${f.hostsStaged} hosts` : ''}.`,
        ].join(' '),
        evidence: {
          title: 'LATERAL MOVEMENT — EDR + AD LOGS',
          content: f => `<span class="log-ok">[05:30:00]</span> DB-PROD-01: SQL Agent — nightly index maintenance completed
<span class="log-warn">[05:44:00]</span> npext.dll activation check: hostname matches *PROD* or *DC*
<span class="log-warn">[05:45:12]</span> Credential harvest: npext.dll → LSASS on DB-PROD-01<!--f:credTheft-->
<span class="log-warn">[05:47:00]</span> <span class="log-highlight">Pass-the-hash</span>: svc_netpulse → DC-01 (local admin)<!--f:credTheft-->
<span class="log-warn">[05:50:33]</span> DC-01: Recon — nltest /dclist, net group "domain admins"<!--f:credTheft-->
<span class="log-ok">[06:00:00]</span> DC-01: Group Policy refresh (scheduled)
<span class="log-warn">[06:02:00]</span> <span class="log-highlight">ALERT</span> New service created on DC-01: "HealthCheck"<!--f:healthCheck-->
<span class="log-warn">[06:02:15]</span> HealthCheck → C:\\Windows\\Temp\\hc.exe (Cobalt Strike)<!--f:healthCheck-->
<span class="log-warn">[06:02:40]</span> hc.exe config: https 203.0.113.88 · fallback dns cdn-healthmetrics[.]net<!--f:dnsFallback-->
<span class="log-warn">[06:15:00]</span> DB-PROD-01: SQL query — SELECT * FROM patients LIMIT 1000<!--f:patientsQuery-->
<span class="log-ok">[07:00:12]</span> DB-PROD-01: EMR app pool recycled (nightly)
<span class="log-ok">[07:45:00]</span> VPN: 12 clinicians connected (on-call)
<span class="log-warn">[08:30:00]</span> Outbound transfer: 203.0.113.88 — 450 MB<!--f:exfil-->
<span class="log-ok">[08:45:00]</span> DC-01: System State backup — OK${f.agentUninstalled ? `
<span class="log-ok">[09:40:00]</span> NetPulse uninstaller: C:\\Program Files\\NetPulse\\ removed — 342 hosts
<span class="log-warn">[09:52:10]</span> DC-01: hc.exe → 203.0.113.88 — beacon still active<!--f:healthCheck-->` : ''}${f.attackerTipped ? `
<span class="log-warn">[10:52:07]</span> npext.dll: self-delete scheduled (MoveFileEx) — 29 hosts<!--f:antiForensics-->
<span class="log-warn">[10:52:30]</span> wevtutil cl Security / wevtutil cl System — same 29 hosts<!--f:antiForensics-->` : ''}`
        },
        choices: [
          {
            key: 'A',
            label: 'Isolate DC-01 and DB-PROD-01, disable svc_netpulse, block secondary C2, preserve memory',
            desc: 'Targeted containment: isolate the two highest-value compromised hosts, kill the compromised service account, block staging server, and capture RAM dumps before isolation.',
            quality: 'good',
            score: { time: 10, containment: 25, evidence: 15, thoroughness: 10 },
            sets: { memoryCaptured: true, c2Blocked: true, dcContained: true },
            outcome: f => 'Memory dumps captured from both hosts before network isolation — preserving volatile evidence of the Cobalt Strike beacon and credential theft. svc_netpulse disabled across the domain. Secondary C2 blocked'
              + (f.c2Blocked ? '.' : ', and the primary 198.51.100.47 with it — nobody had blocked either yet.')
              + ' Lateral movement path severed. The backup DC takes over authentication seamlessly.'
              + (f.evidenceLost ? ' Those memory images are now the best copy of the implant you have.' : '')
              + (f.krbtgtStolen ? ' But DC-01 ran a DCSync before it went dark — the krbtgt hash left with the attacker.' : '')
              + (f.lateral ? ' And it had already pushed Cobalt Strike to three more servers over SMB.' : ''),
          },
          {
            key: 'B',
            label: 'Block all outbound traffic except known-good destinations at the firewall',
            desc: 'Allowlist approach — only permit traffic to verified business destinations.',
            quality: 'partial',
            score: { time: 5, containment: 10, evidence: 5, thoroughness: 5 },
            // DC-01 stays up and in the attacker's hands until eradication
            sets: f => ({ c2Blocked: true, krbtgtStolen: true, lateral: 3, hostsStaged: f.hostsStaged + (f.lateral ? 0 : 3) }),
            outcome: 'HTTPS C2 and the exfil path to 203.0.113.88 are blocked. But DC-01 is also Vertex\'s DNS server, and outbound DNS forwarding is on the allowlist — hc.exe\'s DNS fallback keeps working. The attacker still has local access to DC-01 and DB-PROD-01. They can\'t move bulk data out, but they can still move laterally within the network, access data, and deploy additional persistence: before eradication they replicate the domain\'s hashes from DC-01 and push Cobalt Strike to three more servers. The compromised service account remains active.',
          },
          {
            key: 'C',
            label: 'Shut down the EMR system entirely to protect patient data',
            desc: 'Emergency shutdown of all healthcare database systems.',
            quality: 'bad',
            score: { time: -10, containment: 10, evidence: -15, thoroughness: -10 },
            sets: f => ({ emrHardDown: true, krbtgtStolen: true, lateral: 3, hostsStaged: f.hostsStaged + (f.lateral ? 0 : 3) }),
            outcome: 'The EMR shutdown disrupts patient care across 3 hospital facilities. Emergency departments revert to paper records. Two scheduled surgeries are delayed. Volatile memory evidence on DB-PROD-01 is lost. The attacker still has access to DC-01 and other beaconing hosts — and uses it to replicate the domain\'s hashes and spread to three more servers. Nor does the shutdown buy any time: the 60-day HIPAA notification clock was already running from the moment DB-PROD-01\'s patient table was confirmed accessed.',
          },
          {
            key: 'D',
            when: f => f.saw_dnsFallback,
            label: 'Contain as A, and sinkhole cdn-healthmetrics[.]net to hunt the fallback beacon domain-wide',
            desc: 'Memory, isolation, svc_netpulse, secondary C2 — plus an internal DNS sinkhole for the fallback domain, so every implant that tries it gives itself away.',
            quality: 'good',
            score: { time: 10, containment: 30, evidence: 15, thoroughness: 15 },
            sets: { memoryCaptured: true, c2Blocked: true, dcContained: true, lateralFound: true },
            outcome: f => 'Memory captured from DC-01 and DB-PROD-01, both isolated, svc_netpulse disabled, 203.0.113.88 blocked'
              + (f.c2Blocked ? '' : ' along with 198.51.100.47')
              + '. The fallback domain now resolves to your sinkhole, and every resolver query is logged. '
              + (f.lateral ? 'Within minutes FS-02, HR-APP-01 and PAY-01 come knocking — Cobalt Strike the attacker pushed over SMB, under a new hash no IOC list has. All three isolated.'
                : 'Nothing but DC-01 ever asks for it: the implant hasn\'t spread past the hosts you already know.')
              + (f.krbtgtStolen ? ' The DCSync that ran before isolation still stands — the krbtgt hash is out.' : ''),
          },
        ],
        live: f => f.c2Blocked ? 'DC-01 COBALT STRIKE: LIVE OVER DNS FALLBACK' : `COBALT STRIKE ON ${f.hostsStaged} HOSTS · C2 OPEN`,
        timeline: [
          { at: 5, sev: 'warn', text: f => f.c2Blocked ? 'DC-01: hc.exe falls back to DNS TXT — cdn-healthmetrics[.]net' : 'DC-01: interactive Cobalt Strike session over 203.0.113.88' },
          { at: 10, sev: 'crit', text: 'DC-01: DCSync — krbtgt and 1,912 account hashes replicated',
            sets: { krbtgtStolen: true }, score: { containment: -3 } },
          { at: 16, sev: 'crit', text: 'DC-01 → FS-02, HR-APP-01, PAY-01: Cobalt Strike installed over SMB',
            sets: f => ({ lateral: 3, hostsStaged: f.hostsStaged + (f.lateral ? 0 : 3) }), score: { containment: -3 } },
        ],
        siemEntries: f => [
          { time: '09:30', sev: 'crit', text: 'Lateral movement confirmed: DB-PROD-01 and DC-01 compromised' },
          { time: '09:31', sev: 'warn', text: 'Cobalt Strike beacon on DC-01 — HealthCheck service' },
          { time: '09:32', sev: 'crit', text: '450 MB data exfiltrated to staging server before containment' },
          ...(f.attackerTipped ? [{ time: '10:52', sev: 'crit', text: 'Event logs cleared on 29 hosts — npext.dll self-deleting' }] : []),
          ...(f.agentUninstalled ? [{ time: '09:52', sev: 'warn', text: 'NetPulse removed — RMM unavailable on 342 endpoints' }] : []),
        ],
      },
      { // INVESTIGATION
        name: 'INVESTIGATION',
        carried: f => {
          const out = [];
          if (f.krbtgtStolen) out.push({
            text: 'DC-01\'s replication metadata confirms the DCSync: the attacker holds the krbtgt hash. Until it is reset twice they can forge a Kerberos ticket for any account.',
            score: { containment: -5 },
          });
          if (f.evidenceLost) out.push({
            text: f.attackerTipped
              ? 'npext.dll deleted itself from 29 hosts and their event logs are gone. Reverse engineering waits on whatever sample survived elsewhere.'
              : 'The uninstaller took C:\\Program Files\\NetPulse\\ with it on every host — no npext.dll sample, no agent logs.',
            score: { evidence: -5 },
          });
          if (f.emrHardDown) out.push({
            sev: 'info',
            text: 'Three hospitals are on paper since the hard shutdown; two surgeries have been rescheduled.',
          });
          return out;
        },
        narrative: f => (f.dcContained ? 'Containment is in place. ' : 'Egress is locked down, but DC-01 was never isolated. ')
          + 'You need to determine the full scope of the supply chain compromise: how the NetPulse update was trojanized, all affected systems, what data was accessed, and whether this is an isolated incident or part of a wider campaign targeting NetPulse customers.',
        evidence: {
          title: 'SUPPLY CHAIN ANALYSIS + DATA ACCESS LOGS',
          content: f => `<span class="log-ok">── SUPPLY CHAIN VECTOR (NetPulse IR bridge) ──</span>
<span class="log-warn">[Analysis]</span> NetPulse build server (build.netpulse.io) compromised<!--f:buildServer-->
  Attacker injected npext.dll into build pipeline<!--f:buildServer-->
  Build agent: Jenkins, last patched 14 months ago
  Code-signing key: .pfx file on the build agent — no HSM<!--f:keyTheft-->
  .pfx read by attacker session Mar 4 — 11 days before release<!--f:keyTheft-->
  NetPulse v4.1.x builds — hashes match vendor manifest
  <span class="log-highlight">Estimated 2,400 NetPulse customers received trojanized update</span><!--f:campaign-->

<span class="log-ok">── VERTEX IMPACT ──</span>
  Endpoints updated: 342
  Beacon activated: 47 (hostname filter: *PROD*, *DC*, *EXEC*)
  Second stage (Cobalt Strike): ${f.hostsStaged} hosts
  Lateral movement: DB-PROD-01, DC-01, EXEC-WS-04 (CISO laptop)${f.lateral ? `
  FS-02, HR-APP-01, PAY-01: service "WinTelemetry" → hc.exe variant, new hash<!--f:lateralCS-->` : ''}
  Data accessed: patients table, HR database, board docs

<span class="log-ok">── PHI ACCESS (SQL audit, forwarded to SIEM) ──</span>
  DB-PROD-01 dbo.patients: 180,000 distinct MRNs returned to db_admin<!--f:sqlAudit-->${f.recordsExposed >= 218000 ? `
  BILL-PROD-02 claims_archive: 38,000 former-patient MRNs returned<!--f:sqlAudit-->` : ''}${f.recordsExposed >= 251000 ? `
  OUTPT-DB-01 clinic_visits: 33,000 MRNs not held in the EMR<!--f:sqlAudit-->` : ''}${f.attackerTipped ? `
  <span class="log-highlight">SQL Server Audit on DB-PROD-01 STOPPED 10:55 by db_admin</span><!--f:auditGap-->` : ''}
  DB-PROD-01 reporting_ro: 2,210 routine report queries (clinical staff)

<span class="log-ok">── EXFILTRATION ASSESSMENT ──</span>
  Confirmed exfil: 450 MB to 203.0.113.88
  Content: Patient PII (names, SSN, diagnoses, insurance IDs)
  <span class="log-highlight">HIPAA breach threshold: EXCEEDED</span>
  Additional queries against HR and financial databases — no confirmed exfil`
        },
        choices: [
          {
            key: 'A',
            label: 'Full forensic investigation: image key systems, trace all data access, coordinate with NetPulse',
            desc: 'Comprehensive investigation across Vertex and coordination with NetPulse on the upstream compromise. Full data access audit.',
            quality: 'good',
            score: { time: -5, containment: 5, evidence: 25, thoroughness: 20 },
            sets: f => ({
              vendorCoordinated: true,
              lateralFound: true,
              scopedRecords: f.recordsExposed,
              scopePrecise: !f.attackerTipped,
              // NetPulse only asks the CA to revoke once someone shows them the key itself was taken
              certRevoked: f.certRevoked || !!f.saw_keyTheft,
            }),
            outcome: f => 'Forensic images captured from DC-01, DB-PROD-01, and EXEC-WS-04'
              + (f.lateral ? ', and from FS-02, HR-APP-01 and PAY-01, where a Cobalt Strike variant under a new hash turns up' : '')
              + '. '
              + (f.evidenceLost ? 'EXEC-WS-04 was asleep when the ' + (f.attackerTipped ? 'self-delete ran' : 'uninstaller ran') + ' — its disk still holds npext.dll, the one sample you recover. ' : '')
              + (f.memoryCaptured ? '' : 'With no memory captured before isolation, the in-memory Cobalt Strike config is gone; you rebuild it from EDR telemetry, slower and with gaps. ')
              + (f.attackerTipped
                ? `The SQL audit trail stops at 10:55, when db_admin switched it off. Up to then it is record-level; after it, nothing can be ruled out, so counsel scopes notification to every patient in the systems touched — ${scN(f.recordsExposed)}. `
                : `Complete SQL query audit reveals exactly which patient records were accessed and exfiltrated — ${scN(f.recordsExposed)} patients. `)
              + 'NetPulse confirms upstream compromise and begins notifying other customers. Your findings help NetPulse identify the build server intrusion vector. '
              + (f.saw_keyTheft ? 'Because you showed them the .pfx was read, not just used, NetPulse asks its CA to revoke the certificate — anything that key signs from here on fails validation. '
                : 'NetPulse treats the signing key as merely misused by the pipeline; nobody asks the CA to revoke it. ')
              + (f.attackerTipped ? 'HIPAA breach scope documented — presumptively.' : 'HIPAA breach scope precisely documented.'),
          },
          {
            key: 'B',
            label: 'Focus on Vertex systems only — NetPulse\'s compromise is their problem',
            desc: 'Investigate the local impact. Don\'t spend time on the upstream supply chain issue.',
            quality: 'partial',
            score: { time: 10, containment: 5, evidence: 10, thoroughness: 0 },
            sets: f => ({ lateralFound: true, scopedRecords: f.recordsExposed, scopePrecise: !f.attackerTipped }),
            outcome: f => `Vertex impact documented: 47 active compromises, ${3 + f.lateral} systems with lateral movement, confirmed patient data exfiltration covering ${scN(f.recordsExposed)} patients. `
              + 'But without coordinating with NetPulse, you don\'t know if the attacker has other persistence through the vendor relationship — or whether the signing key itself is still in their hands. NetPulse doesn\'t learn about the compromise for another 3 days, during which other healthcare customers are breached.',
          },
          {
            key: 'C',
            label: 'Run IOC sweeps only — time is critical and the client wants answers fast',
            desc: 'Quick IOC hunt across all endpoints. Skip deep forensics.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: -15, thoroughness: -15 },
            sets: f => ({
              scopedRecords: f.saw_sqlAudit ? f.recordsExposed : 180000,
              scopePrecise: false,
              lateralFound: f.lateralFound || !!f.saw_lateralCS,
            }),
            outcome: f => 'IOC sweep confirms known indicators on 47 hosts'
              + (f.dcContained || f.saw_healthCheck ? '' : ' but misses the Cobalt Strike beacon on DC-01 (different IOCs)')
              + '. '
              + (f.saw_sqlAudit
                ? `The SQL audit lines you tagged give counsel a patient count — ${scN(f.recordsExposed)} — but nobody pulls the record-level list behind it. `
                : 'You can\'t determine exact patient records affected, making the HIPAA breach notification inaccurate: the only number anyone has is the 180,000 from the first alert. ')
              + 'The CISO\'s laptop compromise is undiscovered — board documents and strategic plans were accessed. '
              + (f.lateral && !f.lateralFound ? (f.saw_lateralCS ? 'The three WinTelemetry hosts you tagged are added to the list by hand; the sweep would never have found them. ' : '') : '')
              + 'HHS investigation later finds your scope was inadequate.',
          },
          {
            key: 'D',
            when: f => f.saw_campaign,
            label: 'Full forensics, and run the disclosure: NetPulse, CISA, HHS HC3 and Health-ISAC',
            desc: 'Everything in A, plus an IOC package for CISA and the sector ISAC so the other 2,400 NetPulse customers hear it from you today.',
            quality: 'good',
            score: { time: -5, containment: 10, evidence: 25, thoroughness: 25 },
            sets: f => ({
              vendorCoordinated: true,
              cisaShared: true,
              lateralFound: true,
              scopedRecords: f.recordsExposed,
              scopePrecise: !f.attackerTipped,
              certRevoked: f.certRevoked || !!(f.saw_keyTheft || f.saw_signCert),
            }),
            outcome: f => 'Forensic images from DC-01, DB-PROD-01, EXEC-WS-04' + (f.lateral ? ', FS-02, HR-APP-01 and PAY-01' : '') + '. '
              + (f.attackerTipped
                ? `SQL audit is record-level up to 10:55, when db_admin stopped it; counsel scopes to every patient in the touched systems — ${scN(f.recordsExposed)}. `
                : `SQL audit pins the exposure to ${scN(f.recordsExposed)} named patients. `)
              + 'NetPulse joins a bridge with CISA and HHS HC3 the same afternoon. '
              + (f.saw_c2ip && f.saw_staging
                ? 'Your package — C2 and staging IPs, the spoofed update domain, the npext.dll hash — goes out as a TLP:AMBER Health-ISAC alert within hours; two hospitals find the beacon on their own networks that night. '
                : 'Your package is thin on network indicators — you never documented the C2 and staging infrastructure together — so the ISAC alert leads with the file hash and other customers hunt slower. ')
              + (f.saw_keyTheft || f.saw_signCert
                ? (f.saw_keyTheft ? 'With the key-theft evidence in hand' : 'With the certificate serial proving the malicious DLL carries NetPulse\'s production signature') + ', CISA presses for revocation: the CA revokes NetPulse\'s code-signing certificate by evening.'
                : 'Nobody in the room has the certificate details; revocation waits on NetPulse\'s own review.'),
          },
        ],
        live: f => `PATIENT RECORDS REACHED: ${scN(f.recordsExposed)} · HIPAA CLOCK RUNNING`,
        timeline: [
          { at: 6, sev: 'warn', text: 'Health-ISAC: a second NetPulse customer (regional hospital) reports beacons to 198.51.100.47' },
          { at: 14, sev: 'crit', text: f => `Leak forum post: "Vertex Healthcare — ${scN(f.recordsExposed)} patients, SSN + diagnoses" with 500-row sample`,
            score: { thoroughness: -3 } },
        ],
        siemEntries: [
          { time: '10:30', sev: 'info', text: 'Investigation phase — mapping full compromise scope' },
          { time: '10:35', sev: 'crit', text: 'Patient data exfiltration confirmed — EMR patients table, 180K records accessed' },
          { time: '10:40', sev: 'warn', text: 'NetPulse upstream compromise — 2,400 customers potentially affected' },
          { time: '10:45', sev: 'crit', text: 'HIPAA breach threshold exceeded — notification required' },
        ],
      },
      { // ERADICATION
        name: 'ERADICATION',
        carried: f => {
          const out = [];
          if (!f.vendorCoordinated) out.push({
            text: 'NetPulse still hasn\'t heard from you. Two more NetPulse customers — both hospitals — find the same beacon on their own today.',
            score: { thoroughness: -5 },
          });
          if (f.cisaShared) out.push({
            sev: 'good',
            text: 'CISA\'s alert on the NetPulse compromise cites your indicators; Health-ISAC members are hunting with them.',
          });
          return out;
        },
        narrative: f => (f.lateral && !f.lateralFound
          ? 'Investigation mapped the footprint the IOC sweep could see. '
          : 'Investigation mapped the full attack footprint. ')
          + 'Now remove all attacker access: the trojanized update, Cobalt Strike beacons, compromised credentials, persistence mechanisms, and the poisoned vendor trust relationship.',
        evidence: {
          title: 'PERSISTENCE & ARTIFACT INVENTORY',
          content: f => `<span class="log-highlight">MALICIOUS SOFTWARE:</span>
  [1] npext.dll — ${f.agentUninstalled ? 'removed with the NetPulse uninstall (no sample on disk)' : f.attackerTipped ? 'present on 313 endpoints (self-deleted on 29)' : 'present on 342 endpoints (inactive on 295)'}
  [2] hc.exe (Cobalt Strike) — DC-01, C:\\Windows\\Temp\\${f.hostsStaged - f.lateral > 3 ? ` + ${f.hostsStaged - f.lateral - 3} hosts staged during triage` : ''}
  [3] Service "HealthCheck" — DC-01
  [4] WMI persistence — DB-PROD-01${f.lateral && f.lateralFound ? `
  [5] hc.exe variant, service "WinTelemetry" — FS-02, HR-APP-01, PAY-01` : ''}

<span class="log-highlight">COMPROMISED CREDENTIALS:</span>
  - svc_netpulse (service account — local admin on all endpoints)
  - db_admin (SQL SA equivalent on EMR database)
  - ${f.krbtgtStolen ? 'KRBTGT — DCSync CONFIRMED (hash held by attacker)' : 'KRBTGT exposure likely (DC-01 compromised)'}

<span class="log-highlight">VENDOR TRUST:</span>
${f.agentUninstalled ? '  - NetPulse agent removed from all endpoints — no update channel' : `  - NetPulse update channel still configured on all endpoints
  - ${f.hashPinned ? 'App control: NetPulse pinned to v4.2.1 by hash; auto-update frozen' : 'App control: any binary signed "NetPulse Software, Inc." allowed'}`}
  - NetPulse code-signing cert: ${f.certRevoked ? '<span class="log-ok">REVOKED by issuing CA</span>' : 'still trusted'}
  - NetPulse service account has local admin on every host`
        },
        choices: [
          {
            key: 'A',
            label: 'Remove all artifacts, reset credentials, revoke NetPulse trust, double-reset KRBTGT',
            desc: 'Systematic eradication: clean every host, kill all compromised accounts, sever the poisoned vendor channel, invalidate Kerberos tickets.',
            quality: 'good',
            score: { time: 5, containment: 15, evidence: 5, thoroughness: 20 },
            sets: { updateTrusted: false, krbtgtReset: true, reinfected: 0 },
            outcome: f => (f.agentUninstalled ? 'npext.dll already went with the uninstall. ' : 'npext.dll quarantined and removed from all 342 hosts. ')
              + 'Cobalt Strike beacon and persistence removed from DC-01 and DB-PROD-01'
              + (f.lateral && f.lateralFound ? ', and the WinTelemetry variant from FS-02, HR-APP-01 and PAY-01' : '')
              + '. All compromised credentials reset including KRBTGT double-reset. '
              + (f.agentUninstalled ? 'NetPulse cert untrusted in case anyone reinstalls the agent. '
                : `NetPulse update channel disabled and ${f.saw_signCert ? 'the certificate serial 3A:0F:...:91 added to the untrusted store' : 'the NetPulse publisher untrusted'} pending vendor remediation. `)
              + 'Alternative patching workflow established.',
          },
          {
            key: 'B',
            label: 'Clean the 47 beaconing hosts and reset compromised accounts',
            desc: 'Focus eradication on the actively compromised hosts. Leave the inactive 295 for later cleanup.',
            quality: 'partial',
            score: { time: 10, containment: 5, evidence: 0, thoroughness: -5 },
            sets: f => ({ reinfected: scFakeUpdateLands(f) ? 342 : 0 }),
            outcome: f => 'Active threats removed from 47 hosts and accounts reset. '
              + (f.agentUninstalled ? 'With the agent uninstalled there is no dormant npext.dll to leave behind — ' : 'But npext.dll remains dormant on 295 endpoints — if the attacker regains C2 or the activation criteria change, those hosts could reactivate. ')
              + (f.agentUninstalled ? 'but the NetPulse service account keeps local admin everywhere.'
                : f.hashPinned || f.certRevoked ? 'The NetPulse trust relationship stays configured, though the ' + (f.hashPinned ? 'hash pin' : 'certificate revocation') + ' means nothing new signed with that key will run.'
                : 'The NetPulse trust relationship remains intact, leaving a potential re-compromise vector.')
              + (f.krbtgtStolen ? ' KRBTGT wasn\'t on the reset list — the hash the attacker replicated still signs valid tickets.' : ''),
          },
          {
            key: 'C',
            label: 'Wait for NetPulse to release a clean update that removes the backdoor',
            desc: 'Let the vendor fix their own problem. They\'ll push a clean update that overwrites the malicious one.',
            quality: 'bad',
            score: { time: -15, containment: -10, evidence: -5, thoroughness: -20 },
            sets: f => ({ reinfected: scFakeUpdateLands(f) ? 342 : 0, ransomware: true }),
            outcome: f => 'NetPulse takes 5 days to release a remediation update. '
              + (f.agentUninstalled ? 'It has nothing to land on — you uninstalled the agent in triage — so for five days nobody removes anything. ' : 'During that time, the dormant backdoor sits on 295 endpoints. ')
              + 'Compromised credentials remain active. '
              + (scFakeUpdateLands(f) ? 'On day 2 a "v4.2.3 remediation" appears on update-netpulse[.]com, signed with the stolen key; every endpoint that trusts the NetPulse publisher installs it. '
                : !f.agentUninstalled ? 'On day 2 a "v4.2.3" signed with the stolen key is offered to every endpoint and refused — ' + (f.hashPinned ? 'your hash pin' : 'the revoked certificate') + ' is the one thing that holds. ' : '')
              + 'The attacker uses a secondary C2 channel you didn\'t know about to regain access'
              + (f.krbtgtStolen ? ' — with the krbtgt hash from the DCSync they never need a password — ' : ' through the still-trusted NetPulse service account ')
              + 'and deploys ransomware on day 4.',
          },
        ],
        live: f => f.agentUninstalled ? 'NETPULSE AGENT: REMOVED · SERVICE ACCOUNT STILL LOCAL ADMIN'
          : scFakeUpdateLands(f) ? 'ENDPOINTS TRUST ANYTHING SIGNED "NETPULSE SOFTWARE, INC."'
          : 'NETPULSE UPDATE PATH: CLOSED TO THE STOLEN KEY',
        timeline: [
          { at: 8, sev: 'crit', when: f => scFakeUpdateLands(f), text: 'update-netpulse[.]com: "v4.2.3" package published — signed NetPulse Software, Inc.', score: { containment: -3 } },
          { at: 8, sev: 'warn', when: f => !f.agentUninstalled && !scFakeUpdateLands(f), text: f => `update-netpulse[.]com: "v4.2.3" package published — ${f.hashPinned ? 'not on the hash pin list' : 'signature chains to a revoked certificate'}` },
        ],
        siemEntries: [
          { time: '13:00', sev: 'info', text: 'Eradication phase — removing all attacker artifacts' },
          { time: '13:10', sev: 'success', text: 'Cobalt Strike beacon removed from DC-01' },
          { time: '13:15', sev: 'warn', text: 'NetPulse trust relationship — revocation decision pending' },
        ],
      },
      { // RECOVERY
        name: 'RECOVERY',
        carried: f => {
          const out = [];
          if (f.ransomware) out.push({
            text: 'Day 4, 02:10: ransomware detonated across 64 servers, pushed from DC-02. Recovery now starts from a second incident.',
            score: { containment: -15, time: -5 },
          });
          if (f.reinfected > 0) out.push({
            text: `A "v4.2.3 remediation" signed with NetPulse's stolen key arrived from update-netpulse[.]com. The endpoints trusted the publisher, so ${f.reinfected} hosts installed it; npext is back on 47 of them, beaconing to new infrastructure.`,
            score: { containment: -15 },
          });
          else if (!f.agentUninstalled && f.updateTrusted) out.push({
            sev: 'good',
            text: `Overnight, update-netpulse[.]com offered a "v4.2.3" signed with the stolen key. ${f.hashPinned ? 'App control refused it — the hash wasn\'t on the pin list.' : 'Windows rejected it — the CA had revoked the certificate.'} 342 blocked installs, zero infections.`,
            score: { containment: 5 },
          });
          if (f.lateral && !f.lateralFound) out.push({
            text: 'PAY-01\'s "WinTelemetry" service beaconed over DNS at 02:00 — a Cobalt Strike variant the IOC sweep never looked for, on three hosts nobody cleaned.',
            score: { containment: -10 },
          });
          if (f.krbtgtStolen && !f.krbtgtReset) out.push({
            text: 'A Kerberos ticket for "administrator" with a 10-year lifetime was presented to DC-02 — forged with the krbtgt hash from the DCSync. KRBTGT was never reset.',
            score: { containment: -10 },
          });
          return out;
        },
        narrative: f => (f.reinfected > 0 || f.ransomware || (f.lateral && !f.lateralFound) || (f.krbtgtStolen && !f.krbtgtReset)
          ? 'Eradication was declared complete. It wasn\'t. '
          : 'Eradication is complete. ')
          + 'Vertex Healthcare needs to restore normal operations — particularly the EMR system, which is critical for patient care. The board is asking about HIPAA notification timelines and the IT team needs an alternative to NetPulse for endpoint management.',
        evidence: {
          title: 'RECOVERY STATUS',
          content: f => `<span class="log-ok">SYSTEM STATUS:</span>
  - DC-01: Rebuilt from clean media, rejoined domain ✓
  - DB-PROD-01: EMR database — restored from pre-compromise backup
    (backup image includes NetPulse agent v4.2.1 — auto-update ${f.agentUninstalled ? 'n/a, agent stripped' : f.updateTrusted ? '<span class="log-highlight">ENABLED</span>' : 'disabled'})
  - Patient data integrity: Verified (read-only exfil, no modification)
  - 342 endpoints: ${f.reinfected > 0 ? '<span class="log-highlight">fake v4.2.3 installed — npext variant active ✗</span>'
      : f.agentUninstalled ? 'NetPulse removed, alternative RMM needed'
      : f.updateTrusted ? `NetPulse present, ${f.hashPinned ? 'v4.2.1 pinned by hash' : 'signing cert revoked'} — alternative RMM needed`
      : 'NetPulse disabled, alternative RMM needed'}${f.ransomware ? `
  - <span class="log-highlight">64 servers encrypted (day 4) — rebuild queue</span>` : ''}

<span class="log-warn">BUSINESS IMPACT:</span>
  - EMR downtime: ongoing (~${f.emrHardDown ? '9 hours since the 09:40 hard shutdown' : '6 hours so far'})
  - 3 hospital facilities on paper records
  - ${f.emrHardDown ? 'Two surgeries delayed; surgical schedule disrupted' : 'Surgical schedule disrupted'}
  - Staff unable to access digital patient histories

<span class="log-warn">REGULATORY:</span>
  - HIPAA 60-day notification clock: STARTED (discovery Mar 15)
  - ${scN(f.scopedRecords || 180000)} patients in scope — ${f.scopePrecise ? 'record-level SQL audit' : f.attackerTipped && f.scopedRecords ? 'presumptive (audit trail gap)' : 'estimate, no record-level list'}
  - HHS OCR breach report required (500+ individuals)
  - Prominent media notice required in each state with 500+ affected residents
  - State AG notifications required (multi-state patient base)`
        },
        choices: [
          {
            key: 'A',
            label: 'Staged EMR restoration with verification, deploy temporary RMM, begin HIPAA notification prep',
            desc: 'Restore EMR to isolated segment first, verify data integrity, monitor for 2 hours, then reconnect. Deploy alternative RMM. Start breach notification process.',
            quality: 'good',
            score: { time: 5, containment: 10, evidence: 5, thoroughness: 15 },
            sets: f => ({
              notifyPrepped: true,
              reinfectContained: f.reinfected > 0,
              updateTrusted: false,
              lateralFound: f.lateralFound || f.lateral > 0,
              krbtgtReset: f.krbtgtReset || f.krbtgtStolen,
            }),
            outcome: f => 'EMR restored to isolated VLAN, integrity verified against known-good checksums. '
              + (f.reinfected > 0
                ? 'The monitoring window earns its keep: within minutes the restored DB-PROD-01\'s NetPulse agent pulls the fake v4.2.3 and beacons to a new C2. The EMR stays on the isolated VLAN while the variant is quarantined by hash on all 342 hosts and the update channel is finally cut; the second 2-hour window is clean. '
                : 'After 2-hour monitoring window with no suspicious activity, ')
              + 'EMR reconnected to clinical network. Patient care resumes normally. Temporary RMM deployed for endpoint management. '
              + (f.lateral && !f.lateralFound ? 'The same monitoring pins down PAY-01\'s WinTelemetry beacon; all three hosts are rebuilt. ' : '')
              + (f.krbtgtStolen && !f.krbtgtReset ? 'The forged ticket forces the KRBTGT double reset that eradication skipped. ' : '')
              + (f.scopePrecise ? 'HIPAA breach notification drafted with precise scope from investigation findings.'
                : `HIPAA breach notification drafted for ${scN(f.scopedRecords || 180000)} patients — the best scope the investigation left you.`),
          },
          {
            key: 'B',
            label: 'Restore EMR immediately — patient care is the priority',
            desc: 'Bring the EMR back online as fast as possible. Handle RMM and compliance later.',
            quality: 'partial',
            score: { time: 15, containment: -5, evidence: 0, thoroughness: 0 },
            outcome: f => 'EMR restored and clinical operations resume quickly — staff and patients relieved. But without the verification window, you\'re trusting the backup is clean based on timestamps alone. '
              + (f.reinfected > 0 ? 'The data is — but the NetPulse agent in the image takes the fake v4.2.3 within the hour, and DB-PROD-01 is beaconing again, this time on the clinical network. '
                : 'Fortunately it is, but the approach carries unnecessary risk. ')
              + 'HIPAA notification work is delayed, compressing the 60-day window.',
          },
          {
            key: 'C',
            label: 'Keep EMR offline until a full security audit of the entire infrastructure is complete',
            desc: 'Don\'t bring anything back until you\'re 100% certain the environment is clean.',
            quality: 'bad',
            score: { time: -15, containment: 10, evidence: 0, thoroughness: -10 },
            sets: f => ({
              reinfectContained: f.reinfected > 0,
              updateTrusted: false,
              lateralFound: f.lateralFound || f.lateral > 0,
              krbtgtReset: f.krbtgtReset || f.krbtgtStolen,
            }),
            outcome: f => 'The EMR stays offline for 4 days during the audit. '
              + (scFoothold(f) ? 'The audit does find what eradication left behind, and it is all cleaned out. ' : '')
              + 'Patient care is severely impacted — two patients are transferred to other facilities due to inability to access medical histories. CMS flags the extended downtime. The board overrides your recommendation on day 3 and demands immediate restoration, undermining the security process.',
          },
        ],
        live: (f, st) => {
          const m = (f.emrHardDown ? 540 : 360) + Math.floor(st.phaseClock);
          return `EMR DOWN ${Math.floor(m / 60)} H ${m % 60} MIN · 3 HOSPITALS ON PAPER`;
        },
        timeline: [
          { at: 6, sev: 'warn', text: 'ED boarding times up 40% — clinicians on downtime procedures', score: { time: -3 } },
          { at: 12, sev: 'warn', text: 'Pharmacy: medication orders delayed — paper MAR reconciliation backlog' },
        ],
        siemEntries: f => [
          { time: '15:00', sev: 'info', text: 'Recovery phase — EMR restoration planning' },
          { time: '15:10', sev: 'warn', text: `EMR downtime: ${f.emrHardDown ? 9 : 6} hours — clinical impact escalating` },
          { time: '15:15', sev: 'info', text: 'HIPAA 60-day notification clock running since discovery' },
        ],
      },
      { // POST-INCIDENT
        name: 'POST-INCIDENT',
        carried: f => scFoothold(f) ? [{
          text: 'You are writing the report while the attacker still has a way into Vertex.',
          score: { thoroughness: -10 },
        }] : [],
        narrative: f => (scFoothold(f)
          ? 'Systems are back in service, but not clean. '
          : 'Systems are restored and operations are back to normal. ')
          + 'This was a sophisticated supply chain attack with significant regulatory implications. Your post-incident work will shape Vertex\'s security posture and their vendor risk management program going forward.',
        evidence: {
          title: 'INCIDENT SUMMARY',
          content: f => `<span class="log-ok">TIMELINE:</span>
  Vendor compromise:  Mar 4 or earlier (NetPulse build server)
  Malicious update:   Mar 15 03:12 (auto-update pushed)
  Beacon activation:  Mar 15 05:44 (47 hosts)
  Lateral movement:   Mar 15 05:45–06:15
  Data exfiltration:  Mar 15 06:15–08:30 (450 MB patient data)
  Detection:          Mar 15 09:01 (TI feed match)
  Containment:        Mar 15 ~${f.attackerTipped ? '12:40' : f.agentUninstalled ? '09:40' : '09:30'}
  Recovery complete:  ${f.ransomware ? 'Mar 21 (after day-4 ransomware)' : 'Mar 15 ~17:00'}

<span class="log-warn">IMPACT:</span>
  - ${scN(f.recordsExposed)} patient records exposed (PII + PHI)
  - 342 endpoints received malicious update; ${f.hostsStaged} carried second-stage tooling
  - DC and EMR database directly compromised${f.reinfected > 0 ? `
  - ${f.reinfected} endpoints reinfected by fake v4.2.3` : ''}
  - Estimated breach cost: $${(f.recordsExposed * 40 / 3 / 1e6).toFixed(1)}M (notification, credit monitoring, legal)

<span class="log-warn">VENDOR RISK:</span>
  - NetPulse had local admin on all endpoints (excessive privilege)
  - No verification of update integrity beyond vendor signing
  - No network segmentation between RMM and clinical systems`
        },
        choices: [
          {
            key: 'A',
            label: 'Full report with supply chain risk analysis, HIPAA documentation, and vendor management overhaul plan',
            desc: 'Comprehensive report: technical timeline, patient impact assessment, MITRE ATT&CK mapping, vendor risk recommendations, and HIPAA breach notification package.',
            quality: 'good',
            score: { time: 5, containment: 5, evidence: 10, thoroughness: 25 },
            sets: f => ({ notifyStatus: scNotifyStatus(f, 'mssp') }),
            outcome: (f, st) => 'Report drives a complete overhaul of vendor risk management: least-privilege for all vendor tools, update verification pipelines, network segmentation between IT management and clinical systems. '
              + ((f.scopedRecords || 180000) < f.recordsExposed
                ? `HIPAA notification goes out within the deadline — to ${scN(f.scopedRecords || 180000)} patients. The ${scN(f.recordsExposed - (f.scopedRecords || 180000))} whose records sat in the other systems aren't in it, and HHS OCR finds them during its review. `
                : f.scopePrecise ? 'HIPAA notification executed accurately within deadline. HHS investigation finds Vertex responded appropriately. '
                : `HIPAA notification covers every patient in the affected systems — ${scN(f.recordsExposed)}, over-inclusive but defensible. `
                  + (f.attackerTipped ? (f.saw_auditGap ? 'Your note on the 10:55 audit shutdown explains why to OCR\'s satisfaction. ' : 'OCR asks why record-level logging stops at 10:55; nobody on your team wrote it down. ') : ''))
              + (f.saw_dbprod ? 'The discovery time is documented to the minute — 09:10, when DB-PROD-01 showed up in the beacon list — so the 60-day clock is beyond dispute. ' : 'OCR asks when Vertex first knew PHI systems were involved; the earliest documented answer is the 10:35 alert. ')
              + (f.vendorCoordinated ? 'NetPulse implements build pipeline integrity monitoring based on your findings.' : 'NetPulse rebuilds its pipeline from other customers\' reports; yours arrives a week late.')
              + (st.findings.length >= 8 ? ` The IOC appendix carries ${st.findings.length} documented findings.` : ''),
          },
          {
            key: 'B',
            label: 'Standard incident report with timeline and HIPAA breach notification',
            desc: 'Cover the incident details and handle the regulatory requirements. Skip the vendor risk deep-dive.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 5, thoroughness: 5 },
            sets: f => ({ notifyStatus: scNotifyStatus(f, 'mssp') }),
            outcome: f => ((f.scopedRecords || 180000) < f.recordsExposed
                ? `HIPAA notification filed on time — for ${scN(f.scopedRecords || 180000)} of the ${scN(f.recordsExposed)} patients exposed — and the incident documented. `
                : 'HIPAA notification filed on time and incident documented. ')
              + 'But without the vendor risk analysis, Vertex doesn\'t fundamentally change how they manage third-party software trust. They replace NetPulse with another RMM that gets the same excessive privileges. The systemic risk remains.',
          },
          {
            key: 'C',
            label: 'Let Vertex\'s compliance team handle the HIPAA notification — your job was the technical response',
            desc: 'Hand off the regulatory work. They have a compliance department for that.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: -10, thoroughness: -25 },
            sets: f => ({ notifyStatus: scNotifyStatus(f, 'client') }),
            outcome: 'Without your technical findings informing the HIPAA notification, the compliance team underreports the breach scope. HHS OCR investigation uncovers discrepancies. Vertex faces additional penalties for inaccurate reporting. Your MSSP is named in the investigation for failing to provide adequate documentation.',
          },
        ],
        live: f => `HIPAA NOTICE DUE WITHIN 60 DAYS OF MAR 15 · ${scN(f.scopedRecords || 180000)} IN SCOPE`,
        timeline: [
          { at: 10, sev: 'info', text: 'Local reporter asks Vertex PR for comment on "the NetPulse breach"' },
        ],
        siemEntries: f => [
          { time: '17:30', sev: scFoothold(f) ? 'warn' : 'success', text: scFoothold(f) ? 'Systems restored — attacker foothold unresolved' : 'All systems restored — operations normal' },
          { time: '17:35', sev: 'info', text: 'Post-incident review — documentation phase' },
          { time: '17:40', sev: 'warn', text: `HIPAA breach notification: ${scN(f.scopedRecords || 180000)} patients — 60-day deadline` },
        ],
      },
    ],
  }
);
