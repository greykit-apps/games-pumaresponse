// Cloud Infrastructure Breach — AWS Credential Compromise
// Scenario data for PumaResponse — format documented in README → Development.

// CLOUD_BREACH: game minute 0 is the 06:45 handoff; st.elapsed + st.phaseClock is "now".
// Mining is priced per p3.8xlarge-hour (on-demand, us-east-1); 16 of them is the $196/hour at handoff.
const CB_P3_HOURLY = 12.24;
function cbNow(st) { return st.elapsed + st.phaseClock; }
function cbClock(min) {
  const t = 6 * 60 + 45 + Math.floor(min);
  return `${String(Math.floor(t / 60) % 24).padStart(2, '0')}:${String(t % 60).padStart(2, '0')}`;
}
function cbPublicFor(min) {
  const m = Math.max(0, Math.floor(min));
  return `${Math.floor(m / 60)} hours ${m % 60} minutes`;
}
// Mining spend banked so far plus whatever is still running up to now
function cbMinerSpend(f, st) {
  return f.minerSpend + f.minerCount * CB_P3_HOURLY * Math.max(0, cbNow(st) - f.minerAt) / 60;
}
// Flags for a change in the running miner fleet: bank what has accrued, then switch
function cbMiners(f, st, count, regions) {
  return { minerSpend: cbMinerSpend(f, st), minerCount: count, minerRegions: regions, minerAt: Math.max(cbNow(st), f.minerAt) };
}
function cbTotalMining(f, st) {
  return cbMinerSpend(f, st) + f.returnSpend + f.sessionSpend;
}
// Ways back in that the attacker still holds. The session token is optional: it is
// the one nothing on screen shows, so live readouts leave it out.
function cbFootholds(f, withSession) {
  return [
    f.keyActive && 'leaked access key',
    f.backdoor1Live && 'admin-backup-svc',
    f.backdoor2Live && 'lambda-monitoring-role + CloudWatchSync',
    withSession && f.stsLive && 'dev-jpark session token',
  ].filter(Boolean);
}
// What happens after an eradication that leaves a way back in
function cbAfterEradication(f) {
  const back = f.backdoor1Live || f.backdoor2Live;
  return {
    attackerReturned: back,
    returnVia: back ? (f.backdoor2Live ? 'lambda-monitoring-role' : 'admin-backup-svc') : '',
    returnSpend: back ? Math.round(96 * CB_P3_HOURLY * 32 / 60) : 0, // 96 GPUs, 11:20-11:52
    sessionSpend: f.stsLive ? Math.round(16 * CB_P3_HOURLY * 1.5) : 0, // 16 GPUs for 90 min on the session token
  };
}
function cbFines(f) {
  return 500000 + (f.brandsLate ? 500000 : 0) + (!f.scopeAccurate ? 250000 : 0)
    + (f.proof === 'unknown' ? 150000 : 0) + (f.attackerReturned ? 400000 : 0);
}
function cbExfilSummary(f) {
  const again = f.attackerReturned ? ' + a second full DB copy after eradication' : '';
  if (f.proof === 'confirmed') return (f.snapShared ? '2.1M — confirmed (full DB snapshot shared to attacker account)' : '2.1M — confirmed (flow logs: 1.18 GB out)') + again;
  if (f.proof === 'accessed') return (f.snapShared ? '2.1M stated as accessed — full DB snapshot was actually shared out' : '2.1M queried — exfiltration unproven') + again;
  if (f.proof === 'unknown') return (f.snapShared ? 'Unknown from logs (audit log destroyed) — but a full DB snapshot was shared out' : 'Unknown — RDS audit log destroyed; 2.1M presumed') + again;
  if (f.proof === 'misclassified') return (f.snapShared ? 'Never assessed — a full DB snapshot had been shared out' : 'Never assessed — classed as cryptojacking') + again;
  return 'Unknown' + again;
}
function cbPciStatus(f) {
  if (f.brandsLate) return 'SUSPENDED — late card-brand notification';
  if (f.attackerReturned) return 'Ongoing-compromise finding — acquirer review';
  if (!f.scopeAccurate) return 'Scope restated to brands — under review';
  if (f.proof === 'unknown') return 'PFI inconclusive — full reassessment required';
  if (f.req10Finding) return 'PFI engaged — Requirement 10 logging finding';
  return 'PFI engaged, scope accepted — revalidation pending';
}

registerIncident(
  {
    id: 'CLOUD_BREACH',
    title: 'Cloud Infrastructure Breach — AWS Credential Compromise',
    client: 'NovaPay Financial Technologies',
    severity: 'CRITICAL',
    sevClass: 'high',
    ticketId: 'IR-2024-1231',
    // In-world "today": every date in this file is written relative to it and
    // shown shifted to the real date (see REAL-DATE ANCHORING in js/game.js)
    baseDate: '2024-03-20',
    assignedTime: '06:45 ET',
    summary: 'AWS access keys leaked in a public GitLab.com project. Attacker created new IAM users, spun up crypto miners, and accessed RDS databases containing payment card data. CloudTrail shows privilege escalation to admin.',
    iocs: [
      { type: 'IAM KEY', val: 'AKIA3EXAMPLE7CMPRMSD — pushed to a public GitLab.com project' },
      { type: 'IAM USER', val: 'admin-backup-svc — attacker-created IAM user' },
      { type: 'IP', val: '45.155.205.99 — API calls from Tor exit node' },
      { type: 'EC2', val: 'i-0deadbeef12345678 — unauthorized p3.8xlarge (crypto mining)' },
      { type: 'S3', val: 'novapay-prod-cardholder-data — public ACL detected' },
    ],
    // Run state. Every later phase reads these; choices change them via `sets`.
    initialFlags: {
      minerSpend: 748,        // dollars of GPU time banked (16x p3.8xlarge since 02:55 = $748 at handoff)
      minerCount: 16,         // p3.8xlarge instances the attacker has running right now
      minerRegions: 2,        // regions they are running in
      minerAt: 0,             // game minute minerSpend was last banked
      keyActive: true,        // the leaked AKIA key still works
      stsLive: true,          // the 36h GetSessionToken credential (ASIA...) still works — deactivating the key doesn't end it
      backdoor1Live: true,    // admin-backup-svc (AdministratorAccess) still exists
      backdoor2Live: true,    // lambda-monitoring-role + the CloudWatchSync key-minting Lambda still exist
      trailStopped: false,    // attacker ran cloudtrail:StopLogging
      trailStoppedAt: 0,
      trailRestarted: false,  // we turned it back on
      rdsAuditDeleted: false, // attacker deleted the RDS audit log group — the query history is gone
      auditDeletedAt: 0,
      auditDeletedBy: '',
      snapShared: false,      // db-maint-0320 (full prod DB snapshot) shared to the attacker's AWS account
      snapSharedAt: 0,
      snapDeleted: false,     // the manual snapshot was deleted from NovaPay's account
      dbExposed: true,        // sg-prod-db open to 0.0.0.0/0:3306, PubliclyAccessible=true
      masterPwRotated: false, // RDS master password (set by the attacker at 03:08) changed back
      dbReaccessed: false,    // attacker logged back into the DB over the still-open port
      s3Public: true,         // cardholder bucket policy still public
      s3PublicMin: 225,       // minutes the bucket has been public (since 03:00)
      prodOutage: false,      // the SCP lockdown took payments down
      proof: '',              // what the investigation can prove: confirmed | accessed | unknown | misclassified
      scopeAccurate: true,    // scope stated to the card brands matches what happened
      brandsNotified: false,  // card brands / acquirer notified
      brandsLate: false,      // ... after the deadline
      pfiEngaged: false,      // PCI Forensic Investigator engaged
      req10Finding: false,    // PFI records an unexplained logging gap as a Requirement 10 failure
      consumerLate: false,    // consumer / state breach notices slip
      attackerReturned: false,// a missed backdoor was used after eradication
      returnVia: '',
      returnSpend: 0,         // GPU spend from the return visit
      sessionSpend: 0,        // GPU spend on the leftover session token
      containedAt: 0,         // game minute the Containment action landed
    },
    // 2 real seconds per game minute once the decision clock starts; 10-minute par
    clock: { rate: 0.5, par: 10 },
    // Best achievable total (every finding tagged, instant decisions, best path).
    // Grades are a percentage of this. Recompute with tools/scenario-harness.js after
    // changing this scenario's scores, carried penalties or findings.
    bestScore: 331,
    // MITRE ATT&CK (Enterprise v19) technique per finding, shown in the debrief.
    // Findings that aren't adversary behavior (missing controls, business facts) are omitted.
    attack: {
      torKey: "T1078.004 Valid Accounts: Cloud Accounts",
      stsSession: "T1098.001 Account Manipulation: Additional Cloud Credentials",
      backdoorUser: "T1136.003 Create Account: Cloud Account",
      miners: "T1496.001 Resource Hijacking: Compute Hijacking",
      s3Exfil: "T1530 Data from Cloud Storage",
      backdoor2: "T1136.003 Create Account: Cloud Account",
      exposure: "T1686.001 Disable or Modify System Firewall: Cloud Firewall",
      masterPw: "T1098 Account Manipulation",
      manualSnap: "T1578.001 Modify Cloud Compute Infrastructure: Create Snapshot",
      asiaKey: "T1550.001 Use Alternate Authentication Material: Application Access Token",
      antiForensics: "T1685.002 Disable or Modify Tools: Disable or Modify Cloud Log",
      auditGone: "T1685.002 Disable or Modify Tools: Disable or Modify Cloud Log",
      fullDump: "T1213.006 Data from Information Repositories: Databases",
      flowBytes: "T1048 Exfiltration Over Alternative Protocol",
      piDigest: "T1213.006 Data from Information Repositories: Databases",
      snapShare: "T1537 Transfer Data to Cloud Account",
    },
    debrief: (f, st) => {
      const persist = cbFootholds(f, true);
      return [
        ['AWS Spend on Miners', fmtUSD(cbTotalMining(f, st))],
        ['Card Records Exfiltrated', cbExfilSummary(f)],
        ['Attacker Persistence at Close', persist.length ? 'STILL PRESENT — ' + persist.join(', ') : 'Removed'],
        ['PCI Status', cbPciStatus(f)],
      ];
    },
    phases: [
      { // TRIAGE
        name: 'TRIAGE',
        narrative: 'AWS GuardDuty fires a high-severity alert: IAM access keys associated with a NovaPay developer are being used from a Tor exit node to make API calls including ec2:RunInstances and iam:CreateUser. You check the developer\'s git remotes and find the keys were pushed to a public GitLab.com project 4 hours ago in a .env file — outside GitHub\'s secret-scanning partnership with AWS, so no quarantine policy ever landed on the key.',
        evidence: {
          title: 'GUARDDUTY + CLOUDTRAIL ALERTS',
          content: `<span class="log-warn">[02:33]</span> GitLab.com push 4f1e9c2: novapay/payment-gateway (PUBLIC project)
  File: .env.production — contains AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  <span class="log-highlight">Exposed for 4 hours before detection</span>
<span class="log-warn">[02:41]</span> GuardDuty Recon:EC2/PortProbeUnprotectedPort — bastion-01 (sev 2.0, recurring)
<span class="log-warn">[02:51]</span> <span class="log-highlight">GuardDuty</span> UnauthorizedAccess:IAMUser/TorIPCaller
  Key: AKIA3EXAMPLE7CMPRMSD (user: dev-jpark)<!--f:torKey-->
  Source: 45.155.205.99 (Tor exit node)<!--f:torKey-->
<span class="log-warn">[02:51]</span> API: sts:GetSessionToken — DurationSeconds=129600 (36h)<!--f:stsSession-->
  Returned: ASIA3EXAMPLE9SESSION, expires Mar 21 14:51<!--f:stsSession-->
<span class="log-warn">[02:52]</span> API: iam:CreateUser — "admin-backup-svc"<!--f:backdoorUser-->
<span class="log-warn">[02:53]</span> API: iam:AttachUserPolicy — AdministratorAccess<!--f:backdoorUser-->
<span class="log-warn">[02:55]</span> API: ec2:RunInstances — 8x p3.8xlarge (us-east-1)<!--f:miners-->
<span class="log-warn">[02:57]</span> API: ec2:RunInstances — 8x p3.8xlarge (us-west-2)<!--f:miners-->
  <span class="log-highlight">Estimated cost: $196/hour ($4,704/day)</span><!--f:miners-->
<span class="log-warn">[03:05]</span> codebuild: novapay-ci assumed role deploy-staging (nightly build)
<span class="log-warn">[03:10]</span> API: rds:DescribeDBInstances (enumeration)
<span class="log-warn">[03:15]</span> <span class="log-highlight">ALERT</span> GuardDuty Exfiltration:S3/AnomalousBehavior
  Bucket: novapay-prod-cardholder-data — GetObject spike from 45.155.205.99<!--f:s3Exfil-->
<span class="log-warn">[04:00]</span> AWS Backup: job novapay-prod-daily COMPLETED
<span class="log-warn">[06:45]</span> GuardDuty alert escalated to MSSP`
        },
        choices: [
          {
            key: 'A',
            label: 'Disable compromised keys, delete attacker IAM user, terminate mining instances immediately',
            desc: 'Kill the access: deactivate the leaked keys, remove the attacker\'s IAM user and their access keys, and terminate the unauthorized EC2 instances.',
            quality: 'good',
            score: { time: 20, containment: 20, evidence: 5, thoroughness: 10 },
            sets: (f, st) => ({ ...cbMiners(f, st, 0, 0), keyActive: false, backdoor1Live: false }),
            outcome: (f, st) => `Compromised keys deactivated in IAM. Attacker's admin-backup-svc user deleted along with their access keys. All ${f.minerCount} crypto mining instances terminated across ${f.minerRegions} regions — stopping the ${fmtUSD(f.minerCount * CB_P3_HOURLY)}/hour bleed at ${fmtUSD(cbMinerSpend(f, st))} spent. The attacker's access appears severed within 5 minutes. `
              + (f.rdsAuditDeleted ? 'But while you were deciding, the attacker stopped CloudTrail logging and deleted the RDS audit log group — the database\'s query history is gone.'
                : f.trailStopped ? 'But while you were deciding, the attacker stopped logging on novapay-mgmt-trail.'
                : 'CloudTrail logs preserved for investigation.'),
          },
          {
            key: 'B',
            label: 'Rotate the compromised access keys and investigate the scope',
            desc: 'Generate new keys for dev-jpark and deactivate the old ones. Then investigate what happened.',
            quality: 'partial',
            score: { time: 5, containment: 5, evidence: 10, thoroughness: 5 },
            sets: { keyActive: false },
            outcome: (f, st) => `The leaked keys are rotated — but the attacker already created admin-backup-svc with its own keys and AdministratorAccess policy. They still have full admin access to the AWS account through their backdoor user. The crypto miners continue running: ${f.minerCount} instances in ${f.minerRegions} regions, ${fmtUSD(f.minerCount * CB_P3_HOURLY)}/hour, ${fmtUSD(cbMinerSpend(f, st))} so far. You notice the continued activity 20 minutes later.`,
          },
          {
            key: 'C',
            label: 'Delete the .env file from the repo and force-push to remove it from history',
            desc: 'Remove the leaked credentials from GitLab so no one else can find them.',
            quality: 'bad',
            score: { time: -15, containment: -20, evidence: -5, thoroughness: -10 },
            // Nobody touches IAM for another 90 minutes; the attacker scales up and wipes logs unopposed
            sets: (f, st) => {
              const grown = Math.max(f.minerCount, 48);
              const now = cbNow(st);
              return {
                minerSpend: cbMinerSpend(f, st) + grown * CB_P3_HOURLY * 1.5,
                minerCount: grown,
                minerRegions: Math.max(f.minerRegions, 6),
                minerAt: now + 90,
                keyActive: false,
                trailStopped: true,
                trailStoppedAt: f.trailStopped ? f.trailStoppedAt : now + 25,
                rdsAuditDeleted: true,
                auditDeletedAt: f.rdsAuditDeleted ? f.auditDeletedAt : now + 40,
                auditDeletedBy: f.rdsAuditDeleted ? f.auditDeletedBy : 'admin-backup-svc',
              };
            },
            outcome: (f, st) => {
              const grown = Math.max(f.minerCount, 48);
              return `The keys are removed from GitLab.com but still active in AWS. The attacker has had them for 4 hours already — removing the public exposure doesn't revoke the keys, and anyone who scraped the repo still has them. Meanwhile, the attacker scales to ${grown} GPU instances across ${Math.max(f.minerRegions, 6)} regions, stops CloudTrail logging, deletes the RDS audit log group, and downloads 2 GB more from the cardholder data bucket. The mining bill hits ${fmtUSD(cbMinerSpend(f, st) + grown * CB_P3_HOURLY * 1.5)} before you realize, 90 minutes later, that the keys need to be deactivated in IAM.`;
            },
          },
          {
            key: 'D',
            when: f => f.saw_stsSession,
            label: 'Revoke dev-jpark\'s active sessions, then disable the key, delete the attacker user, terminate the miners',
            desc: 'Attach an explicit deny for tokens issued before now (aws:TokenIssueTime) to dev-jpark so the 36-hour session token dies with the key, then do the rest.',
            quality: 'good',
            score: { time: 20, containment: 25, evidence: 5, thoroughness: 15 },
            sets: (f, st) => ({ ...cbMiners(f, st, 0, 0), keyActive: false, backdoor1Live: false, stsLive: false }),
            outcome: (f, st) => `Deactivating an access key does nothing to temporary credentials already minted from it, so you start with an inline deny-all on dev-jpark conditioned on aws:TokenIssueTime before now — the 36-hour ASIA3EXAMPLE9SESSION token stops working on its next call. Then the key is deactivated, admin-backup-svc deleted with its keys, and all ${f.minerCount} mining instances terminated across ${f.minerRegions} regions at ${fmtUSD(cbMinerSpend(f, st))} spent. `
              + (f.rdsAuditDeleted ? 'The attacker still got to the logs first: CloudTrail logging stopped, RDS audit log group deleted.'
                : f.trailStopped ? 'The attacker did manage to stop logging on novapay-mgmt-trail first.'
                : 'CloudTrail logs preserved for investigation.'),
          },
        ],
        live: (f, st) => `MINER SPEND ${fmtUSD(cbMinerSpend(f, st))} · ${f.minerCount} GPU INSTANCES IN ${f.minerRegions} REGIONS · ${fmtUSD(f.minerCount * CB_P3_HOURLY)}/HR`,
        timeline: [
          { at: 5, sev: 'crit', text: 'ec2:RunInstances — 8x p3.8xlarge in eu-west-1 (admin-backup-svc)',
            sets: (f, st) => cbMiners(f, st, f.minerCount + 8, f.minerRegions + 1), score: { containment: -3 } },
          { at: 10, sev: 'crit', text: 'cloudtrail:StopLogging — novapay-mgmt-trail (admin-backup-svc)',
            sets: (f, st) => ({ trailStopped: true, trailStoppedAt: cbNow(st) }), score: { evidence: -3 } },
          { at: 16, sev: 'crit', text: 'logs:DeleteLogGroup — /aws/rds/instance/novapay-prod/audit (admin-backup-svc)',
            sets: (f, st) => ({ rdsAuditDeleted: true, auditDeletedAt: cbNow(st), auditDeletedBy: 'admin-backup-svc' }), score: { evidence: -5 } },
          { at: 24, sev: 'crit', text: 'ec2:RunInstances — 24x p3.8xlarge across ap-southeast-1, sa-east-1, eu-central-1',
            sets: (f, st) => cbMiners(f, st, f.minerCount + 24, f.minerRegions + 3), score: { containment: -3 } },
        ],
        siemEntries: [
          { time: '06:45', sev: 'crit', text: 'INCIDENT ASSIGNED — Cloud Breach — NovaPay Financial' },
          { time: '06:45', sev: 'warn', text: 'AWS access keys leaked in a public GitLab.com project' },
          { time: '06:46', sev: 'crit', text: 'Attacker created admin IAM user — full privilege escalation' },
          { time: '06:47', sev: 'warn', text: '16x p3.8xlarge crypto miners running in 2 regions — $196/hour' },
        ],
      },
      { // CONTAINMENT
        name: 'CONTAINMENT',
        carried: f => {
          const out = [];
          if (f.stsLive) out.push({
            text: 'dev-jpark\'s key is deactivated, yet ec2:DescribeInstances calls keep arriving from 45.155.205.99 signed with ASIA3EXAMPLE9SESSION. The 36-hour session token issued at 02:51 outlives the key it came from.',
            score: { containment: -5 },
          });
          if (f.backdoor1Live) out.push({
            text: `admin-backup-svc still has AdministratorAccess and working keys. The ${f.minerCount} miners it launched are still running.`,
            score: { containment: -10 },
          });
          if (f.rdsAuditDeleted) out.push({
            sev: 'info',
            text: `The RDS audit log group was deleted at ${cbClock(f.auditDeletedAt)}, before anyone exported it.`,
          });
          return out;
        },
        narrative: f => (f.backdoor1Live
          ? 'The leaked key is dead, but the attacker\'s own admin user still works and the miners are still running. '
          : 'The attacker\'s primary access is revoked. ')
          + 'But CloudTrail shows they made extensive API calls during their 4-hour window. You need to identify all changes they made — backdoor users, policies, security group modifications, Lambda functions, or other persistence mechanisms.',
        evidence: {
          title: 'CLOUDTRAIL AUDIT — ATTACKER ACTIVITY (4-HOUR WINDOW)',
          content: f => `<span class="log-warn">[02:52]</span> iam:CreateUser — admin-backup-svc ${f.backdoor1Live ? '<span class="log-highlight">STILL ACTIVE</span>' : '✓ DELETED'}
<span class="log-warn">[02:53]</span> iam:CreateAccessKey — admin-backup-svc ${f.backdoor1Live ? '<span class="log-highlight">STILL ACTIVE</span>' : '✓ DELETED'}
<span class="log-warn">[02:54]</span> <span class="log-highlight">iam:CreateUser — lambda-monitoring-role</span><!--f:backdoor2-->
<span class="log-warn">[02:54]</span> iam:AttachUserPolicy — lambda-monitoring-role → AdministratorAccess<!--f:backdoor2-->
<span class="log-warn">[02:56]</span> <span class="log-highlight">lambda:CreateFunction — "CloudWatchSync"</span><!--f:backdoor2-->
  Runtime: python3.11, Trigger: EventBridge schedule rate(5 minutes)<!--f:backdoor2-->
  Code: iam:CreateAccessKey for lambda-monitoring-role, POSTs it to an external URL<!--f:backdoor2-->
<span class="log-warn">[02:58]</span> ec2:AuthorizeSecurityGroupIngress — sg-prod-db<!--f:exposure-->
  <span class="log-highlight">0.0.0.0/0 port 3306 (MySQL) — database exposed to internet</span><!--f:exposure-->
<span class="log-warn">[03:00]</span> s3:PutBucketPolicy — novapay-prod-cardholder-data<!--f:exposure-->
  <span class="log-highlight">Policy: public read access (s3:GetObject for *)</span><!--f:exposure-->
<span class="log-warn">[03:08]</span> rds:ModifyDBInstance — novapay-prod<!--f:masterPw-->
  MasterUserPassword changed, PubliclyAccessible=true<!--f:masterPw-->
<span class="log-warn">[03:30]</span> ssm:GetParameter — /prod/payment-gw/processor-key (payment-gw task role)
<span class="log-warn">[04:15]</span> rds:CreateDBSnapshot — novapay-prod → "db-maint-0320" (manual)<!--f:manualSnap-->
<span class="log-warn">[04:40]</span> iam:ListAccessKeys — dev-jpark (NovaPay SSO, IT on-call)
<span class="log-warn">[05:10]</span> ec2:CreateTags — i-0a71c3 (Terraform, ci-deploy role)
<span class="log-warn">[05:45]</span> kms:Decrypt — payment-gw task role (routine)${f.stsLive ? `
<span class="log-warn">[06:49]</span> ec2:DescribeInstances — dev-jpark via <span class="log-highlight">ASIA3EXAMPLE9SESSION</span> from 45.155.205.99<!--f:asiaKey-->` : ''}${f.trailStopped ? `
<span class="log-warn">[${cbClock(f.trailStoppedAt)}]</span> <span class="log-highlight">cloudtrail:StopLogging — novapay-mgmt-trail</span><!--f:antiForensics-->` : ''}${f.rdsAuditDeleted ? `
<span class="log-warn">[${cbClock(f.auditDeletedAt)}]</span> <span class="log-highlight">logs:DeleteLogGroup — /aws/rds/instance/novapay-prod/audit</span><!--f:antiForensics-->` : ''}`
        },
        choices: [
          {
            key: 'A',
            label: 'Audit all CloudTrail events, remove every attacker-created resource, fix security groups and S3 policies',
            desc: 'Systematic review of every API call in the 4-hour window. Remove all backdoors: IAM users, Lambda functions, modified policies, security group rules, and S3 ACLs.',
            quality: 'good',
            score: { time: 10, containment: 25, evidence: 10, thoroughness: 15 },
            sets: (f, st) => ({
              ...cbMiners(f, st, 0, 0), containedAt: cbNow(st),
              backdoor1Live: false, backdoor2Live: false,
              dbExposed: false, s3Public: false, s3PublicMin: 225 + cbNow(st),
              snapDeleted: true, trailRestarted: f.trailStopped,
              masterPwRotated: !!f.saw_masterPw,
            }),
            outcome: f => 'Complete CloudTrail audit identifies all attacker actions. Second backdoor user (lambda-monitoring-role) discovered and deleted. Malicious Lambda function removed.'
              + (f.minerCount ? ` ${f.minerCount} running miners terminated.` : '')
              + ' Security group rule exposing MySQL to the internet reverted and PubliclyAccessible turned off. S3 bucket policy restored to private. '
              + (f.snapShared
                ? `The unauthorized snapshot db-maint-0320 is deleted — but at ${cbClock(f.snapSharedAt)} it was shared with an external AWS account. Deleting your copy does nothing to one they have already made.`
                : 'Unauthorized DB snapshot deleted.')
              + (f.trailStopped ? ' Logging restarted on novapay-mgmt-trail.' : '')
              + (f.saw_masterPw ? ' RDS master password rotated — the attacker had set it at 03:08.' : '')
              + (f.saw_masterPw && !f.snapShared ? ' Every attacker modification reversed.' : ''),
          },
          {
            key: 'B',
            label: 'Remove the IAM users and Lambda function — the obvious backdoors',
            desc: 'Delete the attacker-created users and the persistence Lambda. Check for more later.',
            quality: 'partial',
            score: { time: 10, containment: 10, evidence: 5, thoroughness: -5 },
            sets: (f, st) => ({
              ...cbMiners(f, st, 0, 0), containedAt: cbNow(st),
              backdoor1Live: false, backdoor2Live: false,
              snapDeleted: !!f.saw_manualSnap,
              dbReaccessed: true,
            }),
            outcome: f => 'IAM backdoors and Lambda removed'
              + (f.minerCount ? `, and the ${f.minerCount} running miners terminated with them` : '')
              + (f.saw_manualSnap ? '; you also delete the db-maint-0320 snapshot you flagged' : '')
              + '. But you missed the security group change exposing MySQL to the internet and the S3 bucket policy making cardholder data publicly readable. The database is internet-accessible for 6 more hours until a security scan catches it. Shodan indexes the exposed MySQL port within 2 hours.'
              + (f.saw_masterPw ? ' And you know the attacker set the master password at 03:08 — they don\'t need AWS credentials to log in.' : ''),
          },
          {
            key: 'C',
            label: 'Lock down the AWS account by enabling MFA on root and restricting all IAM',
            desc: 'Global lockdown: enable MFA on root, set an SCP denying all IAM actions, and sort it out later.',
            quality: 'bad',
            score: { time: -10, containment: 15, evidence: -10, thoroughness: -10 },
            // Miners keep running until someone terminates them from the console 2.5 hours later
            sets: (f, st) => ({
              minerSpend: cbMinerSpend(f, st) + f.minerCount * CB_P3_HOURLY * 2.5,
              minerCount: 0,
              minerAt: cbNow(st) + 150,
              containedAt: cbNow(st),
              prodOutage: true,
              dbReaccessed: true,
            }),
            outcome: f => 'The SCP denies iam:* and sts:* — and NovaPay\'s payment gateway calls sts:AssumeRole into the processor\'s cross-account role for every settlement batch. Those calls fail at once and settlement stops: the payment processing system goes down, affecting thousands of transactions. You have to partially roll back the lockdown to restore service, creating a confusing window of mixed state. And an SCP only filters API calls: lambda-monitoring-role\'s existing access keys still work for EC2, S3 and RDS, and CloudWatchSync resumes minting keys the moment IAM is allowed again.'
              + (f.minerCount ? ` Nothing in the lockdown touches the ${f.minerCount} running miners; they run another 2.5 hours.` : '')
              + ' The security group and S3 issues remain.',
          },
          {
            key: 'D',
            when: f => f.saw_asiaKey,
            label: 'Full audit and cleanup, plus kill dev-jpark\'s live session token',
            desc: 'Everything in the full audit, and an explicit deny on tokens issued before now (aws:TokenIssueTime) for dev-jpark — the only way to end a GetSessionToken credential early.',
            quality: 'good',
            score: { time: 10, containment: 30, evidence: 10, thoroughness: 20 },
            sets: (f, st) => ({
              ...cbMiners(f, st, 0, 0), containedAt: cbNow(st),
              backdoor1Live: false, backdoor2Live: false, stsLive: false,
              dbExposed: false, s3Public: false, s3PublicMin: 225 + cbNow(st),
              snapDeleted: true, trailRestarted: f.trailStopped,
              masterPwRotated: !!f.saw_masterPw,
            }),
            outcome: f => 'The ASIA-prefixed key in the 06:49 call is a temporary credential, and deactivating dev-jpark\'s access key never touched it. A deny-all on dev-jpark for tokens issued before now kills it on its next call. Then the full sweep: lambda-monitoring-role and CloudWatchSync deleted'
              + (f.minerCount ? `, ${f.minerCount} running miners terminated` : '')
              + ', sg-prod-db reverted and PubliclyAccessible off, bucket policy private. '
              + (f.snapShared
                ? `db-maint-0320 is deleted — but it was shared with an external account at ${cbClock(f.snapSharedAt)}, and their copy is out of reach.`
                : 'db-maint-0320 deleted.')
              + (f.trailStopped ? ' Logging restarted on novapay-mgmt-trail.' : '')
              + (f.saw_masterPw ? ' RDS master password rotated.' : ''),
          },
        ],
        live: (f, st) => {
          const n = cbFootholds(f, false).length;
          return `ATTACKER BACKDOORS LIVE: ${n} · SNAPSHOT db-maint-0320: ${f.snapShared ? 'SHARED EXTERNALLY' : 'NOT SHARED'}`
            + (f.minerCount ? ` · MINERS ${fmtUSD(cbMinerSpend(f, st))}` : '');
        },
        timeline: [
          { at: 3, when: f => f.stsLive, sev: 'crit', text: 'ec2:RunInstances — 8x p3.8xlarge (us-east-1) signed with ASIA3EXAMPLE9SESSION',
            sets: (f, st) => cbMiners(f, st, f.minerCount + 8, f.minerCount ? f.minerRegions : 1), score: { containment: -3 } },
          { at: 5, sev: 'crit', text: 'Lambda CloudWatchSync: new access key for lambda-monitoring-role POSTed externally', score: { containment: -3 } },
          { at: 9, sev: 'crit', text: 'rds:ModifyDBSnapshotAttribute — db-maint-0320 restore access granted to external account 491803327730',
            sets: (f, st) => ({ snapShared: true, snapSharedAt: cbNow(st) }), score: { containment: -3 } },
          { at: 13, when: f => !f.rdsAuditDeleted, sev: 'crit', text: 'logs:DeleteLogGroup — /aws/rds/instance/novapay-prod/audit (lambda-monitoring-role)',
            sets: (f, st) => ({ rdsAuditDeleted: true, auditDeletedAt: cbNow(st), auditDeletedBy: 'lambda-monitoring-role' }), score: { evidence: -5 } },
          { at: 18, when: f => !f.trailStopped, sev: 'warn', text: 'cloudtrail:StopLogging — novapay-mgmt-trail (lambda-monitoring-role)',
            sets: (f, st) => ({ trailStopped: true, trailStoppedAt: cbNow(st) }), score: { evidence: -3 } },
        ],
        siemEntries: f => [
          { time: '07:00', sev: 'crit', text: 'Second backdoor IAM user found: lambda-monitoring-role' },
          { time: '07:02', sev: 'crit', text: 'Malicious Lambda creating new access keys every 5 minutes' },
          { time: '07:05', sev: 'crit', text: 'Production database exposed to internet via security group change' },
          ...(f.stsLive ? [{ time: '07:06', sev: 'warn', text: 'API calls as dev-jpark continue from 45.155.205.99 (ASIA credential)' }] : []),
        ],
      },
      { // INVESTIGATION
        name: 'INVESTIGATION',
        carried: f => {
          const out = [];
          if (f.stsLive) out.push({
            text: 'dev-jpark\'s session token ASIA3EXAMPLE9SESSION is still valid until Mar 21 14:51. Nothing deleted so far touches it: it draws its permissions from dev-jpark\'s policies at every call, and those still grant S3 and RDS full access.',
            score: { containment: -5 },
          });
          if (f.backdoor2Live) out.push({
            text: 'The SCP was rolled back far enough to restore payments — and CloudWatchSync went straight back to minting access keys for lambda-monitoring-role.',
            score: { containment: -10 },
          });
          if (f.backdoor1Live) out.push({
            text: 'admin-backup-svc was never deleted. Its keys still work for everything the SCP doesn\'t cover.',
            score: { containment: -5 },
          });
          if (f.prodOutage) out.push({
            text: 'Payment processing was down 47 minutes while the SCP was rolled back — roughly 3,900 card transactions declined.',
            score: { containment: -5 },
          });
          if (f.snapShared) out.push({
            text: `At ${cbClock(f.snapSharedAt)} db-maint-0320 — a full copy of the production database — was shared with AWS account 491803327730. A copy in their account is beyond anything you can delete.`,
            score: { containment: -5 },
          });
          if (f.rdsAuditDeleted) out.push({
            sev: 'info',
            text: 'The RDS audit log is gone. Whatever this investigation proves about the database, it has to prove some other way.',
          });
          return out;
        },
        narrative: f => (cbFootholds(f, true).length
          ? 'Containment is done — or looks done. '
          : 'Containment complete — all attacker persistence removed. ')
          + 'Now determine the full data exposure: what was accessed in the cardholder database, whether the S3 bucket was accessed while public, and the total blast radius. PCI-DSS compliance is at stake.',
        evidence: {
          title: 'DATA ACCESS ANALYSIS',
          content: (f, st) => `<span class="log-ok">── RDS AUDIT LOG (/aws/rds/instance/novapay-prod/audit) ──</span>
${f.rdsAuditDeleted ? `  <span class="log-highlight">ResourceNotFoundException: log group does not exist</span><!--f:auditGone-->
  Deleted ${cbClock(f.auditDeletedAt)} by logs:DeleteLogGroup (${f.auditDeletedBy})<!--f:auditGone-->` : `<span class="log-warn">[03:10]</span> SELECT COUNT(*) FROM transactions — 4.2M rows<!--f:fullDump-->
<span class="log-warn">[03:12]</span> SELECT * FROM cardholders LIMIT 10000<!--f:fullDump-->
<span class="log-warn">[03:15]</span> SELECT * FROM cardholders (full dump initiated)<!--f:fullDump-->
  <span class="log-highlight">2.1M cardholder records queried (names, PANs, expiry dates)</span><!--f:fullDump-->
<span class="log-warn">[03:20]</span> INSERT INTO transactions — payment-gw (routine, 412 rows)
<span class="log-warn">[03:25]</span> SELECT * FROM merchants WHERE volume > 100000<!--f:fullDump-->
<span class="log-warn">[03:30]</span> SELECT 1 — rdsadmin (health check)
<span class="log-warn">[03:45]</span> Query connection terminated (timeout)`}

<span class="log-ok">── VPC FLOW LOGS (db subnet, eni-0db4e1) ──</span>
  10.20.4.17:3306 → 45.155.205.99  ACCEPT  <span class="log-highlight">1,184,220,114 bytes</span> (03:10–03:45)<!--f:flowBytes-->
  10.20.4.17:3306 → 10.20.1.33 (payment-gw)  ACCEPT  routine
  172.31.8.4 (bastion-01) → 10.20.4.17:22  REJECT

<span class="log-ok">── PERFORMANCE INSIGHTS (novapay-prod, 7-day retention) ──</span>
  Top SQL 03:00–04:00: SELECT * FROM cardholders — rows sent 2,100,000<!--f:piDigest-->
  Top SQL 03:00–04:00: SELECT … FROM transactions WHERE settled_at > ? (payment-gw)

<span class="log-ok">── S3 ACCESS ANALYSIS ──</span>
  Bucket ${f.s3Public ? `public since 03:00 — <span class="log-highlight">STILL PUBLIC</span> (${cbPublicFor(225 + cbNow(st))} so far)` : `was public for: ${cbPublicFor(f.s3PublicMin)}`}<!--f:s3Blind-->
  S3 server access logs: <span class="log-highlight">NOT ENABLED</span><!--f:s3Blind-->
  CloudTrail S3 data events: Not configured
  Cannot determine if external parties accessed the bucket

<span class="log-ok">── SNAPSHOT ANALYSIS ──</span>
  rds:CreateDBSnapshot 04:15 — db-maint-0320 (full novapay-prod database)
${f.snapShared ? `  <span class="log-highlight">rds:ModifyDBSnapshotAttribute ${cbClock(f.snapSharedAt)} — restore shared with account 491803327730</span><!--f:snapShare-->` : '  Snapshot was NOT shared publicly or cross-account'}
  ${f.snapDeleted ? 'Snapshot deleted during containment ✓' : '<span class="log-warn">Snapshot still present in account</span>'}

<span class="log-ok">── CLOUDTRAIL ──</span>
  Event history (90-day management events): intact
  novapay-mgmt-trail: ${!f.trailStopped ? 'logging' : f.trailRestarted ? `StopLogging at ${cbClock(f.trailStoppedAt)} — restarted during containment` : `<span class="log-highlight">LOGGING STOPPED since ${cbClock(f.trailStoppedAt)}</span>`}${f.trailStopped && !f.saw_antiForensics ? '<!--f:antiForensics-->' : ''}

<span class="log-ok">── PCI-DSS IMPACT ──</span>
  Cardholder Data Environment (CDE) compromised
  <span class="log-highlight">2.1M PANs potentially exposed</span>
  PCI Forensic Investigator (PFI) engagement required
  Card brand notification required within 24 hours`
        },
        choices: [
          {
            key: 'A',
            label: 'Full forensic investigation: RDS query reconstruction, S3 exposure assessment, PFI engagement, card brand notification',
            desc: 'Complete the data breach scope analysis. Engage a PCI Forensic Investigator. Prepare card brand and acquirer notifications. Document everything for PCI compliance.',
            quality: 'good',
            score: { time: -5, containment: 5, evidence: 25, thoroughness: 20 },
            sets: f => ({
              pfiEngaged: true, brandsNotified: true,
              proof: f.snapShared && f.saw_snapShare ? 'confirmed' : !f.rdsAuditDeleted ? 'accessed' : 'unknown',
              scopeAccurate: !(f.snapShared && !f.saw_snapShare),
              req10Finding: f.trailStopped && !f.saw_antiForensics,
            }),
            outcome: f => (f.rdsAuditDeleted
                ? 'The RDS audit log group is gone, so nothing shows which queries ran; you report 2.1M cardholder records as exposed because the database was reachable and its master password had been changed. '
                : 'RDS query logs confirm 2.1M cardholder records were accessed. ')
              + 'S3 exposure is documented as unknown/potentially public (worst-case assumed for notification).'
              + (f.saw_s3Exfil ? ' GuardDuty\'s S3 anomaly finding from triage goes in as evidence that someone did read from it.' : '')
              + (f.snapShared
                ? (f.saw_snapShare
                  ? ' You document the cross-account share of db-maint-0320: a full copy of the production database went to an attacker-controlled account. Exfiltration is confirmed, not presumed, and the notification covers the whole database — cardholders, merchants, 4.2M transactions.'
                  : ` Nobody documented the snapshot share at ${cbClock(f.snapSharedAt)}. The notification tells the brands the exposure is 2.1M cardholder records with no evidence of bulk transfer — the PFI will find the share in CloudTrail event history.`)
                : '')
              + (f.trailStopped
                ? (f.saw_antiForensics
                  ? ' The StopLogging and log-deletion calls you documented go into the evidence pack as deliberate anti-forensics.'
                  : ' Nobody noted why the trail went quiet; the PFI will have to work that out for itself.')
                : '')
              + ' PFI engaged within 24 hours. Card brand notifications sent to Visa, Mastercard, and Amex. Acquiring bank notified. Forensic evidence preserved per PCI requirements. The honest assessment of the S3 gap is noted but not penalized.',
          },
          {
            key: 'B',
            label: 'Focus on the RDS data exposure — the S3 bucket had encryption so it\'s probably fine',
            desc: 'The database query logs tell the story. S3 was encrypted at rest so even if accessed, data was protected.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 5, thoroughness: -5 },
            sets: f => ({
              brandsNotified: true, scopeAccurate: false,
              proof: f.snapShared && f.saw_snapShare ? 'confirmed' : !f.rdsAuditDeleted ? 'accessed' : 'unknown',
              req10Finding: f.trailStopped && !f.saw_antiForensics,
            }),
            outcome: f => (f.rdsAuditDeleted
                ? 'RDS exposure documented as best it can be — the audit log group is gone, so "the query logs tell the story" turns out to mean there is no story on file. '
                : 'RDS exposure documented correctly. ')
              + 'But S3 encryption at rest doesn\'t protect against public read access — anyone with the URL could read the data decrypted via the S3 API. Your assessment understates the breach scope.'
              + (f.saw_s3Exfil ? ' GuardDuty\'s S3 exfiltration finding, sitting in your own triage notes, already said someone had read it.' : '')
              + ' When the PFI later identifies the S3 gap, the card brands question the accuracy of your initial notification.',
          },
          {
            key: 'C',
            label: 'The attacker was crypto mining — this is a resource abuse incident, not a data breach',
            desc: 'The primary intent was cryptojacking. The database queries were probably automated reconnaissance. Don\'t overreact with breach notifications.',
            quality: 'bad',
            score: { time: 15, containment: -10, evidence: -15, thoroughness: -20 },
            sets: f => ({
              proof: 'misclassified', brandsNotified: false, brandsLate: true, scopeAccurate: false,
              req10Finding: f.trailStopped,
            }),
            outcome: 'By misclassifying the incident, you delay card brand notification by a week. The PFI investigation reveals the attacker specifically targeted cardholder data. Card brands add a $500K late-notification penalty on top of the base fine. NovaPay\'s PCI-DSS certification is suspended. Their acquiring bank threatens to terminate the merchant processing relationship.',
          },
          {
            key: 'D',
            when: f => f.saw_flowBytes,
            label: 'Prove what left: correlate VPC Flow Log bytes with Performance Insights, then full PFI and card-brand notification',
            desc: 'Query logs show what was read; flow logs show what left. Size the transfer, tie it to the attacker IP, and notify on proven scope.',
            quality: 'good',
            score: { time: -5, containment: 5, evidence: 30, thoroughness: 25 },
            sets: f => ({
              pfiEngaged: true, brandsNotified: true, proof: 'confirmed',
              scopeAccurate: !(f.snapShared && !f.saw_snapShare),
              req10Finding: f.trailStopped && !f.saw_antiForensics,
            }),
            outcome: f => `Flow logs show 1.18 GB leaving the database ENI on 3306 to ${f.saw_torKey ? 'the Tor exit you flagged in triage' : '45.155.205.99'} between 03:10 and 03:45 — the size of the cardholders table. `
              + (f.rdsAuditDeleted
                ? (f.saw_piDigest
                  ? 'The audit log is gone, but Performance Insights keeps its own digest history: SELECT * FROM cardholders, 2.1M rows sent. You have rebuilt what the audit log would have shown. '
                  : 'Without the audit log you can prove the volume, not the rows; you size it to the cardholders table. ')
                : 'The audit log shows the SELECT; the flow log shows the result leaving. ')
              + 'Exfiltration of 2.1M cardholder records is confirmed, not presumed.'
              + (f.snapShared
                ? (f.saw_snapShare
                  ? ' The snapshot share goes in too, so the scope covers the whole database.'
                  : ` Nobody documented the snapshot share at ${cbClock(f.snapSharedAt)}, so the stated scope stops at the cardholders table.`)
                : '')
              + ' PFI engaged within 24 hours; Visa, Mastercard, Amex and the acquirer notified with a scope the PFI can verify.',
          },
        ],
        live: (f, st) => {
          const left = Math.max(0, 24 * 60 - Math.floor(cbNow(st)));
          return `CARD-BRAND NOTIFICATION DUE IN ${Math.floor(left / 60)}H ${String(left % 60).padStart(2, '0')}M`;
        },
        timeline: [
          { at: 6, when: f => f.stsLive, sev: 'crit', text: 'GuardDuty: s3:GetObject burst on novapay-prod-cardholder-data signed with ASIA3EXAMPLE9SESSION', score: { containment: -3 } },
          { at: 8, when: f => f.backdoor2Live, sev: 'crit', text: 'lambda-monitoring-role: rds:DescribeDBSnapshots from 45.155.205.99', score: { containment: -3 } },
          { at: 12, sev: 'warn', text: 'Acquiring bank requesting preliminary scope for card-brand notification' },
        ],
        siemEntries: f => [
          { time: '08:00', sev: 'info', text: 'Investigation: data exposure assessment in progress' },
          { time: '08:15', sev: 'crit', text: f.rdsAuditDeleted ? 'RDS audit log group deleted — query history unavailable' : '2.1M cardholder records accessed via RDS queries' },
          { time: '08:20', sev: 'warn', text: f.s3Public ? 'S3 cardholder bucket still public — no access logs available' : 'S3 bucket was public — no access logs available' },
          { time: '08:25', sev: 'crit', text: 'PCI-DSS CDE breach — PFI engagement required' },
        ],
      },
      { // ERADICATION
        name: 'ERADICATION',
        carried: f => {
          const out = [];
          if (f.dbReaccessed) out.push({
            text: '09:12 — 45.155.205.99 connected to novapay-prod on 3306, still open to the internet, and logged in as the master user with the password it set at 03:08. Another full SELECT on cardholders — no AWS credentials needed.',
            score: { containment: -10 },
          });
          if (f.backdoor2Live) out.push({
            text: 'CloudWatchSync is still minting lambda-monitoring-role keys every 5 minutes.',
            score: { thoroughness: -5 },
          });
          if (f.stsLive) out.push({
            sev: 'info',
            text: 'The dev-jpark session token is still valid until Mar 21 14:51.',
          });
          return out;
        },
        narrative: f => (f.proof === 'misclassified'
          ? 'The investigation classed this as resource abuse. '
          : 'The investigation has scoped the breach. ')
          + 'Now ensure every trace of the compromise is removed and the systemic vulnerabilities that enabled it are fixed. The public repo still has credentials in its history.',
        evidence: {
          title: 'VULNERABILITY & REMEDIATION INVENTORY',
          content: f => `<span class="log-highlight">ROOT CAUSES:</span>
  [1] Hardcoded credentials in source code (.env committed to Git)
  [2] GitLab project was PUBLIC (should be private)
  [3] IAM user had overly permissive policies (EC2, IAM, RDS, S3 full access)
  [4] No SCPs limiting dangerous actions (iam:CreateUser, ec2:RunInstances)
  [5] S3 bucket allowed public ACLs (Block Public Access not enabled)
  [6] RDS security group allowed modification without approval
  [7] No S3 data event logging in CloudTrail
  [8] GuardDuty alerts not routed to MSSP for 4 hours${f.rdsAuditDeleted ? `
  [9] RDS audit logs deletable by any admin principal (no export, no retention lock)` : ''}

<span class="log-highlight">REMAINING CLEANUP:</span>
  - GitLab: .env in git history (all branches)
  - AWS: 14 other IAM users with long-lived access keys (no rotation)
  - 3 other S3 buckets without Block Public Access
  - No secrets management solution (credentials in .env files throughout codebase)${f.backdoor2Live ? `
  - <span class="log-warn">IAM: 16 users found, 15 expected — lambda-monitoring-role (AdministratorAccess, created 02:54)</span>` : ''}${f.backdoor1Live ? `
  - <span class="log-warn">IAM: admin-backup-svc (AdministratorAccess, created 02:52) still present</span>` : ''}${f.stsLive ? `
  - dev-jpark: 3 policies with full EC2, IAM, RDS, S3 access` : ''}${!f.snapDeleted ? `
  - <span class="log-warn">RDS: manual snapshot db-maint-0320 still present</span>` : ''}${f.s3Public ? `
  - <span class="log-warn">novapay-prod-cardholder-data: public bucket policy still attached</span>` : ''}${f.dbExposed ? `
  - <span class="log-warn">sg-prod-db: 0.0.0.0/0:3306 open, PubliclyAccessible=true</span>` : ''}${!f.masterPwRotated ? `
  - RDS master password: last changed 03:08 (by 45.155.205.99)` : ''}${f.trailStopped && !f.trailRestarted ? `
  - <span class="log-warn">CloudTrail novapay-mgmt-trail: still stopped</span>` : ''}`
        },
        choices: [
          {
            key: 'A',
            label: 'Purge git history, rotate all IAM keys, enable S3 Block Public Access, deploy secrets manager',
            desc: 'Comprehensive remediation: clean git history, rotate every access key, enable preventive controls, and deploy HashiCorp Vault or AWS Secrets Manager.',
            quality: 'good',
            score: { time: 5, containment: 15, evidence: 5, thoroughness: 20 },
            sets: (f, st) => ({
              stsLive: false, backdoor1Live: false, backdoor2Live: false, keyActive: false,
              snapDeleted: true, s3Public: false, s3PublicMin: f.s3Public ? 225 + cbNow(st) : f.s3PublicMin,
              dbExposed: false, masterPwRotated: true, trailRestarted: f.trailStopped,
            }),
            outcome: f => 'Git history purged with BFG Repo-Cleaner. Repo made private. All 14 IAM user keys rotated.'
              + (f.backdoor1Live || f.backdoor2Live ? ` Rotating every key means listing every IAM user — and ${cbFootholds(f, false).join(' and ')} don't belong. Deleted, with every key they minted.` : '')
              + (f.stsLive ? ' dev-jpark\'s policies are cut to least privilege with a deny on tokens issued before today — which is what finally kills the 36-hour session token, since it inherits dev-jpark\'s permissions on every call.' : '')
              + ' S3 Block Public Access enabled account-wide.'
              + (!f.snapDeleted ? ' Snapshot db-maint-0320 deleted.' : '')
              + (f.dbExposed ? ' sg-prod-db reverted and PubliclyAccessible turned off.' : '')
              + (!f.masterPwRotated ? ' RDS master password rotated.' : '')
              + (f.trailStopped && !f.trailRestarted ? ' novapay-mgmt-trail restarted with log file validation.' : '')
              + ' AWS Secrets Manager deployed for credential management. SCPs added preventing public S3, unrestricted security groups, and IAM user creation without MFA. GuardDuty alerts now route to MSSP within 5 minutes.',
          },
          {
            key: 'B',
            label: 'Rotate the compromised keys, fix the repo, and enable S3 Block Public Access',
            desc: 'Fix the immediate issues. Leave the broader credential management problem for a security project.',
            quality: 'partial',
            score: { time: 10, containment: 5, evidence: 0, thoroughness: 5 },
            sets: (f, st) => ({
              ...cbAfterEradication(f),
              s3Public: false, s3PublicMin: f.s3Public ? 225 + cbNow(st) : f.s3PublicMin,
            }),
            outcome: f => 'Immediate gaps closed. But 14 other IAM users still have long-lived, unrotated keys — any future leak repeats this scenario. No secrets management means developers continue putting credentials in code. No SCPs means nothing prevents an attacker from escalating privileges or exposing resources again.'
              + (f.stsLive ? ' And rotating dev-jpark\'s keys a second time does nothing to the session token already issued from the first ones.' : '')
              + (f.backdoor1Live || f.backdoor2Live ? ` ${cbFootholds(f, false).join(' and ')} ${cbFootholds(f, false).length > 1 ? 'are' : 'is'} not on anyone's list.` : ''),
          },
          {
            key: 'C',
            label: 'Just rotate the compromised developer\'s keys — they\'re the ones who leaked them',
            desc: 'Fix the specific mistake. The developer should be more careful.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: 0, thoroughness: -15 },
            // An AWS Config rule catches the public bucket four hours later
            sets: (f, st) => ({
              ...cbAfterEradication(f),
              s3Public: false, s3PublicMin: f.s3Public ? 225 + cbNow(st) + 240 : f.s3PublicMin,
            }),
            outcome: f => 'One key pair rotated. The systemic issues remain: .env files with credentials throughout the codebase, no secrets management, no preventive controls. A month later, a different developer accidentally pushes credentials to a different public repo. This time the attacker goes straight for the cardholder database.'
              + (f.s3Public ? ' The cardholder bucket stays public until an AWS Config rule flags it four hours later.' : ''),
          },
        ],
        live: f => {
          const left = cbFootholds(f, false);
          return left.length ? `ATTACKER BACKDOORS LIVE: ${left.join(', ').toUpperCase()}` : 'NO KNOWN ATTACKER BACKDOORS';
        },
        timeline: [
          { at: 8, when: f => f.stsLive, sev: 'crit', text: 's3:GetObject on novapay-prod-cardholder-data via ASIA3EXAMPLE9SESSION', score: { containment: -3 } },
          { at: 10, when: f => f.backdoor2Live, sev: 'crit', text: 'CloudWatchSync: new lambda-monitoring-role key POSTed externally', score: { containment: -3 } },
        ],
        siemEntries: [
          { time: '10:00', sev: 'info', text: 'Eradication: systemic vulnerability remediation' },
          { time: '10:10', sev: 'warn', text: '14 IAM users with unrotated long-lived access keys' },
          { time: '10:15', sev: 'info', text: 'S3 Block Public Access change pending approval' },
        ],
      },
      { // RECOVERY
        name: 'RECOVERY',
        carried: f => {
          const out = [];
          if (f.attackerReturned) out.push({
            text: `11:20 — the attacker came back through ${f.returnVia}: a fresh snapshot of novapay-prod shared to account 491803327730, and 96x p3.8xlarge across 12 regions until GuardDuty paged at 11:52 (${fmtUSD(f.returnSpend)}). The miners are terminated; the way in is still open.`,
            score: { containment: -15, thoroughness: -5 },
          });
          if (f.sessionSpend) out.push({
            text: `The dev-jpark session token launched 16 miners in ap-south-1 after eradication — ${fmtUSD(f.sessionSpend)} before anyone noticed. It stays valid until Mar 21 14:51.`,
            score: { containment: -5 },
          });
          if (f.brandsNotified && !f.scopeAccurate) out.push({
            text: 'The PFI\'s preliminary findings include what your notification left out. Visa asks NovaPay to restate the scope — the first figure is now on record as wrong.',
            score: { thoroughness: -10 },
          });
          if (f.proof === 'unknown') out.push({
            text: 'PFI preliminary: with the RDS audit log destroyed, the exposure cannot be bounded. The brands will treat every PAN in the CDE as compromised.',
            score: { evidence: -5 },
          });
          if (f.proof === 'accessed') out.push({
            sev: 'info',
            text: 'The PFI accepts that 2.1M records were queried, but needs extra weeks to establish whether they left the environment.',
          });
          if (f.req10Finding) out.push({
            text: 'PFI preliminary: an unexplained gap in CloudTrail delivery, recorded as a Requirement 10 logging failure.',
            score: { evidence: -3 },
          });
          return out;
        },
        narrative: f => (cbFootholds(f, true).length
          ? 'Most attacker artifacts are removed and preventive controls are going in — not all of them. '
          : 'All attacker artifacts removed and preventive controls deployed. ')
          + 'NovaPay needs to resume normal operations, manage the PCI-DSS compliance response, and deal with the financial fallout of the crypto mining and breach costs.',
        evidence: {
          title: 'RECOVERY STATUS',
          content: (f, st) => `<span class="log-ok">AWS ENVIRONMENT:</span>
  - Attacker resources removed: ${cbFootholds(f, true).length ? `<span class="log-highlight">NO — ${cbFootholds(f, true).join(', ')}</span>` : '✓'}
  - IAM keys rotated ✓
  - Security groups restored ${f.dbExposed ? '<span class="log-highlight">✗ sg-prod-db still open</span>' : '✓'}
  - S3 Block Public Access enabled ${f.s3Public ? '✗' : '✓'}
  - Production systems: operational

<span class="log-warn">FINANCIAL IMPACT:</span>
  - Crypto mining bill: ${fmtUSD(cbTotalMining(f, st))} (unauthorized GPU instances, all regions)
  - PFI engagement: ~$150,000
  - Card brand fines: ${f.brandsLate ? `<span class="log-highlight">~${fmtUSD(cbFines(f))} (late notification)</span>` : f.brandsNotified ? 'TBD (notification on time)' : 'TBD (notification not yet filed)'}
  - Breach notification costs: ~$2.1M (2.1M affected individuals)
  - Credit monitoring: ~$4.2M (2 years × 2.1M people)

<span class="log-warn">PCI-DSS STATUS:</span>
  - QSA notified of breach
  - PFI investigation: ${f.pfiEngaged ? 'in progress' : '<span class="log-highlight">not yet engaged</span>'}
  - Scope stated to brands: ${!f.brandsNotified ? 'none' : f.scopeAccurate ? 'matches evidence' : '<span class="log-highlight">understated — restatement likely</span>'}
  - Potential for forced re-assessment
  - Card brand notification: ${f.brandsNotified ? 'filed' : '<span class="log-highlight">NOT FILED</span>'}`
        },
        choices: [
          {
            key: 'A',
            label: f => f.brandsNotified
              ? 'Coordinate PFI investigation, execute card brand notifications, prepare breach notification letters'
              : 'Send the overdue card brand notifications, engage the PFI, prepare breach notification letters',
            desc: 'Full recovery protocol: support the PFI, notify card brands within 24 hours, draft consumer breach notifications, and begin credit monitoring enrollment.',
            quality: 'good',
            score: { time: 5, containment: 5, evidence: 10, thoroughness: 15 },
            sets: { brandsNotified: true, pfiEngaged: true },
            outcome: f => (f.brandsNotified
                ? 'Card brand notifications filed within 24 hours — Visa and Mastercard appreciate the timely disclosure.'
                : 'Card brand notifications finally go out, days after the investigation called this cryptojacking. The brands note the delay.')
              + (f.brandsNotified && !f.scopeAccurate ? ' You file a restated scope alongside the PFI\'s findings, which limits the damage but doesn\'t erase the first figure.' : '')
              + (f.rdsAuditDeleted ? ' PFI has full access to what survived of the forensic evidence and CloudTrail event history.' : ' PFI has full access to forensic evidence and CloudTrail logs.')
              + ` Consumer breach notification drafted with ${f.scopeAccurate ? 'accurate' : 'the corrected'} scope. Credit monitoring vendor engaged. `
              + (f.brandsLate ? 'None of it undoes the late notification.' : 'NovaPay\'s proactive response reduces card brand fines significantly.'),
          },
          {
            key: 'B',
            label: 'Notify card brands and start the PFI — handle consumer notifications later',
            desc: 'Prioritize the PCI requirements. Consumer notification can wait until the PFI confirms scope.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 5, thoroughness: 5 },
            sets: { brandsNotified: true, pfiEngaged: true, consumerLate: true },
            outcome: f => (f.brandsNotified ? 'Card brands notified on time. ' : 'Card brands notified — late, after the resource-abuse call. ')
              + 'PFI begins investigation. But state breach notification deadlines vary — several states require notification within 30 days. Waiting for the PFI to finish (typically 6-8 weeks) means missing the 30-day deadlines in New York, Colorado, Florida and other states with fixed windows.',
          },
          {
            key: 'C',
            label: (f, st) => `Focus on getting the AWS bill credited — ${fmtUSD(cbTotalMining(f, st))} in unauthorized charges needs to be disputed`,
            desc: 'AWS has a fraud abuse process. Get the mining charges reversed while things are fresh.',
            quality: 'bad',
            score: { time: -5, containment: -10, evidence: -5, thoroughness: -20 },
            sets: f => ({ consumerLate: true, brandsLate: f.brandsLate || !f.brandsNotified }),
            outcome: (f, st) => (cbFootholds(f, false).length
                ? `AWS Support won't consider the credit until the account is clean — and ${cbFootholds(f, false).join(' and ')} ${cbFootholds(f, false).length > 1 ? 'are' : 'is'} still in it. `
                : `AWS does credit the ${fmtUSD(cbTotalMining(f, st))}${f.saw_miners ? ' — the instance IDs and regions you documented in triage make it quick' : ''} — a rounding error compared to the ~$${((180000 + cbFines(f) + 6300000 + 350000 + cbTotalMining(f, st)) / 1e6).toFixed(1)}M total breach cost. `)
              + (f.brandsNotified
                ? 'Meanwhile, the PFI waits a week for evidence access and consumer breach notifications are delayed.'
                : 'Meanwhile, card brand notification is late, triggering accelerated fine schedules. Consumer breach notifications are delayed.')
              + ' State AGs in California and New York open investigations into the late disclosure. The focus on a trivial cost while ignoring massive compliance obligations damages NovaPay\'s credibility.',
          },
        ],
        live: f => f.brandsNotified ? 'CARD BRANDS: NOTIFIED · CONSUMERS: NOT YET NOTIFIED' : 'CARD BRANDS: NOT NOTIFIED · CONSUMERS: NOT NOTIFIED',
        siemEntries: f => [
          { time: '12:00', sev: 'info', text: 'Recovery: PCI compliance and breach notification' },
          { time: '12:10', sev: 'warn', text: f.brandsNotified ? 'Card brands notified — consumer notification pending' : 'Card brand notification deadline: 24 hours' },
          { time: '12:15', sev: 'info', text: f.pfiEngaged ? 'PFI investigation commenced — full evidence access provided' : 'PFI not yet engaged' },
        ],
      },
      { // POST-INCIDENT
        name: 'POST-INCIDENT',
        carried: f => {
          const left = cbFootholds(f, true);
          return left.length ? [{
            text: `You are writing the report while ${left.join(', ')} still ${left.length > 1 ? 'work' : 'works'} for the attacker.`,
            score: { thoroughness: -10 },
          }] : [];
        },
        narrative: 'The breach is contained, notifications are in progress, and the PFI is investigating. Time to document everything and ensure NovaPay\'s cloud security posture is fundamentally improved. Their CTO wants to understand how a single .env file brought down their PCI compliance.',
        evidence: {
          title: 'INCIDENT SUMMARY',
          content: (f, st) => {
            const mining = cbTotalMining(f, st);
            const fines = cbFines(f);
            const total = 180000 + fines + 6300000 + 350000 + mining;
            return `<span class="log-ok">TIMELINE:</span>
  Credential leak:   Mar 20 02:33 (public git push)
  Attacker access:   Mar 20 02:51 (18 min after leak)
  Privilege escalation: Mar 20 02:52 (1 min after access)
  Data access:       Mar 20 03:10 (19 min after access)
  Detection:         Mar 20 06:45 (4 hours after leak)
  Containment:       Mar 20 ~${cbClock(f.containedAt)}
  Time on incident:  ${formatElapsed(st.elapsed)}

<span class="log-warn">KEY FAILURES:</span>
  1. Secrets in source code (no secrets management)
  2. Public repository (no repo visibility controls)
  3. Over-privileged IAM user (no least privilege)
  4. No preventive controls (no SCPs, no S3 Block Public Access)
  5. Slow alert routing (4-hour delay from GuardDuty to MSSP)
  6. No S3 data event logging (blind spot)${f.rdsAuditDeleted ? `
  7. Audit logs deletable by the attacker (RDS audit log destroyed)` : ''}

<span class="log-warn">DATA EXPOSURE:</span>
  Card records exfiltrated: ${cbExfilSummary(f)}

<span class="log-warn">TOTAL ESTIMATED COST:</span>
  Crypto mining: ${fmtUSD(mining)}
  Investigation + PFI: ~$180K
  Card brand fines: ~${fmtUSD(fines)} (estimated)
  Consumer notification + credit monitoring: ~$6.3M
  Remediation: ~$350K
  <span class="log-highlight">Total: ~$${(total / 1e6).toFixed(1)}M from a single committed .env file</span>`;
          },
        },
        choices: [
          {
            key: 'A',
            label: 'Full report with cloud security architecture review, PCI remediation plan, and DevSecOps roadmap',
            desc: 'Comprehensive post-incident: root cause analysis, cloud security architecture redesign, CI/CD security integration, PCI re-assessment preparation, and cost-benefit analysis for preventive controls.',
            quality: 'good',
            // A report is only as good as what was documented along the way
            score: (f, st) => ({ time: 5, containment: 5, evidence: 10, thoroughness: 15 + Math.min(10, 2 * st.findings.length) }),
            outcome: (f, st) => {
              const total = 180000 + cbFines(f) + 6300000 + 350000 + cbTotalMining(f, st);
              return (st.findings.length >= 6
                  ? `The evidence appendix lists ${st.findings.length} findings you documented during the response — the PFI cites it directly. `
                  : `The evidence appendix is thin — ${st.findings.length} documented finding${st.findings.length === 1 ? '' : 's'} — and the PFI builds its own timeline instead of using yours. `)
                + 'Report drives a complete cloud security transformation: secrets management mandatory, pre-commit hooks scanning for credentials, GitLab group-level visibility controls preventing public projects, IAM privilege boundaries, SCPs preventing dangerous operations, comprehensive CloudTrail logging with log files locked in a separate account, and real-time alert routing. '
                + (f.brandsLate || f.attackerReturned
                  ? `The QSA accepts the plan, but PCI status is still ${cbPciStatus(f).toLowerCase()} — no report fixes that.`
                  : `PCI QSA is satisfied with the remediation plan. The ~$${(total / 1e6).toFixed(1)}M lesson results in a genuinely secure cloud environment.`);
            },
          },
          {
            key: 'B',
            label: 'Standard incident report with AWS security recommendations',
            desc: 'Document what happened and provide the key technical recommendations.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 5, thoroughness: 5 },
            outcome: 'Technical recommendations are solid but don\'t address the DevSecOps culture that allowed credentials in code. The PCI QSA wants to see a more comprehensive remediation plan before re-certifying. Developers continue using .env files — just more carefully — without systematic secrets management.',
          },
          {
            key: 'C',
            label: 'Blame the developer who committed the .env file and recommend disciplinary action',
            desc: 'This was a human error. The developer needs consequences.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: -10, thoroughness: -25 },
            outcome: 'The developer is reprimanded and quits. The systemic issues remain: no pre-commit hooks, no secrets management, no guardrails preventing this exact mistake. The CTO is furious that the post-incident focused on blame instead of prevention. The PCI QSA flags the lack of systemic remediation. NovaPay\'s engineers are now afraid to report security issues.',
          },
        ],
        siemEntries: (f, st) => [
          { time: '14:00', sev: 'info', text: 'Post-incident: cloud security review and lessons learned' },
          { time: '14:10', sev: 'warn', text: `Total breach cost estimate: ~$${((180000 + cbFines(f) + 6300000 + 350000 + cbTotalMining(f, st)) / 1e6).toFixed(1)}M from a single .env file` },
          { time: '14:15', sev: 'info', text: 'CTO requesting comprehensive cloud security roadmap' },
        ],
      },
    ],
  }
);
