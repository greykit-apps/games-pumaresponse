// Business Email Compromise — CEO Fraud
// Scenario data for PumaResponse — format documented in README → Development.

// BEC: how much of the $340K wire has moved beyond recall, t minutes into the
// Triage decision. $55K was already gone at handoff; the rest drains in steps.
const BEC_WIRE_MOVED = [[0, 55000], [6, 100000], [12, 140000], [25, 200000], [45, 260000], [70, 340000]];
function becWireMoved(t) {
  return BEC_WIRE_MOVED.filter(([at]) => t >= at).pop()[1];
}
// Wall-clock stamp m minutes after the 14:22 handoff (Feb 19). The date is
// included when asked for, or whenever the stamp has rolled past midnight.
function becStamp(m, withDate) {
  const t = 14 * 60 + 22 + Math.floor(m);
  const day = Math.floor(t / 1440);
  const hhmm = `${String(Math.floor(t / 60) % 24).padStart(2, '0')}:${String(t % 60).padStart(2, '0')}`;
  return day || withDate ? `Feb ${19 + day} ${hhmm}` : hhmm;
}

registerIncident(
  {
    id: 'BEC',
    title: 'Business Email Compromise — CEO Fraud',
    client: 'Ashford Manufacturing',
    severity: 'HIGH',
    sevClass: 'high',
    ticketId: 'IR-2024-0913',
    // In-world "today": every date in this file is written relative to it and
    // shown shifted to the real date (see REAL-DATE ANCHORING in js/game.js)
    baseDate: '2024-02-19',
    assignedTime: '14:22 ET',
    summary: 'CFO received urgent wire transfer request appearing to come from CEO. $340,000 wire initiated to unknown offshore account. Email authentication investigation needed.',
    iocs: [
      { type: 'EMAIL', val: 'ceo@ashford-mfg.com (spoofed — reply-to: ceo@ashf0rd-mfg.com)' },
      { type: 'DOMAIN', val: 'ashf0rd-mfg.com — typosquat registered 3 days ago' },
      { type: 'IP', val: '103.145.22.87 — email origin (VPN exit node, Singapore)' },
      { type: 'EMAIL RULE', val: 'Inbox rule "Administrative" — forwards wire/payment mail to the typosquat, hides it in RSS Feeds' },
      { type: 'ACCOUNT', val: 'CEO M365 account — suspicious sign-in from unfamiliar location' },
    ],
    // Run state. Every later phase reads these; choices change them via `sets`.
    initialFlags: {
      wireRecovered: 0,       // dollars of the $340K clawed back
      recallFiled: false,     // did anyone ever ask the bank to recall the wire?
      headersAnalyzed: false, // triage spent time on the headers
      attackerTipped: false,  // the attacker saw us coming
      mfaBackdoor: false,     // attacker registered their own Authenticator on the CEO account
      ceoDisabled: false,     // CEO account disabled rather than cleaned
      rulesRemain: false,     // CEO inbox rule / forwarding still live
      vpSecured: false,       // VP Sales account locked down
      scopeAssessed: false,   // the 847 exposed emails were catalogued
      vendorFraud: false,     // VP Sales account was used to redirect vendor payments
      legalEngaged: false,    // counsel assessed SEC / breach-notification duties
      tippedAt: 0,            // wall-clock minute (since handoff) the reply reached the attacker
      containedAt: 0,         // wall-clock minute the Containment action landed
    },
    // 2 real seconds per game minute once the decision clock starts; 10-minute par
    clock: { rate: 0.5, par: 10 },
    // Best achievable total (every finding tagged, instant decisions, best path).
    // Grades are a percentage of this. Recompute with tools/scenario-harness.js after
    // changing this scenario's scores, carried penalties or findings.
    bestScore: 334,
    // MITRE ATT&CK (Enterprise v19) technique per finding, shown in the debrief.
    // Findings that aren't adversary behavior (missing controls, business facts) are omitted.
    attack: {
      replyTo: "T1583.001 Acquire Infrastructure: Domains",
      spfFail: "T1684.002 Social Engineering: Email Spoofing",
      lagos: "T1078.004 Valid Accounts: Cloud Accounts",
      inboxRule: "T1564.008 Hide Artifacts: Email Hiding Rules",
      forwarding: "T1114.003 Email Collection: Email Forwarding Rule",
      authApp: "T1098.005 Account Manipulation: Device Registration",
      phishLink: "T1566.002 Phishing: Spearphishing Link",
      credsEntered: "T1598.003 Phishing for Information: Spearphishing Link",
      vpSales: "T1078.004 Valid Accounts: Cloud Accounts",
      sspr: "T1098 Account Manipulation",
    },
    debrief: f => {
      const vendorLoss = f.vendorFraud ? 87000 : 0;
      return [
        ['Wire Recovered', `${fmtUSD(f.wireRecovered)} of $340,000`],
        ['Total Client Loss', fmtUSD(340000 - f.wireRecovered + vendorLoss)],
        ['Attacker Access at Close', (f.mfaBackdoor && !f.ceoDisabled) || !f.vpSecured ? 'STILL PRESENT' : 'Removed'],
      ];
    },
    phases: [
      { // TRIAGE
        name: 'TRIAGE',
        narrative: 'The client\'s CFO, Janet Morris, just contacted your MSSP in a panic. She approved a $340,000 wire transfer 2 hours ago based on an "urgent" email from the CEO requesting payment to a new vendor. Then she found there is no purchase order behind the "acquisition", and the CEO — on vacation — isn\'t answering his phone. The wire may still be reversible if you act fast.',
        evidence: {
          title: 'SUSPICIOUS EMAIL — HEADERS EXTRACT',
          content: `<span class="log-warn">From:</span> David Chen &lt;ceo@ashford-mfg.com&gt;
<span class="log-warn">Reply-To:</span> ceo@ashf0rd-mfg.com<!--f:replyTo-->
<span class="log-warn">Subject:</span> URGENT — Wire Transfer Needed Today
<span class="log-warn">Date:</span> Thu, 19 Feb 2024 11:48:00 -0500
<span class="log-warn">X-Originating-IP:</span> 103.145.22.87<!--f:origIP-->

<span class="log-ok">── EMAIL BODY ──</span>
Janet,
I need you to process a wire transfer of $340,000 to the account
below ASAP. This is for a time-sensitive acquisition deal. Please
handle this personally and keep it confidential until I announce.
I'm in meetings all day — email only please.

Bank: First National Bank of Cayman, George Town
SWIFT: FNBCKYKY<!--f:beneficiary-->
Account: 2847193650<!--f:beneficiary-->
Ref: ASHFORD-ACQ-2024

Thanks,
David

<span class="log-warn">── AUTHENTICATION ──</span>
SPF:  <span class="log-highlight">FAIL</span> (ashford-mfg.com does not authorize 103.145.22.87)<!--f:spfFail-->
DKIM: <span class="log-highlight">NONE</span> (no DKIM signature)
DMARC: <span class="log-warn">p=none</span> (policy: report only, no enforcement)`
        },
        choices: [
          {
            key: 'A',
            label: 'Call the bank immediately to freeze/reverse the wire, then investigate',
            desc: 'Priority one: stop the money. Contact CFO to initiate wire recall with their bank.',
            quality: 'good',
            score: { time: 20, containment: 25, evidence: 5, thoroughness: 10 },
            sets: (f, st) => ({ wireRecovered: 340000 - becWireMoved(st.phaseClock), recallFiled: true }),
            outcome: (f, st) => {
              const saved = 340000 - becWireMoved(st.phaseClock);
              return `You instruct Janet to call the bank's wire fraud department. Because it's within the 24-hour recall window, the bank initiates a SWIFT recall. ${fmtUSD(saved)} of the $340,000 is frozen before it leaves the correspondent bank. `
                + (saved >= 285000 ? 'Quick action saved the majority of the funds.' : saved >= 200000 ? 'Most of it — but every minute you spent deciding was money leaving the correspondent bank.' : 'The recall was the right call. It just came late.');
            },
          },
          {
            key: 'B',
            label: 'Investigate the email headers and CEO\'s account first',
            desc: 'Understand the attack before acting. Check if the CEO\'s account is compromised.',
            quality: 'partial',
            score: { time: -10, containment: -15, evidence: 15, thoroughness: 10 },
            // The header analysis itself takes 40 minutes before anyone calls the bank
            sets: (f, st) => ({ wireRecovered: 340000 - becWireMoved(st.phaseClock + 40), recallFiled: true, headersAnalyzed: true }),
            outcome: (f, st) => `Your analysis confirms the SPF failure and pins the reply-to on a typosquat domain, ashf0rd-mfg.com — the attacker never needed to send from the real mailbox to receive the answers. But the analysis takes 40 minutes before you advise the bank recall. By then, ${fmtUSD(becWireMoved(st.phaseClock + 40))} has already been forwarded through intermediary accounts and is unrecoverable.`,
          },
          {
            key: 'C',
            label: 'Reply to the CEO to verify if he sent the email',
            desc: 'Send the CEO an email asking if this wire request is legitimate.',
            quality: 'bad',
            score: { time: -20, containment: -20, evidence: -5, thoroughness: -10 },
            sets: (f, st) => ({ attackerTipped: true, mfaBackdoor: true, tippedAt: st.elapsed }),
            outcome: 'The CEO is on vacation with limited connectivity. He doesn\'t respond for 3 hours. Meanwhile, the wire clears through intermediary banks and no recall is ever requested. Worse: your reply went to the Reply-To address — the attacker\'s typosquat — so they now know the MSSP is involved.',
          },
        ],
        live: (f, st) => `RECALLABLE NOW: ${fmtUSD(340000 - becWireMoved(st.phaseClock))} OF $340,000`,
        timeline: [
          { at: 6, sev: 'crit', text: 'Correspondent bank: $45,000 forwarded to intermediary (Hong Kong)' },
          { at: 12, sev: 'crit', text: 'Correspondent bank: $40,000 more forwarded — second intermediary' },
          { at: 25, sev: 'crit', text: 'Funds split across 4 accounts — $200,000 now beyond recall' },
          { at: 45, sev: 'crit', text: 'OTC crypto desk purchase traced — $260,000 gone' },
          { at: 70, sev: 'crit', text: 'Beneficiary account emptied — wire fully cleared' },
        ],
        siemEntries: [
          { time: '14:22', sev: 'crit', text: 'INCIDENT ASSIGNED — BEC / CEO Fraud — Ashford Mfg' },
          { time: '14:22', sev: 'warn', text: 'Wire transfer: $340,000 initiated 2 hours ago' },
          { time: '14:23', sev: 'info', text: 'Pulling M365 audit logs and email headers' },
          { time: '14:24', sev: 'warn', text: 'DMARC policy set to p=none — no email enforcement' },
        ],
      },
      { // CONTAINMENT
        name: 'CONTAINMENT',
        // Replying to the "CEO" cost three hours of waiting for him to surface
        at: f => f.attackerTipped ? f.tippedAt + 180 : 0,
        narrative: f => [
          f.recallFiled
            ? 'The wire recall is in progress.'
            : 'No wire recall was ever filed — by the time the CEO answered, three hours on, the money had cleared.',
          f.headersAnalyzed
            ? 'Your header work already tied the reply-to to ashf0rd-mfg.com, so you know what to look for.'
            : '',
          f.attackerTipped
            ? 'Your reply landed in the attacker\'s inbox; assume they are moving to keep their access.'
            : '',
          'Now determine whether the CEO\'s M365 account was actually compromised (vs. simple email spoofing) and contain any unauthorized access. Audit logs show a suspicious sign-in to the CEO\'s account from an unusual location.',
        ].filter(Boolean).join(' '),
        evidence: {
          title: 'M365 AUDIT LOG — CEO ACCOUNT',
          content: f => `<span class="log-warn">[Feb 17 02:14]</span> Sign-in: ceo@ashford-mfg.com
  Location: Lagos, Nigeria (IP: 41.190.2.44)<!--f:lagos-->
  Status: <span class="log-highlight">SUCCESS</span>
  MFA: <span class="log-highlight">NOT CONFIGURED</span><!--f:noMfa-->
  Client: Browser (Chrome 121 / Windows)
<span class="log-warn">[Feb 17 02:16]</span> Inbox Rule Created: "Administrative"<!--f:inboxRule-->
  Condition: Subject contains "wire" OR "transfer" OR "payment"<!--f:inboxRule-->
  Actions: Forward to ceo@ashf0rd-mfg.com, Move to RSS Feeds, Mark as Read<!--f:inboxRule-->
<span class="log-warn">[Feb 17 02:18]</span> Mailbox forwarding (SMTP) also set: ceo@ashf0rd-mfg.com<!--f:forwarding-->
<span class="log-warn">[Feb 17 03:00]</span> 847 emails accessed in CEO mailbox
<span class="log-warn">[Feb 19 11:48]</span> Spoofed email sent externally (from different infra)
<span class="log-ok">[Feb 19 14:22]</span> Incident reported to MSSP${f.attackerTipped ? `
<span class="log-warn">[${becStamp(f.tippedAt + 9, true)}]</span> Sign-in: ceo@ashford-mfg.com from 41.190.2.44
<span class="log-warn">[${becStamp(f.tippedAt + 11, true)}]</span> Security info registered: Authenticator app "iPhone 15"<!--f:authApp-->
  Tenant setting: Self-service password reset ENABLED (1 method)<!--f:authApp-->` : ''}`
        },
        choices: [
          {
            key: 'A',
            label: 'Reset CEO password, revoke sessions, remove inbox rules, block typosquat domain',
            desc: 'Full account containment: lock out the attacker, clean up persistence, and block the lookalike domain.',
            quality: 'good',
            score: { time: 10, containment: 25, evidence: 10, thoroughness: 15 },
            sets: (f, st) => ({ containedAt: st.elapsed }),
            outcome: 'CEO\'s password reset and all active sessions revoked. The malicious inbox rule and mail forwarding to the typosquat domain removed. IT blocks ashf0rd-mfg.com at the email gateway and web proxy. The attacker appears to be locked out.',
          },
          {
            key: 'B',
            label: 'Reset the CEO\'s password and enable MFA',
            desc: 'Secure the account with new credentials and add multi-factor authentication.',
            quality: 'partial',
            score: { time: 10, containment: 10, evidence: 0, thoroughness: 0 },
            sets: (f, st) => ({ rulesRemain: true, containedAt: st.elapsed }),
            outcome: f => 'Password reset and MFA enabled — good. But you didn\'t revoke existing sessions (the attacker\'s token stays valid for up to an hour) and didn\'t remove the inbox rule that\'s silently forwarding emails to the typosquat domain.'
              + (f.attackerTipped ? ' And the MFA prompt the CEO gets offers him an Authenticator he never set up — he assumes IT did it.' : ''),
          },
          {
            key: 'C',
            label: 'Disable the CEO\'s entire M365 account',
            desc: 'Completely disable the account to prevent any access.',
            quality: 'bad',
            score: { time: 5, containment: 15, evidence: -10, thoroughness: -5 },
            sets: (f, st) => ({ ceoDisabled: true, rulesRemain: true, containedAt: st.elapsed }),
            outcome: 'Account disabled — attacker is locked out, but so is the CEO. He\'s on vacation and now can\'t access email, Teams, or OneDrive. Important business communications are disrupted. The inbox rule and forwarding are still configured and will reactivate when the account is re-enabled.',
          },
          {
            key: 'D',
            when: f => f.saw_authApp,
            label: 'Full containment, and delete the attacker\'s Authenticator registration first',
            desc: 'Remove the rogue "iPhone 15" method, then reset password, revoke sessions, remove rules and forwarding, block the typosquat.',
            quality: 'good',
            score: { time: 10, containment: 30, evidence: 10, thoroughness: 20 },
            sets: (f, st) => ({ mfaBackdoor: false, containedAt: st.elapsed }),
            outcome: 'You pull the attacker\'s Authenticator off the account before touching the password — with it gone, self-service reset has nothing to verify against. Password reset, sessions revoked, inbox rule and forwarding removed, ashf0rd-mfg.com blocked. This time the lockout actually holds.',
          },
        ],
        live: f => f.attackerTipped ? 'ATTACKER SESSION: ACTIVE · ATTACKER IS AWARE OF YOU' : 'ATTACKER SESSION: ACTIVE',
        timeline: [
          { at: 5, sev: 'warn', text: 'CEO mailbox: 60 more items read from 41.190.2.44', score: { evidence: -3 } },
          { at: 10, sev: 'crit', text: 'Forwarding rule fired: "RE: Q1 vendor payments" sent to ashf0rd-mfg.com', score: { containment: -3 } },
          { at: 18, sev: 'crit', text: 'CEO mailbox: bulk export of board-minutes folder started', score: { containment: -5, evidence: -3 } },
        ],
        siemEntries: f => [
          { time: '14:40', sev: 'crit', text: 'CEO account compromised — sign-in from Lagos, Nigeria' },
          { time: '14:41', sev: 'warn', text: 'Malicious inbox rule found — forwarding wire/payment emails' },
          { time: '14:42', sev: 'warn', text: 'No MFA configured on executive accounts' },
          ...(f.attackerTipped ? [{ time: '14:43', sev: 'crit', text: 'New security info on CEO account — registered from 41.190.2.44' }] : []),
        ],
      },
      { // INVESTIGATION
        name: 'INVESTIGATION',
        carried: f => {
          const out = [];
          if (f.mfaBackdoor && !f.ceoDisabled) out.push({
            text: `${becStamp(f.containedAt + 20)} — the attacker used the Authenticator they registered at ${becStamp(f.tippedAt + 11)} to self-service reset the CEO's password. They are back in the mailbox.`,
            score: { containment: -10, evidence: -5 },
          });
          if (f.mfaBackdoor && f.ceoDisabled) out.push({
            sev: 'info',
            text: `${becStamp(f.containedAt + 20)} — a self-service password reset on the CEO account was attempted from 41.190.2.44 and failed: the account is disabled.`,
          });
          if (f.rulesRemain && !f.ceoDisabled) out.push({
            text: 'The "Administrative" forwarding rule is still live — every wire or payment email since containment went to ashf0rd-mfg.com.',
            score: { containment: -5 },
          });
          if (f.ceoDisabled) out.push({
            sev: 'info',
            text: 'The CEO is locked out of email while traveling; his assistant is fielding board questions by phone.',
          });
          if (!f.recallFiled) out.push({
            text: 'No wire recall was filed. All $340,000 is in the wind.',
          });
          return out;
        },
        narrative: f => (f.mfaBackdoor && !f.ceoDisabled
          ? 'You thought the CEO\'s account was secured. It isn\'t. '
          : 'The CEO\'s account is secured. ')
          + 'You need to determine the full scope: how the credentials were obtained, whether other accounts are compromised, and what data the attacker accessed in the 2 days they had access to the CEO\'s mailbox.',
        evidence: {
          title: 'CREDENTIAL THEFT ANALYSIS',
          content: f => `<span class="log-ok">── PHISHING CAMPAIGN DETECTED ──</span>
<span class="log-warn">[Feb 15 08:33]</span> Email to ceo@ashford-mfg.com
  From: IT-Support@microsoft-365-admin.com
  Subject: "Action Required: Password Expiry Notice"
  Link: hxxps://microsoft-365-admin[.]com/login<!--f:phishLink-->
  <span class="log-highlight">CEO clicked link and entered credentials</span><!--f:credsEntered-->

<span class="log-ok">── SCOPE ANALYSIS ──</span>
  Same phishing campaign sent to: 12 employees
  Clicked link: 4 employees
  Entered credentials: 2 (CEO + VP Sales)
  VP Sales account: <span class="log-highlight">Also compromised</span><!--f:vpSales-->
    Sign-in from 41.190.2.44 on Feb 17 02:30<!--f:vpSales-->
    No inbox rules created (yet)${f.mfaBackdoor && !f.ceoDisabled ? `
  CEO account: <span class="log-highlight">SSPR reset ${becStamp(f.containedAt + 20, true)} via Authenticator "iPhone 15"</span><!--f:sspr-->` : ''}

<span class="log-ok">── CEO MAILBOX ACCESS ──</span>
  Attacker accessed: 847 emails over 2 days
  Categories: Financial reports, board minutes, M&A discussions
  <span class="log-highlight">Sensitive data exposed: Q4 financials, acquisition target list</span><!--f:mnpi-->`
        },
        choices: [
          {
            key: 'A',
            label: 'Secure VP Sales account, audit all 12 targeted users, assess data exposure',
            desc: 'Reset all potentially compromised accounts, check for additional inbox rules, catalogue exposed data.',
            quality: 'good',
            score: { time: 5, containment: 15, evidence: 20, thoroughness: 20 },
            sets: f => ({
              vpSecured: true,
              scopeAssessed: true,
              rulesRemain: false,
              // The audit covers sign-ins and security info — unless the account is disabled, the rogue Authenticator surfaces here
              mfaBackdoor: f.mfaBackdoor && f.ceoDisabled,
            }),
            outcome: f => 'VP Sales account secured (password reset, MFA, session revocation). All 12 phishing targets audited — no additional compromises beyond the two identified. Data exposure assessment documents all 847 accessed emails, including 3 board presentations and the M&A target list. Legal counsel notified about potential material non-public information exposure.'
              + (f.rulesRemain && !f.ceoDisabled ? ' The audit also finds the CEO\'s forwarding rule still live — removed.' : '')
              + (f.mfaBackdoor && !f.ceoDisabled ? ' And it catches the rogue "iPhone 15" Authenticator on the CEO account. You remove it, reset the password again and revoke every session — this time the attacker is out for good.' : ''),
          },
          {
            key: 'B',
            label: 'Secure the VP Sales account and move on to eradication',
            desc: 'Fix the second compromised account. Don\'t audit the other 10 phishing targets.',
            quality: 'partial',
            score: { time: 10, containment: 5, evidence: 5, thoroughness: -5 },
            sets: { vpSecured: true },
            outcome: 'VP Sales account secured. But you didn\'t audit the other 10 employees who received the phishing email — you\'re assuming only those who clicked were at risk. You also didn\'t assess the full scope of data exposed from the CEO\'s mailbox, leaving legal counsel without the information they need for regulatory notifications.',
          },
          {
            key: 'C',
            label: 'Focus only on the wire fraud — the email compromise is a separate ticket',
            desc: 'The wire fraud is the incident. Account compromise is a security hygiene issue for later.',
            quality: 'bad',
            score: { time: 15, containment: -10, evidence: -15, thoroughness: -20 },
            outcome: 'By treating this as two separate issues, you miss the connection between the credential phishing and the BEC. The VP Sales account — the one the attacker hasn\'t used yet — stays in their hands.',
          },
        ],
        live: 'VP SALES ACCOUNT: NOT YET SECURED',
        timeline: [
          { at: 8, sev: 'warn', text: 'VP Sales mailbox: inbox rule "Sync" created from 41.190.2.44' },
          { at: 16, sev: 'crit', text: 'VP Sales → Kessler Steel: "Updated remittance details for open invoices"',
            sets: { vendorFraud: true }, score: { containment: -5 } },
        ],
        siemEntries: f => [
          ...(f.mfaBackdoor && !f.ceoDisabled ? [{ time: '15:02', sev: 'crit', text: 'SSPR password reset — CEO account — from 41.190.2.44' }] : []),
          { time: '15:10', sev: 'warn', text: 'Credential phishing campaign identified — 12 targets' },
          { time: '15:12', sev: 'crit', text: 'Second compromised account found: VP Sales' },
          { time: '15:15', sev: 'warn', text: 'CEO mailbox: 847 emails accessed incl. M&A data' },
        ],
      },
      { // ERADICATION
        name: 'ERADICATION',
        carried: f => {
          const out = [];
          if (!f.vpSecured) out.push({
            text: 'The VP Sales account you left alone now has an inbox rule of its own. Three of Ashford\'s vendors received "updated banking details" from vpsales@ashford-mfg.com.',
            score: { containment: -15, thoroughness: -5 },
          });
          if (f.mfaBackdoor && !f.ceoDisabled) out.push({
            text: 'The attacker still holds the CEO account through the Authenticator they registered.',
            score: { containment: -10 },
          });
          return out;
        },
        narrative: f => (f.scopeAssessed
          ? 'You\'ve mapped the full attack. '
          : 'You have a partial picture of the attack — enough, you hope, to clean up. ')
          + 'Now remove all attacker access and infrastructure. The typosquat domain is still active and could be used against other targets.',
        evidence: {
          title: 'ATTACKER INFRASTRUCTURE',
          content: f => `<span class="log-highlight">DOMAINS:</span>
  ashf0rd-mfg.com — registered Feb 16 via Namecheap
  microsoft-365-admin.com — credential phishing site

<span class="log-highlight">INBOX RULES / FORWARDING:</span>
  CEO: Rule "Administrative" + forward to ashf0rd-mfg.com — ${f.rulesRemain ? '<span class="log-highlight">STILL ACTIVE</span>' : 'removed'}
  VP Sales: ${f.vpSecured ? 'No rules (account secured)' : '<span class="log-highlight">Rule "Sync" created Feb 19 — forwards "invoice" mail externally</span>'}
${f.mfaBackdoor ? `
<span class="log-highlight">AUTHENTICATION METHODS:</span>
  CEO: Authenticator "iPhone 15" — registered from 41.190.2.44
` : ''}
<span class="log-highlight">EMAIL CONFIGURATION GAPS:</span>
  DMARC: p=none (no enforcement)
  DKIM: Not configured
  SPF: Record exists but too permissive (~all instead of -all)
  No external email banner/warning configured
  No MFA on any executive accounts`
        },
        choices: [
          {
            key: 'A',
            label: 'Remove all rules, report typosquat domain, fix email auth (DMARC/DKIM/SPF)',
            desc: 'Clean up all attacker persistence AND fix the underlying email security gaps that allowed this.',
            quality: 'good',
            score: { time: 5, containment: 15, evidence: 5, thoroughness: 20 },
            sets: f => ({ vendorFraud: f.vendorFraud || !f.vpSecured, vpSecured: true, rulesRemain: false, mfaBackdoor: false }),
            outcome: f => 'All malicious inbox rules and forwarding removed. Abuse report filed with Namecheap for ashf0rd-mfg.com — domain suspended within 4 hours. DMARC upgraded to p=reject, DKIM configured, SPF hardened to -all. External email warning banner deployed. MFA enforced for all users.'
              + (f.mfaBackdoor ? ' The MFA rollout includes a review of every registered method — the rogue Authenticator on the CEO account is finally removed.' : '')
              + (!f.vpSecured ? ' Pulling the VP Sales rule is what finally gets that account reset — too late for the vendor payments already redirected.' : ''),
          },
          {
            key: 'B',
            label: 'Remove inbox rules and forwarding, enable MFA across the org',
            desc: 'Clean up the immediate persistence and add MFA. Leave email auth for later.',
            quality: 'partial',
            score: { time: 10, containment: 5, evidence: 0, thoroughness: 5 },
            sets: f => ({ vendorFraud: f.vendorFraud || !f.vpSecured, rulesRemain: false }),
            outcome: 'Rules removed and MFA deployed — good immediate actions. But DMARC remains at p=none, meaning the attacker (or anyone else) can still spoof ashford-mfg.com emails. The typosquat domain stays active. A competitor later uses the same technique.',
          },
          {
            key: 'C',
            label: 'Just remove the inbox rules — the rest is a security project, not incident response',
            desc: 'Minimal cleanup. Email auth improvements are out of scope for this IR engagement.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: 0, thoroughness: -15 },
            sets: f => ({ vendorFraud: f.vendorFraud || !f.vpSecured, rulesRemain: false }),
            outcome: 'Rules removed but nothing else changes. The typosquat domain remains active. Three weeks later, the same attacker uses it to target Ashford\'s AP department with fake vendor invoices. DMARC still allows spoofing. The client questions why their MSSP didn\'t flag these gaps.',
          },
        ],
        live: 'TYPOSQUAT ashf0rd-mfg.com: LIVE',
        timeline: [
          { at: 10, sev: 'crit', text: 'ashf0rd-mfg.com: phishing wave to 6 Ashford AP staff', score: { thoroughness: -3 } },
        ],
        siemEntries: f => [
          { time: '16:00', sev: 'info', text: 'Eradication: removing attacker persistence from M365' },
          ...(f.vpSecured ? [] : [{ time: '16:02', sev: 'crit', text: 'VP Sales mailbox: 3 outbound "banking update" emails to vendors' }]),
          { time: '16:05', sev: 'success', text: 'Malicious inbox rules removed from CEO account' },
          { time: '16:10', sev: 'warn', text: 'Typosquat domain ashf0rd-mfg.com still active' },
        ],
      },
      { // RECOVERY
        name: 'RECOVERY',
        carried: f => {
          const out = [];
          if (f.vendorFraud) out.push({
            text: 'Two vendors paid the "updated" account before anyone caught it: $87,000 lost on top of the wire.',
            score: { containment: -10 },
          });
          if (!f.vpSecured) out.push({
            text: 'The VP Sales account is still attacker-controlled. Removing its rule did nothing about the stolen password.',
            score: { containment: -10 },
          });
          if (f.mfaBackdoor && !f.ceoDisabled) out.push({
            text: 'The CEO account still carries the attacker\'s Authenticator. They can reset their way back in at will.',
            score: { containment: -10 },
          });
          return out;
        },
        narrative: f => {
          const ceo = f.ceoDisabled ? 'The CEO\'s account is still disabled' : (f.mfaBackdoor ? 'The CEO\'s account is not actually clean' : 'The CEO\'s account is secured');
          const vp = f.vpSecured ? 'VP Sales is locked down' : 'VP Sales was never secured';
          return `${ceo}; ${vp}. Now you need to ensure the organization recovers safely and the wire fraud is properly handled through financial and legal channels.`;
        },
        evidence: {
          title: 'RECOVERY STATUS',
          content: f => `<span class="log-ok">ACCOUNT STATUS:</span>
  CEO: ${f.ceoDisabled ? '<span class="log-warn">DISABLED — CEO has had no email for hours</span>'
      : f.mfaBackdoor ? '<span class="log-highlight">Attacker Authenticator still registered ✗</span>'
      : 'Password reset, MFA enabled, sessions revoked ✓'}
  VP Sales: ${f.vpSecured ? 'Password reset, MFA enabled, sessions revoked ✓' : '<span class="log-highlight">NOT SECURED ✗</span>'}
  All users: MFA rollout in progress (ETA: 48 hours)

<span class="log-warn">FINANCIAL STATUS:</span>
  Wire amount:       $340,000
  Recall filed:      ${f.recallFiled ? 'Yes' : '<span class="log-highlight">NO</span>'}
  Recalled/frozen:   ${fmtUSD(f.wireRecovered)}
  Unrecovered:       ${fmtUSD(340000 - f.wireRecovered)}${f.vendorFraud ? `
  Vendor fraud:      <span class="log-highlight">$87,000</span> (via VP Sales account)` : ''}

<span class="log-warn">LEGAL / REGULATORY:</span>
  - IC3 complaint not yet filed
  - Cyber insurance carrier not yet notified
  - Potential SEC implications (Ashford is NASDAQ-listed; M&A data exposed)
  - State breach notification requirements unclear`
        },
        choices: [
          {
            key: 'A',
            label: f => (f.ceoDisabled ? 'Re-enable the CEO with clean credentials, then f' : 'F')
              + 'ile IC3, notify insurance, engage legal for SEC/breach notification assessment',
            desc: 'Full recovery protocol: law enforcement report, insurance claim, legal review of notification obligations.',
            quality: 'good',
            score: { time: 5, containment: 5, evidence: 10, thoroughness: 20 },
            // An IC3 filing inside 72h engages the FBI Recovery Asset Team, which can
            // freeze funds still sitting at an intermediary bank.
            sets: f => ({
              legalEngaged: true,
              ceoDisabled: false,
              mfaBackdoor: false,
              wireRecovered: f.wireRecovered + (!f.recallFiled && f.saw_beneficiary ? 60000 : 0),
            }),
            outcome: f => (f.ceoDisabled ? 'The CEO account is re-enabled with a new password, fresh MFA enrollment and his old security info wiped — the attacker\'s Authenticator goes with it, and the dormant forwarding rule is deleted before it can fire. ' : '')
              + (f.saw_origIP || f.saw_lagos
                ? 'IC3 complaint filed with the attacker infrastructure you documented — FBI opens a case and links it to a known West African BEC ring. '
                : 'IC3 complaint filed, but with no attacker IPs documented it reads as an isolated fraud; nobody connects it to anything bigger. ')
              + (f.recallFiled ? ''
                : f.saw_beneficiary
                  ? 'Because the filing lands inside 72 hours and names the beneficiary account you pulled from the email, the FBI\'s Recovery Asset Team freezes $60,000 still sitting at an intermediary bank — the first money anyone has clawed back. '
                  : 'The Recovery Asset Team asks for the beneficiary bank\'s SWIFT code and the account number. Nobody wrote them down, and the CFO\'s copy of the email was deleted in the panic. By the time the bank supplies them, the funds have moved on. ')
              + 'Cyber insurance carrier notified within policy window — claim is accepted. Legal counsel determines SEC notification required due to M&A data exposure and drafts the filing.',
          },
          {
            key: 'B',
            label: 'File IC3 report and notify cyber insurance',
            desc: 'Handle the financial recovery channels. Let the client handle legal.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 5, thoroughness: 5 },
            sets: f => ({ wireRecovered: f.wireRecovered + (!f.recallFiled && f.saw_beneficiary ? 60000 : 0) }),
            outcome: f => 'IC3 filed and insurance notified — good. '
              + (f.recallFiled ? '' : f.saw_beneficiary ? 'The FBI Recovery Asset Team freezes $60,000 at an intermediary bank. ' : 'Without the beneficiary details the Recovery Asset Team can\'t act in time. ')
              + 'But without prompting legal review, the client misses the Form 8-K Item 1.05 window — four business days from deciding the incident is material. The SEC later questions the delayed disclosure, adding regulatory risk on top of the financial loss.',
          },
          {
            key: 'C',
            when: f => f.recallFiled,
            label: 'The bank is handling the wire recall — recovery is their problem now',
            desc: 'The technical incident is resolved. Financial recovery is a banking matter.',
            quality: 'bad',
            score: { time: 15, containment: -10, evidence: -5, thoroughness: -20 },
            outcome: 'No IC3 report means law enforcement can\'t track the funds or link to known threat actors. Insurance claim filed late — carrier disputes coverage. No legal review means SEC notification obligations are missed entirely. The client\'s board is furious when they learn about the regulatory exposure months later.',
          },
          {
            key: 'C',
            when: f => !f.recallFiled,
            label: 'The wire cleared days ago — the money is gone, focus on the technical cleanup',
            desc: 'There\'s nothing left to recover. Don\'t waste hours on paperwork.',
            quality: 'bad',
            score: { time: 15, containment: -10, evidence: -5, thoroughness: -20 },
            outcome: 'It hadn\'t been days — it had been hours, and IC3 filings inside 72 hours routinely freeze funds at intermediary banks. You never find out. Insurance is notified late and disputes coverage, and no legal review means SEC notification obligations are missed entirely.',
          },
        ],
        siemEntries: f => [
          { time: '17:00', sev: 'info', text: 'Recovery phase — financial and legal workstreams' },
          { time: '17:05', sev: f.recallFiled ? 'warn' : 'crit', text: f.recallFiled ? 'Wire recall status: pending with correspondent bank' : 'Wire recall: NONE FILED' },
          { time: '17:10', sev: 'info', text: 'Cyber insurance notification window: 72 hours' },
        ],
      },
      { // POST-INCIDENT
        name: 'POST-INCIDENT',
        carried: f => ((f.mfaBackdoor && !f.ceoDisabled) || !f.vpSecured) ? [{
          text: 'You are writing the report while the attacker still has a way into Ashford\'s M365 tenant.',
          score: { thoroughness: -10 },
        }] : [],
        narrative: 'The incident is contained and recovery is underway. Time to document everything and ensure this doesn\'t happen again. The client\'s board wants to understand how this happened and what changes are needed.',
        evidence: {
          title: 'INCIDENT METRICS',
          content: (f, st) => {
            const vendorLoss = f.vendorFraud ? 87000 : 0;
            return `<span class="log-ok">TIMELINE:</span>
  Attack start:       Feb 15 08:33 (phishing email)
  Account compromise: Feb 17 02:14 (CEO credentials used)
  BEC email sent:     Feb 19 11:48 (fraudulent wire request)
  Wire initiated:     Feb 19 12:15 (CFO approved)
  Detection:          Feb 19 14:22 (CFO reported)
  Time on incident:   ${formatElapsed(st.elapsed)}

<span class="log-warn">FINANCIAL IMPACT:</span>
  Total attempted fraud: $340,000
  Amount recovered:      ${fmtUSD(f.wireRecovered)}${vendorLoss ? `
  Vendor payment fraud:  <span class="log-highlight">${fmtUSD(vendorLoss)}</span>` : ''}
  Net loss:              <span class="log-highlight">${fmtUSD(340000 - f.wireRecovered + vendorLoss)}</span>
  Investigation costs:   ~$25,000 (MSSP hours)

<span class="log-warn">ROOT CAUSES:</span>
  1. No MFA on executive accounts
  2. DMARC not enforced (p=none)
  3. No external email warning banner
  4. No wire transfer verification procedure (verbal confirmation)
  5. Security awareness training: Last conducted 18 months ago`;
          }
        },
        choices: [
          {
            key: 'A',
            label: 'Full report with financial impact, root cause analysis, and security roadmap',
            desc: 'Executive-ready report with attack narrative, financial summary, and 10 prioritized recommendations.',
            quality: 'good',
            // A report is only as good as what was documented along the way
            score: (f, st) => ({ time: 5, containment: 5, evidence: 10, thoroughness: 15 + Math.min(10, 2 * st.findings.length) }),
            outcome: (f, st) => (st.findings.length >= 5
                ? `The IOC appendix lists ${st.findings.length} findings you documented during the response. `
                : `The IOC appendix is thin — ${st.findings.length} documented finding${st.findings.length === 1 ? '' : 's'} — and the insurer's forensic reviewer notices. `)
              + 'Comprehensive report delivered to the board. Recommendations include: mandatory verbal verification for wire transfers >$10K, DMARC enforcement, MFA for all users, quarterly phishing simulations, and email security gateway upgrade. The board approves a $200K security improvement budget. '
              + (340000 - f.wireRecovered + (f.vendorFraud ? 87000 : 0) > 150000
                ? 'But the net loss is hard to read past — the board also asks procurement to put the MSSP contract out to tender.'
                : 'Your MSSP secures a 2-year managed security contract.'),
          },
          {
            key: 'B',
            label: 'Standard incident report with timeline and key recommendations',
            desc: 'Solid report covering what happened and the top 3 things to fix.',
            quality: 'partial',
            score: { time: 10, containment: 0, evidence: 5, thoroughness: 5 },
            outcome: 'The report covers the incident adequately. Top recommendations (MFA, DMARC, wire verification) are implemented. But without the full root cause analysis, the board doesn\'t understand the systemic issues and allocates minimal budget for improvements.',
          },
          {
            key: 'C',
            label: 'Send a brief email summary and close the ticket',
            desc: 'Wrap it up quickly. The client knows what happened.',
            quality: 'bad',
            score: { time: 15, containment: -5, evidence: -10, thoroughness: -25 },
            outcome: 'A two-paragraph email doesn\'t satisfy the board, insurance carrier, or legal counsel. The client feels underserved by your MSSP and begins evaluating competitors. No systematic improvements are made. Similar attacks continue to succeed against the organization.',
          },
        ],
        siemEntries: [
          { time: '18:00', sev: 'info', text: 'Post-incident: compiling findings and recommendations' },
          { time: '18:10', sev: 'success', text: 'All containment/eradication actions documented' },
          { time: '18:15', sev: 'info', text: 'Board briefing requested — report due by EOD tomorrow' },
        ],
      },
    ],
  }
);
