# PumaResponse

**Six phases of incident response, one decision at a time.** An incident response training simulator that puts you in the seat of a cybersecurity analyst at a Managed Security Service Provider (MSSP). Work through realistic incidents, make critical decisions under pressure, and get graded on the response, with trade-offs grounded in NIST and SANS practice.

**Play:** [greykit.com/games/pumaresponse](https://greykit.com/games/pumaresponse/)

![Triage phase — reading evidence and selecting a response](screenshots/triage.png)

## How it plays

Each incident runs through **Triage, Containment, Investigation, Eradication, Recovery and Post-Incident**. Read the briefing, the IOCs, the evidence and the live SIEM feed, tag the log lines that matter as findings, then pick one of three responses — a fourth appears when a finding unlocks it. Choices cascade: they change what later phases show, which options exist and what they cost. Each phase opens with the clock stopped; once it starts, the attacker keeps moving and over-par decisions cost Response Time. The ↺ menu switches to turn-based play with no clock at all.

![Containment phase — M365 audit logs and three response options](screenshots/containment.png)

Seven scenarios — ransomware, business email compromise, a supply chain compromise, an insider threat, a cloud breach, a DDoS smokescreen and a web application RCE — are picked at random from those not yet played this session, or chosen from the ↺ menu. Decisions score on response time, containment, evidence preservation and thoroughness, graded A to F against the best score the scenario allows. The debrief labels every finding with its MITRE ATT&CK technique and lists what was missed.

![End screen — performance scorecard and phase decision chain](screenshots/endscreen.png)

## Keys

Keyboard, mouse or touch, with a tabbed layout on small screens. `A`–`D` or `1`–`4` pick a response, `Enter` or `Space` starts the clock and advances, `HELP` in the header tours the screen, and `Esc` closes menus.

## Saves

Personal bests, the clock setting and whether the help tour has run are kept in the browser's `localStorage` under keys starting `pumaresponse.`. **Reset progress** in the ↺ menu clears them (two presses).

## Credits

Working on the game: [DEVELOPMENT.md](DEVELOPMENT.md).

By Matthew "Shan" Romanek, with Claude. Built by [greykit.com](https://greykit.com/).

Made for my own play. Nothing here is offered: no support, no updates, no licence.
