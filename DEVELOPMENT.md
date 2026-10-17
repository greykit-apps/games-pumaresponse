# Working on PumaResponse

Vanilla HTML, CSS and JavaScript in plain files: no frameworks, no bundling, no build step and no external dependencies. The CRT terminal look is CSS custom properties and animations, and the game has full keyboard support with ARIA labels and focus management.

## What's in here

```
pumaresponse/
├── index.html          # Markup; loads the stylesheet, engine and scenarios
├── css/
│   └── style.css
├── js/
│   ├── game.js         # Engine: rendering, tagging, clock, scoring, menus
│   └── scenarios/      # One file per incident, each calling registerIncident({...})
│       ├── ransomware.js, bec.js, supply-chain.js, insider.js,
│       └── cloud-breach.js, ddos-diversion.js, webapp-rce.js
├── tools/
│   └── scenario-harness.js   # Dev tool: walks every decision path, checks invariants, calibrates grades
├── screenshots/        # Game screenshots
└── README.md
```

## Scenarios

Each scenario lives in its own file under `js/scenarios/` and registers itself with `registerIncident({...})`; the `<script>` order in `index.html` is the order scenarios appear in the menu. To add one, write a new file and add its `<script>` tag after the others. Every scenario must declare a `baseDate` (the in-world "today"). Write dates relative to it (`Feb 17` two days before a `2024-02-19` base) and the game shows them relative to the real date, so the incident is always happening today. CVE years and times of day are never shifted. Any field can be a plain value or a function of the run's state, which is how later phases react to earlier choices. The incident wall clock (SIEM stamps, time on incident) never runs behind the story: a phase starts no earlier than its first authored SIEM time, or than `at` (minutes since assignment) when a phase declares one — use `at` when a branch skips ahead by hours or days. The mechanics are documented where they're implemented in `js/game.js` — search for `EVIDENCE TAGGING` and `DECISION CLOCK`.

Grades are a percentage of the best score the scenario allows (its `bestScore`): A 85%+, B 65–84%, C 45–64%, D 25–44%, F under 25%.

## The harness

After changing a scenario, check it with the harness. Serve the repo (`python3 -m http.server 8000`), open the game, and in the browser console:

```js
await import('/tools/scenario-harness.js?' + Date.now())
harness('BEC')     // walks the decision tree under six play styles; badCount must be 0
calibrate('BEC')   // if it reports drift, update that scenario's bestScore
```

Run one scenario per call and reload between runs.
