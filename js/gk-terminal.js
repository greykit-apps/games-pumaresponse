/* @gk-terminal-begin v0.2 -- greykit.games shared code (games-meta STANDARD.md §16),
 * the terminal: the Cybersec-CRT games' title. A guideline, not a rule:
 * nothing checks it, and a game may take it, change its copy, or leave it.
 * The copy of record is games-meta's canon/gk-terminal.js; a game that takes
 * a newer version takes it whole.
 * Needs the @gk-title block (escHTML, reduced, the title mountTitle puts in)
 * and the @gk-intro block (the boot, the hold, the switches) loaded first,
 * and changes nothing in either. The boot stays canon's, in canon's colours;
 * what it hands over to is a green-phosphor terminal: the game's ASCII logo
 * typed in as the name, its old boot log scrolling on as the live scene, and
 * the menu printed as a terminal pane with a prompt under it.
 * Plain script, no imports or exports, so a single-file game can paste it
 * into a classic <script>.
 *
 * In order: startIntro(), mountTitle(), gkTerminal(title), then finish() with
 * name: "lines" and the timing gkTerminal returns. Mounting the title again
 * later (back from a game) takes gkIntegrate(), gkTerminal() and gkxReveal(). */

const TERMINAL_CSS = `
/* ---- the terminal: phosphor on a black-green ground. The colours go to §3's
   --gk-title-* names, so the title block is unchanged. They read the game's
   own --green, --amber and --red, the Cybersec-CRT palette, and fall back to
   its values ---- */
.gk-title.gkx{--gkx-green:var(--green,#00ff41);--gkx-amber:var(--amber,#ffb000);--gkx-red:var(--red,#ff3333);
  --gkx-dim:var(--green-dim,#00aa2b);--gkx-ground:#020c03;
  --gk-title-ink:var(--gkx-green);--gk-title-hi:var(--gkx-amber);--gk-title-focus:var(--gkx-green);--gk-title-dim:var(--gkx-dim);
  --gk-title-panel:color-mix(in srgb,var(--gkx-ground) 88%,transparent);--gk-title-line:color-mix(in srgb,var(--gkx-green) 34%,transparent);
  --gk-title-font:'Share Tech Mono','Courier New',monospace;
  --gkx-glow:0 0 6px color-mix(in srgb,var(--gkx-green) 45%,transparent);
  background:var(--gkx-ground);overflow-x:clip}
/* the tube: scanlines, the dark at its edges, and a faint band rolling down
   it, over everything on the title; none of it takes a click */
.gk-title.gkx::before,.gk-title.gkx::after{content:"";position:fixed;inset:0;z-index:3;pointer-events:none}
.gk-title.gkx::before{background:repeating-linear-gradient(0deg,transparent 0 2px,rgba(0,0,0,.2) 2px 4px)}
.gk-title.gkx::after{background:radial-gradient(ellipse at center,transparent 58%,rgba(0,0,0,.6) 100%),
    linear-gradient(transparent,color-mix(in srgb,var(--gkx-green) 4%,transparent) 50%,transparent) 0 -40%/100% 24% no-repeat;
  animation:gkx-roll 11s linear infinite}
@keyframes gkx-roll{to{background-position:0 0,0 140%}}

/* ---- the scene: the game's boot log, still running (gkxFeed), down the right;
   a shade down the left for the name and the menu ---- */
.gk-title.gkx>.scene{background:radial-gradient(120% 100% at 72% 45%,#051a0b 0%,var(--gkx-ground) 58%,#000 100%)}
.gk-title.gkx>.gk-shade{background:linear-gradient(90deg,color-mix(in srgb,var(--gkx-ground) 92%,transparent) 0%,
    color-mix(in srgb,var(--gkx-ground) 76%,transparent) 40%,color-mix(in srgb,var(--gkx-ground) 20%,transparent) 62%,transparent 74%)}
.gkx-feed{position:absolute;top:0;bottom:0;right:clamp(16px,4vw,64px);width:min(620px,46vw);display:flex;flex-direction:column;
  justify-content:flex-end;box-sizing:border-box;padding-bottom:64px;overflow:hidden;
  font:13px/1.7 var(--gk-title-font);color:var(--gkx-dim);white-space:pre;
  -webkit-mask-image:linear-gradient(transparent,#000 35%);mask-image:linear-gradient(transparent,#000 35%)}
.gkx-feed>div{display:flex;gap:1.5ch;flex:none}
.gkx-feed .gkx-ts{opacity:.55}
.gkx-feed .gkx-tag{flex:none;width:5ch}
.gkx-feed .gkx-txt{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:clip}
.gkx-feed .gkx-txt::after{content:" ................................................................................";opacity:.45}
.gkx-feed .gkx-st{flex:none;color:var(--gkx-green)}
.gkx-feed .gkx-warn .gkx-tag,.gkx-feed .gkx-warn .gkx-st{color:var(--gkx-amber)}
.gkx-feed .gkx-alert .gkx-tag,.gkx-feed .gkx-alert .gkx-st,.gkx-feed .gkx-alert .gkx-txt{color:var(--gkx-red)}
/* a line just printed glows, and fades to the rest as phosphor does */
.gkx-feed .gkx-new{animation:gkx-bloom 1.4s ease-out}
@keyframes gkx-bloom{from{filter:brightness(2.2) drop-shadow(0 0 4px var(--gkx-green))}}

/* ---- the name: the game's ASCII logo, as wide as the column lets it be ---- */
.gk-title.gkx>main{width:min(860px,100%);container-type:inline-size}
.gk-title.gkx h1{font-size:clamp(5px,calc(100cqi / var(--gkx-cols,60) / .56),17px);line-height:1.18;font-weight:400;
  letter-spacing:0;text-transform:none;color:var(--t-ink);
  text-shadow:0 0 8px color-mix(in srgb,var(--gkx-green) 70%,transparent),0 0 22px color-mix(in srgb,var(--gkx-green) 32%,transparent)}
.gk-title.gkx h1 span{white-space:pre}
/* the cursor and the untyped rest sit inside a row: inline, not the rows' block */
.gk-title.gkx h1 span span{display:inline}
.gk-title.gkx h1 span+span{color:var(--t-ink)}
.gk-title.gkx .gk-sub{margin:14px 0 0;font-size:12px;font-weight:400;letter-spacing:.2em;color:var(--t-dim);text-shadow:var(--gkx-glow)}
/* typing: what is typed, the cursor on the next cell, the rest held in place
   unseen, so nothing moves as the line fills */
.gkx-cur{color:transparent;background:var(--gkx-amber);text-shadow:none;box-shadow:0 0 8px color-mix(in srgb,var(--gkx-amber) 55%,transparent)}
.gkx-rest{visibility:hidden}
/* in the entrance a row shows at once and types itself (gkTerminal), rather
   than fading as §14's lines do; the line under the name follows the last */
.gk-title.gkx.gki-intro h1>span.gki-on{transition:none}
.gk-title.gkx.gki-intro .gk-sub.gkx-on{opacity:1;transition:none}
.gk-title.gkx.gk-rise .gk-sub{animation:none}

/* ---- the menu: a pane with its name in its frame, each row a key in
   brackets, the item and its meta along a dotted leader; Settings, Help and
   About on one line under a rule; the prompt last ---- */
.gk-title.gkx .gk-menu{position:relative;width:min(580px,100%);margin-top:30px;padding:14px 0 6px;border-radius:0;
  background:var(--t-panel);border:1px solid var(--t-line);box-shadow:0 0 34px color-mix(in srgb,var(--gkx-green) 7%,transparent)}
.gk-title.gkx .gk-menu::before{content:attr(data-gkx-legend);position:absolute;top:-.8em;left:14px;padding:0 8px;
  font-size:12px;letter-spacing:.22em;color:var(--t-dim);background:var(--gkx-ground)}
.gk-title.gkx .gk-menu button{height:36px;padding:0 18px;gap:1.2ch;font-size:16px;font-weight:400;letter-spacing:.06em;
  text-transform:uppercase;color:color-mix(in srgb,var(--t-ink) 80%,transparent);text-shadow:var(--gkx-glow)}
.gk-title.gkx .gk-menu .gk-primary{color:var(--t-ink);font-weight:400}
.gk-title.gkx .gk-menu kbd{min-width:0;padding:0;font-size:inherit;letter-spacing:0;color:var(--gkx-amber);border:0;border-radius:0}
.gk-title.gkx .gk-menu kbd::before{content:"[";color:var(--t-dim)}
.gk-title.gkx .gk-menu kbd::after{content:"]";color:var(--t-dim)}
.gkx-dots{flex:1 1 0;min-width:2ch;overflow:hidden;white-space:nowrap;color:var(--t-dim);opacity:.5}
.gkx-dots::before{content:"................................................................................"}
.gk-title.gkx .gk-menu .gk-meta{flex:none;max-width:45%;margin-left:0;font-size:13px;letter-spacing:.04em;color:var(--t-dim)}
.gk-title.gkx .gk-menu button:hover{color:var(--t-ink);background:color-mix(in srgb,var(--t-focus) 10%,transparent)}
/* the row with the focus in inverse video, as a terminal selects */
.gk-title.gkx .gk-menu button:focus{color:var(--gkx-ground);font-weight:400;text-shadow:none;background:var(--t-focus);
  box-shadow:0 0 16px color-mix(in srgb,var(--gkx-green) 40%,transparent)}
.gk-title.gkx .gk-menu button:focus::before{content:none}
.gk-title.gkx .gk-menu button:focus kbd,.gk-title.gkx .gk-menu button:focus kbd::before,.gk-title.gkx .gk-menu button:focus kbd::after,
.gk-title.gkx .gk-menu button:focus .gk-meta,.gk-title.gkx .gk-menu button:focus .gkx-dots{color:var(--gkx-ground)}
.gk-title.gkx .gk-menu .gk-util{margin:6px 0 0;padding-top:6px;border-top:1px dashed var(--t-line)}
.gk-title.gkx .gk-menu .gk-util button{height:34px;font-size:14px;gap:1ch;padding:0 12px}
.gk-title.gkx .gk-menu .gk-util button:first-child{padding-left:18px}
.gk-title.gkx .gk-menu .gk-util kbd{font-size:inherit;min-width:0}
/* the prompt: the command the focused row would run, typed as the focus
   moves, the cursor blinking after it */
.gkx-prompt{display:flex;margin:8px 18px 4px;padding-top:8px;border-top:1px dashed var(--t-line);font-size:15px;line-height:1.4;
  color:var(--t-ink);text-shadow:var(--gkx-glow);white-space:pre;overflow:hidden}
.gkx-prompt b{font-weight:400;color:var(--t-dim)}
.gkx-prompt i{flex:none;width:1ch;font-style:normal;background:var(--gkx-green);box-shadow:var(--gkx-glow);animation:gkx-blink 1.06s steps(1) infinite}
@keyframes gkx-blink{50%{opacity:0}}
/* the switches and the credit, squared off to the terminal */
.gk-title.gkx .gki-tg,.gk-title.gkx .gki-tg .gki-sw,.gk-title.gkx .gki-tg .gki-sw::after{border-radius:2px}
.gk-title.gkx.gki main>footer{width:min(580px,100%);font-size:14px;letter-spacing:.06em}

/* ---- the entrance. The tube comes on as the boot goes: a line of light
   that opens into the screen (gkx-on, from gkTerminal). Then the pane's
   frame is there at once, and its lines print one after another, each
   glowing as it lands ---- */
.gk-title.gkx.gki-fade:not(.gkx-lit){animation:none;opacity:0}
.gk-title.gkx.gkx-on{animation:gkx-on .62s cubic-bezier(.2,.7,.3,1) both}
@keyframes gkx-on{0%{transform:scale(.02,.004);filter:brightness(5)}28%{transform:scale(1,.004);filter:brightness(4)}
  64%{transform:scale(1,1);filter:brightness(1.6)}100%{transform:none;filter:none}}
.gk-title.gkx.gki-intro.gki-menu .gk-menu{transition:none}
.gk-title.gkx.gk-rise .gk-menu .gk-pr,.gk-title.gkx.gk-rise .gkx-prompt{animation:gkx-print .9s linear calc(var(--i) * 75ms) both}
@keyframes gkx-print{0%{opacity:0}.1%{opacity:1;filter:brightness(2.4)}100%{opacity:1;filter:none}}

/* ---- narrower screens: the log runs on behind the menu, so the shade
   reaches further across and the pane is all but solid ---- */
@media (max-width:1100px){
  .gk-title.gkx>.gk-shade{background:linear-gradient(90deg,color-mix(in srgb,var(--gkx-ground) 94%,transparent) 0%,
    color-mix(in srgb,var(--gkx-ground) 86%,transparent) 55%,color-mix(in srgb,var(--gkx-ground) 45%,transparent) 80%,
    color-mix(in srgb,var(--gkx-ground) 25%,transparent) 100%)}
  .gk-title.gkx{--gk-title-panel:color-mix(in srgb,var(--gkx-ground) 96%,transparent)}
}
/* ---- a phone: the log behind everything, under a shade; no prompt, since
   a phone has no keys to type at it ---- */
@media (max-width:640px){
  .gkx-feed{left:16px;right:16px;width:auto;font-size:11px}
  .gkx-feed .gkx-ts{display:none}
  .gk-title.gkx>.gk-shade{background:color-mix(in srgb,var(--gkx-ground) 82%,transparent)}
  .gk-title.gkx>main{padding-top:64px}
  .gk-title.gkx .gk-menu button{font-size:14px;padding:0 12px}
  .gk-title.gkx .gk-menu .gk-util button,.gk-title.gkx .gk-menu .gk-util button:first-child{padding:0 6px}
  .gkx-prompt{display:none}
}
@media (prefers-reduced-motion:reduce){
  .gk-title.gkx::after,.gkx-feed .gkx-new,.gk-title.gkx.gkx-on,.gk-title.gkx.gk-rise .gk-menu .gk-pr,.gk-title.gkx.gk-rise .gkx-prompt,
  .gkx-prompt i{animation:none}
}
`;

function injectTerminalCSS() {
  if (!document.getElementById("gk-terminal-css")) document.head.insertAdjacentHTML("beforeend", '<style id="gk-terminal-css">' + TERMINAL_CSS + "</style>");
}

/* Type text into el by the clock, not by ticks, so a throttled tab still ends
 * on time: the typed part, the cursor on the next cell, the rest unseen and
 * holding its place. Stops, with the text whole, when stop() says so. */
function gkxType(el, text, ms, stop = () => false, done = () => {}) {
  const t0 = performance.now();
  const draw = n => {
    el.innerHTML = escHTML(text.slice(0, n)) + '<span class="gkx-cur">' + escHTML(text[n] || " ") + '</span><span class="gkx-rest">' +
      escHTML(text.slice(n + 1)) + "</span>";
  };
  draw(0);
  const t = setInterval(() => {
    const p = (performance.now() - t0) / ms;
    if (!el.isConnected || stop() || p >= 1) { clearInterval(t); el.textContent = text; done(); return; }
    draw(Math.floor(text.length * p));
  }, 16);
}

/**
 * The live scene: the game's boot log, printed again as the title comes on
 * at the pace the old boot printed it, then running on as a live log -- a
 * line every second or so, now and then a burst, now and then a warning.
 * Under prefers-reduced-motion, a screenful, still.
 *   el      the .scene (mountTitle's scene(el) hands it over)
 *   boot    the old boot's lines: [tag, kind, text], kind "ok", "warn",
 *           "alert" or "info"
 *   live    lines to run on with, the same shape; the boot's if left out;
 *           an alert among them comes up less often than the rest.
 *           A text may hold {n}, a number, and {ip}, an address, drawn fresh
 *           each time it prints
 * Waits while canon's boot is up, so it starts as the title comes on.
 * Returns { stop() }.
 */
function gkxFeed(el, { boot = [], live = null } = {}) {
  const pool = live && live.length ? live : boot;
  const feed = document.createElement("div");
  feed.className = "gkx-feed";
  feed.setAttribute("aria-hidden", "true");
  el.appendChild(feed);
  const ST = { ok: "[ OK ]", warn: "[WARN]", alert: "[ALRT]", info: "[INFO]" };
  const fill = s => s.replace(/\{n\}/g, () => String(2 + (Math.random() * 97 | 0))).replace(/\{ip\}/g, () => "10." + (Math.random() * 255 | 0) + "." + (Math.random() * 255 | 0) + "." + (1 + Math.random() * 253 | 0));
  const stamp = () => new Date().toTimeString().slice(0, 8);
  const say = ([tag, kind, text], fresh = true) => {
    const d = document.createElement("div");
    d.className = "gkx-" + (ST[kind] ? kind : "ok") + (fresh ? " gkx-new" : "");
    d.innerHTML = '<span class="gkx-ts">' + stamp() + '</span><span class="gkx-tag">' + escHTML(tag) + '</span><span class="gkx-txt">' +
      escHTML(fill(text)) + '</span><span class="gkx-st">' + (ST[kind] || ST.ok) + "</span>";
    feed.appendChild(d);
    /* keep what fits and a little over; the rest scrolled away */
    while (feed.children.length > 60) feed.firstChild.remove();
  };
  if (reduced()) { [...boot, ...pool].slice(-40).forEach(l => say(l, false)); return { stop() {} }; }
  let i = 0, t = null, stopped = false;
  const next = () => {
    if (stopped || !feed.isConnected) return;
    /* not while canon's boot is up: the title is behind it */
    if (document.querySelector(".gk-boot:not(.gk-out)")) { t = setTimeout(next, 120); return; }
    if (i < boot.length) { say(boot[i++]); t = setTimeout(next, 80 + Math.random() * 70); return; }
    /* an alert is the exception: most draws that land on one draw again */
    let l = pool[Math.random() * pool.length | 0];
    if (l[1] === "alert" && Math.random() < 0.7) l = pool[Math.random() * pool.length | 0];
    say(l);
    const burst = Math.random() < 0.18;
    t = setTimeout(next, burst ? 60 + Math.random() * 90 : 450 + Math.random() * 1300);
  };
  next();
  return { stop() { stopped = true; clearTimeout(t); } };
}

/**
 * Lay a mounted .gk-title out as the terminal. Call it after mountTitle and
 * before finish(); a title mounted again later takes it again.
 *   logo     the game's ASCII logo, its rows as strings; it becomes the
 *            name's lines (the h1 keeps the game's name for a screen reader)
 *   sub      optional: the line under the name, typed after the logo
 *            (mountTitle's sub, if left out)
 *   prompt   the prompt's head, as "analyst@pumasoc:~$"
 *   legend   the pane's name, in its frame (default "MAIN MENU")
 *   feed     optional: { boot, live } for gkxFeed, into the title's .scene
 *   type(ms) optional: plays as anything starts typing -- each row of the
 *            logo, the line under it, the prompt's command as the focus
 *            moves -- for the ms the typing takes (gkxChatter). Return the
 *            sound's source node and it is stopped when a skip finishes the
 *            typing early, so no keys go on after the text has stopped.
 *   power()  optional: plays as the tube comes on (gkxPower: the degauss)
 * Returns { timing }: finish()'s timing for name: "lines", so the menu
 * follows the logo and the line under it.
 */
function gkTerminal(title, { logo = null, sub = null, prompt = "greykit@terminal:~$", legend = "MAIN MENU", feed = null, type = null, power = null } = {}) {
  if (!title || title.classList.contains("gkx")) return { timing: {} };
  injectTerminalCSS();
  title.classList.add("gkx");
  const h1 = title.querySelector("main > h1"), menu = title.querySelector(".gk-menu");
  if (h1 && logo) h1.innerHTML = logo.map(l => '<span data-t="' + escHTML(l) + '">' + escHTML(l) + "</span>").join("");
  const rows = h1 ? [...h1.querySelectorAll("span[data-t]")] : [];
  if (h1) h1.style.setProperty("--gkx-cols", Math.max(20, ...rows.map(r => r.dataset.t.length)));
  let subEl = title.querySelector("main > .gk-sub");
  if (sub && !subEl && h1) { h1.insertAdjacentHTML("afterend", '<p class="gk-sub"></p>'); subEl = h1.nextElementSibling; }
  if (sub && subEl) subEl.textContent = sub;
  const subText = subEl ? subEl.textContent : "";
  /* the typing's sound, for as long as the typing takes; hush() cuts it short */
  const keys = ms => { if (!type) return null; try { return type(ms) || null; } catch (e) { return null; } };
  const hush = s => { if (s && s.stop) try { s.stop(); } catch (e) { /* already stopped */ } };

  /* the menu: its name in the frame, a dotted leader before each meta, and
     the prompt under it all, printing in last */
  let line = null;
  if (menu) {
    menu.setAttribute("data-gkx-legend", legend);
    for (const m of menu.querySelectorAll(".gk-meta")) m.insertAdjacentHTML("beforebegin", '<span class="gkx-dots" aria-hidden="true"></span>');
    line = document.createElement("div");
    line.className = "gkx-prompt";
    line.setAttribute("aria-hidden", "true");
    line.style.setProperty("--i", menu.querySelectorAll(".gk-pr").length);
    line.innerHTML = "<b>" + escHTML(prompt) + " </b><span></span><i></i>";
    menu.appendChild(line);
    const cmd = line.querySelector("span");
    const command = b => { const lbl = b && b.querySelector(".gk-lbl"); return lbl ? lbl.textContent.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") : ""; };
    /* the default's command from the start: it prints with the menu, focused or not */
    cmd.textContent = command(menu.querySelector(".gk-primary") || menu.querySelector("button"));
    let typing = null;
    const show = b => {
      const text = command(b);
      if (typing) typing.stop = true;
      if (text === cmd.textContent) return;
      if (reduced()) { cmd.textContent = text; return; }
      /* each new command types over the last, quickly, as an operator would */
      const me = typing = { stop: false };
      const t0 = performance.now(), ms = Math.min(260, 18 * text.length);
      const snd = keys(ms);
      const tick = () => {
        if (me.stop) { hush(snd); return; }
        const p = Math.min(1, (performance.now() - t0) / ms);
        cmd.textContent = text.slice(0, Math.ceil(text.length * p));
        if (p < 1) requestAnimationFrame(tick);
      };
      tick();
    };
    menu.addEventListener("focusin", ev => { const b = ev.target.closest("button"); if (b) show(b); });
  }

  if (feed) {
    const scene = title.querySelector(":scope > .scene");
    if (scene) gkxFeed(scene, feed);
  }

  /* the timing finish() should use: the tube on, then each row of the logo,
     then the line under it, then the menu */
  const T = { name: 700, step: 190 };
  const subAt = T.name + rows.length * T.step + 80, subMs = Math.min(1100, subText.length * 14);
  T.menu = subAt + (subText ? subMs + 280 : 120);
  T.done = T.menu + 1400;

  /* the entrance, alongside §14's: canon's boot going is the tube coming
     on; each row of the logo, as finish() lights it, types itself; the line
     under the name types after the last row. A skip (finish() takes
     gki-intro off) leaves it all whole at once */
  const boot = document.querySelector(".gk-boot:not(.gk-out)");
  const live = () => title.classList.contains("gki-intro");
  if (boot && !reduced()) {
    const on = () => {
      if (title.classList.contains("gkx-lit") || !live()) return;
      title.classList.add("gkx-on", "gkx-lit");
      if (power) try { power(); } catch (e) { /* no sound */ }
      setTimeout(() => title.classList.remove("gkx-on"), 700);
    };
    new MutationObserver((ms, ob) => {
      if (boot.classList.contains("gk-out") || !boot.isConnected) { ob.disconnect(); on(); }
    }).observe(boot, { attributes: true, attributeFilter: ["class"] });
    const typed = new WeakSet();
    const ob = new MutationObserver(() => {
      for (const [k, r] of rows.entries()) {
        if (typed.has(r) || !r.classList.contains("gki-on") || !live()) continue;
        typed.add(r);
        const snd = keys(T.step);
        gkxType(r, r.dataset.t, T.step, () => { if (live()) return false; hush(snd); return true; }, () => {
          if (k !== rows.length - 1 || !subEl || !subText || !live()) return;
          setTimeout(() => {
            if (!live()) return;
            subEl.classList.add("gkx-on");
            const snd2 = keys(subMs);
            gkxType(subEl, subText, subMs, () => { if (live()) return false; hush(snd2); return true; });
          }, 80);
        });
      }
      if (!live() && title.classList.contains("gk-rise")) ob.disconnect();
    });
    ob.observe(title, { attributes: true, attributeFilter: ["class"], subtree: true });
  }
  return { timing: T };
}

/* Coming back to the title from a game: the logo whole, the menu printing in
 * again, the default focused -- §3's revealTitle without its decode, which
 * would scramble the logo. */
function gkxReveal(title) {
  if (!title) return;
  title.classList.remove("gk-rise");
  void title.offsetWidth;
  title.classList.add("gk-rise");
  const b = title.querySelector(".gk-primary") || title.querySelector(".gk-menu button");
  if (b) b.focus({ preventScroll: true });
}

/* a short noise burst, shaped by env(p) for p from 0 to 1, as a buffer */
function gkxNoise(ac, secs, env) {
  const buf = ac.createBuffer(1, Math.max(1, ac.sampleRate * secs | 0), ac.sampleRate), d = buf.getChannelData(0);
  for (let i = 0; i < d.length; i++) d[i] = (Math.random() * 2 - 1) * env(i / d.length);
  const s = ac.createBufferSource();
  s.buffer = buf;
  return s;
}

/**
 * The menu's tick: a key on an old keyboard -- the switch's click and the cap
 * bottoming out -- for finish()'s tick. An effect, under the Sound switch.
 *   ac, out   the AudioContext and the node to play into
 *   gain      level (default 0.1: as loud as §14's gkTick, so a run of
 *             them down the menu stays in the background)
 */
function gkxKey(ac, out, { gain = 0.1 } = {}) {
  if (!ac || ac.state !== "running") return;
  const t = ac.currentTime, bus = ac.createGain();
  bus.gain.value = gain;
  bus.connect(out);
  const n = gkxNoise(ac, 0.008, p => Math.pow(1 - p, 4)), hp = ac.createBiquadFilter();
  hp.type = "highpass";
  hp.frequency.value = 2600;
  n.connect(hp);
  hp.connect(bus);
  n.start(t);
  const o = ac.createOscillator(), g = ac.createGain();
  o.type = "sine";
  o.frequency.setValueAtTime(330, t + 0.006);
  o.frequency.exponentialRampToValueAtTime(140, t + 0.03);
  g.gain.setValueAtTime(0.0001, t);
  g.gain.setValueAtTime(0.35, t + 0.006);
  g.gain.exponentialRampToValueAtTime(0.0001, t + 0.035);
  o.connect(g);
  g.connect(bus);
  o.start(t);
  o.stop(t + 0.045);
}

/**
 * Typing: a quick run of keys, as long as the text takes to type. For
 * gkTerminal's type, which says how long: pass its ms on, and return what
 * this returns, so a skip can stop it.
 *   ac, out   the AudioContext and the node to play into
 *   ms        how long the run lasts (default 190, a row of the logo's)
 *   gain      level (default 0.22)
 * Returns the source node, or nothing when sound cannot play.
 */
function gkxChatter(ac, out, { ms = 190, gain = 0.22 } = {}) {
  if (!ac || ac.state !== "running") return;
  const secs = ms / 1000, buf = ac.createBuffer(1, Math.max(1, ac.sampleRate * secs | 0), ac.sampleRate), d = buf.getChannelData(0);
  /* clicks at a typist's uneven pace, each a few ms of falling noise */
  for (let at = 0; at < secs - 0.006; at += 0.024 + Math.random() * 0.018) {
    const i0 = at * ac.sampleRate | 0, len = 0.005 * ac.sampleRate | 0, lvl = 0.5 + Math.random() * 0.5;
    for (let i = 0; i < len && i0 + i < d.length; i++) d[i0 + i] += (Math.random() * 2 - 1) * lvl * Math.pow(1 - i / len, 3);
  }
  const s = ac.createBufferSource(), bp = ac.createBiquadFilter(), g = ac.createGain();
  s.buffer = buf;
  bp.type = "bandpass";
  bp.frequency.value = 3800;
  bp.Q.value = 0.9;
  g.gain.value = gain;
  s.connect(bp);
  bp.connect(g);
  g.connect(out);
  s.start();
  return s;
}

/**
 * The tube coming on: the degauss, as a CRT monitor recorded powering on
 * plays it (Wikimedia Commons, "CRT monitor turns on.ogg", CC0) -- the
 * relay's click, then a short hum that starts at full and stops. The hum's
 * loudest part is four times the mains (240 Hz at 60), with the mains and
 * twice it under that and nothing much above 500 Hz: the coil's field pulls
 * twice a cycle, so the metal round it buzzes at the mains' even harmonics.
 * About 0.4 s; the click is some 15 dB over the hum, as recorded. For
 * gkTerminal's power.
 *   ac, out   the AudioContext and the node to play into
 *   hz        the mains the set hums at (default 60)
 *   gain      level (default 0.25)
 */
function gkxPower(ac, out, { hz = 60, gain = 0.25 } = {}) {
  if (!ac || ac.state !== "running") return;
  const t = ac.currentTime, bus = ac.createGain();
  bus.gain.value = gain;
  bus.connect(out);
  /* the relay: a short, bright click, gone in 50 ms */
  const n = gkxNoise(ac, 0.05, p => Math.pow(1 - p, 6)), hp = ac.createBiquadFilter(), ng = ac.createGain();
  hp.type = "highpass";
  hp.frequency.value = 1500;
  ng.gain.value = 2.4;
  n.connect(hp);
  hp.connect(ng);
  ng.connect(bus);
  n.start(t);
  /* the hum, at full at once, held, then gone in a tenth of a second; its
     harmonics at the recording's levels (240 Hz at 0 dB, 60 at -7, 120 at
     -9, 360 at -18, 180 at -20) */
  const at = t + 0.01, end = at + 0.42, env = ac.createGain();
  env.gain.setValueAtTime(0.0001, at);
  env.gain.linearRampToValueAtTime(0.18, at + 0.006);
  env.gain.setValueAtTime(0.18, end - 0.12);
  env.gain.linearRampToValueAtTime(0.0001, end);
  env.connect(bus);
  for (const [mul, lvl] of [[4, 1], [1, 0.45], [2, 0.35], [6, 0.13], [3, 0.1]]) {
    const o = ac.createOscillator(), g = ac.createGain();
    o.frequency.value = hz * mul;
    g.gain.value = lvl;
    o.connect(g);
    g.connect(env);
    o.start(at);
    o.stop(end + 0.02);
  }
}
/* @gk-terminal-end */
