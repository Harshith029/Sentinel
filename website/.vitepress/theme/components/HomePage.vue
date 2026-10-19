<script setup lang="ts">
import { withBase } from 'vitepress'
import AttackFlow from './AttackFlow.vue'
import CopyCommand from './CopyCommand.vue'
import LiveTerminal from './LiveTerminal.vue'
import OutboxCompare from './OutboxCompare.vue'

const repo = 'https://github.com/Harshith029/Sentinel'
const install = 'pip install "sentinel-prox>=0.2.2"'

const facts = [
  'No agent code changes',
  'Default-deny policy',
  'Fail-closed authentication',
  'No eval, anywhere',
  'Free and local',
]

const stages = [
  {
    title: 'Trace',
    text: 'Label the origin of everything the agent sees: SYSTEM, USER, AGENT or RETRIEVED_CONTENT.',
    icon: '<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.5 6H14a4 4 0 0 1 4 4v5.5"/>',
  },
  {
    title: 'Authorize',
    text: 'Your policy decides each call from that lineage. Deny-only rules, deny-overrides, unknown tools denied.',
    icon: '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  },
  {
    title: 'Contain',
    text: 'A trust score drops on denied calls and other signals, and can quarantine the agent.',
    icon: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  },
  {
    title: 'Record',
    text: 'Each decision becomes an immutable span. Replay a run, or export it as JSONL for a SIEM.',
    icon: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  },
]

const limits = [
  'Taint is tracked per MCP session',
  'Only the tools you write rules for are guarded',
  'Downstream servers must speak streamable HTTP',
  'State lives in one process',
]

function spotlight(event: MouseEvent) {
  const card = event.currentTarget as HTMLElement
  const box = card.getBoundingClientRect()
  card.style.setProperty('--mx', `${event.clientX - box.left}px`)
  card.style.setProperty('--my', `${event.clientY - box.top}px`)
}
</script>

<template>
  <div class="home">
    <!-- Hero -->
    <section class="hero">
      <div class="hero-bg" aria-hidden="true">
        <div class="grid" />
        <div class="orb orb-a" />
        <div class="orb orb-b" />
        <div class="orb orb-c" />
        <div class="beam" />
      </div>

      <div class="container hero-inner">
        <a class="pill" :href="`${repo}/blob/main/CHANGELOG.md`" target="_blank" rel="noreferrer">
          <span class="pill-tag">Open source</span>
          MIT licensed · Python 3.11+
          <span class="pill-arrow" aria-hidden="true">→</span>
        </a>
        <h1 class="headline">
          Stop prompt injection<br />
          <span class="grad">at the action layer</span>
        </h1>
        <p class="lede">
          SENTINEL is a security proxy for MCP. It tracks where every tool result came from,
          and refuses the actions you guard when their data came from untrusted content.
          Even when the attack got past your content filter.
        </p>
        <div class="ctas">
          <a class="btn primary" :href="withBase('/guide/quick-start')">
            Get started
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6" /></svg>
          </a>
          <a class="btn ghost" :href="withBase('/guide/introduction')">What is SENTINEL?</a>
          <a class="btn ghost" :href="repo" target="_blank" rel="noreferrer">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.53-1.33-1.29-1.69-1.29-1.69-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.04 1.77 2.72 1.26 3.38.96.1-.75.4-1.26.74-1.55-2.56-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.69 5.39-5.25 5.68.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5z" /></svg>
            GitHub
          </a>
        </div>
        <CopyCommand :command="install" />
      </div>

      <div class="container hero-visual">
        <AttackFlow />
      </div>
    </section>

    <!-- Facts strip -->
    <section class="container facts" aria-label="Defaults">
      <span v-for="fact in facts" :key="fact" class="fact">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12l5 5L20 7" /></svg>
        {{ fact }}
      </span>
    </section>

    <!-- The problem -->
    <section class="container section split">
      <div v-reveal class="copy">
        <p class="eyebrow">The problem</p>
        <h2>Filters judge the words. The damage is done by the actions.</h2>
        <p>
          An attacker hides an instruction in content your agent will read: a web page, a
          document, a ticket. Content filters scan the text, and no filter catches everything.
          When one misses, the instruction runs with the agent's full privileges.
        </p>
        <p>
          SENTINEL judges each action by <strong>where its data came from</strong>. Rewording or
          obfuscating the injection does not change that.
        </p>
        <a class="text-link" :href="withBase('/guide/introduction')">Read the full story →</a>
      </div>
      <div v-reveal="120">
        <OutboxCompare />
      </div>
    </section>

    <!-- How it works -->
    <section class="container section">
      <div v-reveal class="section-head">
        <p class="eyebrow">How it works</p>
        <h2>Four stages on every tool call</h2>
        <p>
          To your agent, SENTINEL is an ordinary MCP server. To your tools, it is the only client
          they ever see.
        </p>
      </div>
      <div class="stages">
        <div class="stages-line" aria-hidden="true" />
        <article v-for="(stage, i) in stages" :key="stage.title" v-reveal="i * 90" class="stage">
          <div class="stage-icon">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" v-html="stage.icon" />
          </div>
          <p class="stage-num">0{{ i + 1 }}</p>
          <h3>{{ stage.title }}</h3>
          <p>{{ stage.text }}</p>
        </article>
      </div>
    </section>

    <!-- Observability -->
    <section class="container section split reverse">
      <div v-reveal class="copy">
        <p class="eyebrow">Observability</p>
        <h2>Every decision, logged where you're looking</h2>
        <p>
          Blocks at <code>WARNING</code>, allowed calls at <code>INFO</code>, each with the trace id
          that ties it to the full forensic record.
        </p>
        <ul class="checks">
          <li>Tool arguments are never written to logs</li>
          <li><code>--log-format json</code> for your aggregator</li>
          <li>Replay any run, or export it as JSONL for a SIEM</li>
        </ul>
        <a class="text-link" :href="withBase('/guide/forensics')">Logs and forensics →</a>
      </div>
      <div v-reveal="120">
        <LiveTerminal />
      </div>
    </section>

    <!-- Bento -->
    <section class="container section">
      <div v-reveal class="section-head">
        <p class="eyebrow">Built for security teams</p>
        <h2>Enforcement you can reason about</h2>
        <p>Small, explicit rules over a precise model of where data came from.</p>
      </div>

      <div class="bento">
        <article v-reveal class="card wide" @mousemove="spotlight">
          <h3>Judged by origin, not wording</h3>
          <p>
            Every message and tool result carries a trust label. An action's provenance is the set
            of labels over its whole ancestry, never just the latest step.
          </p>
          <div class="lineage" aria-hidden="true">
            <span class="node n1"><b>USER</b>Summarize this pricing page</span>
            <span class="edge" />
            <span class="node n2 taint"><b>RETRIEVED_CONTENT</b>web_fetch result</span>
            <span class="edge" />
            <span class="node n3"><b>AGENT</b>drafts send_email</span>
            <span class="edge" />
            <span class="node n4 deny"><b>DENY</b>lineage is tainted</span>
          </div>
        </article>

        <article v-reveal="80" class="card" @mousemove="spotlight">
          <h3>Deny-only policy, no eval</h3>
          <p>YAML compiled to a typed condition tree. Unknown tools are denied until you write a rule.</p>
          <pre class="mini-code" aria-label="Policy example"><span class="y-key">send_email</span>:
  <span class="y-key">rules</span>:
    - <span class="y-key">id</span>: <span class="y-str">block-untrusted-origin</span>
      <span class="y-key">deny_if</span>: <span class="y-str">"RETRIEVED_CONTENT in
        effective_provenance"</span></pre>
        </article>

        <article v-reveal class="card" @mousemove="spotlight">
          <h3>Catalogue integrity</h3>
          <p>Attacks that arrive in a tool's definition never reach the agent.</p>
          <ul class="mini-list">
            <li><b>Tool poisoning</b> scanned at connect</li>
            <li><b>Shadowing</b> fails closed</li>
            <li><b>Rug pulls</b> fingerprinted and re-checked</li>
          </ul>
        </article>

        <article v-reveal="80" class="card" @mousemove="spotlight">
          <h3>A record of every decision</h3>
          <p>Immutable spans, with arguments and results redacted before they are stored.</p>
          <ul class="spans" aria-hidden="true">
            <li><span class="ev">ToolExecuted</span> get_customer_record</li>
            <li><span class="ev">ToolExecuted</span> web_fetch</li>
            <li class="bad"><span class="ev">ToolBlocked</span> send_email</li>
          </ul>
        </article>

        <article v-reveal="160" class="card" @mousemove="spotlight">
          <h3>Free to run</h3>
          <p>Enforcement is local and identical everywhere. Paid Azure services are optional upgrades.</p>
          <ul class="mini-list">
            <li><b>Shield</b> local detector</li>
            <li><b>Storage</b> SQLite</li>
            <li><b>Hosting</b> any Docker host</li>
          </ul>
        </article>
      </div>
    </section>

    <!-- Limits -->
    <section class="container section">
      <div v-reveal class="honest">
        <div class="honest-copy">
          <p class="eyebrow warn">Read before you deploy</p>
          <h3>Honest about its limits</h3>
          <p>
            SENTINEL is beta software. Each limitation changes what it protects you from, so they
            are documented, with their consequences, before anything else.
          </p>
          <a class="btn ghost" :href="withBase('/guide/limitations')">Status and limitations →</a>
        </div>
        <ul class="honest-list">
          <li v-for="item in limits" :key="item">{{ item }}</li>
        </ul>
      </div>
    </section>

    <!-- Final CTA -->
    <section class="cta">
      <div class="cta-glow" aria-hidden="true" />
      <div v-reveal class="container cta-inner">
        <h2>Put SENTINEL in front of your agent</h2>
        <p>No agent code changes. No paid services. Five commands from install to enforcement.</p>
        <CopyCommand :command="install" />
        <div class="ctas">
          <a class="btn primary" :href="withBase('/guide/quick-start')">Read the quick start</a>
          <a class="btn ghost" :href="withBase('/guide/demo')">Try the demo</a>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.home {
  overflow: hidden;
}

.container {
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 24px;
}

/* Hero ------------------------------------------------------------------ */

.hero {
  position: relative;
  padding: 72px 0 32px;
}

@media (min-width: 960px) {
  .hero {
    margin-top: calc(var(--vp-nav-height) * -1);
    padding-top: calc(var(--vp-nav-height) + 96px);
  }
}

.hero-bg {
  position: absolute;
  inset: 0;
  pointer-events: none;
}

.grid {
  position: absolute;
  inset: 0;
  background-image: linear-gradient(var(--s-grid) 1px, transparent 1px),
    linear-gradient(90deg, var(--s-grid) 1px, transparent 1px);
  background-size: 56px 56px;
  mask-image: radial-gradient(ellipse 75% 55% at 50% 0%, #000 30%, transparent 100%);
  -webkit-mask-image: radial-gradient(ellipse 75% 55% at 50% 0%, #000 30%, transparent 100%);
}

.orb {
  position: absolute;
  border-radius: 50%;
  filter: blur(90px);
  opacity: var(--s-orb-opacity);
  animation: drift 22s ease-in-out infinite alternate;
}

.orb-a {
  top: -120px;
  left: 8%;
  width: 520px;
  height: 520px;
  background: #22d3ee;
}

.orb-b {
  top: -60px;
  right: 6%;
  width: 460px;
  height: 460px;
  background: #6366f1;
  animation-delay: -7s;
}

.orb-c {
  top: 320px;
  left: 40%;
  width: 380px;
  height: 380px;
  background: #3b82f6;
  animation-delay: -14s;
}

@keyframes drift {
  0% {
    transform: translate(0, 0) scale(1);
  }
  50% {
    transform: translate(40px, 30px) scale(1.08);
  }
  100% {
    transform: translate(-30px, 10px) scale(0.95);
  }
}

.beam {
  position: absolute;
  top: 0;
  left: -30%;
  width: 30%;
  height: 1px;
  background: linear-gradient(90deg, transparent, #22d3ee, transparent);
  animation: beam 7s linear infinite;
}

@media (min-width: 960px) {
  .beam {
    top: var(--vp-nav-height);
  }
}

@keyframes beam {
  to {
    left: 130%;
  }
}

.hero-inner {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}

.hero-inner > * {
  animation: rise 0.9s cubic-bezier(0.2, 0.7, 0.2, 1) both;
}

.hero-inner > :nth-child(2) {
  animation-delay: 0.08s;
}

.hero-inner > :nth-child(3) {
  animation-delay: 0.16s;
}

.hero-inner > :nth-child(4) {
  animation-delay: 0.24s;
}

.hero-inner > :nth-child(5) {
  animation-delay: 0.32s;
}

@keyframes rise {
  from {
    opacity: 0;
    transform: translateY(18px);
  }
  to {
    opacity: 1;
    transform: none;
  }
}

.pill {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 28px;
  padding: 5px 14px 5px 5px;
  border: 1px solid var(--s-border);
  border-radius: 999px;
  background: var(--s-surface);
  backdrop-filter: blur(8px);
  color: var(--vp-c-text-2);
  font-size: 13px;
  font-weight: 500;
  transition: border-color 0.25s, color 0.25s;
}

.pill:hover {
  border-color: var(--vp-c-brand-1);
  color: var(--vp-c-text-1);
}

.pill-tag {
  padding: 3px 10px;
  border-radius: 999px;
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand-1);
  font-weight: 600;
}

.pill-arrow {
  transition: transform 0.25s;
}

.pill:hover .pill-arrow {
  transform: translateX(3px);
}

.headline {
  margin: 0;
  max-width: 900px;
  color: var(--vp-c-text-1);
  font-size: clamp(40px, 7vw, 76px);
  font-weight: 700;
  line-height: 1.04;
  letter-spacing: -0.035em;
}

.grad {
  background: linear-gradient(90deg, #22d3ee, #3b82f6 35%, #818cf8 60%, #22d3ee);
  background-size: 250% 100%;
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  animation: shimmer 9s linear infinite;
}

:root:not(.dark) .grad {
  background-image: linear-gradient(90deg, #0891b2, #2563eb 35%, #4f46e5 60%, #0891b2);
}

@keyframes shimmer {
  to {
    background-position: -250% 0;
  }
}

.lede {
  max-width: 680px;
  margin: 24px 0 0;
  color: var(--vp-c-text-2);
  font-size: clamp(16px, 2vw, 19px);
  line-height: 1.6;
}

.ctas {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 12px;
  margin: 32px 0 24px;
}

.btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 11px 20px;
  border-radius: 10px;
  font-size: 15px;
  font-weight: 600;
  text-decoration: none;
  transition: transform 0.2s, box-shadow 0.25s, background-color 0.25s, border-color 0.25s, color 0.25s;
}

.btn:hover {
  transform: translateY(-1px);
}

.btn.primary {
  background: var(--vp-button-brand-bg);
  color: var(--vp-button-brand-text);
  box-shadow: 0 10px 30px -10px rgba(34, 211, 238, 0.6);
}

.btn.primary:hover {
  background: var(--vp-button-brand-hover-bg);
  box-shadow: 0 14px 36px -10px rgba(34, 211, 238, 0.75);
}

.btn.ghost {
  border: 1px solid var(--s-border);
  background: var(--s-surface);
  color: var(--vp-c-text-1);
}

.btn.ghost:hover {
  border-color: var(--vp-c-brand-1);
}

.hero-visual {
  position: relative;
  margin-top: 56px;
  animation: rise 1.1s cubic-bezier(0.2, 0.7, 0.2, 1) 0.35s both;
}

/* Facts ----------------------------------------------------------------- */

.facts {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 12px 28px;
  padding-top: 40px;
  padding-bottom: 8px;
  color: var(--vp-c-text-2);
  font-size: 14px;
  font-weight: 500;
}

.fact {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.fact svg {
  color: var(--vp-c-brand-1);
}

/* Sections -------------------------------------------------------------- */

.section {
  padding-top: 112px;
}

.section-head {
  max-width: 720px;
  margin: 0 auto 48px;
  text-align: center;
}

.eyebrow {
  margin: 0 0 12px;
  color: var(--vp-c-brand-1);
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}

.eyebrow.warn {
  color: #e11d48;
}

.dark .eyebrow.warn {
  color: #fb7185;
}

h2 {
  margin: 0;
  color: var(--vp-c-text-1);
  font-size: clamp(28px, 4vw, 44px);
  font-weight: 700;
  line-height: 1.12;
  letter-spacing: -0.025em;
}

.section-head p,
.copy p {
  margin: 16px 0 0;
  color: var(--vp-c-text-2);
  font-size: 17px;
  line-height: 1.65;
}

.copy strong {
  color: var(--vp-c-text-1);
}

.copy code {
  font-size: 14px;
}

.split {
  display: grid;
  gap: 48px;
  align-items: center;
}

@media (min-width: 960px) {
  .split {
    grid-template-columns: 1fr 1fr;
    gap: 64px;
  }

  .split.reverse > :first-child {
    order: 2;
  }
}

.text-link {
  display: inline-block;
  margin-top: 20px;
  color: var(--vp-c-brand-1);
  font-weight: 600;
  text-decoration: none;
}

.text-link:hover {
  text-decoration: underline;
}

.checks {
  display: grid;
  gap: 10px;
  margin: 20px 0 0;
  padding: 0;
  list-style: none;
}

.checks li {
  position: relative;
  padding-left: 28px;
  color: var(--vp-c-text-1);
  font-size: 15px;
}

.checks li::before {
  content: '';
  position: absolute;
  top: 3px;
  left: 0;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: var(--vp-c-brand-soft)
    url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2322d3ee' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 12l4 4 8-8'/%3E%3C/svg%3E")
    center / 12px no-repeat;
}

/* Stages ---------------------------------------------------------------- */

.stages {
  position: relative;
  display: grid;
  gap: 16px;
}

@media (min-width: 768px) {
  .stages {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (min-width: 1100px) {
  .stages {
    grid-template-columns: repeat(4, 1fr);
  }
}

.stages-line {
  display: none;
}

@media (min-width: 1100px) {
  .stages-line {
    display: block;
    position: absolute;
    top: 47px;
    left: 12%;
    right: 12%;
    height: 2px;
    background: linear-gradient(90deg, transparent, rgba(34, 211, 238, 0.9), transparent) 0 0 / 30% 100% no-repeat,
      var(--s-border);
    animation: travel 4s linear infinite;
  }
}

@keyframes travel {
  from {
    background-position: -30% 0, 0 0;
  }
  to {
    background-position: 130% 0, 0 0;
  }
}

.stage {
  position: relative;
  padding: 24px;
  border: 1px solid var(--s-border);
  border-radius: 16px;
  background: var(--s-surface-solid);
}

.stage-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 48px;
  height: 48px;
  border: 1px solid var(--s-border);
  border-radius: 12px;
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand-1);
}

.stage-num {
  margin: 18px 0 2px;
  color: var(--vp-c-text-3);
  font-family: var(--vp-font-family-mono);
  font-size: 12px;
}

.stage h3,
.card h3,
.honest h3 {
  margin: 0;
  color: var(--vp-c-text-1);
  font-size: 18px;
  font-weight: 600;
  letter-spacing: -0.01em;
}

.stage p:last-child,
.card > p {
  margin: 8px 0 0;
  color: var(--vp-c-text-2);
  font-size: 14.5px;
  line-height: 1.6;
}

/* Bento ----------------------------------------------------------------- */

.bento {
  display: grid;
  gap: 16px;
}

@media (min-width: 960px) {
  .bento {
    grid-template-columns: repeat(3, 1fr);
  }

  .card.wide {
    grid-column: span 2;
  }
}

.card {
  --mx: 50%;
  --my: 0%;
  position: relative;
  overflow: hidden;
  padding: 26px;
  border: 1px solid var(--s-border);
  border-radius: 18px;
  background: var(--s-surface-solid);
  transition: border-color 0.3s, transform 0.3s;
}

.card::before {
  content: '';
  position: absolute;
  inset: 0;
  background: radial-gradient(420px circle at var(--mx) var(--my), rgba(34, 211, 238, 0.12), transparent 45%);
  opacity: 0;
  transition: opacity 0.3s;
  pointer-events: none;
}

.card:hover {
  border-color: rgba(34, 211, 238, 0.45);
  transform: translateY(-2px);
}

.card:hover::before {
  opacity: 1;
}

.lineage {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin-top: 26px;
}

.node {
  display: inline-flex;
  flex-direction: column;
  gap: 2px;
  padding: 10px 12px;
  border: 1px solid var(--s-border);
  border-radius: 12px;
  background: var(--s-surface);
  color: var(--vp-c-text-2);
  font-size: 12.5px;
  animation: pulse-node 6s ease-in-out infinite;
}

.node b {
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 11.5px;
  letter-spacing: 0.02em;
}

.node.taint b {
  color: #d97706;
}

.dark .node.taint b {
  color: #fbbf24;
}

.node.deny b {
  color: #e11d48;
}

.dark .node.deny b {
  color: #fb7185;
}

.n2 {
  animation-delay: 1.2s;
}

.n3 {
  animation-delay: 2.4s;
}

.n4 {
  animation-name: pulse-deny;
  animation-delay: 3.6s;
}

@keyframes pulse-node {
  0%,
  100% {
    border-color: var(--s-border);
    box-shadow: none;
  }
  10% {
    border-color: rgba(34, 211, 238, 0.7);
    box-shadow: 0 0 0 4px rgba(34, 211, 238, 0.12);
  }
  25% {
    border-color: var(--s-border);
    box-shadow: none;
  }
}

@keyframes pulse-deny {
  0%,
  100% {
    border-color: var(--s-border);
    box-shadow: none;
  }
  10% {
    border-color: rgba(244, 63, 94, 0.8);
    box-shadow: 0 0 0 4px rgba(244, 63, 94, 0.15);
  }
  35% {
    border-color: rgba(244, 63, 94, 0.5);
  }
}

.edge {
  width: 18px;
  height: 2px;
  border-radius: 2px;
  background: var(--s-border);
}

.mini-code {
  margin: 20px 0 0;
  padding: 14px 16px;
  overflow-x: auto;
  border: 1px solid #1a2740;
  border-radius: 12px;
  background: #070c16;
  color: #cbd5e1;
  font-family: var(--vp-font-family-mono);
  font-size: 12.5px;
  line-height: 1.7;
}

.y-key {
  color: #7dd3fc;
}

.y-str {
  color: #fda4af;
}

.mini-list {
  display: grid;
  gap: 8px;
  margin: 18px 0 0;
  padding: 0;
  list-style: none;
  color: var(--vp-c-text-2);
  font-size: 14px;
}

.mini-list li {
  padding: 8px 12px;
  border: 1px solid var(--s-border);
  border-radius: 10px;
  background: var(--s-surface);
}

.mini-list b {
  color: var(--vp-c-text-1);
  font-weight: 600;
}

.spans {
  display: grid;
  gap: 8px;
  margin: 18px 0 0;
  padding: 0;
  list-style: none;
  font-family: var(--vp-font-family-mono);
  font-size: 12.5px;
  color: var(--vp-c-text-2);
}

.spans li {
  padding: 8px 12px;
  border: 1px solid var(--s-border);
  border-left: 3px solid #10b981;
  border-radius: 10px;
  background: var(--s-surface);
}

.spans li.bad {
  border-left-color: #f43f5e;
}

.ev {
  margin-right: 6px;
  color: var(--vp-c-text-1);
  font-weight: 600;
}

/* Limits ---------------------------------------------------------------- */

.honest {
  display: grid;
  gap: 28px;
  padding: 32px;
  border: 1px solid rgba(244, 63, 94, 0.35);
  border-radius: 20px;
  background: linear-gradient(135deg, rgba(244, 63, 94, 0.07), transparent 55%), var(--s-surface-solid);
}

@media (min-width: 960px) {
  .honest {
    grid-template-columns: 1.1fr 1fr;
    align-items: center;
    padding: 40px;
  }
}

.honest-copy p:not(.eyebrow) {
  margin: 10px 0 22px;
  color: var(--vp-c-text-2);
  font-size: 15.5px;
  line-height: 1.6;
}

.honest h3 {
  font-size: 24px;
}

.honest-list {
  display: grid;
  gap: 10px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.honest-list li {
  padding: 12px 16px;
  border: 1px solid var(--s-border);
  border-radius: 12px;
  background: var(--s-surface);
  color: var(--vp-c-text-1);
  font-size: 15px;
}

/* CTA ------------------------------------------------------------------- */

.cta {
  position: relative;
  margin-top: 120px;
  padding: 96px 0 40px;
  border-top: 1px solid var(--s-border);
  text-align: center;
}

.cta-glow {
  position: absolute;
  top: -1px;
  left: 50%;
  width: min(900px, 90vw);
  height: 360px;
  transform: translateX(-50%);
  background: radial-gradient(ellipse at 50% 0%, rgba(34, 211, 238, 0.22), transparent 70%);
  pointer-events: none;
}

.cta-inner {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
}

.cta-inner p {
  margin: 16px 0 28px;
  color: var(--vp-c-text-2);
  font-size: 17px;
}

/* Reduced motion ---------------------------------------------------------- */

@media (prefers-reduced-motion: reduce) {
  .orb,
  .beam,
  .grad,
  .stages-line,
  .node,
  .hero-inner > *,
  .hero-visual {
    animation: none !important;
  }
}
</style>
