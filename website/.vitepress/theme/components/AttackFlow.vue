<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { withBase } from 'vitepress'

// The steps of assets/flow.svg, which loops every 12 seconds. The windows
// match the captions' keyframes in that file, so the list follows the picture.
const LOOP_MS = 12_000
const steps = [
  { tool: 'get_customer_record', verdict: 'allow', text: 'Allowed. The records service is marked trusted, so nothing is tainted yet.', from: 0.03, to: 0.21 },
  { tool: 'web_fetch', verdict: 'allow', text: 'Allowed, but the page it returns is labelled RETRIEVED_CONTENT.', from: 0.21, to: 0.57 },
  { tool: 'send_email', verdict: 'block', text: 'Refused before it runs: its lineage includes the page, whatever the page said.', from: 0.57, to: 0.93 },
]

const run = ref(0)
const active = ref(-1)
const reduced = ref(false)
let started = 0
let frame = 0

function tick() {
  const phase = ((performance.now() - started) % LOOP_MS) / LOOP_MS
  active.value = steps.findIndex((s) => phase >= s.from && phase < s.to)
  frame = requestAnimationFrame(tick)
}

function onLoad() {
  if (reduced.value) {
    active.value = steps.length - 1
    return
  }
  cancelAnimationFrame(frame)
  started = performance.now()
  frame = requestAnimationFrame(tick)
}

function replay() {
  run.value += 1
}

onMounted(() => {
  reduced.value = window.matchMedia('(prefers-reduced-motion: reduce)').matches
})

onBeforeUnmount(() => cancelAnimationFrame(frame))
</script>

<template>
  <div class="attack-flow">
    <div class="window">
      <div class="bar">
        <span class="dot" /><span class="dot" /><span class="dot" />
        <span class="title">sentinel serve</span>
        <button v-if="!reduced" type="button" class="replay" @click="replay">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7" /><path d="M3 3v6h6" /></svg>
          Replay
        </button>
      </div>
      <img
        :key="run"
        :src="withBase(`/flow.svg?run=${run}`)"
        width="1200"
        height="440"
        alt="An AI agent reaches its tools only through SENTINEL. Looking up a record and fetching a page are allowed; emailing the record afterwards is refused, because its lineage includes the page."
        @load="onLoad"
      />
    </div>
    <ol class="steps">
      <li v-for="(step, i) in steps" :key="step.tool" :class="{ on: active === i, block: step.verdict === 'block' }">
        <span class="num">{{ i + 1 }}</span>
        <div>
          <p class="head">
            <code>{{ step.tool }}</code>
            <span class="verdict">{{ step.verdict === 'block' ? 'BLOCK' : 'ALLOW' }}</span>
          </p>
          <p class="text">{{ step.text }}</p>
        </div>
      </li>
    </ol>
  </div>
</template>

<style scoped>
.attack-flow {
  display: grid;
  gap: 24px;
  align-items: center;
}

@media (min-width: 1100px) {
  .attack-flow {
    grid-template-columns: minmax(0, 1fr) 320px;
  }
}

.window {
  position: relative;
  border-radius: 16px;
  padding: 1px;
  background: linear-gradient(140deg, rgba(34, 211, 238, 0.7), rgba(99, 102, 241, 0.35) 40%, rgba(30, 41, 59, 0.6) 70%, rgba(244, 63, 94, 0.5));
  box-shadow: 0 30px 80px -30px rgba(34, 211, 238, 0.35), 0 0 0 1px rgba(255, 255, 255, 0.02);
}

.bar {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 10px 14px;
  border-radius: 15px 15px 0 0;
  background: #0a111e;
  border-bottom: 1px solid #1a2740;
}

.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #1f2b40;
}

.title {
  margin-left: 8px;
  color: #64748b;
  font-family: var(--vp-font-family-mono);
  font-size: 12px;
}

.replay {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-left: auto;
  padding: 4px 10px;
  border: 1px solid #1f2b40;
  border-radius: 999px;
  color: #94a3b8;
  font-size: 12px;
  transition: color 0.2s, border-color 0.2s;
}

.replay:hover {
  color: #e2e8f0;
  border-color: #22d3ee;
}

img {
  display: block;
  width: 100%;
  height: auto;
  border-radius: 0 0 15px 15px;
}

.steps {
  display: grid;
  gap: 12px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.steps li {
  display: flex;
  gap: 14px;
  padding: 14px 16px;
  border: 1px solid var(--s-border);
  border-radius: 12px;
  background: var(--s-surface);
  opacity: 0.55;
  transition: opacity 0.35s, border-color 0.35s, transform 0.35s, box-shadow 0.35s;
}

.steps li.on {
  opacity: 1;
  border-color: rgba(52, 211, 153, 0.6);
  transform: translateX(4px);
  box-shadow: 0 10px 30px -18px rgba(52, 211, 153, 0.6);
}

.steps li.block.on {
  border-color: rgba(244, 63, 94, 0.7);
  box-shadow: 0 10px 30px -14px rgba(244, 63, 94, 0.7);
}

.num {
  display: inline-flex;
  flex-shrink: 0;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  border-radius: 50%;
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand-1);
  font-size: 13px;
  font-weight: 700;
}

.head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin: 0 0 4px;
}

.head code {
  font-size: 13px;
  color: var(--vp-c-text-1);
}

.verdict {
  padding: 1px 8px;
  border-radius: 999px;
  font-family: var(--vp-font-family-mono);
  font-size: 11px;
  font-weight: 700;
  color: #059669;
  background: rgba(16, 185, 129, 0.14);
}

.dark .verdict {
  color: #34d399;
}

.block .verdict {
  color: #e11d48;
  background: rgba(244, 63, 94, 0.14);
}

.dark .block .verdict {
  color: #fb7185;
}

.text {
  margin: 0;
  color: var(--vp-c-text-2);
  font-size: 14px;
  line-height: 1.5;
}
</style>
