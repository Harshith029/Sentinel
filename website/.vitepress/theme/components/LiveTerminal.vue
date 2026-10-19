<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'

// The decision log from the docs, typed out when the terminal scrolls into view.
const command = 'sentinel serve'
const lines = [
  { time: '23:16:40', level: 'INFO', verdict: 'ALLOW', tool: 'get_customer_record', rest: '', trace: '2ad33998e093' },
  { time: '23:16:40', level: 'INFO', verdict: 'ALLOW', tool: 'web_fetch', rest: '', trace: '2ad33998e093' },
  { time: '23:16:40', level: 'WARNING', verdict: 'BLOCK', tool: 'send_email', rest: 'rule=block-untrusted-origin', trace: '2ad33998e093' },
]

const root = ref<HTMLElement>()
const typed = ref('')
const shown = ref(0)
const done = ref(false)
let timers: ReturnType<typeof setTimeout>[] = []
let observer: IntersectionObserver | undefined

function clear() {
  timers.forEach(clearTimeout)
  timers = []
}

function finish() {
  clear()
  typed.value = command
  shown.value = lines.length
  done.value = true
}

function play() {
  clear()
  typed.value = ''
  shown.value = 0
  done.value = false
  let t = 300
  for (let i = 1; i <= command.length; i++) {
    timers.push(setTimeout(() => (typed.value = command.slice(0, i)), t))
    t += 55
  }
  t += 500
  lines.forEach((_, i) => {
    timers.push(setTimeout(() => (shown.value = i + 1), t))
    t += i === lines.length - 2 ? 900 : 650
  })
  timers.push(setTimeout(() => (done.value = true), t))
}

onMounted(() => {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || !('IntersectionObserver' in window)) {
    finish()
    return
  }
  observer = new IntersectionObserver(
    (entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        play()
        observer?.disconnect()
      }
    },
    { threshold: 0.4 },
  )
  if (root.value) observer.observe(root.value)
})

onBeforeUnmount(() => {
  clear()
  observer?.disconnect()
})
</script>

<template>
  <div ref="root" class="terminal" role="img" aria-label="SENTINEL's log: get_customer_record allowed, web_fetch allowed, send_email blocked by rule block-untrusted-origin">
    <div class="bar">
      <span class="dot" /><span class="dot" /><span class="dot" />
      <span class="title">terminal</span>
      <button v-if="done" type="button" class="replay" @click="play">Replay</button>
    </div>
    <pre aria-hidden="true"><span class="ps">$</span> {{ typed }}<span v-if="shown === 0" class="caret" />
<template v-for="(line, i) in lines" :key="i"><span v-if="i < shown" class="line" :class="{ block: line.verdict === 'BLOCK' }"><span class="time">{{ line.time }}</span> <span class="lvl" :class="line.level.toLowerCase()">{{ line.level.padEnd(7) }}</span> <span class="verdict">{{ line.verdict }}</span>  <span class="tool">{{ line.tool }}</span><template v-if="line.rest">  <span class="rule">{{ line.rest }}</span></template>  <span class="trace">[trace {{ line.trace }}]</span>
</span></template><span v-if="shown > 0 && !done" class="caret" /></pre>
  </div>
</template>

<style scoped>
.terminal {
  overflow: hidden;
  border: 1px solid #1a2740;
  border-radius: 16px;
  background: #070c16;
  box-shadow: 0 30px 60px -30px rgba(0, 0, 0, 0.6);
}

.bar {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 10px 14px;
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
  margin-left: auto;
  padding: 3px 10px;
  border: 1px solid #1f2b40;
  border-radius: 999px;
  color: #94a3b8;
  font-size: 12px;
}

.replay:hover {
  color: #e2e8f0;
  border-color: #22d3ee;
}

pre {
  margin: 0;
  min-height: 150px;
  padding: 18px 20px 20px;
  overflow-x: auto;
  color: #cbd5e1;
  font-family: var(--vp-font-family-mono);
  font-size: 13px;
  line-height: 1.9;
}

.ps {
  color: #22d3ee;
}

.line {
  display: inline;
  animation: line-in 0.35s ease-out both;
}

.line.block {
  animation: line-in 0.35s ease-out both, flash 1.6s ease-out 0.2s both;
}

.time,
.trace {
  color: #475569;
}

.lvl.info {
  color: #60a5fa;
}

.lvl.warning {
  color: #fbbf24;
}

.verdict {
  color: #34d399;
  font-weight: 700;
}

.block .verdict,
.block .tool {
  color: #fb7185;
}

.tool {
  color: #e2e8f0;
}

.rule {
  color: #fda4af;
}

.caret {
  display: inline-block;
  width: 8px;
  height: 15px;
  margin-left: 2px;
  vertical-align: -2px;
  background: #22d3ee;
  animation: blink 1s steps(2, start) infinite;
}

@keyframes blink {
  to {
    visibility: hidden;
  }
}

@keyframes line-in {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}

@keyframes flash {
  0% {
    background: rgba(244, 63, 94, 0.35);
  }
  100% {
    background: rgba(244, 63, 94, 0);
  }
}

@media (prefers-reduced-motion: reduce) {
  .line,
  .line.block,
  .caret {
    animation: none;
  }
}
</style>
