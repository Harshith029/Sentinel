<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'

// The demo's synthetic record: the SSN and key are labelled fakes.
const protectedView = ref(true)
const touched = ref(false)
const root = ref<HTMLElement>()
let timer: ReturnType<typeof setInterval> | undefined
let observer: IntersectionObserver | undefined

function choose(value: boolean) {
  touched.value = true
  stop()
  protectedView.value = value
}

function start() {
  if (touched.value || timer) return
  timer = setInterval(() => (protectedView.value = !protectedView.value), 3800)
}

function stop() {
  clearInterval(timer)
  timer = undefined
}

onMounted(() => {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || !('IntersectionObserver' in window)) return
  protectedView.value = false
  observer = new IntersectionObserver((entries) => {
    entries.some((e) => e.isIntersecting) ? start() : stop()
  })
  if (root.value) observer.observe(root.value)
})

onBeforeUnmount(() => {
  stop()
  observer?.disconnect()
})
</script>

<template>
  <div ref="root" class="compare">
    <div class="toggle" role="tablist" aria-label="Compare the outbox">
      <button type="button" role="tab" :aria-selected="!protectedView" :class="{ on: !protectedView }" @click="choose(false)">Without SENTINEL</button>
      <button type="button" role="tab" :aria-selected="protectedView" :class="{ on: protectedView, safe: true }" @click="choose(true)">With SENTINEL</button>
      <span class="thumb" :class="{ right: protectedView }" aria-hidden="true" />
    </div>

    <div class="panel" :class="protectedView ? 'is-safe' : 'is-leak'">
      <div class="panel-head">
        <span class="label">Outbox</span>
        <span class="count">{{ protectedView ? '0 messages' : '1 message' }}</span>
      </div>
      <Transition name="swap" mode="out-in">
        <div v-if="!protectedView" key="leak" class="mail">
          <div class="row"><span class="k">To</span><span class="v bad">attacker@evil-corp.io</span></div>
          <div class="row"><span class="k">Subject</span><span class="v">Account profile</span></div>
          <div class="body">
            As requested in the page note:
            <code>{"name": "Jordan Rivera (...)", "ssn": "<mark>000-00-0000</mark>", "api_key": "<mark>sk-synthetic-DO-NOT-USE-0000</mark>"}</code>
          </div>
          <p class="foot bad">With nothing judging the action, the record reaches the attacker.</p>
        </div>
        <div v-else key="safe" class="refusal">
          <div class="badge">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z" /><path d="M9.5 9.5l5 5M14.5 9.5l-5 5" /></svg>
            send_email refused
          </div>
          <dl>
            <div><dt>rule</dt><dd><code>block-untrusted-origin</code></dd></div>
            <div><dt>why</dt><dd>the action's lineage includes <code>RETRIEVED_CONTENT</code></dd></div>
            <div><dt>record</dt><dd>an immutable span, ready to replay or export</dd></div>
          </dl>
          <p class="foot good">Nothing was sent. The agent got a tool error, and the attack is on record.</p>
        </div>
      </Transition>
    </div>
    <p class="note">The bundled demo's data. The record is a labelled fake.</p>
  </div>
</template>

<style scoped>
.compare {
  width: 100%;
}

.toggle {
  position: relative;
  display: inline-grid;
  grid-template-columns: 1fr 1fr;
  margin-bottom: 16px;
  padding: 4px;
  border: 1px solid var(--s-border);
  border-radius: 999px;
  background: var(--s-surface);
}

.toggle button {
  position: relative;
  z-index: 1;
  padding: 8px 16px;
  border-radius: 999px;
  color: var(--vp-c-text-2);
  font-size: 14px;
  font-weight: 600;
  transition: color 0.3s;
}

.toggle button.on {
  color: #fff;
}

.thumb {
  position: absolute;
  top: 4px;
  bottom: 4px;
  left: 4px;
  width: calc(50% - 4px);
  border-radius: 999px;
  background: linear-gradient(135deg, #e11d48, #f43f5e);
  box-shadow: 0 6px 20px -6px rgba(244, 63, 94, 0.7);
  transition: transform 0.45s cubic-bezier(0.65, 0, 0.35, 1), background 0.45s;
}

.thumb.right {
  transform: translateX(100%);
  background: linear-gradient(135deg, #0891b2, #22d3ee);
  box-shadow: 0 6px 20px -6px rgba(34, 211, 238, 0.7);
}

.panel {
  min-height: 268px;
  padding: 18px 20px;
  border: 1px solid var(--s-border);
  border-radius: 16px;
  background: var(--s-surface);
  transition: border-color 0.45s, box-shadow 0.45s;
}

.panel.is-leak {
  border-color: rgba(244, 63, 94, 0.55);
  box-shadow: 0 20px 50px -30px rgba(244, 63, 94, 0.8);
}

.panel.is-safe {
  border-color: rgba(34, 211, 238, 0.5);
  box-shadow: 0 20px 50px -30px rgba(34, 211, 238, 0.8);
}

.panel-head {
  display: flex;
  justify-content: space-between;
  margin-bottom: 14px;
  color: var(--vp-c-text-3);
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

.row {
  display: flex;
  gap: 12px;
  padding: 6px 0;
  border-bottom: 1px solid var(--s-border);
  font-size: 14px;
}

.k {
  width: 64px;
  flex-shrink: 0;
  color: var(--vp-c-text-3);
}

.v {
  color: var(--vp-c-text-1);
}

.bad {
  color: #e11d48;
}

.dark .bad {
  color: #fb7185;
}

.good {
  color: #0e7490;
}

.dark .good {
  color: #67e8f9;
}

.body {
  margin-top: 12px;
  color: var(--vp-c-text-2);
  font-size: 14px;
  line-height: 1.6;
}

.body code {
  display: block;
  margin-top: 6px;
  padding: 10px 12px;
  border-radius: 8px;
  word-break: break-all;
  white-space: normal;
  font-size: 12.5px;
}

mark {
  border-radius: 4px;
  padding: 0 3px;
  color: inherit;
  background: rgba(244, 63, 94, 0.25);
}

.badge {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  border-radius: 999px;
  color: #e11d48;
  background: rgba(244, 63, 94, 0.12);
  font-family: var(--vp-font-family-mono);
  font-size: 14px;
  font-weight: 700;
}

.dark .badge {
  color: #fb7185;
}

dl {
  display: grid;
  gap: 8px;
  margin: 16px 0 0;
}

dl div {
  display: flex;
  gap: 12px;
  font-size: 14px;
}

dt {
  width: 64px;
  flex-shrink: 0;
  color: var(--vp-c-text-3);
}

dd {
  margin: 0;
  color: var(--vp-c-text-1);
}

.foot {
  margin: 16px 0 0;
  font-size: 14px;
  font-weight: 500;
}

.note {
  margin: 10px 0 0;
  color: var(--vp-c-text-3);
  font-size: 12px;
}

.swap-enter-active,
.swap-leave-active {
  transition: opacity 0.3s, transform 0.3s;
}

.swap-enter-from {
  opacity: 0;
  transform: translateY(8px);
}

.swap-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}

@media (prefers-reduced-motion: reduce) {
  .thumb,
  .swap-enter-active,
  .swap-leave-active {
    transition: none;
  }
}
</style>
