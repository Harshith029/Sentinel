<script setup lang="ts">
import { ref } from 'vue'

const props = defineProps<{ command: string }>()
const copied = ref(false)
let timer: ReturnType<typeof setTimeout> | undefined

async function copy() {
  try {
    await navigator.clipboard.writeText(props.command)
    copied.value = true
    clearTimeout(timer)
    timer = setTimeout(() => (copied.value = false), 1800)
  } catch {
    // Clipboard access can be refused; the command stays selectable.
  }
}
</script>

<template>
  <div class="copy-command">
    <span class="prompt" aria-hidden="true">$</span>
    <code>{{ command }}</code>
    <button type="button" :aria-label="copied ? 'Copied' : 'Copy command'" @click="copy">
      <svg v-if="!copied" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" /></svg>
      <svg v-else viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12l5 5L20 7" /></svg>
      <span class="label">{{ copied ? 'Copied' : 'Copy' }}</span>
    </button>
  </div>
</template>

<style scoped>
.copy-command {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  max-width: 100%;
  padding: 8px 8px 8px 16px;
  border: 1px solid var(--s-border);
  border-radius: 12px;
  background: var(--s-surface);
  backdrop-filter: blur(8px);
  font-family: var(--vp-font-family-mono);
  font-size: 14px;
}

.prompt {
  color: var(--vp-c-brand-1);
  user-select: none;
}

code {
  overflow-x: auto;
  white-space: nowrap;
  color: var(--vp-c-text-1);
  background: none;
  padding: 0;
  font-size: 14px;
}

button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
  padding: 6px 10px;
  border-radius: 8px;
  color: var(--vp-c-text-2);
  font-family: var(--vp-font-family-base);
  font-size: 13px;
  font-weight: 500;
  transition: color 0.2s, background-color 0.2s;
}

button:hover {
  color: var(--vp-c-text-1);
  background: var(--vp-c-default-soft);
}

@media (max-width: 480px) {
  .label {
    display: none;
  }
}
</style>
