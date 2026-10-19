import type { Directive } from 'vue'

// v-reveal: fades an element up the first time it scrolls into view.
//
// Elements already on screen when the page loads are left alone, so nothing
// rendered on the server flashes out and back in. With reduced motion, or
// without IntersectionObserver, everything simply stays visible.
export const reveal: Directive<HTMLElement, number | undefined> = {
  mounted(el, binding) {
    if (
      typeof window === 'undefined' ||
      !('IntersectionObserver' in window) ||
      window.matchMedia('(prefers-reduced-motion: reduce)').matches
    ) {
      return
    }
    const rect = el.getBoundingClientRect()
    if (rect.top < window.innerHeight && rect.bottom > 0) return

    const delay = binding.value ?? 0
    el.classList.add('reveal-pending')
    if (delay) el.style.transitionDelay = `${delay}ms`
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          el.classList.add('reveal-in')
          observer.disconnect()
          // Hand the element back to its own styles (hover transitions and
          // so on) once the reveal has finished.
          setTimeout(() => {
            el.classList.remove('reveal-pending', 'reveal-in')
            el.style.transitionDelay = ''
          }, delay + 900)
        }
      },
      { rootMargin: '0px 0px -10% 0px' },
    )
    observer.observe(el)
  },
}
