import { defineConfig } from 'vitepress'

const repo = 'https://github.com/Harshith029/Sentinel'

// Served by GitHub Pages as a project site, so every URL lives under /Sentinel/.
export default defineConfig({
  title: 'SENTINEL',
  description:
    'Provenance-aware security proxy for AI agents: block prompt-injection actions at the MCP tool boundary.',
  lang: 'en-US',
  base: '/Sentinel/',
  cleanUrls: true,
  lastUpdated: true,
  appearance: 'dark',
  // Internal links are checked at build time; only links to a local
  // SENTINEL (http://localhost:8765) are exempt.
  ignoreDeadLinks: 'localhostLinks',

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/Sentinel/logo.svg' }],
    ['meta', { name: 'theme-color', content: '#0B1220' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'SENTINEL — stop prompt injection at the action layer' }],
    [
      'meta',
      {
        property: 'og:description',
        content:
          'An MCP proxy that tracks where every tool result came from and refuses guarded actions whose lineage includes untrusted content.',
      },
    ],
    ['meta', { property: 'og:image', content: 'https://harshith029.github.io/Sentinel/banner.png' }],
  ],

  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'SENTINEL',

    nav: [
      { text: 'Guide', link: '/guide/introduction', activeMatch: '/guide/' },
      { text: 'Policy', link: '/guide/policy' },
      { text: 'FAQ', link: '/faq' },
      {
        text: '0.2.x',
        items: [
          { text: 'Changelog', link: `${repo}/blob/main/CHANGELOG.md` },
          { text: 'PyPI', link: 'https://pypi.org/project/sentinel-prox/' },
          { text: 'Contributing', link: `${repo}/blob/main/CONTRIBUTING.md` },
          { text: 'Security policy', link: `${repo}/blob/main/SECURITY.md` },
        ],
      },
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'What is SENTINEL?', link: '/guide/introduction' },
          { text: 'Quick start', link: '/guide/quick-start' },
          { text: 'How it works', link: '/guide/how-it-works' },
          { text: 'Try the demo', link: '/guide/demo' },
        ],
      },
      {
        text: 'Using SENTINEL',
        items: [
          { text: 'Writing policy', link: '/guide/policy' },
          { text: 'Configuration', link: '/guide/configuration' },
          { text: 'Authentication', link: '/guide/authentication' },
          { text: 'Logs and forensics', link: '/guide/forensics' },
        ],
      },
      {
        text: 'Operating',
        items: [
          { text: 'Deployment', link: '/guide/deployment' },
          { text: 'Resource limits', link: '/guide/limits' },
          { text: 'Free and paid backends', link: '/guide/backends' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Status and limitations', link: '/guide/limitations' },
          { text: 'FAQ', link: '/faq' },
        ],
      },
    ],

    socialLinks: [{ icon: 'github', link: repo }],

    editLink: {
      pattern: `${repo}/edit/main/website/:path`,
      text: 'Edit this page on GitHub',
    },

    search: { provider: 'local' },

    outline: { level: [2, 3] },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026 Pali Krishna Harshith',
    },
  },
})
