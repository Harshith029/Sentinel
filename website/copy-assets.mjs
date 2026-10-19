// Copies the repository's images (assets/) into the site's public/ folder, so
// the README and the site share one copy of each image. Runs before every dev
// server start and build; public/ is git-ignored.
import { cpSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const target = join(here, 'public')
mkdirSync(target, { recursive: true })
cpSync(join(here, '..', 'assets'), target, { recursive: true })
