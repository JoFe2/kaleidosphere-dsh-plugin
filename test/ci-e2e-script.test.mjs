import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const scripts = [
  'scripts/test-dsh-rc8.sh',
  'scripts/test-dsh-agent-rc8.sh',
]

test('rc.8 E2E scripts use the pinned root dependency and bounded process waits', async () => {
  for (const path of scripts) {
    const source = await readFile(new URL(`../${path}`, import.meta.url), 'utf8')
    assert.doesNotMatch(source, /npm install[^\n]*@deepseek-ai\/dsh/, `${path}: dynamic DSH install`)
    assert.match(source, /tools_root="\$\{DSH_TOOLS_ROOT:-\$repo_root\}"/, `${path}: root tools pin missing`)
    assert.match(source, /wait_for_pid\(\)/, `${path}: wait helper missing`)
    assert.match(source, /timeout "\$seconds" tail --pid="\$pid" -f \/dev\/null/, `${path}: process deadline missing`)
    assert.match(source, /DSH_FILE_TIMEOUT_STEPS:-1200/, `${path}: bounded CI readiness window missing`)
  }

  const workflow = await readFile(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8')
  assert.match(workflow, /timeout-minutes: 15/, 'CI job timeout missing')
  assert.match(workflow, /timeout 300 npm run test:dsh\b/, 'test:dsh step timeout missing')
  assert.match(workflow, /timeout 300 npm run test:dsh-agent\b/, 'test:dsh-agent step timeout missing')
})
