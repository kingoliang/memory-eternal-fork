// MCP：新增 4 个整理工具 + 原有 4 个工具接口不变（对比 v0.10.8 基线快照）。
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { spawn } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildFixture, closeAllDb, FAKE } from './tidy-fixture.mjs'
import { MCP_TOOLS, callTool } from '../lib/mcp.js'
import { getDb } from '../lib/db.js'

after(() => closeAllDb())
const here = path.dirname(fileURLToPath(import.meta.url))
const baseline = JSON.parse(readFileSync(path.join(here, 'fixtures/mcp-tools-baseline-v0.10.8.json'), 'utf8'))
const text = (r) => r.content[0].text

test('原有 4 个工具：name/description/inputSchema 与 v0.10.8 逐字一致', () => {
  for (const old of baseline) {
    const now = MCP_TOOLS.find((t) => t.name === old.name)
    assert.deepEqual(now, old, old.name)
  }
  assert.deepEqual(MCP_TOOLS.map((t) => t.name).slice(0, 4), baseline.map((t) => t.name), '原 4 个顺序不变')
})

test('新增工具已注册，schema 风格一致（description 中文、inputSchema object）', () => {
  const names = MCP_TOOLS.map((t) => t.name)
  for (const n of ['memory_tidy_plan', 'memory_tidy_apply', 'memory_lint', 'memory_tag_normalize']) {
    assert.ok(names.includes(n), n)
    const t = MCP_TOOLS.find((x) => x.name === n)
    assert.equal(t.inputSchema.type, 'object')
    assert.match(t.description, /[一-鿿]/)
  }
  assert.ok('confirm' in MCP_TOOLS.find((t) => t.name === 'memory_tidy_apply').inputSchema.properties)
  assert.ok(!MCP_TOOLS.find((t) => t.name === 'memory_tidy_apply').inputSchema.required?.includes('confirm'), 'confirm 非必填，缺省即 dry-run')
})

test('callTool：plan / lint 只读，返回中文且无密钥值；apply 缺省 dry-run，confirm 才执行', async () => {
  const { root, db } = await buildFixture()
  const total0 = db.prepare('SELECT COUNT(*) n FROM cards').get().n
  const plan = text(await callTool('memory_tidy_plan', {}, root))
  assert.match(plan, /整理计划/); assert.match(plan, /sop-dup1/)
  const lint = text(await callTool('memory_lint', {}, root))
  assert.match(lint, /健康检查/)
  for (const out of [plan, lint]) for (const v of [FAKE.github(), FAKE.pass(), FAKE.aws()]) assert.ok(!out.includes(v))
  const dry = text(await callTool('memory_tidy_apply', {}, root))
  assert.match(dry, /预演/)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM cards').get().n, total0)
  const real = await callTool('memory_tidy_apply', { confirm: true }, root)
  assert.ok(!real.isError, text(real))
  assert.match(text(real), /已执行/)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM cards').get().n, total0 - 6)
  const tn = text(await callTool('memory_tag_normalize', { synonyms: { oncall: 'combo' } }, root))
  assert.match(tn, /预演|无需/)
})

test('confirm 必须是布尔 true（字符串 "true" 不算，防误触）', async () => {
  const { root, db } = await buildFixture()
  const total0 = db.prepare('SELECT COUNT(*) n FROM cards').get().n
  await callTool('memory_tidy_apply', { confirm: 'true' }, root)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM cards').get().n, total0)
})

test('stdio 端到端：initialize → tools/list → tools/call(memory_lint)', async () => {
  const { root } = await buildFixture()
  closeAllDb()
  const child = spawn(process.execPath, ['--no-warnings', path.join(here, '../bin/dsh-memory.mjs'), 'mcp'], { env: { ...process.env, MEMORY_VAULT_DIR: root }, stdio: ['pipe', 'pipe', 'pipe'] })
  const lines = []; let buf = ''
  child.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { lines.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1) } })
  const send = (o) => child.stdin.write(JSON.stringify(o) + '\n')
  const waitFor = async (id) => { for (let i = 0; i < 100; i++) { const m = lines.find((x) => x.id === id); if (m) return m; await new Promise((r) => setTimeout(r, 100)) } throw new Error('timeout ' + id) }
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', clientInfo: { name: 't' } } })
  await waitFor(1)
  send({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
  assert.equal((await waitFor(2)).result.tools.length, 8)
  send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'memory_lint', arguments: {} } })
  const r = await waitFor(3)
  assert.match(r.result.content[0].text, /健康检查/)
  child.stdin.end(); child.kill()
})
