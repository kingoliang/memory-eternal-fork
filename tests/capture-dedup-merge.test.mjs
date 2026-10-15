// memory_capture 入库前近似重复检测 + 合并（COMBO 值班 SOP 这类反复沉淀的卡）。
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { tmpDir, line, cjk } from './tidy-fixture.mjs'
import { runStandaloneCapture } from '../lib/capture-run.js'
import { ensureVault } from '../lib/vault.js'
import { getDb, closeAllDb } from '../lib/db.js'

after(() => closeAllDb())

const baseEnv = async (extra = {}) => ({ DSH_HOME: await tmpDir('mc-dshhome-'), MEMORY_AUDIT_MODE: 'none', ...extra })
const fresh = async () => { const root = await tmpDir('mc-capdup-'); await ensureVault(root); return root }
const rows = (root) => getDb(root).prepare('SELECT path, title, body, tags FROM cards').all()

const shared = Array.from({ length: 5 }, line)
const mk = (extraLines) => '# COMBO 值班 SOP\n' + [...shared, ...extraLines].join('\n')
const textA = mk([line(), line()])
const textB = mk([line(), line()])        // 与 A 共 5/9 行 → 正文相似度约 0.55，低于 0.62

test('旧行为兼容：不相关文本照常新建；全文近重复仍判重（追加而非新增）', async () => {
  const root = await fresh(); const env = await baseEnv()
  const a = await runStandaloneCapture(root, textA, { source: 't', env })
  assert.equal(a.action, 'created')
  const other = await runStandaloneCapture(root, '# 另一件事\n' + cjk(400), { source: 't', env })
  assert.equal(other.action, 'created')
  const again = await runStandaloneCapture(root, textA, { source: 't', env })
  assert.equal(again.action, 'appended')
  assert.equal(again.path, a.path)
  assert.equal(rows(root).length, 2)
})

test('同标题但正文相似度 < 0.62：合并进已有卡而不是新增（标题感知去重）', async () => {
  const root = await fresh(); const env = await baseEnv()
  const a = await runStandaloneCapture(root, textA, { source: 't', env })
  const b = await runStandaloneCapture(root, textB, { source: 't', env })
  assert.equal(b.action, 'appended')
  assert.equal(b.path, a.path)
  assert.ok(b.merged >= 2, '至少合入 2 行独特内容')
  const rs = rows(root)
  assert.equal(rs.length, 1, '不应新增卡')
  const newLines = textB.split('\n').slice(-2)
  for (const l of newLines) assert.ok(rs[0].body.includes(l), '独特行并入正文')
  assert.equal(getDb(root).prepare('SELECT COUNT(*) n FROM card_updates').get().n, 0, '合并写正文，不再堆 card_updates')
  // 第三次同样内容：无新增信息 → 不改正文
  const bodyBefore = rs[0].body
  const c = await runStandaloneCapture(root, textB, { source: 't', env })
  assert.equal(c.action, 'appended'); assert.equal(c.merged, 0)
  assert.equal(rows(root)[0].body, bodyBefore)
})

test('可配置：关闭标题感知 → 保持旧行为（新建）', async () => {
  const root = await fresh(); const env = await baseEnv({ MEMORY_DEDUP_TITLE_AWARE: '0' })
  await runStandaloneCapture(root, textA, { source: 't', env })
  const b = await runStandaloneCapture(root, textB, { source: 't', env })
  assert.equal(b.action, 'created')
  assert.equal(rows(root).length, 2)
})

test('可配置：MEMORY_DEDUP_THRESHOLD 调低/调高', async () => {
  let root = await fresh(); let env = await baseEnv({ MEMORY_DEDUP_TITLE_AWARE: '0', MEMORY_DEDUP_THRESHOLD: '0.4' })
  await runStandaloneCapture(root, textA, { source: 't', env })
  assert.equal((await runStandaloneCapture(root, textB, { source: 't', env })).action, 'appended')
  root = await fresh(); env = await baseEnv({ MEMORY_DEDUP_TITLE_AWARE: '0', MEMORY_DEDUP_THRESHOLD: '0.9' })
  await runStandaloneCapture(root, textA, { source: 't', env })
  assert.equal((await runStandaloneCapture(root, textA.replace(shared[0], line()), { source: 't', env })).action, 'created')
})

test('MEMORY_DEDUP_MERGE=0：命中后退回旧的「追加更新记录」行为', async () => {
  const root = await fresh(); const env = await baseEnv({ MEMORY_DEDUP_MERGE: '0' })
  await runStandaloneCapture(root, textA, { source: 't', env })
  const b = await runStandaloneCapture(root, textB, { source: 't', env })
  assert.equal(b.action, 'appended')
  assert.equal(getDb(root).prepare('SELECT COUNT(*) n FROM card_updates').get().n, 1)
})

test('待审队列里已有近似卡：不再堆新的待审卡（跳过并说明）', async () => {
  const root = await fresh(); const env = await baseEnv({ MEMORY_AUDIT_MODE: 'all' })
  const a = await runStandaloneCapture(root, textA, { source: 't', env })
  assert.equal(a.action, 'created')
  assert.equal(getDb(root).prepare("SELECT COUNT(*) n FROM quarantine WHERE status='pending'").get().n, 1)
  const b = await runStandaloneCapture(root, textB, { source: 't', env })
  assert.equal(b.action, 'skipped')
  assert.match(b.reason, /待审/)
  assert.equal(getDb(root).prepare("SELECT COUNT(*) n FROM quarantine WHERE status='pending'").get().n, 1)
})

test('需要审核的沉淀命中已批准卡：不改正文，只追加更新记录（审核闸门不被绕过），仍不新建卡', async () => {
  const root = await fresh()
  // 先用免审环境放一张已批准卡，再换成「全部需审」的环境捕获近似文本
  const a = await runStandaloneCapture(root, textA, { source: 't', env: await baseEnv() })
  assert.equal(a.action, 'created')
  const bodyBefore = rows(root)[0].body
  const b = await runStandaloneCapture(root, textB, { source: 't', env: await baseEnv({ MEMORY_AUDIT_MODE: 'all' }) })
  assert.equal(b.action, 'appended'); assert.equal(b.path, a.path)
  assert.equal(rows(root).length, 1)
  assert.equal(rows(root)[0].body, bodyBefore, '正文不被未审核内容改写')
  assert.equal(getDb(root).prepare('SELECT COUNT(*) n FROM card_updates').get().n, 1)
})
