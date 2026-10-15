// 记忆库整理（plan / apply / rollback / lint / tag_normalize）测试。
// 先写后实现：这些断言在实现前必然失败（lib/tidy.js 不存在）。
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fs, existsSync } from 'node:fs'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { buildFixture, fingerprint, closeAllDb, FAKE, insertCard, cjk } from './tidy-fixture.mjs'
import { search, stats, restoreCard } from '../lib/vault.js'
import { checkMainStoreInvariant } from '../lib/db.js'
import {
  tidyPlan, tidyApply, tidyLint, tagNormalize, tidyRollback, detectSecrets,
  formatTidyPlan, formatTidyApply, formatTidyLint,
} from '../lib/tidy.js'

after(() => closeAllDb())
const quiet = { logger: () => {} }

test('detectSecrets：只返回类型，不返回值；占位符/只有名字不算', () => {
  assert.deepEqual(detectSecrets('token ' + FAKE.github()), ['github-token'])
  assert.ok(detectSecrets(FAKE.pemHead()).includes('private-key'))
  assert.ok(detectSecrets(FAKE.aws()).includes('aws-access-key'))
  assert.ok(detectSecrets('password = "' + FAKE.pass() + '"').includes('credential-assignment'))
  assert.deepEqual(detectSecrets('API_KEY=your_api_key_here\npassword: ${PASSWORD}\nOPENAI_API_KEY 存放于 ~/.config'), [])
  for (const v of detectSecrets(FAKE.github())) assert.ok(!v.includes('ghp_'))
})

test('tidyPlan：只读，且覆盖五类发现', async () => {
  const { root, db, ids } = await buildFixture()
  const before = fingerprint(db)
  const plan = await tidyPlan(root, quiet)
  assert.equal(fingerprint(db), before, 'plan 不得改库')
  // 噪声：2 个 reminder + 1 个 hello(raw)；非 raw 短卡不算；大 raw 不算噪声
  const noisePaths = plan.noise.map((n) => n.path).sort()
  assert.deepEqual(noisePaths, ['04-Content/n1.md', '04-Content/n2.md', '04-Content/n3.md'])
  assert.ok(!noisePaths.includes('03-Knowledge/short-keep.md'))
  // 重复：保留最长 canon，吸收 dup1/dup2，无关卡不在内
  assert.equal(plan.duplicates.length, 1)
  assert.equal(plan.duplicates[0].canonical.path, '02-Projects/sop-canon.md')
  assert.deepEqual(plan.duplicates[0].absorbs.map((a) => a.path).sort(), ['02-Projects/sop-dup1.md', '02-Projects/sop-dup2.md'])
  assert.ok(plan.duplicates[0].absorbs.every((a) => a.sim >= 0.6 && a.uniqueLines >= 1))
  // 标签：Docker/docker 归一，Docker-Compose/docker compose 归一，超 4 的卡去掉单次标签
  const t3 = plan.tags.changes.find((c) => c.path === '07-Tools/t3.md')
  assert.ok(t3 && t3.new.length <= 4 && t3.new.includes('docker'))
  assert.ok(plan.tags.distinctAfter < plan.tags.distinctBefore)
  // kind 错放
  assert.deepEqual(plan.kindMisplaced.map((k) => [k.path, k.kind, k.expectedKind]), [['03-Knowledge/misplaced.md', 'tool', 'knowledge']])
  // 密钥：3 张，只有类型
  assert.deepEqual(plan.secrets.map((s) => s.path).sort(), ['07-Tools/s1.md', '07-Tools/s2.md', '07-Tools/s3.md'])
  const dump = JSON.stringify(plan) + formatTidyPlan(plan)
  assert.ok(!dump.includes(FAKE.github()) && !dump.includes(FAKE.pass()) && !dump.includes(FAKE.aws()), '输出不得含密钥值')
  assert.ok(/密钥/.test(formatTidyPlan(plan)) && /整理计划/.test(formatTidyPlan(plan)))
  assert.ok(plan.planId && plan.planId.length >= 8)
})

test('tidyPlan：阈值可配（0.99 → 无重复组；默认沿用 dedupThreshold 配置）', async () => {
  const { root } = await buildFixture()
  assert.equal((await tidyPlan(root, { ...quiet, threshold: 0.99 })).duplicates.length, 0)
  const viaEnv = await tidyPlan(root, { ...quiet, env: { MEMORY_DEDUP_THRESHOLD: '0.99' } })
  assert.equal(viaEnv.duplicates.length, 0)
  assert.equal(viaEnv.options.threshold, 0.99)
  assert.equal((await tidyPlan(root, quiet)).options.threshold, 0.62)
})

test('tidyApply：默认 dry-run（不改库、不备份）', async () => {
  const { root, db } = await buildFixture()
  const before = fingerprint(db)
  const res = await tidyApply(root, quiet)
  assert.equal(res.dryRun, true)
  assert.equal(fingerprint(db), before)
  assert.ok(!existsSync(path.join(root, 'backups')), 'dry-run 不应产生备份目录')
  assert.match(formatTidyApply(res), /预演|dry-run/)
})

test('tidyApply confirm：备份 → 软删 → 合并保留独特信息 → 自检 → 可召回 → 可恢复', async () => {
  const { root, db, ids, U1, U2 } = await buildFixture()
  const total0 = db.prepare('SELECT COUNT(*) n FROM cards').get().n
  const res = await tidyApply(root, { ...quiet, confirm: true })
  assert.equal(res.ok, true, JSON.stringify(res))
  assert.equal(res.dryRun, false)
  // 备份：VACUUM INTO 产物，独立可开，integrity ok，行数与整理前一致
  assert.ok(existsSync(res.backup.path))
  const bk = new DatabaseSync(res.backup.path, { readOnly: true })
  assert.equal(bk.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
  assert.equal(bk.prepare('SELECT COUNT(*) n FROM cards').get().n, total0)
  bk.close()
  assert.equal(res.backup.verified, true)
  // 三个批次都 applied
  assert.deepEqual(res.batches.map((b) => [b.name, b.status]), [['noise', 'applied'], ['merge', 'applied'], ['tags', 'applied']])
  // 删除只走软删：回收站里能找到，且主库不再有
  const del = db.prepare("SELECT path FROM quarantine WHERE status='deleted' ORDER BY path").all().map((r) => r.path)
  assert.deepEqual(del, ['02-Projects/sop-dup1.md', '02-Projects/sop-dup2.md', '04-Content/n1.md', '04-Content/n2.md', '04-Content/n3.md'])
  assert.equal(db.prepare('SELECT COUNT(*) n FROM cards').get().n, total0 - 5)
  // 合并保留独特信息，且仍可被 recall 召回
  const canon = db.prepare("SELECT body, tags FROM cards WHERE path='02-Projects/sop-canon.md'").get()
  assert.ok(canon.body.includes(U1) && canon.body.includes(U2))
  assert.ok(canon.body.includes('合并补充'))
  assert.ok(JSON.parse(canon.tags).includes('oncall'), '被吸收卡的标签并入')
  const hits = await search(root, U2.slice(6, 20), { limit: 5 })
  assert.ok(hits.some((h) => h.path === '02-Projects/sop-canon.md'))
  // 对账：stats 与库一致、主库不变量
  const s = await stats(root)
  assert.equal(s.total, total0 - 5)
  assert.equal(s.quarantine.deleted, 5)
  assert.equal(checkMainStoreInvariant(root).ok, true)
  // 审计日志留痕
  assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE changed_by='tidy'").get().n >= 5)
  // 回滚文件存在，且能恢复
  assert.ok(existsSync(res.rollbackFile))
  const rb = await tidyRollback(root, res.rollbackFile, quiet)
  assert.equal(rb.ok, true, JSON.stringify(rb))
  assert.equal(db.prepare('SELECT COUNT(*) n FROM cards').get().n, total0)
  const canon2 = db.prepare("SELECT body FROM cards WHERE path='02-Projects/sop-canon.md'").get()
  assert.ok(!canon2.body.includes(U1))
  assert.equal(JSON.parse(db.prepare("SELECT tags FROM cards WHERE path='07-Tools/t3.md'").get().tags).length, 6)
})

test('tidyApply：整理后幂等（再 plan 无噪声/重复/标签变更）', async () => {
  const { root } = await buildFixture()
  await tidyApply(root, { ...quiet, confirm: true })
  const p2 = await tidyPlan(root, quiet)
  assert.equal(p2.noise.length, 0)
  assert.equal(p2.duplicates.length, 0)
  assert.equal(p2.tags.changes.length, 0)
})

test('批次失败自动回滚：中途 SQL 报错 → 该批全部撤销', async () => {
  const { root, db } = await buildFixture()
  // n3 进回收站时炸：整批 noise 必须回滚（n1/n2 也要留在主库）
  db.exec("CREATE TRIGGER boom BEFORE INSERT ON quarantine WHEN NEW.path = '04-Content/n3.md' BEGIN SELECT RAISE(ABORT, 'boom'); END")
  const res = await tidyApply(root, { ...quiet, confirm: true, batches: ['noise'] })
  assert.equal(res.ok, false)
  assert.equal(res.batches[0].status, 'rolled_back')
  assert.match(res.batches[0].error, /boom/)
  for (const p of ['04-Content/n1.md', '04-Content/n2.md', '04-Content/n3.md']) {
    assert.ok(db.prepare('SELECT 1 FROM cards WHERE path=?').get(p), p + ' 应仍在主库')
  }
  assert.equal(db.prepare("SELECT COUNT(*) n FROM quarantine WHERE status='deleted'").get().n, 0)
})

test('自检失败自动回滚：tags 被写成非法 JSON → 回滚，库保持原样', async () => {
  const { root, db } = await buildFixture()
  db.exec("CREATE TRIGGER corrupt AFTER UPDATE OF tags ON cards BEGIN UPDATE cards SET tags='not-json' WHERE id=NEW.id; END")
  const before = fingerprint(db)
  const res = await tidyApply(root, { ...quiet, confirm: true, batches: ['tags'] })
  assert.equal(res.ok, false)
  assert.equal(res.batches[0].status, 'rolled_back')
  assert.match(res.batches[0].error, /tags|自检/)
  assert.equal(fingerprint(db), before)
})

test('planId 不匹配（库在 plan 之后变了）→ 拒绝执行', async () => {
  const { root, db } = await buildFixture()
  const plan = await tidyPlan(root, quiet)
  insertCard(db, { path: '04-Content/n9.md', kind: 'content', title: 'late', tags: ['raw'], body: '[SCHEDULE REMINDER] ' + cjk(120) })
  const res = await tidyApply(root, { ...quiet, confirm: true, planId: plan.planId })
  assert.equal(res.ok, false)
  assert.match(res.error, /planId|计划已过期/)
  assert.ok(db.prepare('SELECT 1 FROM cards WHERE path=?').get('04-Content/n1.md'))
})

test('maxDelete 保险：计划删除数超限则拒绝（不部分执行）', async () => {
  const { root, db } = await buildFixture()
  const res = await tidyApply(root, { ...quiet, confirm: true, maxDelete: 2 })
  assert.equal(res.ok, false)
  assert.match(res.error, /maxDelete/)
  assert.equal(db.prepare("SELECT COUNT(*) n FROM quarantine WHERE status='deleted'").get().n, 0)
})

test('tidyLint：只读指标，不含密钥值', async () => {
  const { root, db } = await buildFixture()
  const before = fingerprint(db)
  const m = await tidyLint(root, quiet)
  assert.equal(fingerprint(db), before)
  assert.equal(m.total, db.prepare('SELECT COUNT(*) n FROM cards').get().n)
  assert.equal(m.noise, 3)
  assert.equal(m.duplicateGroups, 1)
  assert.equal(m.duplicateAbsorbable, 2)
  assert.equal(m.secretSuspects, 3)
  assert.equal(m.kindMisplaced, 1)
  assert.equal(m.oversizeRaw.length, 1)
  assert.equal(m.oversizeRaw[0].path, '04-Content/big-raw.md')
  assert.ok(m.tagsOver4 >= 1 && m.tagVariantGroups >= 1)
  assert.equal(m.integrity, 'ok')
  const text = formatTidyLint(m)
  assert.ok(/健康检查/.test(text) && !text.includes(FAKE.github()) && !text.includes(FAKE.pass()))
})

test('tagNormalize：默认 dry-run；confirm 才改；支持自定义同义映射', async () => {
  const { root, db } = await buildFixture()
  const before = fingerprint(db)
  const dry = await tagNormalize(root, { ...quiet, synonyms: { oncall: 'combo' } })
  assert.equal(dry.dryRun, true)
  assert.equal(fingerprint(db), before)
  const res = await tagNormalize(root, { ...quiet, synonyms: { oncall: 'combo' }, confirm: true })
  assert.equal(res.ok, true, JSON.stringify(res))
  const tags = (p) => JSON.parse(db.prepare('SELECT tags FROM cards WHERE path=?').get(p).tags)
  assert.deepEqual(tags('02-Projects/sop-dup2.md'), ['combo'])
  assert.deepEqual(tags('07-Tools/t1.md').sort(), ['docker', 'docker-compose'].sort())
  assert.ok(existsSync(res.backup.path))
  // 只动标签：没有任何卡被删
  assert.equal(db.prepare("SELECT COUNT(*) n FROM quarantine WHERE status='deleted'").get().n, 0)
})
