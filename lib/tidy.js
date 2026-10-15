// 记忆核心 · 记忆库整理（tidy）：plan / apply / lint / tag-normalize / rollback
//
// 来源：把 2026-10 在 58 上人工整理一次的流程（噪声卡清理、近似重复合并、标签归一、
// kind 一致性检查、明文密钥扫描、回收站导出）做成可重复、可回滚的内置功能。
//
// 安全模型（逐条对应需求）：
//   - plan / lint 纯只读，不写库；
//   - apply 默认 dry-run，必须显式 confirm === true（布尔）才执行；
//   - 执行前先 VACUUM INTO 做一致性备份并校验（不是裸拷贝 WAL 库）；
//   - 删除只走软删（进回收站，30 天内可 restoreCard）；合并只把「独特行」并入保留卡，被吸收卡进回收站；
//   - 每个批次一个事务：执行后自检（总数对账 / integrity_check / tags 合法 JSON / title·path·body 非空 /
//     主库不变量），任何一步失败 → ROLLBACK 整批，并停止后续批次；
//   - 批次提交后写回滚文件（被删卡路径、保留卡合并前的 body/tags、标签变更前值），tidyRollback 可还原；
//   - 密钥扫描只返回「卡路径 + 命中类型」，值永远不出现在返回值、日志、回滚文件里。
//
// 日志：走 stderr（MCP 的 stdout 是协议通道）。INFO = 关键决策（阈值、合并了谁、删了谁），ERROR = 失败。

import path from 'node:path'
import fs from 'node:fs'
import crypto from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import {
  getDb, checkMainStoreInvariant,
} from './db.js'
import {
  KIND_ROOTS, bigramHashSet, jaccardSets, uniqueLinesAgainst, withMergeSection,
  softDeleteCardSync, restoreCardSync,
} from './vault.js'
import { resolveDedupConfig } from './dedup-config.js'

export const TIDY_BATCHES = ['noise', 'merge', 'tags']
export const NOISE_CATEGORIES = ['schedule-reminder', 'timeout-notice', 'fragment', 'agent-chatter']
const DEFAULT_NOISE_CATEGORIES = ['schedule-reminder', 'timeout-notice', 'fragment']
const DEFAULTS = { maxTags: 4, rawMaxChars: 6000, maxDelete: 50, simBodyLimit: 8000, mergeLinesPerGroup: 15, mergedTagCap: 10 }

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------

function makeLogger(opts) {
  if (typeof opts?.logger === 'function') return opts.logger
  return (level, msg) => process.stderr.write(`[memory-eternal] ${level} tidy ${msg}\n`)
}

// ---------------------------------------------------------------------------
// 密钥扫描（只回类型）
// ---------------------------------------------------------------------------

const SECRET_PATTERNS = [
  ['private-key', /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----/],
  ['aws-access-key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['github-token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/],
  ['slack-token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/],
  ['openai-style-key', /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b/],
  ['google-api-key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ['url-embedded-credentials', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s@/]{3,}@/i],
  ['bearer-token', /\bBearer\s+[A-Za-z0-9._~+/-]{24,}=*/],
]
const ASSIGN_RE = /(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|口令|密码|密钥)\s*[:=：]\s*["'`]?([^\s"'`,;]{8,})/gi
const PLACEHOLDER_RE = /^(?:your|xxx|\*+|<|\$|\{|%|example|changeme|placeholder|null|none|true|false|\.\.\.)|your_|_here|x{4,}|<[^>]*>|\$\{|\.\.\./i

/**
 * 扫描文本里的明文密钥疑似项。**只返回命中的类型名数组**（去重、有序），绝不返回匹配到的值。
 * 占位符（your_xxx / ${VAR} / <token>）、只有变量名没有值的「密钥目录」条目不算命中。
 */
export function detectSecrets(text) {
  const s = String(text || '')
  const types = []
  for (const [name, re] of SECRET_PATTERNS) if (re.test(s)) types.push(name)
  for (const m of s.matchAll(ASSIGN_RE)) {
    const v = m[1]
    if (PLACEHOLDER_RE.test(v)) continue
    if (!/[A-Za-z]/.test(v) || !/\d/.test(v)) continue // 真密钥几乎总是字母数字混合
    types.push('credential-assignment')
    break
  }
  return [...new Set(types)]
}

// ---------------------------------------------------------------------------
// 噪声
// ---------------------------------------------------------------------------

// 真实库里的标题是 `[SCHEDULE REMINDER BATCH]`（带 BATCH），所以括号前允许任意尾缀词
const SCHEDULE_RE = /\[SCHEDULE REMINDER[^\]]*\]|\[定时提醒[^\]]*\]/i
const PROBE_TITLE_RE = /^(?:hello|hi|ping|pong|test|你好|对话原文记录)$|^Reply with the single word\b|^Time sampled while preparing turn\b/i

const NOISE_RULES = {
  'schedule-reminder': {
    label: '定时提醒批次',
    test: (c) => SCHEDULE_RE.test(c.title) || SCHEDULE_RE.test(c.body.slice(0, 300)),
  },
  'timeout-notice': {
    label: '超时通知',
    test: (c) => c.body.length < 1500 && /(超时|time(?:d)?[ -]?out).{0,12}(通知|notice|notification)|(通知|notice|notification).{0,12}(超时|time(?:d)?[ -]?out)/i.test(c.title + '\n' + c.body.slice(0, 200)),
  },
  fragment: {
    label: '无信息碎片',
    test: (c) => {
      const bare = c.body.replace(/[\s\p{P}\p{S}]+/gu, '')
      return bare.length < 40 || PROBE_TITLE_RE.test(c.title.trim()) || (c.body.length < 60 && /^(hello|hi|pong|ping|ok|time sampled)\b/i.test(c.body.trim()))
    },
  },
  'agent-chatter': {
    label: 'agent 间通信原文',
    test: (c) => c.body.length < 3000 && (/^\[(?:Message|Reply) from [^\]]+\]$/i.test(c.title.trim()) || /^<teammate-message/i.test(c.title.trim())),
  },
}

/** 噪声判定：**只对 raw（未蒸馏原文）卡生效**——蒸馏过的卡即使很短也可能是有用的结论。 */
export function classifyNoise(card, categories = DEFAULT_NOISE_CATEGORIES) {
  if (!card.tags.includes('raw')) return null
  for (const cat of categories) {
    const rule = NOISE_RULES[cat]
    if (rule && rule.test(card)) return { category: cat, reason: rule.label }
  }
  return null
}

// ---------------------------------------------------------------------------
// 标签归一
// ---------------------------------------------------------------------------

/** 归一键：NFKC + 小写 + 去掉空白/下划线/连字符/点/中点。 */
export const tagKey = (t) => String(t).normalize('NFKC').toLowerCase().replace(/[\s_\-·.]+/g, '')

function parseTags(raw) {
  try {
    const v = JSON.parse(raw || '[]')
    if (Array.isArray(v)) return { tags: v.map((t) => String(t).trim()).filter(Boolean), malformed: false }
  } catch { /* 落到下面 */ }
  return { tags: [], malformed: true }
}

/** 变体里选规范写法：次数多者胜；平手 → 小写优先 → 连字符优先于空格 → 短者 → 字典序。 */
function pickCanonical(variants, counts) {
  return [...variants].sort((a, b) =>
    counts.get(b) - counts.get(a)
    || (b === b.toLowerCase()) - (a === a.toLowerCase())
    || (!/\s/.test(b)) - (!/\s/.test(a))
    || a.length - b.length
    || (a < b ? -1 : a > b ? 1 : 0))[0]
}

/**
 * 计算标签归一计划（纯函数）。
 * @param rows [{id,path,title,tags(JSON 字符串)}]
 * @param opts {synonyms:{from:to}, maxTags}
 */
export function planTagNormalize(rows, { synonyms = {}, maxTags = DEFAULTS.maxTags } = {}) {
  const syn = new Map(Object.entries(synonyms || {}).map(([k, v]) => [tagKey(k), String(v).trim()]).filter(([, v]) => v))
  const parsed = rows.map((r) => ({ row: r, ...parseTags(r.tags) }))
  const mapped = parsed.map((p) => ({ ...p, tags: p.tags.map((t) => syn.get(tagKey(t)) ?? t) }))
  const counts = new Map()
  for (const p of mapped) for (const t of p.tags) counts.set(t, (counts.get(t) || 0) + 1)
  const groups = new Map()
  for (const t of counts.keys()) { const k = tagKey(t); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(t) }
  const canon = new Map()
  for (const variants of groups.values()) { const c = pickCanonical(variants, counts); for (const v of variants) canon.set(v, c) }
  const step1 = mapped.map((p) => ({ ...p, tags: [...new Set(p.tags.map((t) => canon.get(t) ?? t))] }))
  const finalCount = new Map()
  for (const p of step1) for (const t of p.tags) finalCount.set(t, (finalCount.get(t) || 0) + 1)

  const changes = []
  const after = new Set()
  for (const p of step1) {
    let next = p.tags
    if (next.length > maxTags) {
      const title = String(p.row.title || '').toLowerCase()
      // 去掉「全库只出现一次且不在标题里」的标签，长的先去、同长的靠后的先去，直到不超限
      const cands = next.map((t, i) => ({ t, i })).filter(({ t }) => finalCount.get(t) === 1 && !title.includes(t.toLowerCase()))
        .sort((a, b) => b.t.length - a.t.length || b.i - a.i)
      for (const { t } of cands) { if (next.length <= maxTags) break; next = next.filter((x) => x !== t) }
    }
    next.forEach((t) => after.add(t))
    const old = parseTags(p.row.tags)
    if (p.malformed || JSON.stringify(old.tags) !== JSON.stringify(next)) {
      changes.push({ id: p.row.id, path: p.row.path, old: old.tags, new: next, malformed: p.malformed })
    }
  }
  const map = {}
  for (const [from, to] of canon) if (from !== to) map[from] = to
  for (const p of parsed) for (const t of p.tags) { const s = syn.get(tagKey(t)); if (s && s !== t) map[t] = canon.get(s) ?? s }
  return { changes, map, distinctBefore: new Set(parsed.flatMap((p) => p.tags)).size, distinctAfter: after.size }
}

// ---------------------------------------------------------------------------
// 近似重复
// ---------------------------------------------------------------------------

/**
 * 近似重复分组（纯函数）：最长者为保留卡（canonical），与它直接相似度 ≥ threshold 且 kind 相同的卡被吸收。
 * 刻意用「星形」而非传递闭包，避免 A≈B、B≈C 链式把互不相关的 A 和 C 并到一起。
 */
export function planDuplicateGroups(cards, threshold, { limit = DEFAULTS.simBodyLimit, linesPerGroup = DEFAULTS.mergeLinesPerGroup } = {}) {
  const items = cards.map((c) => ({ c, set: bigramHashSet(c.body.slice(0, limit)) }))
    .sort((a, b) => b.c.body.length - a.c.body.length || a.c.id - b.c.id)
  const used = new Set()
  const groups = []
  for (let i = 0; i < items.length; i++) {
    if (used.has(items[i].c.path)) continue
    const absorbs = []
    for (let j = i + 1; j < items.length; j++) {
      if (used.has(items[j].c.path) || items[j].c.kind !== items[i].c.kind) continue
      const sim = jaccardSets(items[i].set, items[j].set, threshold)
      if (sim >= threshold) absorbs.push({ item: items[j], sim })
    }
    if (!absorbs.length) continue
    used.add(items[i].c.path)
    let body = items[i].c.body
    let budget = linesPerGroup
    const out = []
    for (const { item, sim } of absorbs) {
      used.add(item.c.path)
      const lines = budget > 0 ? uniqueLinesAgainst(body, item.c.body, { max: budget }).filter((l) => detectSecrets(l).length === 0) : []
      budget -= lines.length
      body += '\n' + lines.join('\n')
      out.push({ id: item.c.id, path: item.c.path, title: item.c.title, sim: Math.round(sim * 100) / 100, uniqueLines: lines.length })
    }
    groups.push({ canonical: { id: items[i].c.id, path: items[i].c.path, title: items[i].c.title }, absorbs: out })
  }
  return groups
}

// ---------------------------------------------------------------------------
// 读库 + 计划
// ---------------------------------------------------------------------------

const DIR_TO_KIND = Object.fromEntries(Object.entries(KIND_ROOTS).map(([k, v]) => [v.toLowerCase(), k]))

function loadCards(db) {
  return db.prepare('SELECT id, path, kind, title, tags, body FROM cards ORDER BY id').all().map((r) => ({
    id: r.id, path: r.path, kind: r.kind, title: r.title || '', body: r.body || '', tagsRaw: r.tags, tags: parseTags(r.tags).tags,
  }))
}

function resolveOptions(opts = {}) {
  const dd = resolveDedupConfig(opts.env ?? process.env, opts.shared)
  const num = (v, d, lo, hi) => { const n = Number(v); return v !== undefined && v !== null && v !== '' && Number.isFinite(n) && n >= lo && n <= hi ? n : d }
  const cats = Array.isArray(opts.noiseCategories) && opts.noiseCategories.length ? opts.noiseCategories.filter((c) => NOISE_CATEGORIES.includes(c)) : DEFAULT_NOISE_CATEGORIES
  return {
    threshold: num(opts.threshold, dd.threshold, 0.05, 1),
    maxTags: Math.floor(num(opts.maxTags, DEFAULTS.maxTags, 1, 20)),
    rawMaxChars: Math.floor(num(opts.rawMaxChars, DEFAULTS.rawMaxChars, 500, 10_000_000)),
    maxDelete: Math.floor(num(opts.maxDelete, DEFAULTS.maxDelete, 0, 100000)),
    noiseCategories: cats,
    synonyms: opts.synonyms && typeof opts.synonyms === 'object' && !Array.isArray(opts.synonyms) ? opts.synonyms : {},
  }
}

/**
 * 生成整理计划（只读，不改库）。
 * @param opts.sections 只算其中几类：['noise','duplicates','tags','kind','secrets','oversize']，默认全部
 */
export async function tidyPlan(root, opts = {}) {
  const log = makeLogger(opts)
  const o = resolveOptions(opts)
  const want = new Set(opts.sections ?? ['noise', 'duplicates', 'tags', 'kind', 'secrets', 'oversize'])
  const db = getDb(root)
  const cards = loadCards(db)
  const plan = { generatedAt: new Date().toISOString(), options: o, totals: { cards: cards.length }, noise: [], duplicates: [], tags: { changes: [], map: {}, distinctBefore: 0, distinctAfter: 0 }, kindMisplaced: [], secrets: [], oversizeRaw: [] }

  const noisePaths = new Set()
  if (want.has('noise') || want.has('duplicates')) {
    for (const c of cards) {
      const n = classifyNoise(c, o.noiseCategories)
      if (n) { noisePaths.add(c.path); if (want.has('noise')) plan.noise.push({ id: c.id, path: c.path, title: c.title, category: n.category, reason: n.reason }) }
    }
  }
  if (want.has('duplicates')) plan.duplicates = planDuplicateGroups(cards.filter((c) => !noisePaths.has(c.path)), o.threshold)
  if (want.has('tags')) {
    plan.tags = planTagNormalize(db.prepare('SELECT id, path, title, tags FROM cards ORDER BY id').all(), { synonyms: o.synonyms, maxTags: o.maxTags })
  }
  if (want.has('kind')) {
    for (const c of cards) {
      const expected = DIR_TO_KIND[c.path.split('/')[0].toLowerCase()]
      if (expected && expected !== c.kind) plan.kindMisplaced.push({ id: c.id, path: c.path, kind: c.kind, expectedKind: expected })
    }
  }
  if (want.has('secrets')) {
    for (const c of cards) {
      const types = detectSecrets(c.title + '\n' + c.body)
      if (types.length) plan.secrets.push({ id: c.id, path: c.path, types })
    }
  }
  if (want.has('oversize')) {
    for (const c of cards) if (c.tags.includes('raw') && c.body.length > o.rawMaxChars) plan.oversizeRaw.push({ id: c.id, path: c.path, title: c.title, chars: c.body.length })
  }
  plan.planId = crypto.createHash('sha1').update(JSON.stringify({
    o: { t: o.threshold, m: o.maxTags, n: o.noiseCategories, s: o.synonyms },
    noise: plan.noise.map((n) => n.path),
    dup: plan.duplicates.map((g) => [g.canonical.path, g.absorbs.map((a) => a.path)]),
    tags: plan.tags.changes.map((c) => [c.path, c.new]),
  })).digest('hex').slice(0, 12)
  log('INFO', `plan 完成：cards=${cards.length} 阈值=${o.threshold} 噪声=${plan.noise.length} 重复组=${plan.duplicates.length} 标签变更=${plan.tags.changes.length} kind错放=${plan.kindMisplaced.length} 密钥疑似=${plan.secrets.length}`)
  return plan
}

// ---------------------------------------------------------------------------
// 备份 + 自检
// ---------------------------------------------------------------------------

const tsStamp = () => new Date().toISOString().replace(/[:.]/g, '-')

/** VACUUM INTO 一致性备份并校验（integrity_check + 行数与整理前一致）。失败则抛错，调用方不得继续改库。 */
export function backupBeforeTidy(root, log = () => {}) {
  const db = getDb(root)
  const dir = path.join(path.resolve(root), 'backups')
  fs.mkdirSync(dir, { recursive: true })
  const file = path.join(dir, `pre-tidy-${tsStamp()}.db`)
  const count = () => ({ cards: db.prepare('SELECT COUNT(*) n FROM cards').get().n, quarantine: db.prepare('SELECT COUNT(*) n FROM quarantine').get().n })
  const b0 = count()
  db.exec(`VACUUM INTO '${file.replace(/'/g, "''")}'`)
  const b1 = count()
  const bk = new DatabaseSync(file, { readOnly: true })
  try {
    const integrity = bk.prepare('PRAGMA integrity_check').get().integrity_check
    const got = { cards: bk.prepare('SELECT COUNT(*) n FROM cards').get().n, quarantine: bk.prepare('SELECT COUNT(*) n FROM quarantine').get().n }
    // 备份期间若有并发写入（如常驻 web 同时沉淀），行数允许落在前后两次计数之间
    const within = (v, a, b) => v >= Math.min(a, b) && v <= Math.max(a, b)
    if (integrity !== 'ok') throw new Error(`备份 integrity_check 失败：${integrity}`)
    if (!within(got.cards, b0.cards, b1.cards) || !within(got.quarantine, b0.quarantine, b1.quarantine)) {
      throw new Error(`备份行数与库不符：备份 ${JSON.stringify(got)} vs 库 ${JSON.stringify(b0)}`)
    }
    log('INFO', `备份完成并校验通过：${file}（cards=${got.cards} quarantine=${got.quarantine}）`)
    return { path: file, verified: true, cards: got.cards, quarantine: got.quarantine, bytes: fs.statSync(file).size }
  } finally { bk.close() }
}

function snapshotCounts(db) {
  const q = Object.fromEntries(db.prepare('SELECT status, COUNT(*) n FROM quarantine GROUP BY status').all().map((r) => [r.status, r.n]))
  return { cards: db.prepare('SELECT COUNT(*) n FROM cards').get().n, deleted: q.deleted || 0, pending: q.pending || 0, rejected: q.rejected || 0 }
}

/** 批次后自检；返回 {ok, failures[], checks}。 */
function selfCheck(db, root, before, expectRemoved) {
  const failures = []
  const now = snapshotCounts(db)
  if (now.cards !== before.cards - expectRemoved) failures.push(`总数对账失败：cards ${before.cards} → ${now.cards}，预期 ${before.cards - expectRemoved}`)
  if (now.deleted !== before.deleted + expectRemoved) failures.push(`回收站对账失败：deleted ${before.deleted} → ${now.deleted}，预期 +${expectRemoved}`)
  if (now.pending !== before.pending || now.rejected !== before.rejected) failures.push('待审/驳回队列数量被改动')
  const integrity = db.prepare('PRAGMA integrity_check').get().integrity_check
  if (integrity !== 'ok') failures.push(`integrity_check：${integrity}`)
  let badTags = 0
  for (const r of db.prepare('SELECT tags FROM cards').all()) {
    try { const v = JSON.parse(r.tags); if (!Array.isArray(v) || v.some((t) => typeof t !== 'string')) badTags++ } catch { badTags++ }
  }
  if (badTags) failures.push(`tags 不是合法 JSON 字符串数组的卡：${badTags} 张`)
  const empty = db.prepare("SELECT COUNT(*) n FROM cards WHERE TRIM(COALESCE(title,'')) = '' OR TRIM(COALESCE(path,'')) = '' OR TRIM(COALESCE(body,'')) = ''").get().n
  if (empty) failures.push(`title/path/body 为空的卡：${empty} 张`)
  const inv = checkMainStoreInvariant(root)
  if (!inv.ok) failures.push('主库不变量被破坏（出现非 approved 卡）')
  return { ok: failures.length === 0, failures, checks: { integrity, totalCards: now.cards, deletedInRecycle: now.deleted, badTags, emptyFields: empty } }
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

/**
 * 按计划执行整理。默认 dry-run；`confirm === true`（严格布尔）才真正执行。
 * @param opts {confirm, batches, planId, threshold, maxTags, maxDelete, synonyms, noiseCategories}
 */
export async function tidyApply(root, opts = {}) {
  const log = makeLogger(opts)
  const o = resolveOptions(opts)
  const batches = Array.isArray(opts.batches) && opts.batches.length ? opts.batches : TIDY_BATCHES
  const unknown = batches.filter((b) => !TIDY_BATCHES.includes(b))
  if (unknown.length) return { ok: false, dryRun: true, error: `未知批次：${unknown.join(',')}（可选 ${TIDY_BATCHES.join('/')}）` }
  const confirm = opts.confirm === true
  // planId 由 noise/duplicates/tags 三类共同决定，所以不论只执行哪些批次，这里都按这三类生成计划，
  // 才能与 memory_tidy_plan 返回的 planId 对得上。
  const plan = await tidyPlan(root, { ...opts, sections: ['noise', 'duplicates', 'tags'], logger: () => {} })
  const plannedDeletes = (batches.includes('noise') ? plan.noise.length : 0) + (batches.includes('merge') ? plan.duplicates.reduce((n, g) => n + g.absorbs.length, 0) : 0)
  const base = { plan, planId: plan.planId, plannedDeletes }

  if (opts.planId && opts.planId !== plan.planId) {
    log('WARN', `planId 不匹配（给定 ${opts.planId}，当前 ${plan.planId}）：库在 plan 之后变化，拒绝执行`)
    return { ok: false, dryRun: !confirm, ...base, error: `planId 不匹配：计划已过期（库在 plan 之后变化），请重新运行 memory_tidy_plan 并核对后再执行` }
  }
  if (plannedDeletes > o.maxDelete) {
    log('WARN', `计划软删 ${plannedDeletes} 张，超过 maxDelete=${o.maxDelete}，拒绝执行`)
    return { ok: false, dryRun: !confirm, ...base, error: `计划软删 ${plannedDeletes} 张，超过 maxDelete=${o.maxDelete}；确认无误后请显式调大 maxDelete 再执行` }
  }
  if (!confirm) {
    log('INFO', `dry-run：批次=${batches.join(',')} 预计软删 ${plannedDeletes} 张（未传 confirm=true，库未改动）`)
    return {
      ok: true, dryRun: true, ...base,
      batches: batches.map((name) => ({ name, status: 'dry-run', counts: batchPreview(name, plan) })),
    }
  }

  // ---- 真正执行 ----
  const db = getDb(root)
  try { db.exec('PRAGMA busy_timeout = 20000') } catch { /* 忽略 */ }
  log('INFO', `开始整理：批次=${batches.join(',')} 阈值=${o.threshold} 计划软删=${plannedDeletes} maxDelete=${o.maxDelete}`)
  let backup
  try { backup = backupBeforeTidy(root, log) } catch (e) {
    log('ERROR', `备份失败，未改动任何数据：${e.message}`)
    return { ok: false, dryRun: false, ...base, error: `备份失败，未改动任何数据：${e.message}` }
  }
  const rollback = { version: 1, tool: 'memory-eternal-tidy', createdAt: new Date().toISOString(), vault: path.resolve(root), backup: backup.path, removed: [], merged: [], tags: [] }
  const rollbackFile = backup.path.replace(/pre-tidy-/, 'tidy-').replace(/\.db$/, '.rollback.json')
  const results = []
  let ok = true
  for (const name of batches) {
    const r = runBatch(db, root, name, o, rollback, log)
    results.push(r)
    if (r.status === 'applied') fs.writeFileSync(rollbackFile, JSON.stringify(rollback, null, 1))
    if (r.status !== 'applied') { ok = false; break }
  }
  for (const name of batches.slice(results.length)) results.push({ name, status: 'skipped', counts: {}, reason: '前一批次失败，已停止' })
  const after = snapshotCounts(db)
  log(ok ? 'INFO' : 'ERROR', `整理${ok ? '完成' : '中止'}：cards=${after.cards} 回收站=${after.deleted} 回滚文件=${fs.existsSync(rollbackFile) ? rollbackFile : '(无)'}`)
  return { ok, dryRun: false, ...base, backup, batches: results, rollbackFile: fs.existsSync(rollbackFile) ? rollbackFile : null, after }
}

function batchPreview(name, plan) {
  if (name === 'noise') return { removed: plan.noise.length }
  if (name === 'merge') return { groups: plan.duplicates.length, removed: plan.duplicates.reduce((n, g) => n + g.absorbs.length, 0) }
  return { tagsChanged: plan.tags.changes.length }
}

/** 一个批次 = 一个事务。基于「批次开始时的实时库状态」重算子计划，所以前一批的结果会被后一批看到。 */
function runBatch(db, root, name, o, rollback, log) {
  const before = snapshotCounts(db)
  const mark = { removed: rollback.removed.length, merged: rollback.merged.length, tags: rollback.tags.length }
  db.exec('BEGIN IMMEDIATE')
  try {
    const counts = name === 'noise' ? batchNoise(db, o, rollback, log) : name === 'merge' ? batchMerge(db, o, rollback, log) : batchTags(db, o, rollback, log)
    const check = selfCheck(db, root, before, counts.removed || 0)
    if (!check.ok) throw new Error('自检失败：' + check.failures.join('；'))
    db.exec('COMMIT')
    log('INFO', `批次 ${name} 已提交：${JSON.stringify(counts)}`)
    return { name, status: 'applied', counts, checks: check.checks }
  } catch (e) {
    try { db.exec('ROLLBACK') } catch { /* 已回滚 */ }
    rollback.removed.length = mark.removed; rollback.merged.length = mark.merged; rollback.tags.length = mark.tags
    log('ERROR', `批次 ${name} 失败，已整批回滚：${e.message}`)
    return { name, status: 'rolled_back', counts: {}, error: String(e.message || e) }
  }
}

function recordRemoved(db, rollback, p, why) {
  rollback.removed.push({ path: p, why })
}

function batchNoise(db, o, rollback, log) {
  const cards = loadCards(db)
  const hits = cards.map((c) => ({ c, n: classifyNoise(c, o.noiseCategories) })).filter((x) => x.n)
  if (hits.length > o.maxDelete) throw new Error(`实时计划软删 ${hits.length} 张，超过 maxDelete=${o.maxDelete}`)
  let shown = 0
  for (const { c, n } of hits) {
    softDeleteCardSync(db, c.path, { changedBy: 'tidy', reason: `整理：噪声卡（${n.reason}）` , quarantineReason: `整理：${n.reason}` })
    recordRemoved(db, rollback, c.path, `noise:${n.category}`)
    if (shown++ < 30) log('INFO', `软删噪声卡 ${c.path}（${n.reason}）`)
  }
  if (hits.length > 30) log('INFO', `… 其余 ${hits.length - 30} 张噪声卡见回滚文件`)
  return { removed: hits.length }
}

function batchMerge(db, o, rollback, log) {
  const cards = loadCards(db).filter((c) => !classifyNoise(c, o.noiseCategories))
  const byPath = new Map(cards.map((c) => [c.path, c]))
  const groups = planDuplicateGroups(cards, o.threshold)
  const total = groups.reduce((n, g) => n + g.absorbs.length, 0)
  if (total > o.maxDelete) throw new Error(`实时计划软删 ${total} 张，超过 maxDelete=${o.maxDelete}`)
  let removed = 0
  const now = new Date().toISOString()
  for (const g of groups) {
    const canon = byPath.get(g.canonical.path)
    let body = canon.body
    let budget = DEFAULTS.mergeLinesPerGroup
    const tagSet = new Set(canon.tags)
    const extra = []
    for (const a of g.absorbs) {
      const src = byPath.get(a.path)
      const lines = budget > 0 ? uniqueLinesAgainst(body + '\n' + extra.join('\n'), src.body, { max: budget }).filter((l) => detectSecrets(l).length === 0) : []
      budget -= lines.length
      extra.push(...lines)
      src.tags.forEach((t) => tagSet.add(t))
    }
    const newBody = withMergeSection(body, extra).trim()
    const tags = [...tagSet].slice(0, DEFAULTS.mergedTagCap)
    rollback.merged.push({ path: canon.path, before: db.prepare('SELECT body, summary, tags, updated_at FROM cards WHERE path = ?').get(canon.path) })
    db.prepare('UPDATE cards SET body = ?, summary = ?, tags = ?, updated_at = ? WHERE path = ?').run(newBody, newBody.slice(0, 200), JSON.stringify(tags), now, canon.path)
    if (!newBody.startsWith(canon.body.trim())) throw new Error(`合并后正文丢失原内容：${canon.path}`)
    for (const a of g.absorbs) {
      softDeleteCardSync(db, a.path, { changedBy: 'tidy', reason: `整理：并入 ${canon.path}（相似度 ${a.sim}）`, quarantineReason: `整理：并入 ${canon.path}` })
      recordRemoved(db, rollback, a.path, `merged-into:${canon.path}`)
      removed++
    }
    log('INFO', `合并：保留 ${canon.path} ← 吸收 [${g.absorbs.map((a) => `${a.path}(${a.sim},独特${a.uniqueLines}行)`).join(', ')}]，并入独特行 ${extra.length}，阈值 ${o.threshold}`)
  }
  return { groups: groups.length, removed }
}

function batchTags(db, o, rollback, log) {
  const plan = planTagNormalize(db.prepare('SELECT id, path, title, tags FROM cards ORDER BY id').all(), { synonyms: o.synonyms, maxTags: o.maxTags })
  const up = db.prepare('UPDATE cards SET tags = ? WHERE path = ?')
  for (const c of plan.changes) {
    const prev = db.prepare('SELECT tags FROM cards WHERE path = ?').get(c.path)
    rollback.tags.push({ path: c.path, before: prev.tags })
    up.run(JSON.stringify(c.new), c.path)
  }
  log('INFO', `标签归一：改动 ${plan.changes.length} 张卡，标签种类 ${plan.distinctBefore} → ${plan.distinctAfter}，同义映射 ${Object.keys(plan.map).length} 条`)
  return { removed: 0, tagsChanged: plan.changes.length, distinctBefore: plan.distinctBefore, distinctAfter: plan.distinctAfter }
}

/** memory_tag_normalize：只做标签批次的 apply（同一套备份 / 自检 / 回滚）。 */
export async function tagNormalize(root, opts = {}) {
  return tidyApply(root, { ...opts, batches: ['tags'] })
}

// ---------------------------------------------------------------------------
// rollback
// ---------------------------------------------------------------------------

/** 依回滚文件还原：被删卡从回收站恢复、保留卡正文/标签还原、标签变更还原。整体一个事务。 */
export async function tidyRollback(root, file, opts = {}) {
  const log = makeLogger(opts)
  const rb = JSON.parse(fs.readFileSync(file, 'utf8'))
  if (rb.tool !== 'memory-eternal-tidy' || rb.version !== 1) return { ok: false, error: '不是有效的整理回滚文件' }
  const db = getDb(root)
  try { db.exec('PRAGMA busy_timeout = 20000') } catch { /* 忽略 */ }
  db.exec('BEGIN IMMEDIATE')
  try {
    let restored = 0; let reverted = 0
    // 必须按「后做的先撤」：标签批次(最后) → 合并批次 → 噪声/被吸收卡恢复。
    // 反过来会让标签批次记录的「合并后标签」盖掉合并前的原标签。
    for (const t of [...rb.tags].reverse()) { db.prepare('UPDATE cards SET tags = ? WHERE path = ?').run(t.before, t.path); reverted++ }
    for (const m of [...rb.merged].reverse()) {
      db.prepare('UPDATE cards SET body = ?, summary = ?, tags = ?, updated_at = ? WHERE path = ?').run(m.before.body, m.before.summary, m.before.tags, m.before.updated_at, m.path); reverted++
    }
    for (const r of rb.removed) {
      const inRecycle = db.prepare("SELECT 1 FROM quarantine WHERE path = ? AND status = 'deleted'").get(r.path)
      if (inRecycle) { restoreCardSync(db, r.path, { changedBy: 'tidy-rollback', reason: '整理回滚' }); restored++ }
    }
    const integrity = db.prepare('PRAGMA integrity_check').get().integrity_check
    if (integrity !== 'ok') throw new Error('integrity_check：' + integrity)
    db.exec('COMMIT')
    log('INFO', `回滚完成：恢复 ${restored} 张卡，还原 ${reverted} 处正文/标签（来自 ${file}）`)
    return { ok: true, restored, reverted }
  } catch (e) {
    try { db.exec('ROLLBACK') } catch { /* 已回滚 */ }
    log('ERROR', `回滚失败，已撤销：${e.message}`)
    return { ok: false, error: String(e.message || e) }
  }
}

// ---------------------------------------------------------------------------
// lint
// ---------------------------------------------------------------------------

/** 健康检查（只读）。 */
export async function tidyLint(root, opts = {}) {
  const plan = await tidyPlan(root, { ...opts, logger: () => {} })
  const db = getDb(root)
  const cards = loadCards(db)
  const tagCount = new Map()
  for (const c of cards) for (const t of c.tags) tagCount.set(t, (tagCount.get(t) || 0) + 1)
  const groups = new Map()
  for (const t of tagCount.keys()) { const k = tagKey(t); groups.set(k, (groups.get(k) || 0) + 1) }
  const q = Object.fromEntries(db.prepare('SELECT status, COUNT(*) n FROM quarantine GROUP BY status').all().map((r) => [r.status, r.n]))
  const oldest = db.prepare("SELECT MIN(deleted_at) d FROM quarantine WHERE status = 'deleted'").get().d
  const m = {
    vault: path.resolve(root),
    total: cards.length,
    threshold: plan.options.threshold,
    noise: plan.noise.length,
    noiseByCategory: plan.noise.reduce((a, n) => ({ ...a, [n.category]: (a[n.category] || 0) + 1 }), {}),
    duplicateGroups: plan.duplicates.length,
    duplicateAbsorbable: plan.duplicates.reduce((n, g) => n + g.absorbs.length, 0),
    tagsDistinct: tagCount.size,
    tagsSingleton: [...tagCount.values()].filter((n) => n === 1).length,
    tagVariantGroups: [...groups.values()].filter((n) => n > 1).length,
    tagsOver4: cards.filter((c) => c.tags.length > plan.options.maxTags).length,
    tagsMalformed: db.prepare('SELECT tags FROM cards').all().filter((r) => parseTags(r.tags).malformed).length,
    secretSuspects: plan.secrets.length,
    secrets: plan.secrets.map((s) => ({ path: s.path, types: s.types })),
    kindMisplaced: plan.kindMisplaced.length,
    kindMisplacedList: plan.kindMisplaced.map((k) => ({ path: k.path, kind: k.kind, expectedKind: k.expectedKind })),
    oversizeRaw: plan.oversizeRaw.map((r) => ({ path: r.path, chars: r.chars })),
    rawMaxChars: plan.options.rawMaxChars,
    quarantine: { pending: q.pending || 0, rejected: q.rejected || 0, deleted: q.deleted || 0 },
    recycleOldest: oldest || null,
    integrity: db.prepare('PRAGMA integrity_check').get().integrity_check,
  }
  return m
}

// ---------------------------------------------------------------------------
// 中文文本渲染（MCP / CLI 共用）。密钥只出现「路径 + 类型」。
// ---------------------------------------------------------------------------

const cap = (arr, n, fmt) => {
  const shown = arr.slice(0, n).map(fmt)
  if (arr.length > n) shown.push(`… 另有 ${arr.length - n} 项`)
  return shown
}

export function formatTidyPlan(plan, { limit = 15 } = {}) {
  const o = plan.options
  const L = [`整理计划（只读，未改动任何数据）· planId=${plan.planId} · 共 ${plan.totals.cards} 张卡 · 重复阈值 ${o.threshold}`]
  L.push('', `一、噪声卡（仅 raw 原文卡）：${plan.noise.length} 张，执行时软删进回收站`)
  L.push(...cap(plan.noise, limit, (n) => `  - [${n.reason}] ${n.path}`))
  const absorbN = plan.duplicates.reduce((n, g) => n + g.absorbs.length, 0)
  L.push('', `二、近似重复：${plan.duplicates.length} 组，共 ${absorbN} 张将被吸收（保留最长，独特行并入「合并补充」，被吸收卡软删）`)
  L.push(...cap(plan.duplicates, limit, (g) => `  - 保留 ${g.canonical.path} ← ${g.absorbs.map((a) => `${a.path}(相似${a.sim}，独特${a.uniqueLines}行)`).join('、')}`))
  L.push('', `三、标签归一：${plan.tags.changes.length} 张卡变更，标签种类 ${plan.tags.distinctBefore} → ${plan.tags.distinctAfter}`)
  const mapEntries = Object.entries(plan.tags.map)
  L.push(...cap(mapEntries, limit, ([a, b]) => `  - 「${a}」→「${b}」`))
  L.push('', `四、kind 与路径前缀不一致：${plan.kindMisplaced.length} 张（只报告，不自动改）`)
  L.push(...cap(plan.kindMisplaced, limit, (k) => `  - ${k.path}：kind=${k.kind}，路径暗示 ${k.expectedKind}`))
  L.push('', `五、明文密钥疑似：${plan.secrets.length} 张（只列卡路径与命中类型，不含值；不自动处理，请人工确认后吊销/改写）`)
  L.push(...cap(plan.secrets, limit, (s) => `  - ${s.path}：${s.types.join('、')}`))
  L.push('', `六、超大 raw 卡（> ${o.rawMaxChars} 字，长会话原文未蒸馏）：${plan.oversizeRaw.length} 张（只报告）`)
  L.push(...cap(plan.oversizeRaw, limit, (r) => `  - ${r.path}（${r.chars} 字）`))
  L.push('', '下一步：memory_tidy_apply（不传 confirm 为预演；confirm=true 才执行，可带 planId 防止库变化后误执行）。')
  return L.join('\n')
}

export function formatTidyApply(res, { limit = 15 } = {}) {
  if (res.error && !res.batches) return `整理未执行：${res.error}`
  const L = []
  if (res.dryRun) {
    L.push(`整理预演（dry-run，库未改动）· planId=${res.planId} · 预计软删 ${res.plannedDeletes} 张`)
    for (const b of res.batches || []) L.push(`  - 批次 ${b.name}：${JSON.stringify(b.counts)}`)
    L.push('', '确认无误后再次调用并传 confirm=true 才会执行（执行前自动备份）。')
    return L.join('\n')
  }
  L.push(res.ok ? '整理已执行完成。' : `整理已中止：${res.error || '有批次失败（已自动回滚该批）'}`)
  if (res.backup) L.push(`备份：${res.backup.path}（已校验：integrity_check=ok，cards=${res.backup.cards}）`)
  for (const b of res.batches) {
    L.push(`  - 批次 ${b.name}：${{ applied: '已提交', rolled_back: '失败，已整批回滚', skipped: '跳过' }[b.status] || b.status} ${JSON.stringify(b.counts || {})}${b.error ? ' · ' + b.error : ''}`)
  }
  if (res.after) L.push(`整理后：主库 ${res.after.cards} 张，回收站 ${res.after.deleted} 张`)
  if (res.rollbackFile) L.push(`回滚文件：${res.rollbackFile}（dsh-memory tidy rollback <文件> 可还原；回收站内的卡 30 天内可恢复）`)
  return L.join('\n')
}

export function formatTidyLint(m, { limit = 10 } = {}) {
  const L = [`记忆库健康检查（只读）· ${m.total} 张卡 · integrity_check=${m.integrity}`]
  L.push(`- 噪声卡：${m.noise} 张${Object.keys(m.noiseByCategory).length ? '（' + Object.entries(m.noiseByCategory).map(([k, v]) => `${k}:${v}`).join('，') + '）' : ''}`)
  L.push(`- 近似重复：${m.duplicateGroups} 组 / 可吸收 ${m.duplicateAbsorbable} 张（阈值 ${m.threshold}）`)
  L.push(`- 标签：${m.tagsDistinct} 种，其中仅出现 1 次 ${m.tagsSingleton} 种；大小写/空格/连字符变体组 ${m.tagVariantGroups} 个；超 4 个标签的卡 ${m.tagsOver4} 张；非法 tags ${m.tagsMalformed} 张`)
  L.push(`- 明文密钥疑似：${m.secretSuspects} 张${m.secretSuspects ? '（只列路径与类型，不含值）' : ''}`)
  L.push(...cap(m.secrets, limit, (s) => `    · ${s.path}：${s.types.join('、')}`))
  L.push(`- kind 与路径前缀不一致：${m.kindMisplaced} 张`)
  L.push(...cap(m.kindMisplacedList, limit, (k) => `    · ${k.path}：kind=${k.kind}，路径暗示 ${k.expectedKind}`))
  L.push(`- 超大 raw 卡（> ${m.rawMaxChars} 字，长会话原文未蒸馏）：${m.oversizeRaw.length} 张`)
  L.push(...cap(m.oversizeRaw, limit, (r) => `    · ${r.path}（${r.chars} 字）`))
  L.push(`- 隔离区：待审 ${m.quarantine.pending}，驳回 ${m.quarantine.rejected}，回收站 ${m.quarantine.deleted}${m.recycleOldest ? '（最早 ' + String(m.recycleOldest).slice(0, 10) + '，满 30 天自动清除）' : ''}`)
  return L.join('\n')
}
