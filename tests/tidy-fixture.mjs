// 整理功能测试夹具：构造一个带「噪声 / 近似重复 / 标签变体 / kind 错放 / 密钥疑似 / 超大 raw」的 vault。
// 全部用固定种子伪随机，保证确定性（相似度断言不会抖）。
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { getDb, nextCardId, closeAllDb } from '../lib/db.js'
import { ensureVault } from '../lib/vault.js'

let seed = 12345
const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296 }
export const cjk = (n) => Array.from({ length: n }, () => String.fromCharCode(0x4e00 + Math.floor(rnd() * 0x2000))).join('')
export const line = () => cjk(40)

export async function tmpDir(prefix = 'mc-tidy-') {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix))
}

export function insertCard(db, { path: p, kind = 'knowledge', title, tags = [], body, status = 'approved', updatedAt, rawTags }) {
  const id = nextCardId(db)
  const now = updatedAt || new Date().toISOString()
  db.prepare(`INSERT INTO cards (id, path, kind, title, tags, body, summary, status, source, submitted_by, severity, reason, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'test', 'test', 'info', '', ?, ?)`)
    .run(id, p, kind, title, rawTags ?? JSON.stringify(tags), body, body.slice(0, 200), status, now, now)
  return id
}

/** 假密钥：运行时拼接，测试文件里不出现完整字面量。 */
export const FAKE = {
  github: () => 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8',
  aws: () => 'AKIA' + 'IOSFODNN7EXAMPLQ',
  pass: () => 'Zx9' + 'kLm2Qw8Rt5Yp4Uv7',
  pemHead: () => '-----BEGIN ' + 'RSA PRIVATE KEY-----',
}

export async function buildFixture() {
  const root = await tmpDir()
  await ensureVault(root)
  const db = getDb(root)
  const L = Array.from({ length: 8 }, line)
  const U1 = '独特补充一：' + cjk(30)
  const U2 = '独特补充二：' + cjk(30)
  const ids = {}
  // 近似重复组 A：canon（最长）+ 两张被吸收
  ids.canon = insertCard(db, { path: '02-Projects/sop-canon.md', kind: 'project', title: 'COMBO 值班 SOP', tags: ['sop', 'combo'], body: '# COMBO 值班 SOP\n\n' + L.slice(0, 7).join('\n') })
  ids.dup1 = insertCard(db, { path: '02-Projects/sop-dup1.md', kind: 'project', title: 'COMBO 值班 SOP 2', tags: ['sop'], body: '# COMBO 值班 SOP\n\n' + L.slice(0, 6).join('\n') + '\n' + U1 })
  ids.dup2 = insertCard(db, { path: '02-Projects/sop-dup2.md', kind: 'project', title: 'COMBO 值班 SOP 3', tags: ['combo', 'oncall'], body: '# COMBO 值班 SOP\n\n' + L.slice(0, 6).join('\n') + '\n' + U2 })
  // 完全无关的卡（不得被误合并）
  ids.other = insertCard(db, { path: '02-Projects/other.md', kind: 'project', title: '无关项目', tags: ['other'], body: '# 无关项目\n\n' + cjk(300) })
  // 噪声（均为 raw）
  ids.n1 = insertCard(db, { path: '04-Content/n1.md', kind: 'content', title: '[SCHEDULE REMINDER] 例行', tags: ['raw'], body: '[SCHEDULE REMINDER] ' + cjk(200) })
  ids.n2 = insertCard(db, { path: '04-Content/n2.md', kind: 'content', title: '[SCHEDULE REMINDER] 例行二', tags: ['raw'], body: '[SCHEDULE REMINDER] ' + cjk(200) })
  ids.n3 = insertCard(db, { path: '04-Content/n3.md', kind: 'content', title: 'hello', tags: ['raw'], body: 'hello' })
  // 非 raw 的短卡：不是噪声（安全边界）
  ids.shortKeep = insertCard(db, { path: '03-Knowledge/short-keep.md', kind: 'knowledge', title: '短但有用', tags: ['note'], body: '端口 7999' })
  // 标签变体
  ids.t1 = insertCard(db, { path: '07-Tools/t1.md', kind: 'tool', title: 'Docker 笔记一', tags: ['Docker', 'Docker-Compose'], body: cjk(300) })
  ids.t2 = insertCard(db, { path: '07-Tools/t2.md', kind: 'tool', title: 'Docker 笔记二', tags: ['docker', 'docker compose'], body: cjk(300) })
  ids.t3 = insertCard(db, { path: '07-Tools/t3.md', kind: 'tool', title: '标签膨胀', tags: ['docker', 'a-单', 'b-单', 'c-单', 'd-单', 'e-单'], body: cjk(300) })
  // kind 错放：路径在 03-Knowledge 但 kind=tool
  ids.mis = insertCard(db, { path: '03-Knowledge/misplaced.md', kind: 'tool', title: '错放', tags: ['note'], body: cjk(300) })
  // 密钥疑似
  ids.s1 = insertCard(db, { path: '07-Tools/s1.md', kind: 'tool', title: '含 github token', tags: ['secret-test'], body: '部署用 token ' + FAKE.github() + ' 请勿外传。' + cjk(100) })
  ids.s2 = insertCard(db, { path: '07-Tools/s2.md', kind: 'tool', title: '含口令赋值', tags: ['secret-test'], body: 'password = "' + FAKE.pass() + '"\n' + FAKE.aws() + '\n' + cjk(100) })
  ids.s3 = insertCard(db, { path: '07-Tools/s3.md', kind: 'tool', title: '含私钥头', tags: ['secret-test'], body: FAKE.pemHead() + '\n' + cjk(100) })
  // 误报防线：占位符 / 只有名字的密钥目录
  ids.fp1 = insertCard(db, { path: '07-Tools/fp1.md', kind: 'tool', title: '密钥目录', tags: ['catalog'], body: '密钥目录：OPENAI_API_KEY 存放于 ~/.config/keys，取用 `get-key openai`。\nAPI_KEY=your_api_key_here\npassword: ${PASSWORD}' })
  // 超大 raw 卡
  ids.big = insertCard(db, { path: '04-Content/big-raw.md', kind: 'content', title: '长会话原文', tags: ['raw'], body: cjk(9000) })
  closeAllDbKeep()
  return { root, db, ids, L, U1, U2 }
}
function closeAllDbKeep() { /* 连接保持打开：测试直接复用单例 */ }

/** 取全库内容指纹（用于证明只读/回滚后库没变）。 */
export function fingerprint(db) {
  const rows = (t) => db.prepare(`SELECT id, path, kind, title, tags, body, status, updated_at FROM ${t} ORDER BY path`).all()
  return JSON.stringify({ cards: rows('cards'), quarantine: rows('quarantine'), upd: db.prepare('SELECT * FROM card_updates ORDER BY id').all() })
}
export { closeAllDb }
