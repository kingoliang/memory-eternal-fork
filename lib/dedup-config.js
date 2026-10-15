// 记忆核心 · 去重相关配置解析（capture 入库去重与 tidy 整理共用）。
//
// 优先级（阈值）：环境变量 MEMORY_DEDUP_THRESHOLD > 共享配置文件 memory-eternal-config.json 的
// dedupThreshold（即 DSH 设置页里的「去重阈值」）> 默认 0.62。
// 显式环境变量压过配置文件，是为了让运维能临时覆盖而不用改设置页。
//
// 其它开关只走环境变量（不动宿主 zod 配置 schema，保持配置面兼容）：
//   MEMORY_DEDUP_TITLE_AWARE=0      关闭「同标题 + 中等正文相似」去重（默认开）
//   MEMORY_DEDUP_TITLE_SIM=0.8      标题相似度下限
//   MEMORY_DEDUP_TITLE_BODY_MIN=0.35 标题命中时正文相似度的下限（低于默认阈值 0.62）
//   MEMORY_DEDUP_MERGE=0            去重命中后退回旧行为「追加更新记录」，而非合并独特行进正文（默认合并）
//   MEMORY_DEDUP_PENDING=0          不检查待审队列里的近似卡（默认检查，命中则跳过不再堆新的待审卡）

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export const DEFAULT_DEDUP_THRESHOLD = 0.62

function readShared(env) {
  try {
    return JSON.parse(fs.readFileSync(path.join(env.DSH_HOME || path.join(os.homedir(), '.dsh'), 'memory-eternal-config.json'), 'utf8'))
  } catch { return null }
}

const num = (v, lo, hi) => {
  if (v === undefined || v === null || String(v).trim() === '') return null
  const n = Number(v)
  return Number.isFinite(n) && n >= lo && n <= hi ? n : null
}
const off = (v) => ['0', 'false', 'off', 'no'].includes(String(v ?? '').trim().toLowerCase())

/**
 * @param {NodeJS.ProcessEnv} env
 * @param {object|null} [shared] 已读好的共享配置；不传则自己读
 */
export function resolveDedupConfig(env = process.env, shared) {
  const cfg = shared === undefined ? readShared(env) : shared
  const threshold = num(env.MEMORY_DEDUP_THRESHOLD, 0, 1) ?? num(cfg?.dedupThreshold, 0, 1) ?? DEFAULT_DEDUP_THRESHOLD
  return {
    threshold,
    titleAware: !off(env.MEMORY_DEDUP_TITLE_AWARE),
    titleSim: num(env.MEMORY_DEDUP_TITLE_SIM, 0, 1) ?? 0.8,
    titleBodyMin: num(env.MEMORY_DEDUP_TITLE_BODY_MIN, 0, 1) ?? 0.35,
    merge: !off(env.MEMORY_DEDUP_MERGE),
    pendingGuard: !off(env.MEMORY_DEDUP_PENDING),
  }
}
