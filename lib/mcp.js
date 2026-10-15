// 记忆核心 · MCP server（零依赖 stdio JSON-RPC 2.0）。
//
// 让 Claude Code / Codex CLI / Cursor / 任何 MCP 客户端共享同一个记忆库。
// 传输：MCP stdio —— stdin/stdout 每行一条 JSON-RPC 消息；日志一律走 stderr
// （stdout 是协议通道，被 console.log 污染会破坏握手）。
//
// 支持的协议版本：2025-06-18 / 2025-03-26 / 2024-11-05（协商取请求版本）。
// 工具：memory_recall / memory_capture / memory_stats / memory_audit_list（原有 4 个，接口不变），
//       memory_tidy_plan / memory_tidy_apply / memory_lint / memory_tag_normalize（整理，见 lib/tidy.js）。
//
// 整理边界：memory_tidy_plan / memory_lint 只读；memory_tidy_apply / memory_tag_normalize 默认 dry-run，
// 仅当 confirm 为布尔 true 才执行（执行前自动备份，删除只走软删进回收站，不碰审核队列 pending/rejected）。
//
// 审核边界（issue #17）：MCP 侧**只读**。新增的 memory_audit_list 只列待审/驳回，
// 不提供任何 approve/reject —— 否则任何接了 MCP 的智能体都能批准自己刚写进去的卡，
// 「人类把关」就形同不存在（写入路径留在审核中心面板与 CLI：dsh-memory audit）。
//
// 启动：node bin/dsh-memory.mjs mcp   （或 node lib/mcp.js）

import readline from 'node:readline'
import { search, overview, stats, ensureVault, listCards, countCards } from './vault.js'
import { runStandaloneCapture, defaultVaultDir } from './capture-run.js'
import { tidyPlan, tidyApply, tidyLint, tagNormalize, formatTidyPlan, formatTidyApply, formatTidyLint } from './tidy.js'

const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05']
const DEFAULT_PROTOCOL_VERSION = '2024-11-05'

export const MCP_TOOLS = [
  {
    name: 'memory_recall',
    description:
      '从本地记忆核心（Markdown 知识库）检索相关知识卡。需要项目背景、历史决策、之前讨论过的方案、' +
      '或领域知识时调用；返回最相关的卡片摘要。用 query 描述要找的内容，支持中文整词与字符片段检索。' +
      '需要 API key / token / 令牌等**凭证**时也先查这里（查「密钥 目录」）：记忆里存的是目录' +
      '（名字、存放位置、取用命令），**值不在记忆库里**，请按卡片给的本机命令取用，不要直接读凭据文件。',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: '检索关键词或自然语言描述，如「数据库选型」「用户偏好」' },
        limit: { type: 'number', description: '返回卡片数上限，默认 5' },
      },
      required: ['query'],
    },
  },
  {
    name: 'memory_capture',
    description:
      '把一段值得长期复用的对话/知识沉淀进记忆库。配置了 MEMORY_LLM_* 环境变量时会用 LLM 蒸馏压缩成知识卡；' +
      '未配置时降级为原文卡。通常由会话结束 hook 自动调用，手动调用用于显式保存重要结论。',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: '要沉淀的对话文本或知识内容（建议 >120 字符）' },
        source: { type: 'string', description: '来源标记，如 session:xxx / claude-code / codex' },
      },
      required: ['text'],
    },
  },
  {
    name: 'memory_stats',
    description: '查看记忆库概览：总卡数、分类分布、最近新增、vault 目录路径。',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'memory_audit_list',
    description:
      '只读：列出记忆库里待审核 / 已驳回的卡片（不会批准或驳回任何卡）。' +
      '返回文本里的「待处理 N 张」永远是匹配总数；limit 只限制列出条数，被截断时会明确写出还有多少张未显示。' +
      '用于主动提醒用户「有 N 张待审卡」；批准/驳回必须由人在审核中心面板或 CLI（dsh-memory audit approve/reject）显式发起。',
    inputSchema: {
      type: 'object',
      properties: {
        status: { type: 'string', description: 'pending（默认）| rejected | all（= pending + rejected）' },
        limit: { type: 'number', description: '列出条数上限，默认 20（最大 500）；总数不受它影响' },
      },
    },
  },
  {
    name: 'memory_tidy_plan',
    description:
      '只读：扫描记忆库并产出「整理计划」，不改任何数据。包含：噪声卡（定时提醒批次/超时通知/无信息碎片，仅 raw 原文卡）、' +
      '近似重复组（保留最长卡、独特行并入）、标签归一映射、kind 与路径前缀不一致的卡、明文密钥疑似卡（只给卡路径与命中类型，绝不返回值）、超大 raw 卡。' +
      '返回 planId，可在 memory_tidy_apply 里带上以确保执行的正是这份计划。',
    inputSchema: {
      type: 'object',
      properties: {
        threshold: { type: 'number', description: '近似重复相似度阈值（0~1），默认沿用去重阈值 dedupThreshold（环境变量 MEMORY_DEDUP_THRESHOLD > 配置 > 0.62）' },
        maxTags: { type: 'number', description: '每张卡标签数上限，默认 4' },
        rawMaxChars: { type: 'number', description: '超大 raw 卡的字数门槛，默认 6000' },
        noiseCategories: { type: 'array', items: { type: 'string' }, description: '噪声类别，默认 schedule-reminder / timeout-notice / fragment；可加 agent-chatter' },
        synonyms: { type: 'object', description: '自定义标签同义映射，如 {"k8s":"kubernetes"}' },
        limit: { type: 'number', description: '每类最多列出多少项，默认 15' },
      },
    },
  },
  {
    name: 'memory_tidy_apply',
    description:
      '按整理计划执行：噪声卡与被合并的重复卡只做软删（进回收站，30 天内可恢复），合并保留独特信息，标签归一。' +
      '默认是预演（dry-run，不改库）；必须显式传 confirm=true 才执行。执行前自动用 VACUUM INTO 备份并校验，每个批次后自检' +
      '（总数对账 / integrity_check / tags 合法 JSON / 标题路径正文非空），失败自动回滚该批并停止。返回备份与回滚文件路径。',
    inputSchema: {
      type: 'object',
      properties: {
        confirm: { type: 'boolean', description: '必须为 true 才真正执行；缺省 / false = 预演' },
        planId: { type: 'string', description: 'memory_tidy_plan 返回的 planId；库在 plan 之后变化则拒绝执行' },
        batches: { type: 'array', items: { type: 'string' }, description: '要执行的批次：noise / merge / tags，默认全部（按此顺序）' },
        threshold: { type: 'number', description: '近似重复相似度阈值（0~1），默认沿用 dedupThreshold' },
        maxDelete: { type: 'number', description: '单次最多软删张数的保险，默认 50；计划超限则拒绝执行' },
        maxTags: { type: 'number', description: '每张卡标签数上限，默认 4' },
        synonyms: { type: 'object', description: '自定义标签同义映射' },
        noiseCategories: { type: 'array', items: { type: 'string' }, description: '噪声类别' },
      },
    },
  },
  {
    name: 'memory_lint',
    description:
      '只读：记忆库健康检查。输出重复 / 噪声 / 标签膨胀与变体 / 明文密钥疑似（只给卡路径与类型，不含值）/ kind 错放 / ' +
      '超大 raw 卡（长会话原文未蒸馏）/ 隔离区与回收站 / integrity_check 等指标。',
    inputSchema: {
      type: 'object',
      properties: {
        threshold: { type: 'number', description: '近似重复相似度阈值，默认沿用 dedupThreshold' },
        rawMaxChars: { type: 'number', description: '超大 raw 卡字数门槛，默认 6000' },
      },
    },
  },
  {
    name: 'memory_tag_normalize',
    description:
      '标签归一：合并大小写 / 空格 / 连字符变体，超 4 个标签的卡去掉全库仅出现一次且不在标题里的标签，可传自定义同义映射。' +
      '默认预演；confirm=true 才执行（同样先备份、批后自检、失败回滚）。',
    inputSchema: {
      type: 'object',
      properties: {
        synonyms: { type: 'object', description: '自定义同义映射，如 {"k8s":"kubernetes","oncall":"on-call"}' },
        maxTags: { type: 'number', description: '每张卡标签数上限，默认 4' },
        confirm: { type: 'boolean', description: '必须为 true 才真正执行；缺省 / false = 预演' },
      },
    },
  },
]

function toolResult(text, isError = false) {
  return { content: [{ type: 'text', text: String(text) }], ...(isError ? { isError: true } : {}) }
}

/** 整理类工具的公共参数（类型/范围校验在 tidy.js 的 resolveOptions 里做）。 */
function tidyArgs(args) {
  return { threshold: args?.threshold, maxTags: args?.maxTags, rawMaxChars: args?.rawMaxChars, noiseCategories: args?.noiseCategories, synonyms: args?.synonyms }
}

export async function callTool(name, args, vaultRoot, meta = {}) {
  switch (name) {
    case 'memory_recall': {
      const query = String(args?.query || '').trim()
      if (!query) return toolResult('（未提供检索词）')
      const limit = Math.min(Math.max(Number(args?.limit) || 5, 1), 20)
      const hits = await search(vaultRoot, query, { limit, minScore: 2 })
      if (hits.length === 0) return toolResult(`记忆库中没有与「${query}」相关的内容。`)
      const lines = hits.map((h, i) => {
        const tags = h.tags.length ? ` [${h.tags.join(', ')}]` : ''
        const snippet = String(h.summary || '').replace(/\s+/g, ' ').trim().slice(0, 130)
        return `### ${i + 1}. ${h.title}${tags}\n路径：${h.path}\n${snippet}`
      })
      return toolResult(`从记忆核心检索到 ${hits.length} 条相关卡片：\n\n${lines.join('\n\n')}`)
    }
    case 'memory_capture': {
      const text = String(args?.text || '')
      const out = await runStandaloneCapture(vaultRoot, text, {
        source: String(args?.source || meta.submittedBy || 'mcp'),
      })
      if (!out.ok && out.action === 'failed') return toolResult(`沉淀失败：${out.reason}`, true)
      return toolResult(JSON.stringify(out))
    }
    case 'memory_audit_list': {
      await ensureVault(vaultRoot)
      const wanted = String(args?.status || 'pending').toLowerCase()
      const STATUS = { pending: ['pending'], rejected: ['rejected'], approved: ['approved'], deleted: ['deleted'], all: ['pending', 'rejected'], queue: ['pending', 'rejected'] }
      const status = STATUS[wanted] || ['pending']
      // issue #20：默认上限只为控制上下文（不给 agent 灌 500 张卡），但**不能把截断后的条数
      // 当总数报出去** —— 总数取匹配总数，截断时明确写出「还有 N 张未显示」。
      const rawLimit = Number(args?.limit)
      const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(Math.floor(rawLimit), 500) : 20
      const total = await countCards(vaultRoot, { status })
      if (!total) return toolResult(`记忆库里没有 ${wanted} 状态的卡片（vault: ${vaultRoot}）。`)
      const cards = await listCards(vaultRoot, { status, limit })
      const hidden = Math.max(0, total - cards.length)
      const lines = cards.map((c, i) => `${i + 1}. [${c.status}] ${c.kind} · ${c.title}\n   路径：${c.path}`)
      const head = hidden > 0
        ? `待处理 ${total} 张，显示前 ${cards.length} 张（status=${wanted}，vault: ${vaultRoot}）：`
        : `待处理 ${total} 张（status=${wanted}，vault: ${vaultRoot}）：`
      const tail = hidden > 0 ? `\n\n… 还有 ${hidden} 张未显示（可加大 limit，最大 500）。` : ''
      return toolResult(
        `${head}\n\n${lines.join('\n')}${tail}\n\n` +
        '（只读列表。批准/驳回请由用户在「审核中心」面板或运行 dsh-memory audit approve/reject 显式完成。）',
      )
    }
    case 'memory_stats': {
      await ensureVault(vaultRoot)
      const ov = await overview(vaultRoot)
      const s = await stats(vaultRoot)
      return toolResult(JSON.stringify({ vaultDir: vaultRoot, total: ov.total, byKind: ov.byKind, tags: s.tags, week: s.week }, null, 2))
    }
    case 'memory_tidy_plan': {
      await ensureVault(vaultRoot)
      const plan = await tidyPlan(vaultRoot, tidyArgs(args))
      return toolResult(formatTidyPlan(plan, { limit: Math.min(Math.max(Number(args?.limit) || 15, 1), 100) }))
    }
    case 'memory_tidy_apply': {
      await ensureVault(vaultRoot)
      const res = await tidyApply(vaultRoot, { ...tidyArgs(args), confirm: args?.confirm === true, planId: args?.planId ? String(args.planId) : undefined, batches: args?.batches, maxDelete: args?.maxDelete })
      return toolResult(formatTidyApply(res), res.ok === false)
    }
    case 'memory_lint': {
      await ensureVault(vaultRoot)
      return toolResult(formatTidyLint(await tidyLint(vaultRoot, tidyArgs(args))))
    }
    case 'memory_tag_normalize': {
      await ensureVault(vaultRoot)
      const res = await tagNormalize(vaultRoot, { ...tidyArgs(args), confirm: args?.confirm === true })
      return toolResult(formatTidyApply(res), res.ok === false)
    }
    default:
      throw new Error(`未知工具：${name}`)
  }
}

export function startMcpServer({ vaultRoot = defaultVaultDir() } = {}) {
  const rl = readline.createInterface({ input: process.stdin })
  const write = (msg) => process.stdout.write(JSON.stringify(msg) + '\n')
  let pendingCalls = 0
  let closing = false
  // MCP 客户端信息：initialize 时记录（agent 名），供 memory_capture 署名用
  let clientInfo = {}
  const maybeExit = () => { if (closing && pendingCalls === 0) process.exit(0) }

  rl.on('line', (line) => {
    const raw = line.trim()
    if (!raw) return
    let msg
    try {
      msg = JSON.parse(raw)
    } catch {
      write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })
      return
    }
    const { id, method, params } = msg
    // notification（无 id）不回包
    if (id === undefined || id === null) {
      if (method === 'notifications/initialized' || method === 'notifications/cancelled') return
      return
    }
    try {
      if (method === 'initialize') {
        const requested = String(params?.protocolVersion || '')
        const negotiated = SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : DEFAULT_PROTOCOL_VERSION
        clientInfo = params?.clientInfo || {}
        write({
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: negotiated,
            capabilities: { tools: {} },
            serverInfo: { name: 'memory-eternal', version: '1.0.0' },
          },
        })
        return
      }
      if (method === 'ping') {
        write({ jsonrpc: '2.0', id, result: {} })
        return
      }
      if (method === 'tools/list') {
        write({ jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } })
        return
      }
      if (method === 'tools/call') {
        const name = params?.name
        const args = params?.arguments ?? {}
        const sub = clientInfo?.name ? `${clientInfo.name}${clientInfo.version ? '@' + clientInfo.version : ''}` : 'mcp'
        pendingCalls++
        callTool(name, args, vaultRoot, { submittedBy: sub })
          .then((result) => write({ jsonrpc: '2.0', id, result }))
          .catch((error) => write({ jsonrpc: '2.0', id, result: toolResult(String(error?.message || error), true) }))
          .finally(() => { pendingCalls--; maybeExit() })
        return
      }
      write({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } })
    } catch (error) {
      write({ jsonrpc: '2.0', id, error: { code: -32603, message: String(error?.message || error) } })
    }
  })

  rl.on('close', () => { closing = true; maybeExit() })
  process.stderr.write(`[memory-eternal] MCP server ready (vault: ${vaultRoot})\n`)
}

// 作为脚本直接运行（node lib/mcp.js / node bin/dsh-memory.mjs mcp 的转发目标）时自动启动。
if (process.argv[1] && /[\\/]mcp\.js$/.test(process.argv[1])) {
  startMcpServer()
}
