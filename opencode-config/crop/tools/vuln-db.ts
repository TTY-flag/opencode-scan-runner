/// <reference path="../env.d.ts" />
import { tool } from "@opencode-ai/plugin"
import DESCRIPTION from "./vuln-db.txt"
import { Database } from "bun:sqlite"
import { writeFile, mkdir } from "node:fs/promises"
import { dirname } from "node:path"

const SCHEMA = `
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    phase TEXT NOT NULL DEFAULT 'candidate'
        CHECK(phase IN ('candidate', 'verified')),
    source_agent TEXT NOT NULL,
    source_module TEXT,
    type TEXT,
    cwe TEXT,
    severity TEXT,
    description TEXT,
    file TEXT,
    line_start INTEGER,
    line_end INTEGER,
    function_name TEXT,
    code_snippet TEXT,
    data_flow TEXT,
    pre_validated INTEGER DEFAULT 0,
    cross_module INTEGER DEFAULT 0,
    modules_involved TEXT,
    confidence INTEGER,
    status TEXT CHECK(status IN ('CONFIRMED','LIKELY','POSSIBLE','FALSE_POSITIVE') OR status IS NULL),
    original_severity TEXT,
    verified_severity TEXT,
    scoring_details TEXT,
    veto_applied INTEGER DEFAULT 0,
    veto_reason TEXT,
    verification_reason TEXT,
    control_flow TEXT,
    mitigations_found TEXT,
    source_agents TEXT,
    dedup_kept INTEGER DEFAULT 1,
    merged_into TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS agent_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_name TEXT NOT NULL,
    module_name TEXT,
    phase TEXT,
    status TEXT,
    message TEXT,
    item_count INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_vuln_phase ON vulnerabilities(phase);
CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vuln_module ON vulnerabilities(source_module);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_file ON vulnerabilities(file);
CREATE INDEX IF NOT EXISTS idx_vuln_dedup ON vulnerabilities(file, line_start, function_name, type);
CREATE INDEX IF NOT EXISTS idx_vuln_kept ON vulnerabilities(dedup_kept);
`

function openDb(dbPath: string): Database {
  const db = new Database(dbPath)
  db.exec("PRAGMA journal_mode=WAL")
  db.exec("PRAGMA busy_timeout=5000")
  return db
}

const SEVERITY_ORDER: Record<string, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
}

function severityRank(s: string | null): number {
  return SEVERITY_ORDER[s ?? ""] ?? 0
}

interface VulnRow {
  id: string
  source_agent: string
  source_module: string | null
  file: string | null
  line_start: number | null
  function_name: string | null
  type: string | null
  severity: string | null
  [key: string]: unknown
}

function handleInit(dbPath: string): string {
  const dir = dirname(dbPath)
  const fs = require("node:fs")
  fs.mkdirSync(dir, { recursive: true })
  const db = openDb(dbPath)
  try {
    db.exec(SCHEMA)
    return `Database initialized: ${dbPath}\nTables: vulnerabilities, scan_metadata, agent_log`
  } finally {
    db.close()
  }
}

function handleInsert(dbPath: string, vulnsJson: string): string {
  const vulns = JSON.parse(vulnsJson) as Record<string, unknown>[]
  if (vulns.length === 0) return "No vulnerabilities to insert"

  const db = openDb(dbPath)
  try {
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO vulnerabilities (
        id, source_agent, source_module, type, cwe, severity, description,
        file, line_start, line_end, function_name, code_snippet, data_flow,
        pre_validated, cross_module, modules_involved, source_agents
      ) VALUES (
        $id, $source_agent, $source_module, $type, $cwe, $severity, $description,
        $file, $line_start, $line_end, $function_name, $code_snippet, $data_flow,
        $pre_validated, $cross_module, $modules_involved, $source_agents
      )
    `)

    const tx = db.transaction(() => {
      for (const v of vulns) {
        stmt.run({
          $id: v.id,
          $source_agent: v.source_agent,
          $source_module: v.source_module ?? null,
          $type: v.type ?? null,
          $cwe: v.cwe ?? null,
          $severity: v.severity ?? null,
          $description: v.description ?? null,
          $file: v.file ?? null,
          $line_start: v.line_start ?? null,
          $line_end: v.line_end ?? null,
          $function_name: v.function ?? v.function_name ?? null,
          $code_snippet: v.code_snippet ?? null,
          $data_flow: v.data_flow ?? null,
          $pre_validated: v.pre_validated ? 1 : 0,
          $cross_module: v.cross_module ? 1 : 0,
          $modules_involved: Array.isArray(v.modules_involved) ? JSON.stringify(v.modules_involved) : v.modules_involved ?? null,
          $source_agents: v.source_agent ? JSON.stringify([v.source_agent]) : null,
        })
      }
    })
    tx()

    return `Inserted ${vulns.length} vulnerabilities into database`
  } finally {
    db.close()
  }
}

function handleQuery(db: Database, args: Record<string, unknown>): string {
  const conditions: string[] = ["dedup_kept = 1"]
  const params: Record<string, unknown> = {}

  if (args.phase) {
    conditions.push("phase = $phase")
    params.$phase = args.phase
  }
  if (args.status) {
    conditions.push("status = $status")
    params.$status = args.status
  }
  if (args.source_module) {
    conditions.push("source_module = $source_module")
    params.$source_module = args.source_module
  }
  if (args.source_agent) {
    conditions.push("source_agent = $source_agent")
    params.$source_agent = args.source_agent
  }
  if (args.min_confidence != null) {
    conditions.push("confidence >= $min_confidence")
    params.$min_confidence = args.min_confidence
  }
  if (args.exclude_status) {
    conditions.push("status != $exclude_status")
    params.$exclude_status = args.exclude_status
  }
  if (args.ids) {
    const idList = (args.ids as string).split(",").map((s) => s.trim())
    const placeholders = idList.map((_, i) => `$id_${i}`).join(",")
    conditions.push(`id IN (${placeholders})`)
    idList.forEach((id, i) => {
      params[`$id_${i}`] = id
    })
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : ""
  let sql = `SELECT * FROM vulnerabilities ${where} ORDER BY
    CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
    confidence DESC`

  if (args.limit) {
    sql += ` LIMIT ${Number(args.limit)}`
    if (args.offset) sql += ` OFFSET ${Number(args.offset)}`
  }

  const rows = db.prepare(sql).all(params)

  for (const row of rows as Record<string, unknown>[]) {
    for (const key of ["modules_involved", "scoring_details", "source_agents", "mitigations_found"]) {
      if (typeof row[key] === "string") {
        try {
          row[key] = JSON.parse(row[key] as string)
        } catch {}
      }
    }
    row.pre_validated = row.pre_validated === 1
    row.cross_module = row.cross_module === 1
    row.veto_applied = row.veto_applied === 1
    row.dedup_kept = row.dedup_kept === 1
  }

  return JSON.stringify(rows, null, 2)
}

function handleUpdate(db: Database, id: string, fieldsJson: string): string {
  const fields = JSON.parse(fieldsJson) as Record<string, unknown>
  fields.phase = "verified"
  fields.updated_at = new Date().toISOString()

  const setClauses: string[] = []
  const params: Record<string, unknown> = { $id: id }

  for (const [key, value] of Object.entries(fields)) {
    const paramName = `$${key}`
    setClauses.push(`${key} = ${paramName}`)
    if (typeof value === "object" && value !== null) {
      params[paramName] = JSON.stringify(value)
    } else if (typeof value === "boolean") {
      params[paramName] = value ? 1 : 0
    } else {
      params[paramName] = value
    }
  }

  const sql = `UPDATE vulnerabilities SET ${setClauses.join(", ")} WHERE id = $id`
  const result = db.prepare(sql).run(params)
  return `Updated vulnerability ${id} (${result.changes} row affected)`
}

function handleBatchUpdate(db: Database, updatesJson: string): string {
  const updates = JSON.parse(updatesJson) as Array<{ id: string; fields: Record<string, unknown> }>
  let totalChanged = 0

  const tx = db.transaction(() => {
    for (const { id, fields } of updates) {
      fields.phase = "verified"
      fields.updated_at = new Date().toISOString()

      const setClauses: string[] = []
      const params: Record<string, unknown> = { $id: id }

      for (const [key, value] of Object.entries(fields)) {
        const paramName = `$${key}`
        setClauses.push(`${key} = ${paramName}`)
        if (typeof value === "object" && value !== null) {
          params[paramName] = JSON.stringify(value)
        } else if (typeof value === "boolean") {
          params[paramName] = value ? 1 : 0
        } else {
          params[paramName] = value
        }
      }

      const sql = `UPDATE vulnerabilities SET ${setClauses.join(", ")} WHERE id = $id`
      const result = db.prepare(sql).run(params)
      totalChanged += result.changes
    }
  })
  tx()

  return `Batch updated ${updates.length} vulnerabilities (${totalChanged} rows affected)`
}

function handleDedup(db: Database): string {
  const dupes = db
    .prepare(
      `SELECT file, line_start, function_name, type, GROUP_CONCAT(id) as ids, COUNT(*) as cnt
     FROM vulnerabilities
     WHERE phase = 'candidate' AND dedup_kept = 1
     GROUP BY file, line_start, function_name, type
     HAVING cnt > 1`,
    )
    .all() as Array<{ file: string; line_start: number; function_name: string; type: string; ids: string; cnt: number }>

  let mergedCount = 0
  let groupCount = 0

  const tx = db.transaction(() => {
    for (const group of dupes) {
      groupCount++
      const ids = group.ids.split(",")
      const rows = db
        .prepare(`SELECT id, severity, source_agent, source_agents FROM vulnerabilities WHERE id IN (${ids.map(() => "?").join(",")})`)
        .all(...ids) as Array<{ id: string; severity: string; source_agent: string; source_agents: string | null }>

      rows.sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
      const primary = rows[0]
      const others = rows.slice(1)

      const allAgents = new Set<string>()
      for (const r of rows) {
        if (r.source_agents) {
          try {
            for (const a of JSON.parse(r.source_agents)) allAgents.add(a)
          } catch {}
        }
        if (r.source_agent) allAgents.add(r.source_agent)
      }

      db.prepare(`UPDATE vulnerabilities SET source_agents = ?, updated_at = datetime('now') WHERE id = ?`).run(
        JSON.stringify([...allAgents]),
        primary.id,
      )

      for (const other of others) {
        db.prepare(`UPDATE vulnerabilities SET dedup_kept = 0, merged_into = ?, updated_at = datetime('now') WHERE id = ?`).run(
          primary.id,
          other.id,
        )
        mergedCount++
      }
    }
  })
  tx()

  const total = (db.prepare("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE phase = 'candidate'").get() as { cnt: number }).cnt
  const kept = (
    db.prepare("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE phase = 'candidate' AND dedup_kept = 1").get() as { cnt: number }
  ).cnt

  return [
    `Deduplication complete`,
    `  Duplicate groups found: ${groupCount}`,
    `  Entries merged: ${mergedCount}`,
    `  Total candidates: ${total}`,
    `  After dedup: ${kept}`,
  ].join("\n")
}

function handleStats(db: Database, phase?: string): string {
  const wherePhase = phase ? `WHERE phase = '${phase}' AND dedup_kept = 1` : "WHERE dedup_kept = 1"

  const total = (db.prepare(`SELECT COUNT(*) as cnt FROM vulnerabilities ${wherePhase}`).get() as { cnt: number }).cnt

  const byStatus = db
    .prepare(`SELECT status, COUNT(*) as cnt FROM vulnerabilities ${wherePhase} GROUP BY status ORDER BY cnt DESC`)
    .all() as Array<{ status: string | null; cnt: number }>

  const bySeverity = db
    .prepare(
      `SELECT COALESCE(verified_severity, severity) as sev, COUNT(*) as cnt FROM vulnerabilities ${wherePhase} GROUP BY sev ORDER BY
      CASE sev WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END`,
    )
    .all() as Array<{ sev: string; cnt: number }>

  const byModule = db
    .prepare(`SELECT source_module, COUNT(*) as cnt FROM vulnerabilities ${wherePhase} GROUP BY source_module ORDER BY cnt DESC`)
    .all() as Array<{ source_module: string; cnt: number }>

  const lines = [`Total: ${total}`, "", "By status:"]
  for (const r of byStatus) lines.push(`  ${r.status ?? "(none)"}: ${r.cnt}`)
  lines.push("", "By severity:")
  for (const r of bySeverity) lines.push(`  ${r.sev ?? "(none)"}: ${r.cnt}`)
  lines.push("", "By module:")
  for (const r of byModule) lines.push(`  ${r.source_module ?? "(none)"}: ${r.cnt}`)

  return lines.join("\n")
}

function handleLog(db: Database, args: Record<string, unknown>): string {
  db.prepare(
    `INSERT INTO agent_log (agent_name, module_name, phase, status, message, item_count)
     VALUES ($agent_name, $module_name, $phase, $status, $message, $item_count)`,
  ).run({
    $agent_name: args.agent_name,
    $module_name: args.module_name ?? null,
    $phase: args.phase ?? null,
    $status: args.status ?? null,
    $message: args.message ?? null,
    $item_count: args.item_count ?? null,
  })
  return `Logged event for ${args.agent_name}`
}

async function handleExportJson(db: Database, args: Record<string, unknown>): Promise<string> {
  const json = handleQuery(db, args)
  const rows = JSON.parse(json)
  const output = args.output as string
  await mkdir(dirname(output), { recursive: true })
  await writeFile(output, JSON.stringify({ vulnerabilities: rows }, null, 2), "utf-8")
  return `Exported ${rows.length} vulnerabilities to ${output}`
}

export default tool({
  description: DESCRIPTION,
  args: {
    command: tool.schema
      .enum(["init", "insert", "query", "update", "batch-update", "dedup", "stats", "log", "export-json"])
      .describe("The operation to perform"),
    db_path: tool.schema.string().describe("Absolute path to the SQLite database file"),
    vulnerabilities: tool.schema.string().optional().describe("JSON array of vulnerability objects (for insert)"),
    id: tool.schema.string().optional().describe("Vulnerability ID (for update)"),
    fields: tool.schema.string().optional().describe("JSON object of fields to update (for update)"),
    updates: tool.schema.string().optional().describe("JSON array of {id, fields} objects (for batch-update)"),
    phase: tool.schema.string().optional().describe("Filter by phase: candidate or verified"),
    status: tool.schema.string().optional().describe("Filter by status: CONFIRMED, LIKELY, POSSIBLE, FALSE_POSITIVE"),
    source_module: tool.schema.string().optional().describe("Filter by module name"),
    source_agent: tool.schema.string().optional().describe("Filter by source agent name"),
    min_confidence: tool.schema.number().optional().describe("Minimum confidence score"),
    exclude_status: tool.schema.string().optional().describe("Exclude vulnerabilities with this status"),
    limit: tool.schema.number().optional().describe("Max results to return"),
    offset: tool.schema.number().optional().describe("Pagination offset"),
    ids: tool.schema.string().optional().describe("Comma-separated vulnerability IDs to query"),
    agent_name: tool.schema.string().optional().describe("Agent name (for log)"),
    module_name: tool.schema.string().optional().describe("Module name (for log)"),
    message: tool.schema.string().optional().describe("Log message"),
    item_count: tool.schema.number().optional().describe("Item count (for log)"),
    output: tool.schema.string().optional().describe("Output file path (for export-json)"),
  },
  async execute(args) {
    const { command, db_path } = args

    if (command === "init") {
      return handleInit(db_path)
    }

    if (command === "insert") {
      if (!args.vulnerabilities) return "Error: vulnerabilities parameter required for insert"
      return handleInsert(db_path, args.vulnerabilities)
    }

    const db = openDb(db_path)
    try {
      switch (command) {
        case "query":
          return handleQuery(db, args)
        case "update":
          if (!args.id || !args.fields) return "Error: id and fields parameters required for update"
          return handleUpdate(db, args.id, args.fields)
        case "batch-update":
          if (!args.updates) return "Error: updates parameter required for batch-update"
          return handleBatchUpdate(db, args.updates)
        case "dedup":
          return handleDedup(db)
        case "stats":
          return handleStats(db, args.phase as string | undefined)
        case "log":
          if (!args.agent_name) return "Error: agent_name required for log"
          return handleLog(db, args)
        case "export-json":
          if (!args.output) return "Error: output parameter required for export-json"
          return await handleExportJson(db, args)
        default:
          return `Unknown command: ${command}`
      }
    } finally {
      db.close()
    }
  },
})
