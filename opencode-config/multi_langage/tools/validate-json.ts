/// <reference path="../env.d.ts" />
import { tool } from "@opencode-ai/plugin"
import DESCRIPTION from "./validate-json.txt"
import { readFile, stat } from "node:fs/promises"
import { basename } from "node:path"

function positionToLineCol(content: string, offset: number): { line: number; col: number } {
  let line = 1
  let col = 1
  for (let i = 0; i < offset && i < content.length; i++) {
    if (content[i] === "\n") {
      line++
      col = 1
    } else {
      col++
    }
  }
  return { line, col }
}

function extractSnippet(content: string, errorLine: number, context: number = 3): string {
  const lines = content.split("\n")
  const start = Math.max(0, errorLine - context - 1)
  const end = Math.min(lines.length, errorLine + context)
  const snippet: string[] = []
  for (let i = start; i < end; i++) {
    const lineNum = i + 1
    const marker = lineNum === errorLine ? ">>>" : "   "
    snippet.push(`${marker} ${String(lineNum).padStart(4)}| ${lines[i]}`)
  }
  return snippet.join("\n")
}

function parseErrorPosition(message: string): number | null {
  const match = message.match(/position\s+(\d+)/i)
  return match ? parseInt(match[1], 10) : null
}

type JsonObject = Record<string, unknown>

type Diagnostics = {
  errors: string[]
  warnings: string[]
  schemaName?: string
}

const SUPPORTED_LANGUAGES = new Set(["c_cpp", "python", "go", "lua", "java"])
const MODULE_LANGUAGES = new Set([...SUPPORTED_LANGUAGES, "mixed"])
const CONFIDENCE_VALUES = new Set(["high", "medium", "low"])
const ANALYSIS_BACKENDS = new Set(["lsp", "grep", "language_rule", "manual", "model_inference"])
const SCAN_PROFILE_NAMES = new Set(["quick", "standard", "deep", "paranoid"])

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function asArray(value: unknown): unknown[] | null {
  return Array.isArray(value) ? value : null
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0
}

function requireObject(value: unknown, path: string, errors: string[]): JsonObject | null {
  if (!isObject(value)) {
    errors.push(`${path} must be an object`)
    return null
  }
  return value
}

function requireArray(value: unknown, path: string, errors: string[]): unknown[] {
  const arr = asArray(value)
  if (!arr) {
    errors.push(`${path} must be an array`)
    return []
  }
  return arr
}

function requireString(obj: JsonObject, key: string, path: string, errors: string[]): string | null {
  const value = obj[key]
  if (!isNonEmptyString(value)) {
    errors.push(`${path}.${key} must be a non-empty string`)
    return null
  }
  return value
}

function checkEnum(value: unknown, allowed: Set<string>, path: string, errors: string[]): string | null {
  if (!isNonEmptyString(value)) {
    errors.push(`${path} must be a non-empty string`)
    return null
  }
  if (!allowed.has(value)) {
    errors.push(`${path} has invalid value "${value}"`)
    return null
  }
  return value
}

function checkConfidence(value: unknown, path: string, errors: string[], required = false): void {
  if (value === undefined || value === null) {
    if (required) errors.push(`${path} is required`)
    return
  }
  checkEnum(value, CONFIDENCE_VALUES, path, errors)
}

function stringArray(value: unknown, path: string, errors: string[], required = false): string[] {
  if (value === undefined || value === null) {
    if (required) errors.push(`${path} is required`)
    return []
  }
  const arr = requireArray(value, path, errors)
  return arr.filter((item, index) => {
    if (!isNonEmptyString(item)) {
      errors.push(`${path}[${index}] must be a non-empty string`)
      return false
    }
    return true
  }) as string[]
}

function hasEvidence(value: unknown): boolean {
  return Array.isArray(value) && value.some((item) => isNonEmptyString(item))
}

function validateUniqueId(
  obj: JsonObject,
  path: string,
  seen: Set<string>,
  errors: string[],
): string | null {
  const id = requireString(obj, "id", path, errors)
  if (!id) return null
  if (seen.has(id)) errors.push(`${path}.id duplicates "${id}"`)
  seen.add(id)
  return id
}

function validateProjectModel(data: unknown): Diagnostics {
  const errors: string[] = []
  const warnings: string[] = []
  const root = requireObject(data, "$", errors)
  if (!root) return { errors, warnings, schemaName: "project_model" }

  if (root.schema_version !== "1.0") errors.push("$.schema_version must be \"1.0\"")
  requireString(root, "project_name", "$", errors)
  requireString(root, "source_root", "$", errors)
  requireString(root, "scan_time", "$", errors)
  if (typeof root.lsp_available !== "boolean") errors.push("$.lsp_available must be a boolean")
  if (typeof root.total_files !== "number") errors.push("$.total_files must be a number")
  if (typeof root.total_lines !== "number") errors.push("$.total_lines must be a number")
  requireObject(root.project_profile, "$.project_profile", errors)

  const scanScope = requireObject(root.scan_scope, "$.scan_scope", errors)
  if (scanScope) {
    stringArray(scanScope.include, "$.scan_scope.include", errors, true)
    stringArray(scanScope.exclude, "$.scan_scope.exclude", errors, true)
    stringArray(scanScope.ignored_dirs, "$.scan_scope.ignored_dirs", errors, true)
  }

  const moduleIds = new Set<string>()
  const modules = requireArray(root.modules, "$.modules", errors)
  if (modules.length === 0) warnings.push("$.modules is empty; scanners will only have fallback file grouping")

  for (const [index, item] of modules.entries()) {
    const path = `$.modules[${index}]`
    const module = requireObject(item, path, errors)
    if (!module) continue
    const id = validateUniqueId(module, path, moduleIds, errors)
    requireString(module, "name", path, errors)
    requireString(module, "path", path, errors)
    const language = checkEnum(module.language, MODULE_LANGUAGES, `${path}.language`, errors)
    const languages = stringArray(module.languages, `${path}.languages`, errors, true)
    for (const [langIndex, lang] of languages.entries()) {
      if (!SUPPORTED_LANGUAGES.has(lang)) errors.push(`${path}.languages[${langIndex}] has invalid value "${lang}"`)
    }
    if (language === "mixed" && languages.length < 2) errors.push(`${path}.language is mixed but languages has fewer than 2 entries`)
    if (language && language !== "mixed" && languages.length > 0 && !languages.includes(language)) {
      warnings.push(`${path}.languages does not include primary language "${language}"`)
    }
    checkConfidence(module.confidence, `${path}.confidence`, errors)
    if ((module.risk === "Critical" || module.risk === "High") && !hasEvidence(module.evidence)) {
      errors.push(`${path}.evidence is required for ${module.risk} risk module${id ? ` "${id}"` : ""}`)
    }
  }

  const fileIds = new Set<string>()
  const filePaths = new Set<string>()
  const files = requireArray(root.files, "$.files", errors)
  for (const [index, item] of files.entries()) {
    const path = `$.files[${index}]`
    const file = requireObject(item, path, errors)
    if (!file) continue
    validateUniqueId(file, path, fileIds, errors)
    const filePath = requireString(file, "path", path, errors)
    if (filePath) filePaths.add(filePath)
    checkEnum(file.language, SUPPORTED_LANGUAGES, `${path}.language`, errors)
    if (isNonEmptyString(file.module_id) && !moduleIds.has(file.module_id)) {
      errors.push(`${path}.module_id references unknown module "${file.module_id}"`)
    }
  }

  const entryIds = new Set<string>()
  const entryPoints = requireArray(root.entry_points, "$.entry_points", errors)
  for (const [index, item] of entryPoints.entries()) {
    const path = `$.entry_points[${index}]`
    const entry = requireObject(item, path, errors)
    if (!entry) continue
    validateUniqueId(entry, path, entryIds, errors)
    const file = requireString(entry, "file", path, errors)
    if (file && filePaths.size > 0 && !filePaths.has(file)) {
      errors.push(`${path}.file references file not present in $.files: "${file}"`)
    }
    if (typeof entry.line !== "number") errors.push(`${path}.line must be a number`)
    requireString(entry, "function", path, errors)
    requireString(entry, "type", path, errors)
    requireString(entry, "trust_level", path, errors)
    requireString(entry, "justification", path, errors)
    if (isNonEmptyString(entry.module_id) && !moduleIds.has(entry.module_id)) {
      errors.push(`${path}.module_id references unknown module "${entry.module_id}"`)
    }
    checkConfidence(entry.confidence, `${path}.confidence`, errors, true)
    if (entry.trust_level !== "internal" && !hasEvidence(entry.evidence)) {
      errors.push(`${path}.evidence is required for externally reachable entry point`)
    }
  }

  if (root.attack_surfaces !== undefined) stringArray(root.attack_surfaces, "$.attack_surfaces", errors)
  return { errors, warnings, schemaName: "project_model" }
}

function validateCallGraph(data: unknown): Diagnostics {
  const errors: string[] = []
  const warnings: string[] = []
  const root = requireObject(data, "$", errors)
  if (!root) return { errors, warnings, schemaName: "call_graph" }

  if (root.schema_version !== "1.0") errors.push("$.schema_version must be \"1.0\"")
  if (root.functions !== undefined) errors.push("$.functions is deprecated; use nodes/edges/data_flows")

  const scope = requireObject(root.scope, "$.scope", errors)
  if (scope) {
    if (scope.mode !== "risk_focused") errors.push("$.scope.mode must be \"risk_focused\"")
    stringArray(scope.covered_modules, "$.scope.covered_modules", errors, true)
    stringArray(scope.covered_entry_points, "$.scope.covered_entry_points", errors, true)
    if (typeof scope.truncated !== "boolean") errors.push("$.scope.truncated must be a boolean")
  }

  const nodeIds = new Set<string>()
  const nodes = requireArray(root.nodes, "$.nodes", errors)
  for (const [index, item] of nodes.entries()) {
    const path = `$.nodes[${index}]`
    const node = requireObject(item, path, errors)
    if (!node) continue
    validateUniqueId(node, path, nodeIds, errors)
    checkEnum(node.language, SUPPORTED_LANGUAGES, `${path}.language`, errors)
    requireString(node, "kind", path, errors)
    requireString(node, "symbol", path, errors)
    requireString(node, "file", path, errors)
    if (typeof node.line !== "number") errors.push(`${path}.line must be a number`)
    if (node.risk !== undefined && !["Critical", "High", "Medium", "Low"].includes(String(node.risk))) {
      errors.push(`${path}.risk has invalid value "${node.risk}"`)
    }
  }

  const edgeIds = new Set<string>()
  const edges = requireArray(root.edges, "$.edges", errors)
  for (const [index, item] of edges.entries()) {
    const path = `$.edges[${index}]`
    const edge = requireObject(item, path, errors)
    if (!edge) continue
    validateUniqueId(edge, path, edgeIds, errors)
    const from = requireString(edge, "from", path, errors)
    const to = requireString(edge, "to", path, errors)
    if (from && !nodeIds.has(from)) errors.push(`${path}.from references unknown node "${from}"`)
    if (to && !nodeIds.has(to)) errors.push(`${path}.to references unknown node "${to}"`)
    requireString(edge, "callsite", path, errors)
    requireString(edge, "edge_type", path, errors)
    checkConfidence(edge.confidence, `${path}.confidence`, errors, true)
    checkEnum(edge.analysis_backend, ANALYSIS_BACKENDS, `${path}.analysis_backend`, errors)
    if (!isNonEmptyString(edge.evidence) && !hasEvidence(edge.evidence)) {
      errors.push(`${path}.evidence must be a non-empty string or string array`)
    }
  }

  const flowIds = new Set<string>()
  const flows = requireArray(root.data_flows, "$.data_flows", errors)
  for (const [index, item] of flows.entries()) {
    const path = `$.data_flows[${index}]`
    const flow = requireObject(item, path, errors)
    if (!flow) continue
    validateUniqueId(flow, path, flowIds, errors)
    const source = requireString(flow, "source_node", path, errors)
    const sink = requireString(flow, "sink_node", path, errors)
    if (source && !nodeIds.has(source)) errors.push(`${path}.source_node references unknown node "${source}"`)
    if (sink && !nodeIds.has(sink)) errors.push(`${path}.sink_node references unknown node "${sink}"`)
    requireString(flow, "source_kind", path, errors)
    requireString(flow, "sink_kind", path, errors)
    checkConfidence(flow.confidence, `${path}.confidence`, errors, true)
    const pathNodes = stringArray(flow.path, `${path}.path`, errors, true)
    for (const [nodeIndex, nodeId] of pathNodes.entries()) {
      if (!nodeIds.has(nodeId)) errors.push(`${path}.path[${nodeIndex}] references unknown node "${nodeId}"`)
    }
    if (!hasEvidence(flow.evidence)) warnings.push(`${path}.evidence is recommended for data flow review`)
  }

  if (root.unresolved !== undefined) requireArray(root.unresolved, "$.unresolved", errors)
  return { errors, warnings, schemaName: "call_graph" }
}

function validateScanProfile(data: unknown): Diagnostics {
  const errors: string[] = []
  const warnings: string[] = []
  const root = requireObject(data, "$", errors)
  if (!root) return { errors, warnings, schemaName: "scan_profile" }

  if (root.schema_version !== "1.0") errors.push("$.schema_version must be \"1.0\"")
  checkEnum(root.scan_profile, SCAN_PROFILE_NAMES, "$.scan_profile", errors)
  if (typeof root.max_rounds !== "number" || root.max_rounds < 1) errors.push("$.max_rounds must be a number >= 1")
  const config = requireObject(root.profile_config, "$.profile_config", errors)
  if (config) {
    if (typeof config.max_rounds !== "number" || config.max_rounds < 1) errors.push("$.profile_config.max_rounds must be a number >= 1")
    if (typeof config.min_independent_passes !== "number" || config.min_independent_passes < 1) {
      errors.push("$.profile_config.min_independent_passes must be a number >= 1")
    }
    if (typeof config.high_risk_min_passes !== "number" || config.high_risk_min_passes < 1) {
      errors.push("$.profile_config.high_risk_min_passes must be a number >= 1")
    }
    if (typeof config.max_expansions_per_module !== "number") errors.push("$.profile_config.max_expansions_per_module must be a number")
    if (config.repeat_pass_kinds !== undefined) stringArray(config.repeat_pass_kinds, "$.profile_config.repeat_pass_kinds", errors)
    if (typeof config.rescan_high_risk_empty_modules !== "boolean") {
      errors.push("$.profile_config.rescan_high_risk_empty_modules must be a boolean")
    }
    if (typeof config.require_negative_evidence !== "boolean") errors.push("$.profile_config.require_negative_evidence must be a boolean")
    if (typeof config.duplicate_high_risk_review !== "boolean") {
      errors.push("$.profile_config.duplicate_high_risk_review must be a boolean")
    }
  }
  requireString(root, "source", "$", errors)
  if (root.available_profiles !== undefined) stringArray(root.available_profiles, "$.available_profiles", errors)
  if (root.warnings !== undefined) stringArray(root.warnings, "$.warnings", errors)

  return { errors, warnings, schemaName: "scan_profile" }
}

function collectSchemaDiagnostics(filename: string, data: unknown): Diagnostics | null {
  const lower = filename.toLowerCase()
  if (lower === "project_model.json") return validateProjectModel(data)
  if (lower === "call_graph.json") return validateCallGraph(data)
  if (lower === "scan_profile.json") return validateScanProfile(data)
  return null
}

export default tool({
  description: DESCRIPTION,
  args: {
    path: tool.schema.string().describe("Absolute path to the JSON file to validate"),
  },
  async execute(args) {
    const filePath = args.path

    let fileInfo
    try {
      fileInfo = await stat(filePath)
    } catch {
      return `FAIL: File not found: ${filePath}`
    }

    if (fileInfo.size === 0) {
      return `FAIL: File is empty (0 bytes): ${basename(filePath)}`
    }

    const raw = await readFile(filePath, "utf-8")

    try {
      const data = JSON.parse(raw)
      const keys = typeof data === "object" && data !== null ? Object.keys(data) : []
      const diagnostics = collectSchemaDiagnostics(basename(filePath), data)
      if (diagnostics && diagnostics.errors.length > 0) {
        return [
          `FAIL: ${basename(filePath)}`,
          `  Schema: ${diagnostics.schemaName}`,
          "",
          "Errors:",
          ...diagnostics.errors.map((error) => `  - ${error}`),
          ...(diagnostics.warnings.length > 0
            ? ["", "Warnings:", ...diagnostics.warnings.map((warning) => `  - ${warning}`)]
            : []),
        ].join("\n")
      }
      return [
        `PASS: ${basename(filePath)}`,
        `  Size: ${fileInfo.size} bytes`,
        `  Top-level keys: [${keys.join(", ")}]`,
        ...(diagnostics
          ? [
              `  Schema: ${diagnostics.schemaName}`,
              ...(diagnostics.warnings.length > 0
                ? ["  Warnings:", ...diagnostics.warnings.map((warning) => `    - ${warning}`)]
                : []),
            ]
          : []),
      ].join("\n")
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err)
      const offset = parseErrorPosition(message)
      let errorLine = 1
      let errorCol = 1
      if (offset !== null) {
        const pos = positionToLineCol(raw, offset)
        errorLine = pos.line
        errorCol = pos.col
      }
      const snippet = extractSnippet(raw, errorLine)
      return [
        `FAIL: ${basename(filePath)}`,
        `  Error: ${message}`,
        `  Location: line ${errorLine}, column ${errorCol}`,
        "",
        "Context:",
        snippet,
      ].join("\n")
    }
  },
})
