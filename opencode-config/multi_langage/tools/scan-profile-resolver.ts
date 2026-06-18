/// <reference path="../env.d.ts" />
import { tool } from "@opencode-ai/plugin"
import DESCRIPTION from "./scan-profile-resolver.txt"
import { constants } from "node:fs"
import { access, mkdir, readFile, writeFile } from "node:fs/promises"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

interface ProfileConfig {
  max_rounds: number
  min_independent_passes: number
  high_risk_min_passes: number
  max_expansions_per_module: number
  repeat_pass_kinds: string[]
  rescan_high_risk_empty_modules: boolean
  require_negative_evidence: boolean
  duplicate_high_risk_review: boolean
  description: string
}

interface ProfilesFile {
  default_profile: string
  profiles: Record<string, ProfileConfig>
  rounds: Record<string, string>
}

const BUILTIN_PROFILES: ProfilesFile = {
  default_profile: "deep",
  profiles: {
    quick: {
      max_rounds: 1,
      min_independent_passes: 1,
      high_risk_min_passes: 1,
      max_expansions_per_module: 0,
      repeat_pass_kinds: ["primary"],
      rescan_high_risk_empty_modules: false,
      require_negative_evidence: false,
      duplicate_high_risk_review: false,
      description: "Fast smoke scan. One broad pass only.",
    },
    standard: {
      max_rounds: 2,
      min_independent_passes: 1,
      high_risk_min_passes: 1,
      max_expansions_per_module: 1,
      repeat_pass_kinds: ["primary", "sink_to_source"],
      rescan_high_risk_empty_modules: true,
      require_negative_evidence: true,
      duplicate_high_risk_review: false,
      description: "Default balanced scan with one follow-up round for shallow or empty high-risk areas.",
    },
    deep: {
      max_rounds: 4,
      min_independent_passes: 2,
      high_risk_min_passes: 2,
      max_expansions_per_module: 3,
      repeat_pass_kinds: ["primary", "sink_to_source", "negative_review", "cross_module"],
      rescan_high_risk_empty_modules: true,
      require_negative_evidence: true,
      duplicate_high_risk_review: true,
      description: [
        "Longer audit scan. Adds low-coverage follow-up, sink-to-source review,",
        "high-risk negative review, and cross-module follow-up.",
      ].join(" "),
    },
    paranoid: {
      max_rounds: 5,
      min_independent_passes: 2,
      high_risk_min_passes: 3,
      max_expansions_per_module: 5,
      repeat_pass_kinds: [
        "primary",
        "sink_to_source",
        "negative_review",
        "cross_module",
        "disagreement_review",
      ],
      rescan_high_risk_empty_modules: true,
      require_negative_evidence: true,
      duplicate_high_risk_review: true,
      description: [
        "Maximum-depth scan for unstable AI runs.",
        "Rechecks high-risk empty modules and unresolved graph edges more aggressively.",
      ].join(" "),
    },
  },
  rounds: {
    "1": "broad coverage: entrypoint, sink, and module sweep work items",
    "2": [
      "low-coverage follow-up: expansion_needed, shallow, partial,",
      "unresolved call graph, missing source/sink evidence",
    ].join(" "),
    "3": [
      "independent repeat pass: high-risk modules are rescanned from a different viewpoint",
      "even if coverage is complete",
    ].join(" "),
    "4": "cross-module deepening: data/security flows across module and language boundaries",
    "5": "consistency review: duplicate high-risk review and disagreement checks",
  },
}

function unique(values: string[]): string[] {
  return [...new Set(values.map((value) => resolve(value)))]
}

function candidatePaths(projectRoot: string, harnessRoot?: string): string[] {
  const paths = [join(projectRoot, ".opencode", "scan-profiles.json")]
  if (harnessRoot) {
    paths.push(join(harnessRoot, "scan-profiles.json"))
    paths.push(join(harnessRoot, ".opencode", "scan-profiles.json"))
  }
  const toolDir = dirname(fileURLToPath(import.meta.url))
  paths.push(join(toolDir, "..", "scan-profiles.json"))
  return unique(paths)
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path, constants.R_OK)
    return true
  } catch {
    return false
  }
}

function isProfilesFile(value: unknown): value is ProfilesFile {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false
  const root = value as Record<string, unknown>
  if (typeof root.default_profile !== "string") return false
  if (typeof root.profiles !== "object" || root.profiles === null || Array.isArray(root.profiles)) return false
  return true
}

function normalizeProfile(name: string, config: ProfileConfig): ProfileConfig {
  const fallback = BUILTIN_PROFILES.profiles[name] ?? BUILTIN_PROFILES.profiles.deep
  const hasRepeatPassKinds =
    Array.isArray(config.repeat_pass_kinds) && config.repeat_pass_kinds.length > 0
  const repeatPassKinds = hasRepeatPassKinds
    ? config.repeat_pass_kinds
    : fallback.repeat_pass_kinds
  return {
    ...fallback,
    ...config,
    min_independent_passes: config.min_independent_passes ?? fallback.min_independent_passes,
    high_risk_min_passes: config.high_risk_min_passes ?? fallback.high_risk_min_passes,
    repeat_pass_kinds: repeatPassKinds,
  }
}

async function loadProfiles(paths: string[]): Promise<{ profiles: ProfilesFile; source: string; warnings: string[] }> {
  const warnings: string[] = []
  for (const path of paths) {
    if (!(await exists(path))) continue
    try {
      const raw = await readFile(path, "utf-8")
      const parsed = JSON.parse(raw)
      if (!isProfilesFile(parsed)) {
        warnings.push(`${path}: invalid scan profiles schema, using next fallback`)
        continue
      }
      return { profiles: parsed, source: path, warnings }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      warnings.push(`${path}: failed to parse (${message}), using next fallback`)
    }
  }
  warnings.push("scan-profiles.json not found; using built-in default profiles")
  return { profiles: BUILTIN_PROFILES, source: "builtin", warnings }
}

function selectProfile(
  profiles: ProfilesFile,
  requested?: string,
): { name: string; config: ProfileConfig; warnings: string[] } {
  const warnings: string[] = []
  const normalizedRequested = requested?.trim().toLowerCase()
  if (normalizedRequested && profiles.profiles[normalizedRequested]) {
    return {
      name: normalizedRequested,
      config: normalizeProfile(normalizedRequested, profiles.profiles[normalizedRequested]),
      warnings,
    }
  }
  if (normalizedRequested) {
    warnings.push(`requested scan_profile "${requested}" was not found; using configured default`)
  }
  if (profiles.profiles[profiles.default_profile]) {
    return {
      name: profiles.default_profile,
      config: normalizeProfile(profiles.default_profile, profiles.profiles[profiles.default_profile]),
      warnings,
    }
  }
  if (profiles.profiles.deep) {
    warnings.push(`default_profile "${profiles.default_profile}" was not found; using deep`)
    return { name: "deep", config: normalizeProfile("deep", profiles.profiles.deep), warnings }
  }
  const first = Object.keys(profiles.profiles)[0]
  if (first) {
    warnings.push(`deep profile was not found; using first available profile "${first}"`)
    return { name: first, config: normalizeProfile(first, profiles.profiles[first]), warnings }
  }
  warnings.push("no valid profiles were found; using built-in deep")
  return { name: "deep", config: BUILTIN_PROFILES.profiles.deep, warnings }
}

export default tool({
  description: DESCRIPTION,
  args: {
    project_root: tool.schema.string().describe("Absolute path to the target project root"),
    context_dir: tool.schema.string().describe("Absolute path to {SCAN_OUTPUT}/.context"),
    scan_profile: tool.schema.string().optional().describe("Requested scan profile: quick, standard, deep, paranoid"),
    harness_root: tool.schema
      .string()
      .optional()
      .describe("Optional absolute path to .opencode or a repo root containing .opencode"),
    output_path: tool.schema
      .string()
      .optional()
      .describe("Optional absolute output path, defaults to {context_dir}/scan_profile.json"),
  },
  async execute(args) {
    const paths = candidatePaths(args.project_root, args.harness_root)
    const loaded = await loadProfiles(paths)
    const selected = selectProfile(loaded.profiles, args.scan_profile)
    const output = args.output_path ?? join(args.context_dir, "scan_profile.json")
    const warnings = [...loaded.warnings, ...selected.warnings]
    const normalized = {
      schema_version: "1.0",
      scan_profile: selected.name,
      max_rounds: selected.config.max_rounds,
      profile_config: selected.config,
      rounds: loaded.profiles.rounds ?? BUILTIN_PROFILES.rounds,
      source: loaded.source,
      requested_profile: args.scan_profile ?? null,
      available_profiles: Object.keys(loaded.profiles.profiles),
      warnings,
      resolved_at: new Date().toISOString(),
    }

    await mkdir(dirname(output), { recursive: true })
    await writeFile(output, JSON.stringify(normalized, null, 2), "utf-8")

    return [
      "Scan profile resolved",
      `  profile: ${selected.name}`,
      `  max_rounds: ${selected.config.max_rounds}`,
      `  source: ${loaded.source}`,
      `  output: ${output}`,
      warnings.length > 0 ? `  warnings: ${warnings.join("; ")}` : "  warnings: none",
    ].join("\n")
  },
})
