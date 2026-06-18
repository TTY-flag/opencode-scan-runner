/// <reference path="../env.d.ts" />
import { tool } from "@opencode-ai/plugin"
import DESCRIPTION from "./merge-json.txt"
import { readdir, readFile, writeFile, mkdir } from "node:fs/promises"
import { join, basename } from "node:path"

function matchPattern(filename: string, pattern: string): boolean {
  const regex = new RegExp(
    "^" +
      pattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*")
        .replace(/\?/g, ".") +
      "$",
  )
  return regex.test(filename)
}

export default tool({
  description: DESCRIPTION,
  args: {
    directory: tool.schema.string().describe("Directory containing the JSON files to merge"),
    pattern: tool.schema
      .string()
      .describe("Filename glob pattern to match (e.g. candidates_df_*.json)"),
    output: tool.schema.string().describe("Output file path for the merged result"),
    key: tool.schema
      .string()
      .describe("The array field name to merge from each file")
      .default("vulnerabilities"),
  },
  async execute(args) {
    const dir = args.directory
    const entries = await readdir(dir)
    const matched = entries.filter((f) => matchPattern(f, args.pattern)).sort()

    if (matched.length === 0) {
      return `No files matched pattern "${args.pattern}" in ${dir}`
    }

    const merged: unknown[] = []
    const details: string[] = []
    const warnings: string[] = []

    for (const filename of matched) {
      const filepath = join(dir, filename)
      const raw = await readFile(filepath, "utf-8")
      let data
      try {
        data = JSON.parse(raw)
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err)
        warnings.push(`  ⚠ ${filename}: JSON parse failed - ${message}`)
        continue
      }
      const items = Array.isArray(data[args.key]) ? data[args.key] : []
      merged.push(...items)
      details.push(`  ${filename}: ${items.length} items`)
    }

    const outputDir = join(args.output, "..")
    await mkdir(outputDir, { recursive: true })

    const result = { [args.key]: merged }
    await writeFile(args.output, JSON.stringify(result, null, 2), "utf-8")

    const lines = [
      `Merged ${matched.length - warnings.length}/${matched.length} files → ${basename(args.output)}`,
      `Total ${args.key}: ${merged.length}`,
      "",
      "Source files:",
      ...details,
    ]

    if (warnings.length > 0) {
      lines.push("", "Warnings (skipped files):", ...warnings)
    }

    lines.push("", `Output: ${args.output}`)
    return lines.join("\n")
  },
})
