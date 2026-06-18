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
      return [
        `PASS: ${basename(filePath)}`,
        `  Size: ${fileInfo.size} bytes`,
        `  Top-level keys: [${keys.join(", ")}]`,
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
