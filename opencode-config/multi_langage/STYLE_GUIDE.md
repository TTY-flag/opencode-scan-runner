# OpenCode Harness Style Guide

## Supported Languages

This harness supports `c_cpp`, `python`, `go`, `lua`, and `java`.

Every generated `project_model.json` file must mark each source file with one of those language values. Modules should use the same value when they are single-language, or `mixed` with a `languages` array when they contain multiple supported languages.

## Structured Context

`project_model.json` and `call_graph.json` are shared facts, not prose summaries.

- Use `schema_version: "1.0"` in both files.
- Prefer stable IDs (`mod-*`, `file-*`, `ep-*`, `fn-*`, `edge-*`, `flow-*`) over natural-language names.
- Attach `evidence` and `confidence` to high-risk modules, entry points, call edges, and data flows.
- Treat `call_graph.json` as a risk-focused sparse graph. It should contain `nodes`, `edges`, `data_flows`, and `unresolved`, not a full-project graph.
- Do not promote model-only inference to a high-confidence fact.
- Every scanner work item must produce a `COVERAGE_LEDGER` summary. Coordinators must persist it with `vuln-db coverage-add` before marking the work item complete.
- Use `scan-profile-resolver` to normalize scan duration into `{CONTEXT_DIR}/scan_profile.json`. `deep` is the default for vulnerability hunting, and scanners should consume the resolved profile instead of searching for `scan-profiles.json`.
- For `deep` and `paranoid`, high-risk work items must be rescanned with distinct `pass_kind` values. Do not treat one `complete` primary pass as enough evidence for model-stability-sensitive findings.

## Evidence First

Scanner agents should write complete vulnerability details to `scan.db` through `vuln-db` before returning to the coordinator. Return text should contain only counts and compact cross-module hints.

For each candidate, prefer filling:

- `language`
- `framework`
- `source_kind`
- `sink_kind`
- `sanitizer_checked`
- `evidence_json`
- `rule_id`
- `analysis_backend`

## Language Packs

Language-specific knowledge lives in `.opencode/language/*.json` and `.opencode/skills/*-taint-tracking/SKILL.md`.

Do not add a new dedicated worker for every language unless the generic language worker cannot express the required behavior.
