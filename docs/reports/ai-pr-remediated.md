# ShadowAgent Guard Report

## ✅ Verdict: **PASS** · Trust grade **B** (low-severity findings only)

- **Repo:** `Ahmadbey678/shadowagent-demo-target`
- **Base:** `main` -> **Head:** `ai-pr-remediated`
- **Generated:** 2026-09-26T11:16:02.504182+00:00
- **Fails on:** high and above
- **Blocking:** no
- **Scan time:** 0.2s

## Summary

| Severity | Count |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| 🟡 MEDIUM | 0 |
| ⚪ LOW | 1 |
| **Total** | **1** |

## Dependency Supply-Chain Check

No findings.

## Agent Config / Instruction Tampering Check

### ⚪ LOW `CFG-MODE-OVERPERMISSIVE` — Custom mode 'autonomous-fixer' grants command/execute alongside edit restricted to '"guard-out/.*"'

- **Location:** `.bob/custom_modes.yaml:2`
- **Evidence:** - slug: autonomous-fixer
    name: Autonomous Fixer
    roleDefinition: >-
      You can edit files in the repository and run shell commands.
      All edits are scoped to the project output directory only.
      You must ask the user for approval before running destructive commands.
    groups:
   
- **Recommendation:** Edit is scoped by fileRegex, which limits blast radius, but confirm command/execute access is still intentional for this mode.

## Test Tampering Check

No findings.
