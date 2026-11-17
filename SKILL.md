---
name: security-findings
description: Record security-finding candidates and verdicts as structured reports. Record one CVE case study only when the user asks for a case study in explicit words. Use this skill when the user asks you to create, revise, index, classify, or format security findings or case studies.
---

# Security Findings

Use after analysis finds one candidate security finding. One unique flaw per finding README. This skill does not cover analysis, target study, testing, or exploit-chain work.

An intermediate primitive with established security impact counts. No end-to-end exploit needed. Reader is human and lacks hidden target context. Each report must reproduce from the report alone: state every input, command, path, value, precondition, and step.

Write reports with `caveman` and `stop-slop`. Explain how each cited fact supports its conclusion. Give a concrete cited example for each abstract point. Keep every technical detail that affects the conclusion.

Finding mode is default: write under `findings/` in the active target workspace. Case-study mode needs explicit user words; user gives CVE id, component, and patch info. Case-study rules override finding rules only where `references/case-studies/case-study-rules.md` says so.

## References

- Finding format: `references/findings/finding-rules.md`. For a `static-unknown` candidate use `references/findings/finding-template-unknown.md`.
- Component-index format: `references/findings/component-index-rules.md`.
- Case-study format: `references/case-studies/case-study-rules.md`.

## Hard constraints

- Do not add, remove, or reorder finding sections or frontmatter keys.
- Do not add, remove, or reorder component index columns.
- No finding README when the evidence supports no verdict in `references/findings/finding-rules.md`.
- Do not repeat general preconditions inside a primitive subsection.
- No separate `Evidence` section or paragraph.
- No `: ` inside a frontmatter value.
- Do not rewrite code, commands, paths, identifiers, hashes, frontmatter keys, enum values, JSON structure, citations, or evidence locators.
- No status labels and no statements about what the report does not establish. Only exception: `## Open Questions` in the `static-unknown` profile.
- Do not wrap lines. Each paragraph, table row, and list item is one line.
- English and ASCII only: no emoji, curly quotes, en/em dashes, non-breaking spaces, or zero-width characters.
- After every write or edit, run `scripts/output-validate.py <README.md or folder>`. A folder checks every `README.md` under it. Fix every violation before finishing.

## Evidence contract

Base every material claim on concrete evidence. Cite it beside every claim, step, edge, and precondition. A material claim supports weakness, root cause, reachability, primitive, severity, impact, or uniqueness.

Use the smallest decisive evidence:

- source: file, symbol, line range, decisive snippet.
- binary: artifact, function, address or offset, decisive evidence.
- execution: command, input, observed output, artifact.
- patch: diff and changed lines.
- documentation, configuration, logs, or tests: precise locator and decisive content.

An inference needs an explicit, complete evidence chain of ordered steps. Each step names its evidence item and the operation, value, or state that item establishes, and follows the prior step. State only conclusions the chain supports. Keep every mechanism, address, value, offset, condition, transformation, and state the chain shows. The reader must re-derive each conclusion from the report alone.

Search cited material for contradicting or limiting evidence. Drop any conclusion it removes. Write only about the target, and only about subjects a required section needs and the chain supports.

No status word or uncertainty word in your own sentences. `scripts/output-validate.py` owns both word lists and reports them as `BW-001` and `UW-001`. Establish each flagged claim as fact, or remove it.
