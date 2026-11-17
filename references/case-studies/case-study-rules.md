# Case-study rules

One case study lives at `case-studies/<component>/<cve_id>/README.md`. CVE id folder is lowercase, for example `cve-2024-1234`. No date or weakness folder. Finding PoC policy applies to `poc/` beside the README.

Read `case-study-template.md` before creating or changing a case-study README. The template fixes the ordered frontmatter keys and sections. Every value is nonempty.

- `description`, `weakness`, `impact`: as `../findings/finding-rules.md` requires.
- `severity`: `low`, `medium`, `high`, or `critical`, picked with the severity table in the finding rules.
- `deterministic`: from the cited patch, advisory, or reproduction. `unknown` only when sources do not establish trigger type.
- `cve-id`: exact published id.

No verdict. All other finding rules stay in force, including the evidence contract and hard constraints. Each primitive in `Triggering Steps` gives reproduction steps, triggering call path, and `Impact:` as the finding rules require.

`The Patch`: cite the patch locator (commit, release, or diff). Show the decisive diff in a code block. Explain each changed part and how the fix removes the root cause stated in `Root Cause`. No patch: write this exact sentence: `No patch identified for this case study.` Then list the sources you checked.

### Case-study index

Location and rules: `../findings/component-index-rules.md`.
