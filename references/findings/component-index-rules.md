# Component index rules

Read the matching template before creating or changing an index. The template fixes the ordered columns.

- Finding index: `findings/<component>/README.md`, template `finding-index-template.md`, one `Security findings` section.
- Case-study index: `case-studies/<component>/README.md`, template `../case-studies/case-study-index-template.md`, one `Case studies` section.
- One row per record README in the component. No record twice.
- Copy frontmatter values into their cells. Never recompute them.
- `Date`: the finding date folder; for a case study, the day it was written.
- `Root Cause summarize`: short root-cause summary, no link. Do not repeat the full record.
- `Path`: one relative markdown link to the record README, no other text. Keep every cell short.
- Sort rows by severity, then date newest first. Severity order: `critical`, `high`, `medium`, `low`, `unknown`, `none`.
