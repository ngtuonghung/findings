# Finding record rules

One component folder per target component. Use one consistent component identifier from the user or existing output.

Inside the component folder: one `dd-mm-yyyy` folder for the current day. Inside it: one folder per weakness, named with the lowercase CWE id from `../cwes.txt`, for example `cwe-79`. Inside that: one lowercase `snake_case` folder per finding. The folder name identifies the concrete trigger or primitive.

One finding lives at `findings/<component>/<dd-mm-yyyy>/<cwe_id>/<finding_name>/README.md`.

Put every proof-of-concept (PoC) file in `poc/`, a sibling of `README.md`. A PoC is an input, command sequence, script, or recorded result that demonstrates the claimed behavior. Save each user-supplied PoC file unchanged. Reference it from the reproduction step by relative path, for example `poc/trigger.py`. No PoC, no `poc/`.

Read `finding-template.md` before creating or changing a finding README; for a `static-unknown` candidate read `finding-template-unknown.md`. The template fixes the ordered frontmatter keys and sections. Every value is nonempty.

- `description`: short executive summary.
- `weakness`: one exact CWE id and title from `../cwes.txt`.
- `impact`: consequence of the flaw at the affected boundary. No vendor classification, severity rating, CVSS vector, reference to the report, or statement about what the evidence does not establish.

Allowed values by verdict:

| verdict | severity | impact | deterministic |
|---|---|---|---|
| `static-false` | `none` | `none` | `none` |
| `dynamic-false` | `none` | `none` | `none` |
| `static-unknown` | `unknown` | `unknown` | `yes`, `timing/race`, `unknown` |
| `static-true-dynamic-pending` | `low`, `medium`, `high`, `critical`, `unknown` | consequence description | `yes`, `timing/race`, `unknown` |
| `confirmed` | `low`, `medium`, `high`, `critical`, `unknown` | consequence description | `yes`, `timing/race`, `unknown` |

### deterministic

- `yes`: the stated path reaches the primitive under the stated preconditions, with no dependence on timing, scheduler interleaving, a race condition, memory layout, or a random value.
- `timing/race`: a necessary step depends on timing, scheduler interleaving, a race condition, or another run-dependent condition.
- `unknown`: evidence does not establish the trigger type.

The value covers the full stated path to the reported impact. One non-deterministic necessary primitive makes it `timing/race`. Full finding: state the exact condition in `Attacker Model` and the exact interleaving in `Triggering Steps`. `static-unknown` candidate: state the condition in `Evidence Reviewed`.

### verdict

Allowed transitions only: `static-true-dynamic-pending` to `confirmed` or `dynamic-false`; `static-unknown` to `static-true-dynamic-pending` or `static-false`. The current workflow assigns only the verdicts its analysis mode allows. A static workflow assigns `static-false`, `static-true-dynamic-pending`, and `static-unknown`.

- `static-false`: static evidence refutes reachability, material attacker control, or security impact.
- `static-true-dynamic-pending`: static evidence establishes all three; dynamic evidence absent, incomplete, or inconclusive.
- `static-unknown`: static evidence establishes neither `static-true-dynamic-pending` nor `static-false`.
- `confirmed`: dynamic evidence establishes path, control, and impact.
- `dynamic-false`: dynamic evidence refutes a necessary fact.

### Target

Name the exact product, binary, package, device, or service under assessment. State the exact version, taken from the target: banner, build metadata, package manifest, or file metadata. No version in evidence: state the artifact identity the evidence does establish. Name the component that contains the flaw.

### Weakness

Read `../cwes.txt` first. Pick one exact weakness from it. Never invent one. Then name the concrete mechanism: faulty operation, resource, state, invariant, or boundary. Overlapping weaknesses: pick the one matching the root cause, never by severity or impact alone.

### Background

Detailed, self-contained internal context: subsystem, data structures, object lifecycle, execution state, protocol or message flow, privilege model, invariants. Show how it supports the later root-cause, attacker-model, reachability, and impact conclusions. Do not restate those sections or add unrelated target design.

### Root Cause

First sentence states the flaw. Then the minimum logical chain from evidence to root cause; each step states the assumption, guard, invariant, operation, or transition the evidence establishes.

Keep root cause apart from trigger and impact. Trigger causes the flaw. Impact is the consequence. Neither replaces the defect that makes the finding unique. Evidence does not identify the root cause: no finding.

### Attacker Model

State attacker origin, initial privilege and capability, entrypoint, access method, relevant limits, and trust boundary. Prose or list.

State every general precondition that must hold before any primitive: software, hardware, deployment, configuration, environment, privilege, resource, timing. A claim needs a precondition the evidence does not establish: remove the claim.

Access method can name the protocol, input format, command, API, or syscall. Evidence misses a fact the reachability path needs: do not state that step or any later step. The reachability path stays inside this attacker model.

### Triggering Steps

One `### Primitive N` subsection per immediate primitive. Never combine primitives. Start each with the capability gained.

State only primitive-specific preconditions. Different entrypoint, access method, limit, or trust boundary than Attacker Model: state only the difference.

Each primitive gives reproduction steps, for a reader in the attacker-model position, and the triggering call chain.

Call chain starts at the attacker-model entrypoint (first point that accepts the input) and ends at the operation that creates the primitive (bug location). Show the full chain from source or pseudo code as an indented call tree. Name every caller and callee in call order. Never skip an intermediate function. Evidence refutes a required step: stop there.

State the execution condition for every edge. Track attacker-controlled data through each transformation, copy, cast, field extraction, and reassignment. State who controls the data after each material transformation.

List every gate check that can block the path: permission, bounds, type, state, capability, or configuration check. For each: locator, exact predicate, and how the attacker input or required state passes it. A gate check fails: stop the path there.

Establish deployment reachability apart from code reachability.

Each primitive also states:

- exact trigger and pre-state
- operation that creates the primitive
- attacker-controlled aspects and evidence of control
- evidence that establishes the capability
- security impact: affected boundary, privilege, data, process, resource, or execution state. An abnormal value or crash alone is not impact.

Evidence blocks the path before any primitive: use `Blocked path`. Show the established steps and the decisive stopping condition. Say whether a code step or a deployment precondition stops it. Never use it when an immediate primitive exists.

### static-unknown profile

`Evidence Reviewed` lists each exact locator and the facts it establishes. `Open Questions` is a numbered list. Each item gives the exact question (phrased as a question), the evidence locator that answers it, and the next static route. No uncertainty word or status label. `Open Questions` is the only place this profile states missing target evidence. Never infer `severity` or `impact` from the weakness alone.

### Duplication Check

Before drafting, read the component index and every finding in the same component with the same weakness, across all dates.

Compare only with prior internal findings. For each one check concrete flaw, root-cause location, violated invariant, trigger conditions, reachable path, and primitive.

Show the underlying flaw differs from each prior finding. Different symptom, PoC, code format, symbol name, refactoring, or repeated analysis does not establish uniqueness. A prior finding looks like the same flaw: state the exact difference in object, invariant, state machine, or execution path. Evidence does not show the flaw differs: no finding.

### References

List every source the conclusions depend on. Each numbered item is one web URL or one file path, no added text. Order by first citation in the report. Never list a source the report does not use.
