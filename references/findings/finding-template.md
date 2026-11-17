---
title: <short human-readable bug title>
description: <executive summary>
weakness: <exact CWE id and title from references/cwes.txt>
severity: <low, medium, high, critical, unknown, or none when the verdict is static-false or dynamic-false>
impact: <security-impact description, or none for static-false or dynamic-false, or unknown for static-unknown>
deterministic: <yes, timing/race, unknown, or none>
verdict: <verdict value>
---

## Target

<target identity, version, affected component>

## Weakness

<weakness and concrete mechanism>

## Background

<self-contained internal context>

## Root Cause

<flaw first, then the evidence chain>

## Attacker Model

<origin, privilege and capability, entrypoint, access, limits, boundary>

Preconditions:

<general preconditions, with evidence>

## Triggering Steps

### Primitive 1: <capability gained>

Additional preconditions:

<primitive-specific preconditions, with evidence>

Reproduction steps:

<steps for a reader in the attacker-model position, with evidence>

Triggering path:

```
<attacker-model entrypoint or request> [execution condition, evidence locator]
    -> <caller> -> <callee> [execution condition, evidence locator]
        -> <processing step, controlled data after transformation, evidence locator>
            -> <primitive-creating operation, pre-state, evidence locator>
```

Gate checks:

- <check locator>: <exact check> - passed by <input or state, evidence locator>

<trigger, operation, controlled data, capability evidence>

Impact:

<impact, boundary>

// (if the evidence blocks the path before any primitive, this subsection replaces every Primitive subsection)
### Blocked path

Triggering path:

```
<attacker-model entrypoint or request> [execution condition, evidence locator]
    -> <caller> -> <callee> [execution condition, evidence locator]
        -> <decisive failed gate check, reason, evidence locator>
```

Impact:

<impact of the blocked path, boundary>

## Duplication Check

<comparison with prior internal findings, uniqueness evidence>

## References

1. <web URL or file path>
