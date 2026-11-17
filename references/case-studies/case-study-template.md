---
title: <short human-readable bug title>
description: <executive summary>
weakness: <CWE id and title for the CVE, listed in references/cwes.txt>
severity: <low, medium, high, or critical>
impact: <security-impact description>
deterministic: <yes, timing/race, or unknown>
cve-id: <exact CVE id>
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
    -> <processing step, controlled data after transformation, evidence locator>
        -> <primitive-creating operation, pre-state, evidence locator>
```

<trigger, operation, controlled data, capability evidence>

Impact:

<impact, boundary>

// (if the evidence blocks the path before any primitive)
Blocked path:

```
<attacker-model entrypoint or request> [execution condition, evidence locator]
    -> <processing step, controlled data after transformation, evidence locator>
        -> <decisive failed condition, reason, evidence locator>
```

Impact:

<impact of the blocked path, boundary>

## The Patch

<patch locator: commit, release, or advisory>

```diff
<decisive diff with context lines>
```

<changed parts and how the fix removes the root cause, with evidence locators>

// (if no patch exists)
<No patch identified for this case study. Then the sources you checked.>

## References

1. <web URL or file path>
