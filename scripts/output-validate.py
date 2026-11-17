#!/usr/bin/env python3
"""Check security-findings README.md files against the skill's format rules.

Reports must use ASCII characters only. Every non-ASCII character is a
violation (EN-001).

Usage:
    python output-validate.py <README.md or folder> [...]
    python output-validate.py --selftest

A folder argument checks every README.md under it, except inside poc/.

Exit codes: 0 clean, 1 violations, 2 unreadable input.
"""

import contextlib
import functools
import io
import re
import sys
import tempfile
from pathlib import Path

REFERENCES = Path(__file__).resolve().parent.parent / "references"
CWES_FILE = REFERENCES / "cwes.txt"
TEMPLATES = {
    "finding": REFERENCES / "findings" / "finding-template.md",
    "unknown": REFERENCES / "findings" / "finding-template-unknown.md",
    "case": REFERENCES / "case-studies" / "case-study-template.md",
    "finding-index": REFERENCES / "findings" / "finding-index-template.md",
    "case-index": REFERENCES / "case-studies" / "case-study-index-template.md",
}

VERDICTS = ["static-false", "static-true-dynamic-pending", "static-unknown",
            "dynamic-false", "confirmed"]
DETERMINISTIC_VALUES = ["yes", "timing/race", "unknown", "none"]
SEVERITIES = ["low", "medium", "high", "critical", "unknown", "none"]
SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown", "none"]
CASE_STUDY_SEVERITIES = ["low", "medium", "high", "critical"]
SEVERITY_BY_VERDICT = {
    "static-false": ["none"],
    "dynamic-false": ["none"],
    "static-unknown": ["unknown"],
    "static-true-dynamic-pending": ["low", "medium", "high", "critical", "unknown"],
    "confirmed": ["low", "medium", "high", "critical", "unknown"],
}
FIXED_IMPACT = {"static-false": "none", "dynamic-false": "none",
                "static-unknown": "unknown"}
OPEN_IMPACT_VERDICTS = ["static-true-dynamic-pending", "confirmed"]
DETERMINISTIC_BY_VERDICT = {
    "static-false": ["none"],
    "dynamic-false": ["none"],
    "static-unknown": ["yes", "timing/race", "unknown"],
    "static-true-dynamic-pending": ["yes", "timing/race", "unknown"],
    "confirmed": ["yes", "timing/race", "unknown"],
}
CASE_STUDY_DETERMINISTIC = ["yes", "timing/race", "unknown"]

BANNED = ["not demonstrated", "does not establish", "does not prove",
          "not established", "not claimed", "not proven", "no evidence",
          "outside the analyzed", "microsoft's classification", "unverified",
          "speculation", "continuation", "dead end", "unproven", "proven",
          "unknown"]
BANNED_RE = re.compile(r"\b(?:" + "|".join(re.escape(w) for w in BANNED) + r")\b",
                       re.IGNORECASE)

UNCERTAIN = ["likely", "probably", "maybe", "perhaps", "possibly", "presumably",
             "seemingly", "apparently", "supposedly", "uncertain", "uncertainty",
             "unclear", "unsure", "unconfirmed", "seems", "seem", "suggests",
             "suggest", "suspected", "assume", "assumed", "roughly",
             "approximately", "potentially", "typically", "usually", "might",
             "would", "should", "appears to", "appear to"]
UNCERTAIN_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(w) for w in UNCERTAIN) + r")\b", re.IGNORECASE)
UNCERTAIN_MESSAGE = ("uncertainty word '%s'. State evidence for the claim, "
                     "or delete it.")
# "May 11, 2021" is a date, not a hedge; "May fail." still flags.
MAY_RE = re.compile(r"\bmay\b(?!\s+\d{1,2},)", re.IGNORECASE)
INLINE_CODE_RE = re.compile(r"`[^`]*`")

CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
CWE_RE = re.compile(r"^(CWE-\d+) - (.+)$")
REF_RE = re.compile(r"^(\d+)\. \S")
DATE_RE = re.compile(r"^\d{2}-\d{2}-\d{4}$")
SEPARATOR_RE = re.compile(r"^:?-+:?$")

PRIMITIVE_LABELS = ["Additional preconditions:", "Reproduction steps:",
                    "Triggering path:", "Gate checks:", "Impact:"]
BLOCKED_LABELS = ["Triggering path:", "Impact:"]
BLOCKED_VERDICTS = ["static-false", "dynamic-false"]

WEAKNESS = ("CWE-79 - Improper Neutralization of Input During Web Page "
            "Generation ('Cross-site Scripting')")


def violation(rule, line, message, col=1, snippet=""):
    return {"rule": rule, "line": line, "col": col,
            "message": message, "snippet": snippet.strip()[:120]}


@functools.lru_cache(maxsize=None)
def load_cwes():
    table = {}
    if not CWES_FILE.exists():
        return table
    for raw in CWES_FILE.read_text(encoding="utf-8-sig").splitlines():
        if not raw.strip():
            continue
        head = raw.split(": ", 1)[0]
        match = CWE_RE.match(head)
        if match:
            table[match.group(1)] = match.group(2).strip()
    return table


def parse_frontmatter(lines):
    """Return (pairs, status, body_start); pairs are (key, value, line)."""
    if not lines or lines[0].strip() != "---":
        return None, "missing", 0
    for end in range(1, len(lines)):
        if lines[end].strip() != "---":
            continue
        pairs = []
        for index in range(1, end):
            raw = lines[index]
            if not raw.strip():
                continue
            key, _, value = raw.partition(":")
            pairs.append((key.strip(), value.strip(), index + 1))
        return pairs, "ok", end + 1
    return None, "unclosed", len(lines)


def frontmatter_values(pairs):
    return {key: value for key, value, _ in pairs}


def visible_indexes(lines):
    out = []
    in_fence = False
    for index, raw in enumerate(lines):
        if raw.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append(index)
    return out


def section_lines(lines):
    return [(index + 1, lines[index].rstrip())
            for index in visible_indexes(lines)
            if lines[index].startswith("## ")]


def section_list(lines):
    return [name for _, name in section_lines(lines)]


@functools.lru_cache(maxsize=None)
def index_header(kind):
    for raw in TEMPLATES[kind].read_text(encoding="utf-8-sig").splitlines():
        if raw.startswith("| Date"):
            return split_row(raw)
    return []


@functools.lru_cache(maxsize=None)
def load_template(kind):
    text = TEMPLATES[kind].read_text(encoding="utf-8-sig")
    lines = text.splitlines()
    pairs, _, body_start = parse_frontmatter(lines)
    keys = [key for key, _, _ in pairs] if pairs else []
    return keys, section_list(lines[body_start:])


def classify(values, sections):
    if "verdict" in values:
        return "unknown" if values["verdict"] == "static-unknown" else "finding"
    if "cve-id" in values:
        return "case"
    if not values and "## Security findings" in sections:
        return "finding-index"
    if not values and "## Case studies" in sections:
        return "case-index"
    return None


def check_frontmatter(path, pairs, kind, cwes, expected):
    out = []
    actual = [key for key, _, _ in pairs]
    at_line = {key: line for key, _, line in pairs}
    values = frontmatter_values(pairs)

    for key in actual:
        if key not in expected:
            out.append(violation("FM-002", at_line[key],
                                 "unexpected frontmatter key '%s'" % key))
    for key in expected:
        if key not in actual:
            out.append(violation("FM-003", 1,
                                 "missing frontmatter key '%s'" % key))
    if not out:
        if actual != expected:
            out.append(violation("FM-004", 1,
                                 "frontmatter keys are out of order"))

    for key in expected:
        if key in values and not values[key]:
            out.append(violation("FM-005", at_line.get(key, 1),
                                 "empty value for '%s'" % key))

    for key, value, line in pairs:
        if ": " in value:
            out.append(violation("FM-011", line,
                                 "value of '%s' contains ': '" % key))

    severity = values.get("severity")
    impact = values.get("impact")
    verdict = values.get("verdict")
    if severity and severity not in SEVERITIES:
        out.append(violation("FM-006", at_line.get("severity", 1),
                             "severity '%s' is not one of %s"
                             % (severity, ", ".join(SEVERITIES))))
    if kind in ("finding", "unknown"):
        allowed = SEVERITY_BY_VERDICT.get(verdict)
        if severity and allowed and severity not in allowed:
            out.append(violation("FM-012", at_line.get("severity", 1),
                                 "severity '%s' is not allowed for verdict '%s'"
                                 % (severity, verdict)))
        if impact and verdict in FIXED_IMPACT and impact != FIXED_IMPACT[verdict]:
            out.append(violation("FM-013", at_line.get("impact", 1),
                                 "impact '%s' must be '%s' for verdict '%s'"
                                 % (impact, FIXED_IMPACT[verdict], verdict)))
        if (impact and verdict in OPEN_IMPACT_VERDICTS
                and impact in ("none", "unknown")):
            out.append(violation("FM-013", at_line.get("impact", 1),
                                 "impact '%s' is not allowed for verdict '%s'"
                                 % (impact, verdict)))
    else:
        if severity and severity not in CASE_STUDY_SEVERITIES:
            out.append(violation("FM-014", at_line.get("severity", 1),
                                 "case-study severity '%s' is not one of %s"
                                 % (severity, ", ".join(CASE_STUDY_SEVERITIES))))
        if impact and impact in ("none", "unknown"):
            out.append(violation("FM-014", at_line.get("impact", 1),
                                 "case-study impact '%s' is not allowed" % impact))

    cve_id = values.get("cve-id")
    if cve_id:
        if not CVE_RE.match(cve_id):
            out.append(violation("FM-007", at_line.get("cve-id", 1),
                                 "cve-id '%s' does not match CVE-YYYY-NNNN"
                                 % cve_id))
        elif path.parent.name.lower() != cve_id.lower():
            out.append(violation("FM-007", at_line.get("cve-id", 1),
                                 "cve-id '%s' does not match folder '%s'"
                                 % (cve_id, path.parent.name)))

    if verdict and verdict not in VERDICTS:
        out.append(violation("FM-009", at_line.get("verdict", 1),
                             "verdict '%s' is not one of %s"
                             % (verdict, ", ".join(VERDICTS))))

    deterministic = values.get("deterministic")
    if deterministic:
        if deterministic not in DETERMINISTIC_VALUES:
            out.append(violation("FM-015", at_line.get("deterministic", 1),
                                 "deterministic '%s' is not one of %s"
                                 % (deterministic,
                                    ", ".join(DETERMINISTIC_VALUES))))
        elif kind in ("finding", "unknown"):
            allowed = DETERMINISTIC_BY_VERDICT.get(verdict)
            if allowed and deterministic not in allowed:
                out.append(violation("FM-016", at_line.get("deterministic", 1),
                                     "deterministic '%s' is not allowed for "
                                     "verdict '%s'" % (deterministic, verdict)))
        elif deterministic not in CASE_STUDY_DETERMINISTIC:
            out.append(violation("FM-016", at_line.get("deterministic", 1),
                                 "case-study deterministic '%s' is not one of %s"
                                 % (deterministic,
                                    ", ".join(CASE_STUDY_DETERMINISTIC))))

    weakness = values.get("weakness")
    if weakness:
        match = CWE_RE.match(weakness)
        if not match:
            out.append(violation("FM-010", at_line.get("weakness", 1),
                                 "weakness is not 'CWE-N - Title'"))
        else:
            cwe_id, title = match.group(1), match.group(2).strip()
            if cwe_id not in cwes:
                out.append(violation("FM-010", at_line.get("weakness", 1),
                                     "%s is not listed in references/cwes.txt"
                                     % cwe_id))
            elif cwes[cwe_id] != title:
                out.append(violation("FM-010", at_line.get("weakness", 1),
                                     "%s title is '%s', cwes.txt says '%s'"
                                     % (cwe_id, title, cwes[cwe_id])))
    return out


def check_sections(lines, expected):
    out = []
    actual = section_lines(lines)
    names = [name for _, name in actual]
    for name in expected:
        if name not in names:
            out.append(violation("ST-001", 1, "missing section '%s'" % name))
    for line, name in actual:
        if name not in expected:
            out.append(violation("ST-003", line, "unexpected section '%s'" % name))
    if not out and names != expected:
        out.append(violation("ST-002", 1, "sections are out of order"))
    return out


def next_heading(lines, start, visible):
    for index in visible:
        if index <= start:
            continue
        if lines[index].startswith("### ") or lines[index].startswith("## "):
            return index
    return len(lines)


def check_labels(lines, start, end, visible, labels):
    out = []
    title = lines[start].strip()
    stripped = [lines[index].strip() for index in visible
                if start <= index < end]
    positions = [stripped.index(label) if label in stripped else -1
                 for label in labels]
    for label, position in zip(labels, positions):
        if position < 0:
            out.append(violation("PR-002", start + 1,
                                 "'%s' is missing label '%s'" % (title, label)))
    found = [position for position in positions if position >= 0]
    if found != sorted(found):
        out.append(violation("PR-003", start + 1,
                             "'%s' has labels out of order" % title))
    return out


def check_primitives(lines, kind, verdict):
    if kind == "unknown":
        return []
    visible = visible_indexes(lines)
    starts = [index for index in visible
              if lines[index].startswith("### Primitive")]
    blocked = [index for index in visible
               if re.fullmatch(r"### Blocked path\b.*", lines[index].strip())]
    if not starts and not blocked:
        return [violation("PR-001", 1, "no '### Primitive N' subsection and "
                          "no '### Blocked path' subsection")]
    out = []
    if starts and blocked:
        out.append(violation("PR-004", blocked[0] + 1,
                             "'### Blocked path' cannot sit beside a "
                             "'### Primitive N' subsection"))
    elif blocked and kind == "finding" and verdict not in BLOCKED_VERDICTS:
        out.append(violation("PR-004", blocked[0] + 1,
                             "'### Blocked path' is only for verdict %s, "
                             "not '%s'" % (" or ".join(BLOCKED_VERDICTS),
                                           verdict)))
    for start in starts:
        out += check_labels(lines, start, next_heading(lines, start, visible),
                            visible, PRIMITIVE_LABELS)
    for start in blocked:
        out += check_labels(lines, start, next_heading(lines, start, visible),
                            visible, BLOCKED_LABELS)
    return out


def check_fences(lines):
    fences = sum(1 for line in lines if line.lstrip().startswith("```"))
    if fences % 2:
        return [violation("CD-001", 1,
                          "unbalanced code fence: %d fence lines" % fences)]
    return []


def check_ascii(text):
    out = []
    for index, raw in enumerate(text.split("\n")):
        bad = [(column, char) for column, char in enumerate(raw)
               if ord(char) > 127]
        if not bad:
            continue
        codes = sorted({ord(char) for _, char in bad})
        out.append(violation(
            "EN-001", index + 1,
            "non-ASCII character%s %s; write ASCII English"
            % ("s" if len(codes) > 1 else "",
               ", ".join("U+%04X" % code for code in codes)),
            bad[0][0] + 1, raw))
    return out


def check_banned(lines, skip_lines=None):
    out = []
    in_references = False
    skip_lines = skip_lines or set()
    for index in visible_indexes(lines):
        if index + 1 in skip_lines:
            continue
        raw = lines[index]
        stripped = raw.lstrip()
        if stripped.startswith("## "):
            in_references = stripped.startswith("## References")
        if in_references:
            continue
        if stripped.startswith(">") or stripped.startswith("|"):
            # Index tables copy frontmatter values. Blockquotes are quotations.
            continue
        text = INLINE_CODE_RE.sub(lambda hit: " " * len(hit.group(0)), raw)
        for match in BANNED_RE.finditer(text):
            out.append(violation("BW-001", index + 1,
                                 "banned phrase '%s'" % match.group(0),
                                 match.start() + 1, raw))
        for match in UNCERTAIN_RE.finditer(text):
            out.append(violation("UW-001", index + 1,
                                 UNCERTAIN_MESSAGE % match.group(0),
                                 match.start() + 1, raw))
        for match in MAY_RE.finditer(text):
            out.append(violation("UW-001", index + 1,
                                 UNCERTAIN_MESSAGE % match.group(0),
                                 match.start() + 1, raw))
    return out


def check_references(lines):
    out = []
    visible = visible_indexes(lines)
    start = next((index for index in visible
                  if lines[index].rstrip() == "## References"), None)
    if start is None:
        return out
    numbers = []
    for index in visible:
        if index <= start:
            continue
        raw = lines[index]
        if not raw.strip():
            continue
        if raw.startswith("## "):
            break
        match = REF_RE.match(raw)
        if not match:
            out.append(violation("RF-001", index + 1,
                                 "reference is not 'N. <url or path>'", 1, raw))
            continue
        numbers.append(int(match.group(1)))
    if numbers and numbers != list(range(1, len(numbers) + 1)):
        out.append(violation("RF-002", start + 1,
                             "reference numbers are not continuous: %s" % numbers))
    return out


def split_row(raw):
    cells = raw.split("|")
    if cells and not cells[0].strip():
        cells = cells[1:]
    if cells and not cells[-1].strip():
        cells = cells[:-1]
    return [cell.strip() for cell in cells]


def is_separator(cells):
    return bool(cells) and all(SEPARATOR_RE.match(cell) for cell in cells if cell)


def read_frontmatter(path):
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeDecodeError):
        return {}
    pairs, status, _ = parse_frontmatter(lines)
    if status != "ok":
        return {}
    return frontmatter_values(pairs)


def check_index(path, lines, is_finding):
    out = []
    expected_header = index_header("finding-index" if is_finding
                                   else "case-index")
    layout = {name: index for index, name in enumerate(expected_header)}
    expected_columns = len(expected_header)
    template = ("references/findings/finding-index-template.md" if is_finding
                else "references/case-studies/case-study-index-template.md")
    base = path.parent.resolve()

    header = None
    rows = []
    for index in visible_indexes(lines):
        stripped = lines[index].lstrip()
        if not stripped.startswith("|"):
            continue
        cells = split_row(stripped)
        if is_separator(cells):
            continue
        if header is None:
            header = (index + 1, cells)
            continue
        rows.append((index + 1, cells))

    if header is None:
        out.append(violation("IX-001", 1,
                             "The index has no table. Add the table from %s"
                             % template))
        return out
    if header[1] != expected_header:
        out.append(violation("IX-007", header[0],
                             "Header must be: %s. See %s"
                             % (" | ".join(expected_header), template)))

    sort_keys = []
    linked = {}
    for line, cells in rows:
        if len(cells) != expected_columns:
            out.append(violation("IX-001", line,
                                 "Row has %d columns, expected %d. See %s"
                                 % (len(cells), expected_columns, template)))
            continue
        date = cells[layout["Date"]]
        if (cells[layout["Severity"]] in SEVERITY_ORDER
                and DATE_RE.match(date)):
            day, month, year = date.split("-")
            newest = -int(year + month + day)
            sort_keys.append((line, (SEVERITY_ORDER.index(
                cells[layout["Severity"]]), newest)))
        if not DATE_RE.match(cells[layout["Date"]]):
            out.append(violation("IX-002", line,
                                 "date '%s' is not dd-mm-yyyy"
                                 % cells[layout["Date"]]))
        link = re.fullmatch(r"\[[^\]]+\]\(([^)]+)\)", cells[layout["Path"]])
        if not link:
            out.append(violation("IX-005", line,
                                 "Path cell must be one markdown link. See %s"
                                 % template))
            continue
        link_target = link.group(1)
        if (Path(link_target).is_absolute()
                or link_target.startswith(("/", "\\"))
                or re.match(r"^[A-Za-z]:", link_target)):
            out.append(violation("IX-005", line,
                                 "Path must be relative: %s" % link_target))
            continue
        target = (base / link_target).resolve()
        if base not in target.parents:
            out.append(violation("IX-005", line,
                                 "Path leaves the index folder: %s. Use a "
                                 "relative link." % link_target))
            continue
        if not target.is_file():
            out.append(violation("IX-005", line,
                                 "link target does not exist: %s"
                                 % link_target))
            continue
        parts = target.relative_to(base).parts
        if len(parts) != (4 if is_finding else 2) or parts[-1] != "README.md":
            out.append(violation(
                "IX-005", line,
                "Path must be %s. See %s."
                % ("<dd-mm-yyyy>/<cwe>/<name>/README.md"
                   if is_finding else "<cve-id>/README.md", template)))
            continue
        if target in linked:
            out.append(violation("IX-009", line, "row links %s twice"
                                 % "/".join(parts)))
        linked[target] = line
        if is_finding and cells[layout["Date"]] != parts[0]:
            out.append(violation("IX-002", line,
                                 "date '%s' does not match path folder '%s'"
                                 % (cells[layout["Date"]], parts[0])))
        if not is_finding and cells[layout["CVE"]].lower() != parts[0].lower():
            out.append(violation("IX-004", line,
                                 "CVE cell '%s' does not match path folder '%s'"
                                 % (cells[layout["CVE"]], parts[0])))

        front = read_frontmatter(target)
        if not front:
            out.append(violation("IX-008", line,
                                 "linked README has no valid frontmatter"))
            continue

        expected_severity = front.get("severity")
        allowed = SEVERITIES if is_finding else CASE_STUDY_SEVERITIES
        if expected_severity not in allowed:
            out.append(violation("IX-008", line,
                                 "linked README has no valid severity"))
        elif cells[layout["Severity"]] != expected_severity:
            out.append(violation("IX-003", line,
                                 "severity cell '%s' does not match '%s'"
                                 % (cells[layout["Severity"]],
                                    expected_severity)))

        fields = [("weakness", layout["Weakness"]),
                  ("impact", layout["Impact"]),
                  ("deterministic", layout["Deterministic"])]
        if is_finding:
            fields.append(("verdict", layout["Verdict"]))
        else:
            fields.append(("cve-id", layout["CVE"]))
        for field, column in fields:
            value = front.get(field)
            if value is None:
                out.append(violation("IX-008", line,
                                     "linked README has no '%s'" % field))
            elif cells[column] != value:
                out.append(violation("IX-004", line,
                                     "%s cell '%s' does not match '%s'"
                                     % (field, cells[column], value)))

        root = cells[layout["Root Cause summarize"]]
        if not root:
            out.append(violation("IX-004", line,
                                 "Root Cause summarize cell is empty"))
        elif re.search(r"\]\([^)]+\)", root):
            out.append(violation("IX-004", line,
                                 "Root Cause summarize must not contain a link"))

    for (_, before), (line, key) in zip(sort_keys, sort_keys[1:]):
        if key < before:
            out.append(violation("IX-006", line,
                                 "row is out of order: sort by severity, "
                                 "then date newest first"))
            break
    pattern = "*/*/*/README.md" if is_finding else "*/README.md"
    for record in sorted(base.glob(pattern)):
        if record.resolve() not in linked:
            out.append(violation("IX-009", header[0], "README not in index: %s"
                                 % record.relative_to(base).as_posix()))
    return out


def check(path):
    text = Path(path).read_text(encoding="utf-8-sig")
    lines = text.splitlines()
    pairs, status, body_start = parse_frontmatter(lines)
    body = lines[body_start:]
    sections = section_list(body)
    values = frontmatter_values(pairs) if pairs else {}
    kind = classify(values, sections)
    ascii_errors = check_ascii(text)

    if status == "unclosed":
        return None, ascii_errors + [violation(
            "FM-001", 1, "frontmatter has no closing '---'")]
    if kind is None:
        return None, ascii_errors + [violation(
            "FM-000", 1, "cannot determine file kind")]

    if kind.endswith("index"):
        errors = ascii_errors
        errors += check_fences(lines)
        errors += check_banned(lines)
        errors += check_index(Path(path), lines, kind == "finding-index")
        return kind, errors

    keys, required = load_template(kind)

    cwes = load_cwes()
    exempt = {line for key, value, line in pairs
              if (key == "severity" and value == "unknown")
              or (key == "impact" and value == "unknown")
              or (key == "verdict" and value == "static-unknown")
              or (key == "deterministic" and value == "unknown")}
    errors = ascii_errors
    errors += check_frontmatter(Path(path), pairs, kind, cwes, keys)
    errors += check_sections(lines, required)
    errors += check_primitives(lines, kind, values.get("verdict"))
    errors += check_fences(lines)
    errors += check_banned(lines, exempt)
    errors += check_references(lines)
    return kind, errors


DEFAULTS = {
    "finding": {"verdict": "static-false", "deterministic": "none",
                "severity": "none", "impact": "none",
                "weakness": WEAKNESS},
    "unknown": {"verdict": "static-unknown", "deterministic": "yes",
                "severity": "unknown", "impact": "unknown",
                "weakness": WEAKNESS},
    "case": {"severity": "low", "deterministic": "yes",
             "impact": "code execution", "cve-id": "CVE-2024-1000",
             "weakness": WEAKNESS},
}


def strip_index_rows(text):
    return "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith("| <")) + "\n"


def make_valid(kind, blocked=False):
    text = TEMPLATES[kind].read_text(encoding="utf-8-sig")
    lines = text.splitlines()
    pairs, status, body_start = parse_frontmatter(lines)
    if status != "ok":
        return strip_index_rows(text) if kind.endswith("index") else text
    defaults = DEFAULTS[kind]
    out = ["---"]
    for key, value, _ in pairs:
        if value.startswith("<"):
            value = defaults.get(key, "x")
        out.append("%s: %s" % (key, value))
    out.append("---")
    skip = False
    for line in lines[body_start:]:
        # The template shows both Primitive and Blocked path; keep one.
        if line.startswith("### Primitive"):
            skip = blocked
        elif line.startswith("// (if the evidence blocks"):
            skip = not blocked
            continue
        elif line.startswith("## "):
            skip = False
        if not skip:
            out.append(re.sub(r"<[^>\n]*>", "x", line))
    return "\n".join(out) + "\n"


def selftest():
    cases = []
    finding_index_header = ("| Date | Weakness | Severity | Impact | "
                            "Deterministic | Root Cause summarize | "
                            "Path | Verdict |")
    finding_index_sep = "|---|---|---|---|---|---|---|---|"
    finding_row = ("| 12-08-2026 | %s | none | none | none | root cause | "
                   "[reflected-xss](12-08-2026/cwe-79/reflected-xss/README.md) "
                   "| static-false |" % WEAKNESS)
    case_index_header = ("| Date | CVE | Weakness | Severity | Impact | "
                         "Deterministic | Root Cause summarize | Path |")
    case_index_sep = "|---|---|---|---|---|---|---|---|"
    case_row = ("| 12-08-2026 | CVE-2024-1000 | %s | low | code execution | "
                "yes | root cause | [cve-2024-1000](cve-2024-1000/README.md) |"
                % WEAKNESS)
    finding_path = "findings/component/12-08-2026/cwe-79/reflected-xss/README.md"
    missing = ("IX-009", "README not in index: "
               "12-08-2026/cwe-79/reflected-xss/README.md")
    case_path = "case-studies/component/cve-2024-1000/README.md"

    def finding_index(row):
        return ("# component\n\nsummary\n\n## Security findings\n\n%s\n%s\n%s\n"
                % (finding_index_header, finding_index_sep, row))

    def case_index(row):
        return ("# component\n\nsummary\n\n## Case studies\n\n%s\n%s\n%s\n"
                % (case_index_header, case_index_sep, row))

    def write(relative, text):
        path = Path(folder) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def expect(name, text, wanted):
        path = write(name, text)
        _, errors = check(path)
        got = [(item["rule"], item["message"]) for item in errors]
        cases.append((name, got, wanted))

    def replace(text, old, new):
        return text.replace(old, new)

    with tempfile.TemporaryDirectory() as folder:
        finding = make_valid("finding")
        unknown = make_valid("unknown")
        case = make_valid("case")

        expect("finding-ok.md", finding, [])
        expect("unknown-ok.md", unknown, [])
        expect("cve-2024-1000/README.md", case, [])
        expect("templates/finding-index-ok.md", make_valid("finding-index"), [])
        expect("templates/case-index-ok.md", make_valid("case-index"), [])

        expect("unclosed.md", "---\nverdict: static-false\n",
               [("FM-001", "frontmatter has no closing '---'")])
        expect("stray.md", "hello\n",
               [("FM-000", "cannot determine file kind")])
        expect("finding-extra-key.md",
               replace(finding, "title: x\n",
                       "title: x\nconfidence_score: 50\n"),
               [("FM-002", "unexpected frontmatter key 'confidence_score'")])
        expect("finding-order.md",
               replace(finding, "severity: none\nimpact: none\n",
                       "impact: none\nseverity: none\n"),
               [("FM-004", "frontmatter keys are out of order")])
        expect("finding-empty.md", replace(finding, "title: x\n", "title: \n"),
               [("FM-005", "empty value for 'title'")])
        expect("finding-colon.md",
               replace(finding, "title: x\n", "title: a: b\n"),
               [("FM-011", "value of 'title' contains ': '")])
        expect("finding-no-key.md",
               replace(finding, "deterministic: none\n", ""),
               [("FM-003", "missing frontmatter key 'deterministic'")])
        expect("finding-bad-severity.md",
               replace(finding, "severity: none\n", "severity: nope\n"),
               [("FM-006", "severity 'nope' is not one of %s"
                 % ", ".join(SEVERITIES)),
                ("FM-012", "severity 'nope' is not allowed for verdict "
                 "'static-false'")])
        expect("finding-bad-verdict.md",
               replace(finding, "verdict: static-false", "verdict: nope"),
               [("FM-009", "verdict 'nope' is not one of %s"
                 % ", ".join(VERDICTS))])

        pending = replace(finding, "verdict: static-false",
                          "verdict: static-true-dynamic-pending")
        pending = replace(pending, "impact: none", "impact: code execution")
        pending = replace(pending, "deterministic: none", "deterministic: yes")
        pending = replace(pending, "severity: none", "severity: low")

        expect("finding-pending-ok.md", pending, [])
        expect("finding-confirmed-ok.md",
               replace(pending, "verdict: static-true-dynamic-pending",
                       "verdict: confirmed"), [])
        expect("finding-dynamic-false-ok.md",
               replace(finding, "verdict: static-false",
                       "verdict: dynamic-false"), [])
        pending_unknown = replace(pending, "severity: low", "severity: unknown")
        pending_unknown = replace(pending_unknown, "deterministic: yes",
                                  "deterministic: unknown")
        expect("finding-pending-unknown-ok.md", pending_unknown, [])

        expect("finding-severity-coupling.md",
               replace(pending, "severity: low", "severity: none"),
               [("FM-012", "severity 'none' is not allowed for verdict "
                 "'static-true-dynamic-pending'")])
        expect("finding-impact-coupling.md",
               replace(pending, "impact: code execution", "impact: none"),
               [("FM-013", "impact 'none' is not allowed for verdict "
                 "'static-true-dynamic-pending'")])
        expect("finding-det-coupling.md",
               replace(pending, "deterministic: yes", "deterministic: none"),
               [("FM-016", "deterministic 'none' is not allowed for verdict "
                 "'static-true-dynamic-pending'")])
        expect("cve-2024-9999/README.md",
               replace(case, "cve-id: CVE-2024-1000", "cve-id: BAD"),
               [("FM-007", "cve-id 'BAD' does not match CVE-YYYY-NNNN")])
        expect("cve-2024-9999/README.md",
               replace(case, "cve-id: CVE-2024-1000", "cve-id: CVE-2024-1000"),
               [("FM-007", "cve-id 'CVE-2024-1000' does not match folder "
                 "'cve-2024-9999'")])
        expect("cve-2024-1000/README.md",
               replace(case, "severity: low", "severity: unknown"),
               [("FM-014", "case-study severity 'unknown' is not one of %s"
                 % ", ".join(CASE_STUDY_SEVERITIES))])
        expect("cve-2024-1000/README.md",
               replace(case, "impact: code execution", "impact: none"),
               [("FM-014", "case-study impact 'none' is not allowed")])
        expect("cve-2024-1000/README.md",
               replace(case, "deterministic: yes", "deterministic: unknown"),
               [])
        expect("cve-2024-1000/README.md",
               replace(case, "deterministic: yes", "deterministic: none"),
               [("FM-016", "case-study deterministic 'none' is not one of %s"
                 % ", ".join(CASE_STUDY_DETERMINISTIC))])

        expect("finding-bad-weakness.md",
               replace(finding, WEAKNESS, "bad"),
               [("FM-010", "weakness is not 'CWE-N - Title'")])
        expect("finding-unknown-cwe.md",
               replace(finding, WEAKNESS, "CWE-9999 - X"),
               [("FM-010", "CWE-9999 is not listed in references/cwes.txt")])
        expect("finding-cwe-title.md",
               replace(finding, WEAKNESS, "CWE-79 - Wrong Title"),
               [("FM-010", "CWE-79 title is 'Wrong Title', cwes.txt says '%s'"
                 % load_cwes()["CWE-79"])])
        expect("finding-det-bad.md",
               replace(finding, "deterministic: none",
                       "deterministic: sometimes"),
               [("FM-015", "deterministic 'sometimes' is not one of %s"
                 % ", ".join(DETERMINISTIC_VALUES))])

        expect("finding-no-score-section.md",
               replace(finding, "## Duplication Check\n", "## Not The Check\n"),
               [("ST-001", "missing section '## Duplication Check'"),
                ("ST-003", "unexpected section '## Not The Check'")])
        swapped = replace(finding, "## Target", "## TEMP")
        swapped = replace(swapped, "## Weakness", "## Target")
        swapped = replace(swapped, "## TEMP", "## Weakness")
        expect("finding-section-order.md", swapped,
               [("ST-002", "sections are out of order")])
        expect("finding-extra-section.md",
               replace(finding, "## References",
                       "## Extra\n\ntext\n\n## References"),
               [("ST-003", "unexpected section '## Extra'")])

        expect("finding-no-primitive.md",
               replace(finding, "### Primitive 1: x", "### Not A Primitive"),
               [("PR-001", "no '### Primitive N' subsection and no "
                 "'### Blocked path' subsection")])
        expect("finding-missing-label.md",
               replace(finding, "Reproduction steps:\n", "Steps:\n"),
               [("PR-002", "'### Primitive 1: x' is "
                 "missing label 'Reproduction steps:'")])
        label_swap = replace(finding, "Additional preconditions:", "TEMP")
        label_swap = replace(label_swap, "Reproduction steps:",
                             "Additional preconditions:")
        label_swap = replace(label_swap, "TEMP", "Reproduction steps:")
        expect("finding-label-order.md", label_swap,
               [("PR-003", "'### Primitive 1: x' has "
                 "labels out of order")])
        blocked = make_valid("finding", blocked=True)
        expect("finding-blocked-ok.md", blocked, [])
        expect("finding-blocked-bad.md",
               replace(blocked, "Impact:\n", "Effect:\n"),
               [("PR-002", "'### Blocked path' is missing label 'Impact:'")])
        expect("finding-blocked-confirmed.md",
               replace(pending, "### Primitive 1: x",
                       "### Blocked path").replace(
                   "verdict: static-true-dynamic-pending", "verdict: confirmed"),
               [("PR-004", "'### Blocked path' is only for verdict "
                 "static-false or dynamic-false, not 'confirmed'")])
        expect("finding-blocked-and-primitive.md",
               replace(finding, "## Duplication Check",
                       "### Blocked path\n\nTriggering path:\n\nImpact:\n\n"
                       "## Duplication Check"),
               [("PR-004", "'### Blocked path' cannot sit beside a "
                 "'### Primitive N' subsection")])
        expect("finding-no-gate-checks.md",
               replace(finding, "Gate checks:\n", ""),
               [("PR-002", "'### Primitive 1: x' is missing label "
                 "'Gate checks:'")])
        expect("finding-fenced-blocked.md",
               replace(replace(finding, "## Duplication Check",
                               "```\n### Blocked path\n```\n\n"
                               "## Duplication Check"),
                       "### Primitive 1: x", "### Not A Primitive"),
               [("PR-001", "no '### Primitive N' subsection and no "
                 "'### Blocked path' subsection")])
        expect("finding-fence.md", finding + "\n```\n",
               [("CD-001", "unbalanced code fence: 3 fence lines")])
        expect("finding-banned.md",
               replace(finding, "## References",
                       "This is proven.\n\n## References"),
               [("BW-001", "banned phrase 'proven'")])
        expect("finding-table-skip.md",
               replace(finding, "## References",
                       "| x | proven |\n|---|---|\n\n## References"),
               [])
        expect("finding-blockquote-skip.md",
               replace(finding, "## References",
                       "> This is proven.\n\n## References"),
               [])
        expect("finding-reference-skip.md",
               replace(finding, "1. x", "1. <proven likely path>"),
               [])
        expect("finding-uncertain.md",
               replace(finding, "## References",
                       "This is likely.\n\n## References"),
               [("UW-001", "uncertainty word 'likely'. State evidence for the "
                 "claim, or delete it.")])
        expect("finding-may.md",
               replace(finding, "## References",
                       "This may fail.\n\n## References"),
               [("UW-001", "uncertainty word 'may'. State evidence for the "
                 "claim, or delete it.")])
        expect("finding-may-capital.md",
               replace(finding, "## References",
                       "May fail.\n\n## References"),
               [("UW-001", "uncertainty word 'May'. State evidence for the "
                 "claim, or delete it.")])
        expect("finding-may-date.md",
               replace(finding, "## References",
                       "May 11, 2021.\n\n## References"),
               [])
        expect("finding-ref-bad.md",
               replace(finding, "1. x", "one. https://example.com"),
               [("RF-001", "reference is not 'N. <url or path>'")])
        expect("finding-ref-gap.md",
               replace(finding, "1. x", "1. x\n3. x"),
               [("RF-002", "reference numbers are not continuous: [1, 3]")])

        expect("finding-ascii-latin.md",
               replace(finding, "## References",
                       "caf\u00e9\n\n## References"),
               [("EN-001",
                 "non-ASCII character U+00E9; write ASCII English")])
        expect("finding-ascii-punctuation.md",
               replace(finding, "## References",
                       "a \u2014 \u201Cb\u201D\n\n## References"),
               [("EN-001", "non-ASCII characters U+2014, U+201C, U+201D; "
                 "write ASCII English")])
        expect("finding-ascii-zero-width.md",
               replace(finding, "## References",
                       "a\u200Bb\n\n## References"),
               [("EN-001",
                 "non-ASCII character U+200B; write ASCII English")])
        expect("finding-ascii-line-separator.md",
               replace(finding, "## References",
                       "a\u2028b\n\n## References"),
               [("EN-001",
                 "non-ASCII character U+2028; write ASCII English")])
        expect("finding-ascii-emoji.md",
               replace(finding, "## References",
                       "\U0001F534\n\n## References"),
               [("EN-001",
                 "non-ASCII character U+1F534; write ASCII English")])

        write(finding_path, make_valid("finding"))
        expect("findings/component/README.md", finding_index(finding_row), [])
        emoji_row = finding_row.replace(
            "| none | none | none |",
            "| \U0001F534 none | none | none |")
        expect("findings/component/README.md", finding_index(emoji_row),
               [("EN-001",
                 "non-ASCII character U+1F534; write ASCII English"),
                ("IX-003", "severity cell '\U0001F534 none' does not match "
                 "'none'")])
        expect("findings/component/README.md",
               finding_index(finding_row).replace(
                   "summary", "summary \U0001F534"),
               [("EN-001",
                 "non-ASCII character U+1F534; write ASCII English")])
        expect("findings/component/README.md",
               "# component\n\n## Security findings\n\nno table\n",
               [("IX-001", "The index has no table. Add the table from "
                 "references/findings/finding-index-template.md")])
        expect("findings/component/README.md",
               finding_index(replace(finding_row, " | static-false |", " |")),
               [("IX-001", "Row has 7 columns, expected 8. See "
                 "references/findings/finding-index-template.md"), missing])
        expect("findings/component/README.md",
               finding_index(finding_row).replace("| Verdict |", "| Confidence |"),
               [("IX-007", "Header must be: %s. See "
                 "references/findings/finding-index-template.md"
                 % " | ".join(index_header("finding-index")))])
        expect("findings/component/README.md",
               finding_index(replace(finding_row, "| 12-08-2026 |",
                                     "| 13-08-2026 |")),
               [("IX-002", "date '13-08-2026' does not match path folder "
                 "'12-08-2026'")])
        expect("findings/component/README.md",
               finding_index(replace(finding_row,
                                     "[reflected-xss](12-08-2026/cwe-79/reflected-xss/README.md)",
                                     "12-08-2026/cwe-79/reflected-xss/README.md")),
               [("IX-005", "Path cell must be one markdown link. See "
                 "references/findings/finding-index-template.md"), missing])
        absolute_target = str(Path(folder).resolve()
                              / "findings/component/12-08-2026"
                              / "cwe-79/reflected-xss/README.md")
        expect("findings/component/README.md",
               finding_index(replace(finding_row,
                                     "12-08-2026/cwe-79/reflected-xss/README.md",
                                     absolute_target)),
               [("IX-005", "Path must be relative: %s" % absolute_target),
                missing])
        expect("findings/component/README.md",
               finding_index(replace(finding_row,
                                     "12-08-2026/cwe-79/reflected-xss/README.md",
                                     "missing/README.md")),
               [("IX-005", "link target does not exist: missing/README.md"),
                missing])
        expect("findings/component/README.md",
               finding_index(replace(finding_row,
                                     "12-08-2026/cwe-79/reflected-xss/README.md",
                                     "../../outside.md")),
               [("IX-005", "Path leaves the index folder: ../../outside.md. "
                 "Use a relative link."), missing])
        write("findings/component/other/README.md", make_valid("finding"))
        expect("findings/component/README.md",
               finding_index(replace(finding_row,
                                     "12-08-2026/cwe-79/reflected-xss/README.md",
                                     "other/README.md")),
               [("IX-005", "Path must be <dd-mm-yyyy>/<cwe>/<name>/README.md. "
                 "See references/findings/finding-index-template.md."),
                missing])
        expect("findings/component/README.md",
               finding_index(replace(finding_row,
                                     "| none | none | none |",
                                     "| low | none | none |")),
               [("IX-003", "severity cell 'low' does not match 'none'")])
        expect("findings/component/README.md",
               finding_index(replace(finding_row, "| root cause |", "|  |")),
               [("IX-004", "Root Cause summarize cell is empty")])
        expect("findings/component/README.md",
               finding_index(replace(finding_row, "| root cause |",
                                     "| [root](x) |")),
               [("IX-004", "Root Cause summarize must not contain a link")])
        expect("findings/component/README.md",
               finding_index(replace(finding_row,
                                     "| 12-08-2026 |",
                                     "| 2026-08-12 |")),
               [("IX-002", "date '2026-08-12' is not dd-mm-yyyy"),
                ("IX-002", "date '2026-08-12' does not match path folder "
                 "'12-08-2026'")])
        write(finding_path, "hello\n")
        expect("findings/component/README.md", finding_index(finding_row),
               [("IX-008", "linked README has no valid frontmatter")])
        write(finding_path, replace(make_valid("finding"),
                                    "verdict: static-false\n", ""))
        expect("findings/component/README.md", finding_index(finding_row),
               [("IX-008", "linked README has no 'verdict'")])
        write(finding_path, replace(make_valid("finding"),
                                    "severity: none", "severity: nope"))
        expect("findings/component/README.md", finding_index(finding_row),
               [("IX-008", "linked README has no valid severity")])

        write(case_path, make_valid("case"))
        expect("case-studies/component/README.md", case_index(case_row), [])
        write(case_path, replace(make_valid("case"),
                                 "severity: low", "severity: unknown"))
        expect("case-studies/component/README.md", case_index(case_row),
               [("IX-008", "linked README has no valid severity")])
        write(case_path, make_valid("case"))
        expect("case-studies/component/README.md",
               case_index(replace(case_row, "| CVE-2024-1000 |",
                                  "| CVE-2024-9999 |")),
               [("IX-004", "CVE cell 'CVE-2024-9999' does not match path "
                 "folder 'cve-2024-1000'"),
                ("IX-004", "cve-id cell 'CVE-2024-9999' does not match "
                 "'CVE-2024-1000'")])

        # Sort, duplicate rows, and folder arguments use a fresh component.
        older = "findings/sorted/11-08-2026/cwe-79/a/README.md"
        newer = "findings/sorted/12-08-2026/cwe-79/b/README.md"
        write(older, make_valid("finding"))
        write(newer, make_valid("finding"))
        older_row = (finding_row.replace("12-08-2026", "11-08-2026")
                     .replace("reflected-xss/", "a/"))
        newer_row = finding_row.replace("reflected-xss/", "b/")
        expect("findings/sorted/README.md",
               finding_index(newer_row + "\n" + older_row), [])
        expect("findings/sorted/README.md",
               finding_index(older_row + "\n" + newer_row),
               [("IX-006", "row is out of order: sort by severity, then "
                 "date newest first")])
        write(older, pending)
        low_row = older_row.replace("| none | none | none |",
                                    "| low | code execution | yes |").replace(
            "| static-false |", "| static-true-dynamic-pending |")
        expect("findings/sorted/README.md",
               finding_index(low_row + "\n" + newer_row), [])
        expect("findings/sorted/README.md",
               finding_index(newer_row + "\n" + low_row),
               [("IX-006", "row is out of order: sort by severity, then "
                 "date newest first")])
        expect("findings/sorted/README.md",
               finding_index(low_row + "\n" + newer_row + "\n" + newer_row),
               [("IX-009", "row links 12-08-2026/cwe-79/b/README.md twice")])

        tree = Path(folder) / "findings/sorted"
        write("findings/sorted/README.md",
              finding_index(low_row + "\n" + newer_row))
        write("findings/sorted/12-08-2026/cwe-79/b/poc/README.md", "junk\n")
        with contextlib.redirect_stdout(io.StringIO()) as shown:
            status = main([str(tree)])
        cases.append(("folder-ok", (status, shown.getvalue()), (0, "")))
        write(newer, "junk\n")
        with contextlib.redirect_stdout(io.StringIO()) as shown:
            status = main([str(tree)])
        cases.append(("folder-bad", (status, "FM-000" in shown.getvalue()),
                      (1, True)))

    failed = [(name, got, want) for name, got, want in cases if got != want]
    for name, got, want in failed:
        print("%s: got %s, want %s" % (name, got, want))
    print("%d checks, %d failed" % (len(cases), len(failed)))
    return 1 if failed else 0


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    if not argv:
        print("usage: output-validate.py <report.md> [...]")
        return 2

    files = []
    for name in argv:
        root = Path(name)
        if not root.is_dir():
            files.append(name)
            continue
        found = sorted(str(path) for path in root.rglob("README.md")
                       if "poc" not in path.relative_to(root).parts)
        files.extend(found or [str(root / "README.md")])

    bad = 0
    unreadable = 0
    for name in files:
        path = Path(name)
        if not path.is_file():
            print("%s: error: file not found" % name)
            unreadable += 1
            continue
        try:
            _, errors = check(path)
        except (OSError, UnicodeDecodeError) as exc:
            print("%s: error: %s" % (name, exc))
            unreadable += 1
            continue
        errors.sort(key=lambda item: (item["line"], item["col"]))
        for item in errors:
            print("%s:%d:%d: %s %s" % (name, item["line"], item["col"],
                                       item["rule"], item["message"]))
        bad += bool(errors)

    if unreadable:
        return 2
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
