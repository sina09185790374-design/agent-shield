"""CLI for agent-shield.

Usage:
    python3 -m agent_shield audit <directory> [--json] [--exclude DIR ...]
                                        [--fail-on critical|high|medium|low|never]
                                        [--redact OUTDIR]
Exit codes: 0 = clean (or only findings below --fail-on), 1 = failing
findings, 2 = usage/runtime error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .scan import redact_tree, scan_tree, score

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-shield",
        description="Audit a codebase for what an AI reverse-engineering "
                    "agent can extract: secrets, internal endpoints, "
                    "architecture leaks.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Scan a directory and report exposure.")
    audit.add_argument("directory", help="Directory to scan")
    audit.add_argument("--json", action="store_true",
                       help="Print the full report as JSON")
    audit.add_argument("--exclude", action="append", default=[],
                       metavar="DIR", help="Extra directory/file to skip "
                       "(repeatable)")
    audit.add_argument("--fail-on", default="high",
                       choices=["critical", "high", "medium", "low", "never"],
                       help="Fail (exit 1) when a finding of at least this "
                       "severity exists (default: high)")
    audit.add_argument("--redact", metavar="OUTDIR",
                       help="Also write a redacted copy of the tree to OUTDIR")
    return parser


def _human_report(root: str, findings, result: dict) -> str:
    lines = [f"agent-shield — {root}",
             f"exposure {result['exposure']}/100  grade {result['grade']}  "
             f"{result['findings']} finding(s)"]
    if not findings:
        lines.append("clean: nothing an RE agent could lift from this tree.")
        return "\n".join(lines)
    for sev in reversed(SEVERITY_ORDER):
        group = [f for f in findings if f.severity == sev]
        for f in group:
            lines.append(f"[{sev.upper():8}] {f.path}:{f.line} "
                         f"{f.category}/{f.rule} — {f.snippet}")
    lines.append("")
    lines.append("by severity: " + ", ".join(
        f"{sev}={result['by_severity'][sev]}" for sev in SEVERITY_ORDER))
    lines.append("by category: " + ", ".join(
        f"{cat}={n}" for cat, n in sorted(result['by_category'].items())))
    return "\n".join(lines)


def cmd_audit(args) -> int:
    root = args.directory
    if not os.path.isdir(root):
        print(f"agent-shield: not a directory: {root}", file=sys.stderr)
        return 2
    findings = scan_tree(root, excludes=args.exclude)
    result = score(findings)
    result["root"] = os.path.abspath(root)
    result["findings_list"] = [f.to_dict() for f in findings]

    manifest = None
    if args.redact:
        manifest = redact_tree(root, args.redact, findings,
                               excludes=args.exclude)
        result["redaction"] = manifest

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(_human_report(root, findings, result))
        if manifest is not None:
            print(f"\nredacted copy: {args.redact} — "
                  f"{manifest['files_redacted']} file(s), "
                  f"{manifest['values_redacted']} value(s) redacted")

    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER.index(args.fail_on)
    failing = [f for f in findings
               if SEVERITY_ORDER.index(f.severity) >= threshold]
    return 1 if failing else 0


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        return cmd_audit(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
