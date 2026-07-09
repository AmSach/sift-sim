"""Top-level :class:`Sift` scanner and CLI-friendly entry points."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable, List, Optional

from .detectors import ALL_DETECTORS
from .report import Finding, SiftReport


class Sift:
    """Run all (or a subset of) detectors over a piece of text."""

    def __init__(self, detectors: Optional[Iterable[str]] = None) -> None:
        if detectors is None:
            self.detectors = dict(ALL_DETECTORS)
        else:
            self.detectors = {k: ALL_DETECTORS[k] for k in detectors}
            unknown = set(detectors) - set(ALL_DETECTORS)
            if unknown:
                raise KeyError(f"unknown detectors: {sorted(unknown)}")

    def scan(self, text: str) -> SiftReport:
        report = SiftReport(text_length=len(text))
        for fn in self.detectors.values():
            for finding in fn(text):
                report.add(finding)
        report.findings.sort(key=lambda f: f.span[0])
        report.compute_risk()
        return report

    def explain(self, text: str) -> str:
        """Human-readable summary of the report."""
        report = self.scan(text)
        lines = [
            f"text_length={report.text_length}  risk={report.risk_score:.1f}/100  "
            f"findings={len(report.findings)}"
        ]
        for f in report.findings:
            lines.append(
                f"  - {f.detector:<22} conf={f.confidence:.2f}  {f.reason}"
            )
            lines.append(f"      span={f.span}  snippet={f.snippet!r}")
        return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sift",
        description="Scan text for hidden prompts, encoded payloads, and other suspicious patterns.",
    )
    p.add_argument("text", nargs="?", help="text to scan (reads stdin if omitted)")
    p.add_argument(
        "--detectors",
        "-d",
        nargs="+",
        choices=list(ALL_DETECTORS),
        help="restrict to a subset of detectors",
    )
    p.add_argument(
        "--format",
        "-f",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    p.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="drop findings with confidence below this (0..1)",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    text = args.text if args.text is not None else sys.stdin.read()
    sift = Sift(detectors=args.detectors)
    report = sift.scan(text)
    if args.min_confidence > 0:
        report.findings = [
            f for f in report.findings if f.confidence >= args.min_confidence
        ]
        report.compute_risk()
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(sift.explain(text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
