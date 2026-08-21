#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path

from awssec.assessment import run_assessment
from reporting.reports import write_json_report, write_html_report
from reporting.sarif import write_sarif


VERSION = "1.0.0"


def load_fixture(path: str):
    fixture = Path(path)

    if not fixture.is_file():
        raise FileNotFoundError(
            f"Fixture not found: {fixture}"
        )

    with fixture.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def print_banner():
    print()
    print(f"AWS Security Posture Scanner v{VERSION}")
    print("Cloud Security Assessment")
    print("-" * 60)


def print_findings(findings):
    print()
    print("SECURITY FINDINGS")
    print("-" * 60)

    if not findings:
        print("[+] No security findings detected.")
        return

    for finding in findings:
        print(
            f"{finding.id:<12} "
            f"{finding.severity:<10} "
            f"{finding.service:<12} "
            f"{finding.resource}"
        )
        print(f"    {finding.title}")


def print_risk(summary):
    print()
    print("RISK SUMMARY")
    print("-" * 60)
    print(f"Risk score:       {summary['risk_score']}/100")
    print(f"Raw risk score:   {summary['raw_risk_score']}")
    print(f"Critical:         {summary['critical']}")
    print(f"High:             {summary['high']}")
    print(f"Medium:           {summary['medium']}")
    print(f"Low:              {summary['low']}")
    print(f"Info:             {summary['info']}")
    print(f"Total findings:   {summary['total']}")
    print(f"Overall risk:     {summary['overall_risk']}")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "AWS Security Posture Scanner"
        )
    )

    parser.add_argument(
        "--fixture",
        help=(
            "Local normalized AWS environment JSON "
            "used for offline assessment."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"AWS Security Posture Scanner {VERSION}",
    )

    args = parser.parse_args()

    if not args.fixture:
        parser.error(
            "--fixture is required in offline mode."
        )

    try:
        environment = load_fixture(args.fixture)
        assessment = run_assessment(environment)

    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    print_banner()
    print(f"[+] Assessment source: {args.fixture}")
    print("[+] Mode: OFFLINE / LOCAL FIXTURE")

    print_findings(
        assessment["findings"]
    )

    print_risk(
        assessment["risk"]
    )

    report_dir = Path("reports")
    report_dir.mkdir(parents=True, exist_ok=True)

    json_path = report_dir / "aws_posture.json"
    html_path = report_dir / "aws_posture.html"
    sarif_path = report_dir / "aws_posture.sarif"

    write_json_report(assessment, json_path)
    write_html_report(assessment, html_path)
    write_sarif(assessment, sarif_path)

    print()
    print("REPORTS")
    print("-" * 60)
    print(f"[+] JSON:  {json_path}")
    print(f"[+] HTML:  {html_path}")
    print(f"[+] SARIF: {sarif_path}")

    if assessment["findings"]:
        print()
        print("⚠️ SECURITY ISSUES DETECTED")
        return 1

    print()
    print("✅ SECURITY POSTURE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
