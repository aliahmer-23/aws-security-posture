#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path

from awssec.assessment import run_assessment
from collectors.live import run_live_assessment
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
        "--live",
        action="store_true",
        help="Run a read-only assessment against AWS.",
    )

    parser.add_argument(
        "--region",
        help="AWS region used for live assessment.",
    )

    parser.add_argument(
        "--profile",
        help="Optional AWS CLI profile used for live assessment.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"AWS Security Posture Scanner {VERSION}",
    )

    args = parser.parse_args()

    if args.fixture and args.live:
        parser.error(
            "--fixture and --live cannot be used together."
        )

    if not args.fixture and not args.live:
        parser.error(
            "one assessment mode is required: --fixture or --live."
        )

    if not args.live and (args.region or args.profile):
        parser.error(
            "--region and --profile require --live."
        )

    try:
        if args.live:
            assessment = run_live_assessment(
                region=args.region,
                profile=args.profile,
            )
            source = args.profile or "AWS credential provider chain"
            mode = "LIVE AWS / READ-ONLY"
        else:
            environment = load_fixture(args.fixture)
            assessment = run_assessment(environment)
            source = args.fixture
            mode = "OFFLINE / LOCAL FIXTURE"

    except (
        OSError,
        json.JSONDecodeError,
        ValueError,
        RuntimeError,
    ) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    print_banner()
    print(f"[+] Assessment source: {source}")
    print(f"[+] Mode: {mode}")

    if args.live and args.region:
        print(f"[+] Region: {args.region}")

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
