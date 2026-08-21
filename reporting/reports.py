import json
from pathlib import Path
from typing import Any, Dict


def write_json_report(
    assessment: Dict[str, Any],
    path: Path,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)

    document = {
        "risk": assessment["risk"],
        "coverage": assessment["coverage"],
        "findings": [
            finding.to_dict()
            for finding in assessment["findings"]
        ],
    }

    path.write_text(
        json.dumps(document, indent=2),
        encoding="utf-8",
    )

    return path


def write_html_report(assessment: Dict[str, Any], path: Path) -> Path:
    import html

    path.parent.mkdir(parents=True, exist_ok=True)
    risk = assessment["risk"]
    findings = assessment["findings"]

    rows = []

    for finding in findings:
        data = finding.to_dict()

        compliance_items = []

        for mapping in data.get("compliance", []):
            compliance_items.append(
                f"{html.escape(mapping['framework'])}: "
                f"{html.escape(mapping['control_id'])} "
                f"({html.escape(mapping['relationship'])})"
            )

        compliance_text = (
            "<br>".join(compliance_items)
            if compliance_items
            else "—"
        )

        evidence_items = []

        for key, value in data.get("evidence", {}).items():
            label = key.replace("_", " ").title()

            if isinstance(value, list):
                rendered_value = ", ".join(
                    str(item)
                    for item in value
                )
            elif value is None:
                rendered_value = "Not configured"
            else:
                rendered_value = str(value)

            evidence_items.append(
                f"<strong>{html.escape(label)}:</strong> "
                f"{html.escape(rendered_value)}"
            )

        evidence_text = (
            "<br>".join(evidence_items)
            if evidence_items
            else "—"
        )

        rows.append(
            "<tr>"
            f"<td>{html.escape(data['id'])}</td>"
            f"<td>{html.escape(data['severity'])}</td>"
            f"<td>{html.escape(data['service'])}</td>"
            f"<td>{html.escape(data['resource'])}</td>"
            f"<td>{html.escape(data['title'])}</td>"
            f"<td>{evidence_text}</td>"
            f"<td>{compliance_text}</td>"
            f"<td>{html.escape(data['recommendation'])}</td>"
            "</tr>"
        )

    if not rows:
        rows.append("<tr><td colspan=\"8\">No security findings detected.</td></tr>")

    content = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AWS Security Posture Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.5; }
table { width: 100%; border-collapse: collapse; margin-top: 20px; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
th { background: #f3f3f3; }
</style>
</head>
<body>
<h1>AWS Security Posture Scanner</h1>
<h2>Security Assessment Report</h2>
"""

    content += f"<p><strong>Overall risk:</strong> {html.escape(str(risk['overall_risk']))}</p>"
    content += f"<p><strong>Risk score:</strong> {risk['risk_score']}/100</p>"
    content += f"<p><strong>Total findings:</strong> {risk['total']}</p>"
    content += f"<p><strong>Critical:</strong> {risk['critical']}</p>"
    content += f"<p><strong>High:</strong> {risk['high']}</p>"
    content += f"<p><strong>Medium:</strong> {risk['medium']}</p>"
    content += f"<p><strong>Low:</strong> {risk['low']}</p>"

    coverage = assessment["coverage"]
    services = coverage["services"]

    content += """
<h2>Assessment Coverage</h2>
<table>
<thead>
<tr>
<th>Service</th>
<th>Status</th>
</tr>
</thead>
<tbody>
"""

    for service in (
        "iam",
        "s3",
        "ec2",
        "cloudtrail",
        "rds",
        "kms",
        "lambda",
    ):
        status = services[service]["status"]

        content += (
            "<tr>"
            f"<td>{html.escape(service.upper())}</td>"
            f"<td>{html.escape(str(status))}</td>"
            "</tr>"
        )

    content += "</tbody></table>"

    content += (
        "<p><strong>Services assessed:</strong> "
        f"{coverage['services_assessed']}</p>"
    )
    content += (
        "<p><strong>Complete:</strong> "
        f"{coverage['complete']}</p>"
    )
    content += (
        "<p><strong>Partial:</strong> "
        f"{coverage['partial']}</p>"
    )
    content += (
        "<p><strong>Failed:</strong> "
        f"{coverage['failed']}</p>"
    )
    content += (
        "<p><strong>Collection errors:</strong> "
        f"{coverage['collection_errors']}</p>"
    )
    content += (
        "<p><strong>Assessment confidence:</strong> "
        f"{html.escape(str(coverage['confidence']))}</p>"
    )

    content += """
<h2>Security Findings</h2>
<table>
<thead>
<tr>
<th>ID</th>
<th>Severity</th>
<th>Service</th>
<th>Resource</th>
<th>Finding</th>
<th>Evidence</th>
<th>Compliance</th>
<th>Recommendation</th>
</tr>
</thead>
<tbody>
"""
    content += "".join(rows)
    content += "</tbody></table></body></html>"

    path.write_text(content, encoding="utf-8")
    return path
