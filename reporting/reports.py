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
        rows.append(
            "<tr>"
            f"<td>{html.escape(data['id'])}</td>"
            f"<td>{html.escape(data['severity'])}</td>"
            f"<td>{html.escape(data['service'])}</td>"
            f"<td>{html.escape(data['resource'])}</td>"
            f"<td>{html.escape(data['title'])}</td>"
            f"<td>{html.escape(data['recommendation'])}</td>"
            "</tr>"
        )

    if not rows:
        rows.append("<tr><td colspan=\"6\">No security findings detected.</td></tr>")

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
<th>Recommendation</th>
</tr>
</thead>
<tbody>
"""
    content += "".join(rows)
    content += "</tbody></table></body></html>"

    path.write_text(content, encoding="utf-8")
    return path
