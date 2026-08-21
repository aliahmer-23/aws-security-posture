import json
from pathlib import Path
from typing import Any, Dict


SARIF_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def build_sarif(assessment: Dict[str, Any]) -> Dict[str, Any]:
    rules = {}
    results = []

    for finding in assessment["findings"]:
        data = finding.to_dict()
        rule_id = data["id"]

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {
                    "text": data["title"],
                },
                "help": {
                    "text": data["recommendation"],
                },
            }

        results.append({
            "ruleId": rule_id,
            "level": SARIF_LEVELS[data["severity"]],
            "message": {
                "text": data["title"],
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": data["resource"],
                        }
                    }
                }
            ],
        })

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AWS Security Posture Scanner",
                        "version": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(assessment: Dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(build_sarif(assessment), indent=2),
        encoding="utf-8",
    )
    return path
