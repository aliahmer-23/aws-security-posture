from typing import Dict, List


DIRECT = "DIRECT"
PARTIAL = "PARTIAL"
RELATED = "RELATED"

VALID_RELATIONSHIPS = {
    DIRECT,
    PARTIAL,
    RELATED,
}


COMPLIANCE_MAPPINGS: Dict[str, List[Dict[str, str]]] = {
    "ASP-IAM-001": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "IAM.4",
            "relationship": DIRECT,
        }
    ],
    "ASP-IAM-002": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "IAM.9",
            "relationship": DIRECT,
        }
    ],
    "ASP-IAM-003": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "IAM.8",
            "relationship": DIRECT,
        }
    ],
    "ASP-S3-001": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "S3.8",
            "relationship": DIRECT,
        }
    ],
    "ASP-S3-003": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "S3.14",
            "relationship": DIRECT,
        }
    ],
    "ASP-CT-001": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "CloudTrail.3",
            "relationship": DIRECT,
        }
    ],
    "ASP-CT-003": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "CloudTrail.4",
            "relationship": DIRECT,
        }
    ],
    "ASP-CT-004": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "CloudTrail.1",
            "relationship": PARTIAL,
        }
    ],
    "ASP-RDS-001": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "RDS.3",
            "relationship": DIRECT,
        }
    ],
    "ASP-RDS-002": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "RDS.2",
            "relationship": DIRECT,
        }
    ],
    "ASP-RDS-003": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "RDS.11",
            "relationship": DIRECT,
        }
    ],
    "ASP-RDS-004": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "RDS.8",
            "relationship": DIRECT,
        }
    ],
    "ASP-KMS-002": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "KMS.4",
            "relationship": DIRECT,
        }
    ],
    "ASP-LAMBDA-002": [
        {
            "framework": "AWS Security Hub CSPM",
            "control_id": "Lambda.3",
            "relationship": DIRECT,
        }
    ],
}


def get_compliance_mappings(
    finding_id: str,
) -> List[Dict[str, str]]:
    """Return defensive copies of compliance mappings for a finding."""

    return [
        dict(mapping)
        for mapping in COMPLIANCE_MAPPINGS.get(
            finding_id,
            [],
        )
    ]
