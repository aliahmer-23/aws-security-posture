from typing import Any, Dict, List

from awssec.models import Finding


def analyze_rds(
    instances: List[Dict[str, Any]],
) -> List[Finding]:
    """
    Analyze normalized RDS DB instances.

    Unknown values do not create findings because collection
    uncertainty must not be treated as proof of insecurity.
    """

    findings = []

    for instance in instances:
        identifier = instance.get(
            "DBInstanceIdentifier",
            "unknown",
        )

        resource = f"rds:{identifier}"

        if instance.get("StorageEncrypted") is False:
            findings.append(
                Finding(
                    id="ASP-RDS-001",
                    severity="HIGH",
                    service="RDS",
                    resource=resource,
                    title=(
                        "RDS storage encryption disabled"
                    ),
                    observation=(
                        "The RDS DB instance reports that "
                        "storage encryption is disabled."
                    ),
                    recommendation=(
                        "Use encrypted RDS storage for "
                        "database workloads and manage "
                        "encryption keys according to the "
                        "workload security requirements."
                    ),
                    evidence={
                        "storage_encrypted": False,
                    },
                )
            )

        if instance.get("PubliclyAccessible") is True:
            findings.append(
                Finding(
                    id="ASP-RDS-002",
                    severity="HIGH",
                    service="RDS",
                    resource=resource,
                    title=(
                        "RDS instance publicly accessible"
                    ),
                    observation=(
                        "The RDS DB instance is configured "
                        "as publicly accessible."
                    ),
                    recommendation=(
                        "Disable public accessibility unless "
                        "it is explicitly required, and "
                        "prefer private network connectivity "
                        "with tightly controlled access."
                    ),
                    evidence={
                        "publicly_accessible": True,
                    },
                )
            )

        retention = instance.get(
            "BackupRetentionPeriod"
        )

        if (
            retention is not None
            and retention == 0
        ):
            findings.append(
                Finding(
                    id="ASP-RDS-003",
                    severity="MEDIUM",
                    service="RDS",
                    resource=resource,
                    title=(
                        "RDS automated backups disabled"
                    ),
                    observation=(
                        "The RDS DB instance has a backup "
                        "retention period of zero days."
                    ),
                    recommendation=(
                        "Configure an appropriate automated "
                        "backup retention period based on "
                        "recovery and business requirements."
                    ),
                    evidence={
                        "backup_retention_period": retention,
                    },
                )
            )

        if instance.get("DeletionProtection") is False:
            findings.append(
                Finding(
                    id="ASP-RDS-004",
                    severity="MEDIUM",
                    service="RDS",
                    resource=resource,
                    title=(
                        "RDS deletion protection disabled"
                    ),
                    observation=(
                        "Deletion protection is disabled "
                        "for the RDS DB instance."
                    ),
                    recommendation=(
                        "Enable deletion protection for "
                        "production or otherwise critical "
                        "database instances where accidental "
                        "deletion presents material risk."
                    ),
                    evidence={
                        "deletion_protection": False,
                    },
                )
            )

    return findings
