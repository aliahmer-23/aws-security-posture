from typing import Dict, List

from awssec.models import Finding


def analyze_iam(
    account: Dict,
) -> List[Finding]:

    findings = []

    resource = "iam:account"

    if account.get("root_access_keys", 0) > 0:
        findings.append(
            Finding(
                id="ASP-IAM-001",
                severity="CRITICAL",
                service="IAM",
                resource=resource,
                title="Root account access key detected",
                observation=(
                    "The AWS root account has an active "
                    "access key."
                ),
                recommendation=(
                    "Delete root account access keys, avoid using the "
                    "root user for routine administration, and use "
                    "least-privilege IAM roles or identities instead."
                ),
                evidence={
                    "root_access_keys":
                        account.get("root_access_keys"),
                },
            )
        )

    if not account.get("root_mfa_enabled", False):
        findings.append(
            Finding(
                id="ASP-IAM-002",
                severity="HIGH",
                service="IAM",
                resource=resource,
                title="Root MFA not enabled",
                observation=(
                    "Multi-factor authentication is not "
                    "enabled for the root account."
                ),
                recommendation=(
                    "Enable MFA for the AWS root user and securely "
                    "protect the MFA device used for account recovery "
                    "and privileged access."
                ),
                evidence={
                    "root_mfa_enabled": False,
                },
            )
        )

    unused_access_keys = account.get(
        "unused_access_keys"
    )

    if (
        unused_access_keys is not None
        and unused_access_keys > 0
    ):
        findings.append(
            Finding(
                id="ASP-IAM-003",
                severity="MEDIUM",
                service="IAM",
                resource=resource,
                title="Unused IAM access keys detected",
                observation=(
                    "One or more IAM access keys are "
                    "reported as unused."
                ),
                recommendation=(
                    "Review and remove unused IAM "
                    "credentials."
                ),
                evidence={
                    "unused_access_keys":
                        unused_access_keys,
                },
            )
        )

    admin_users = account.get(
        "admin_users"
    )

    if (
        admin_users is not None
        and admin_users > 1
    ):
        findings.append(
            Finding(
                id="ASP-IAM-004",
                severity="MEDIUM",
                service="IAM",
                resource=resource,
                title="Multiple administrative users detected",
                observation=(
                    "Multiple IAM identities have "
                    "administrative privileges."
                ),
                recommendation=(
                    "Review administrative access and "
                    "apply least privilege."
                ),
                evidence={
                    "admin_users":
                        admin_users,
                },
            )
        )

    password_policy = account.get(
        "password_policy"
    )

    minimum_length = None

    if password_policy is not None:
        minimum_length = password_policy.get(
            "minimum_length"
        )

    if (
        minimum_length is not None
        and minimum_length < 14
    ):
        findings.append(
            Finding(
                id="ASP-IAM-005",
                severity="MEDIUM",
                service="IAM",
                resource=resource,
                title="Weak IAM password minimum length",
                observation=(
                    f"IAM password minimum length is "
                    f"{minimum_length}."
                ),
                recommendation=(
                    "Require IAM passwords of at least "
                    "14 characters."
                ),
                evidence={
                    "minimum_length": minimum_length,
                },
            )
        )

    return findings
