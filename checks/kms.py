from typing import Any, Dict, List

from awssec.models import Finding


def analyze_kms(
    keys: List[Dict[str, Any]],
) -> List[Finding]:
    """
    Analyze normalized KMS customer-managed keys.

    Unknown values do not create findings. AWS-managed keys
    are excluded from customer-managed-key posture findings.
    """

    findings = []

    for key in keys:
        key_id = key.get(
            "KeyId",
            "unknown",
        )

        manager = key.get("KeyManager")
        state = key.get("KeyState")

        # Do not assess AWS-managed keys against controls that
        # customers cannot configure themselves.
        if manager != "CUSTOMER":
            continue

        resource = f"kms:{key_id}"

        if state == "PendingDeletion":
            findings.append(
                Finding(
                    id="ASP-KMS-001",
                    severity="HIGH",
                    service="KMS",
                    resource=resource,
                    title=(
                        "KMS key pending deletion"
                    ),
                    observation=(
                        "The customer-managed KMS key is "
                        "scheduled for deletion."
                    ),
                    recommendation=(
                        "Confirm that key deletion is "
                        "intentional and that no required "
                        "workloads or encrypted data depend "
                        "on this key. Cancel deletion when "
                        "the key remains operationally "
                        "required."
                    ),
                    evidence={
                        "key_state": state,
                    },
                )
            )

        key_spec = key.get("KeySpec")
        rotation = key.get("RotationEnabled")

        if (
            state == "Enabled"
            and key_spec
            in (
                None,
                "SYMMETRIC_DEFAULT",
            )
            and rotation is False
        ):
            findings.append(
                Finding(
                    id="ASP-KMS-002",
                    severity="MEDIUM",
                    service="KMS",
                    resource=resource,
                    title=(
                        "KMS automatic key rotation disabled"
                    ),
                    observation=(
                        "Automatic rotation is disabled for "
                        "an enabled customer-managed "
                        "symmetric KMS key."
                    ),
                    recommendation=(
                        "Enable automatic key rotation when "
                        "appropriate for the cryptographic "
                        "and operational requirements of "
                        "the workload."
                    ),
                    evidence={
                        "rotation_enabled": False,
                        "key_spec": key_spec,
                    },
                )
            )

    return findings
