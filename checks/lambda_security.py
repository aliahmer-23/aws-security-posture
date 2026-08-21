from typing import Any, Dict, List

from awssec.models import Finding


def analyze_lambda(
    functions: List[Dict[str, Any]],
) -> List[Finding]:
    """Analyze normalized AWS Lambda security posture."""

    findings: List[Finding] = []

    for function in functions:
        name = function.get(
            "FunctionName",
            "unknown-function",
        )

        resource = f"lambda:{name}"

        if function.get("TracingMode") == "PassThrough":
            findings.append(
                Finding(
                    id="ASP-LAMBDA-001",
                    severity="LOW",
                    service="LAMBDA",
                    resource=resource,
                    title="Lambda active tracing disabled",
                    observation=(
                        "AWS X-Ray active tracing is not "
                        "enabled for the Lambda function."
                    ),
                    recommendation=(
                        "Enable AWS X-Ray active tracing where "
                        "appropriate to improve observability "
                        "and investigation capabilities."
                    ),
                    evidence={
                        "tracing_mode": "PassThrough",
                    },
                )
            )

        if function.get("VpcAttached") is False:
            findings.append(
                Finding(
                    id="ASP-LAMBDA-002",
                    severity="INFO",
                    service="LAMBDA",
                    resource=resource,
                    title="Lambda function not attached to VPC",
                    observation=(
                        "The Lambda function does not have a "
                        "VPC configuration."
                    ),
                    recommendation=(
                        "Review whether the function requires "
                        "access to private VPC resources. "
                        "Attach it to appropriate private "
                        "subnets only when required."
                    ),
                    evidence={
                        "vpc_attached": False,
                    },
                )
            )

        if function.get("EnvironmentEncryptionConfigured") is False:
            findings.append(
                Finding(
                    id="ASP-LAMBDA-003",
                    severity="MEDIUM",
                    service="LAMBDA",
                    resource=resource,
                    title=(
                        "Lambda environment variables do not "
                        "use a customer-managed KMS key"
                    ),
                    observation=(
                        "No customer-managed KMS key is "
                        "configured for Lambda environment "
                        "variable encryption."
                    ),
                    recommendation=(
                        "For functions processing sensitive "
                        "configuration, configure an "
                        "appropriate customer-managed KMS key "
                        "and avoid storing secrets directly "
                        "in environment variables."
                    ),
                    evidence={
                        "kms_key_configured": False,
                    },
                )
            )

        if function.get("DeadLetterConfigured") is False:
            findings.append(
                Finding(
                    id="ASP-LAMBDA-004",
                    severity="LOW",
                    service="LAMBDA",
                    resource=resource,
                    title=(
                        "Lambda dead-letter queue not configured"
                    ),
                    observation=(
                        "The Lambda function does not have a "
                        "dead-letter queue configured."
                    ),
                    recommendation=(
                        "For asynchronous workloads where "
                        "failed-event retention is required, "
                        "configure an SQS queue or SNS topic "
                        "for failed event handling."
                    ),
                    evidence={
                        "dead_letter_configured": False,
                    },
                )
            )

    return findings
