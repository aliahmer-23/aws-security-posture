from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from awssec.compliance import get_compliance_mappings


VALID_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
}


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    service: str
    resource: str
    title: str
    observation: str
    recommendation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    compliance: List[Dict[str, str]] = field(default_factory=list)

    def __post_init__(self):
        severity = self.severity.upper()

        if severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid finding severity: {self.severity}"
            )

        object.__setattr__(self, "severity", severity)

        if not self.compliance:
            object.__setattr__(
                self,
                "compliance",
                get_compliance_mappings(self.id),
            )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
