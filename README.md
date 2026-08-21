# AWS Security Posture Scanner

Python-based AWS security assessment and posture-management project.

## Project Goals

- Read-only AWS security assessment
- AWS asset discovery
- IAM security analysis
- S3 security analysis
- EC2 and Security Group analysis
- CloudTrail security checks
- Encryption checks
- Risk scoring
- JSON / HTML / SARIF reporting
- Automated security testing

## Safety

The scanner is designed around read-only AWS API access.

It does not deploy, modify, or delete AWS infrastructure.

---

## Automated Security Validation

AWS Security Posture Scanner includes a GitHub Actions CI workflow that automatically validates the project on pushes and pull requests.

The pipeline performs:

- Python source compilation
- Automated unit testing
- Secure AWS fixture validation
- Insecure AWS configuration detection
- Exit-code validation for security findings

### GitHub Actions — Security Validation Passed

![AWS Security Posture Scanner CI success](docs/images/aws-posture-ci-success.png)

The successful workflow demonstrates automated security validation as part of a CI/CD pipeline.

