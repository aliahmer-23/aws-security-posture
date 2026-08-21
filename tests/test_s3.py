import unittest

from checks.s3 import analyze_s3, analyze_s3_bucket


SECURE_BUCKET = {
    "name": "secure-data",
    "public_access_block": {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    },
    "encryption": {
        "algorithm": "AES256",
    },
    "versioning": "Enabled",
}


INSECURE_BUCKET = {
    "name": "insecure-data",
    "public_access_block": {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    },
    "encryption": None,
    "versioning": "Suspended",
}


class TestS3Security(unittest.TestCase):

    def test_secure_bucket_has_zero_findings(self):
        findings = analyze_s3_bucket(
            SECURE_BUCKET
        )

        self.assertEqual(len(findings), 0)

    def test_insecure_bucket_has_three_findings(self):
        findings = analyze_s3_bucket(
            INSECURE_BUCKET
        )

        self.assertEqual(len(findings), 3)

    def test_public_access_detected(self):
        findings = analyze_s3_bucket(
            INSECURE_BUCKET
        )

        ids = {
            finding.id
            for finding in findings
        }

        self.assertIn(
            "ASP-S3-001",
            ids,
        )

    def test_missing_encryption_detected(self):
        findings = analyze_s3_bucket(
            INSECURE_BUCKET
        )

        ids = {
            finding.id
            for finding in findings
        }

        self.assertIn(
            "ASP-S3-002",
            ids,
        )

    def test_disabled_versioning_detected(self):
        findings = analyze_s3_bucket(
            INSECURE_BUCKET
        )

        ids = {
            finding.id
            for finding in findings
        }

        self.assertIn(
            "ASP-S3-003",
            ids,
        )

    def test_findings_use_s3_resource(self):
        findings = analyze_s3_bucket(
            INSECURE_BUCKET
        )

        for finding in findings:
            self.assertEqual(
                finding.resource,
                "s3://insecure-data",
            )

    def test_multiple_buckets_analyzed(self):
        findings = analyze_s3(
            [
                SECURE_BUCKET,
                INSECURE_BUCKET,
            ]
        )

        self.assertEqual(len(findings), 3)

    def test_public_access_evidence_present(self):
        findings = analyze_s3_bucket(
            INSECURE_BUCKET
        )

        finding = next(
            item
            for item in findings
            if item.id == "ASP-S3-001"
        )

        self.assertEqual(
            len(
                finding.evidence[
                    "disabled_controls"
                ]
            ),
            4,
        )


if __name__ == "__main__":
    unittest.main()
