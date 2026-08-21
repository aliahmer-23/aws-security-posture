import unittest

from checks.cloudtrail import analyze_cloudtrail


SECURE_TRAIL = {
    "Name": "security-trail",
    "IsLogging": True,
    "LogFileValidationEnabled": True,
    "MultiRegionTrail": True,
}


INSECURE_TRAIL = {
    "Name": "legacy-trail",
    "IsLogging": False,
    "LogFileValidationEnabled": False,
    "MultiRegionTrail": False,
}


class TestCloudTrailSecurity(unittest.TestCase):

    def test_secure_trail_has_zero_findings(self):
        findings = analyze_cloudtrail(
            [SECURE_TRAIL]
        )

        self.assertEqual(len(findings), 0)

    def test_missing_trail_detected(self):
        findings = analyze_cloudtrail([])

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].id,
            "ASP-CT-001",
        )

    def test_missing_trail_is_high(self):
        finding = analyze_cloudtrail([])[0]

        self.assertEqual(
            finding.severity,
            "HIGH",
        )

    def test_disabled_logging_detected(self):
        ids = {
            finding.id
            for finding in analyze_cloudtrail(
                [INSECURE_TRAIL]
            )
        }

        self.assertIn(
            "ASP-CT-002",
            ids,
        )

    def test_validation_disabled_detected(self):
        ids = {
            finding.id
            for finding in analyze_cloudtrail(
                [INSECURE_TRAIL]
            )
        }

        self.assertIn(
            "ASP-CT-003",
            ids,
        )

    def test_non_multi_region_detected(self):
        ids = {
            finding.id
            for finding in analyze_cloudtrail(
                [INSECURE_TRAIL]
            )
        }

        self.assertIn(
            "ASP-CT-004",
            ids,
        )

    def test_insecure_trail_has_three_findings(self):
        findings = analyze_cloudtrail(
            [INSECURE_TRAIL]
        )

        self.assertEqual(len(findings), 3)

    def test_cloudtrail_resource_name(self):
        findings = analyze_cloudtrail(
            [INSECURE_TRAIL]
        )

        for finding in findings:
            self.assertEqual(
                finding.resource,
                "cloudtrail:legacy-trail",
            )


class TestCloudTrailCollectionErrors(unittest.TestCase):

    def test_logging_access_denied_does_not_create_false_finding(self):
        trail = {
            "Name": "security-trail",
            "IsLogging": None,
            "LogFileValidationEnabled": True,
            "MultiRegionTrail": True,
            "collection_errors": [
                {
                    "operation": "get_trail_status",
                    "code": "AccessDeniedException",
                }
            ],
        }

        findings = analyze_cloudtrail([trail])

        ids = {
            finding.id
            for finding in findings
        }

        self.assertNotIn(
            "ASP-CT-002",
            ids,
        )

    def test_explicit_disabled_logging_still_detected(self):
        trail = {
            "Name": "disabled-trail",
            "IsLogging": False,
            "LogFileValidationEnabled": True,
            "MultiRegionTrail": True,
            "collection_errors": [],
        }

        findings = analyze_cloudtrail([trail])

        ids = {
            finding.id
            for finding in findings
        }

        self.assertIn(
            "ASP-CT-002",
            ids,
        )

    def test_unknown_logging_status_without_error_not_false_positive(self):
        trail = {
            "Name": "unknown-trail",
            "IsLogging": None,
            "LogFileValidationEnabled": True,
            "MultiRegionTrail": True,
        }

        findings = analyze_cloudtrail([trail])

        ids = {
            finding.id
            for finding in findings
        }

        self.assertNotIn(
            "ASP-CT-002",
            ids,
        )


if __name__ == "__main__":
    unittest.main()
