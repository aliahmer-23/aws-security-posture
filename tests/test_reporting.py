import json
import tempfile
import unittest
from pathlib import Path

from awssec.assessment import run_assessment
from reporting.reports import write_json_report


class TestJSONReporting(unittest.TestCase):

    def setUp(self):
        self.environment = {
            "iam": {
                "root_access_keys": 1,
                "root_mfa_enabled": True,
                "unused_access_keys": 0,
                "admin_users": 1,
                "password_policy": {"minimum_length": 14},
            },
            "s3": [],
            "security_groups": [],
            "cloudtrail": [
                {
                    "Name": "security-trail",
                    "IsLogging": True,
                    "LogFileValidationEnabled": True,
                    "MultiRegionTrail": True,
                }
            ],
        }

        self.assessment = run_assessment(self.environment)

    def test_json_report_written(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            write_json_report(self.assessment, path)
            self.assertTrue(path.is_file())

    def test_json_report_contains_risk(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            write_json_report(self.assessment, path)
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("risk", document)
            self.assertEqual(document["risk"]["total"], 1)

    def test_json_contains_compliance_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            write_json_report(self.assessment, path)

            document = json.loads(
                path.read_text(encoding="utf-8")
            )

            compliance = document["findings"][0][
                "compliance"
            ]

            self.assertEqual(
                compliance[0]["framework"],
                "AWS Security Hub CSPM",
            )
            self.assertEqual(
                compliance[0]["control_id"],
                "IAM.4",
            )
            self.assertEqual(
                compliance[0]["relationship"],
                "DIRECT",
            )

    def test_json_report_serializes_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            write_json_report(self.assessment, path)
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(len(document["findings"]), 1)
            self.assertEqual(document["findings"][0]["id"], "ASP-IAM-001")


if __name__ == "__main__":
    unittest.main()


class TestHTMLReporting(unittest.TestCase):

    def setUp(self):
        self.environment = {
            "iam": {
                "root_access_keys": 1,
                "root_mfa_enabled": True,
                "unused_access_keys": 0,
                "admin_users": 1,
                "password_policy": {"minimum_length": 14},
            },
            "s3": [],
            "security_groups": [],
            "cloudtrail": [
                {
                    "Name": "security-trail",
                    "IsLogging": True,
                    "LogFileValidationEnabled": True,
                    "MultiRegionTrail": True,
                }
            ],
        }
        self.assessment = run_assessment(self.environment)

    def test_html_report_written(self):
        from reporting.reports import write_html_report
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.html"
            write_html_report(self.assessment, path)
            self.assertTrue(path.is_file())

    def test_html_contains_scanner_name(self):
        from reporting.reports import write_html_report
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.html"
            write_html_report(self.assessment, path)
            text = path.read_text(encoding="utf-8")
            self.assertIn("AWS Security Posture Scanner", text)

    def test_html_contains_compliance_metadata(self):
        from reporting.reports import write_html_report

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.html"
            write_html_report(self.assessment, path)

            text = path.read_text(encoding="utf-8")

            self.assertIn("Compliance", text)
            self.assertIn(
                "AWS Security Hub CSPM",
                text,
            )
            self.assertIn("IAM.4", text)
            self.assertIn("DIRECT", text)

    def test_html_contains_finding(self):
        from reporting.reports import write_html_report
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.html"
            write_html_report(self.assessment, path)
            text = path.read_text(encoding="utf-8")
            self.assertIn("ASP-IAM-001", text)
            self.assertIn("Root account access key detected", text)


class TestSARIFReporting(unittest.TestCase):

    def setUp(self):
        from reporting.sarif import build_sarif
        self.build_sarif = build_sarif
        self.environment = {
            "iam": {
                "root_access_keys": 1,
                "root_mfa_enabled": True,
                "unused_access_keys": 0,
                "admin_users": 1,
                "password_policy": {"minimum_length": 14},
            },
            "s3": [],
            "security_groups": [],
            "cloudtrail": [
                {
                    "Name": "security-trail",
                    "IsLogging": True,
                    "LogFileValidationEnabled": True,
                    "MultiRegionTrail": True,
                }
            ],
        }
        self.assessment = run_assessment(self.environment)

    def test_sarif_version(self):
        sarif = self.build_sarif(self.assessment)
        self.assertEqual(sarif["version"], "2.1.0")

    def test_sarif_tool_name(self):
        sarif = self.build_sarif(self.assessment)
        driver = sarif["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "AWS Security Posture Scanner")

    def test_sarif_contains_result(self):
        sarif = self.build_sarif(self.assessment)
        results = sarif["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "ASP-IAM-001")

    def test_critical_maps_to_error(self):
        sarif = self.build_sarif(self.assessment)
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["level"], "error")

    def test_sarif_file_written(self):
        from reporting.sarif import write_sarif
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "results.sarif"
            write_sarif(self.assessment, path)
            self.assertTrue(path.is_file())
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["version"], "2.1.0")


class TestCoverageReporting(unittest.TestCase):

    def setUp(self):
        self.environment = {
            "iam": {
                "root_access_keys": 0,
                "root_mfa_enabled": True,
                "unused_access_keys": 0,
                "admin_users": 1,
                "password_policy": {
                    "minimum_length": 14,
                },
                "collection_errors": [],
            },
            "s3": [],
            "security_groups": [],
            "ec2_collection_errors": [],
            "cloudtrail": [],
        }

        self.assessment = run_assessment(
            self.environment
        )

    def test_json_contains_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"

            write_json_report(
                self.assessment,
                path,
            )

            document = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )

            self.assertIn(
                "coverage",
                document,
            )

            self.assertEqual(
                document["coverage"]["confidence"],
                "COMPLETE",
            )

            self.assertEqual(
                document["coverage"][
                    "services"
                ]["iam"]["status"],
                "COMPLETE",
            )

    def test_html_contains_coverage(self):
        from reporting.reports import (
            write_html_report,
        )

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.html"

            write_html_report(
                self.assessment,
                path,
            )

            text = path.read_text(
                encoding="utf-8"
            )

            self.assertIn(
                "Assessment Coverage",
                text,
            )

            self.assertIn(
                "Assessment confidence:",
                text,
            )

            self.assertIn(
                "Collection errors:",
                text,
            )
