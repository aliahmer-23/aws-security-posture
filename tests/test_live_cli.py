import sys
import unittest
from unittest.mock import patch

import aws_posture


SECURE_ASSESSMENT = {
    "coverage": {
                "services": {
                    "iam": {
                        "status": "COMPLETE",
                        "collection_errors": [],
                    },
                    "s3": {
                        "status": "COMPLETE",
                        "collection_errors": [],
                    },
                    "ec2": {
                        "status": "COMPLETE",
                        "collection_errors": [],
                    },
                    "cloudtrail": {
                        "status": "COMPLETE",
                        "collection_errors": [],
                    },
                    "rds": {
                        "status": "COMPLETE",
                        "collection_errors": [],
                    },
                    "kms": {
                        "status": "COMPLETE",
                        "collection_errors": [],
                    },
                },
                "services_assessed": 6,
                "complete": 6,
                "partial": 0,
                "failed": 0,
                "collection_errors": 0,
                "confidence": "COMPLETE",
            },
            "findings": [],
    "risk": {
        "risk_score": 0,
        "raw_risk_score": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": 0,
        "overall_risk": "PASS",
    },
}


class TestLiveCLIIntegration(unittest.TestCase):

    @patch("aws_posture.write_sarif")
    @patch("aws_posture.write_html_report")
    @patch("aws_posture.write_json_report")
    @patch("aws_posture.run_live_assessment")
    def test_live_mode_calls_pipeline(
        self,
        run_live,
        write_json,
        write_html,
        write_sarif,
    ):
        run_live.return_value = SECURE_ASSESSMENT

        with patch.object(
            sys,
            "argv",
            [
                "aws_posture.py",
                "--live",
                "--region",
                "us-east-1",
            ],
        ):
            status = aws_posture.main()

        self.assertEqual(status, 0)

        run_live.assert_called_once_with(
            region="us-east-1",
            profile=None,
        )

        write_json.assert_called_once()
        write_html.assert_called_once()
        write_sarif.assert_called_once()

    @patch("aws_posture.write_sarif")
    @patch("aws_posture.write_html_report")
    @patch("aws_posture.write_json_report")
    @patch("aws_posture.run_live_assessment")
    def test_live_profile_forwarded(
        self,
        run_live,
        write_json,
        write_html,
        write_sarif,
    ):
        run_live.return_value = SECURE_ASSESSMENT

        with patch.object(
            sys,
            "argv",
            [
                "aws_posture.py",
                "--live",
                "--region",
                "us-east-1",
                "--profile",
                "security-audit",
            ],
        ):
            status = aws_posture.main()

        self.assertEqual(status, 0)

        run_live.assert_called_once_with(
            region="us-east-1",
            profile="security-audit",
        )


if __name__ == "__main__":
    unittest.main()
