import unittest

from checks.lambda_security import analyze_lambda


class TestLambdaSecurity(unittest.TestCase):

    def secure_function(self):
        return {
            "FunctionName": "secure-function",
            "TracingMode": "Active",
            "VpcAttached": True,
            "EnvironmentEncryptionConfigured": True,
            "DeadLetterConfigured": True,
        }

    def test_secure_function_has_zero_findings(self):
        findings = analyze_lambda(
            [self.secure_function()]
        )

        self.assertEqual(findings, [])

    def test_tracing_disabled_detected(self):
        function = self.secure_function()
        function["TracingMode"] = "PassThrough"

        findings = analyze_lambda([function])

        self.assertIn(
            "ASP-LAMBDA-001",
            [finding.id for finding in findings],
        )

    def test_missing_vpc_is_info(self):
        function = self.secure_function()
        function["VpcAttached"] = False

        findings = analyze_lambda([function])

        finding = next(
            item
            for item in findings
            if item.id == "ASP-LAMBDA-002"
        )

        self.assertEqual(finding.severity, "INFO")

    def test_missing_kms_key_detected(self):
        function = self.secure_function()
        function[
            "EnvironmentEncryptionConfigured"
        ] = False

        findings = analyze_lambda([function])

        self.assertIn(
            "ASP-LAMBDA-003",
            [finding.id for finding in findings],
        )

    def test_missing_dlq_detected(self):
        function = self.secure_function()
        function["DeadLetterConfigured"] = False

        findings = analyze_lambda([function])

        self.assertIn(
            "ASP-LAMBDA-004",
            [finding.id for finding in findings],
        )

    def test_unknown_values_do_not_false_positive(self):
        findings = analyze_lambda([
            {
                "FunctionName": "unknown-function",
            }
        ])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
