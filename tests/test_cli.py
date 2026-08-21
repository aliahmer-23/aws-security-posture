import subprocess
import sys
import unittest


class TestCLI(unittest.TestCase):

    def run_cli(self, fixture):
        return subprocess.run(
            [
                sys.executable,
                "aws_posture.py",
                "--fixture",
                fixture,
            ],
            capture_output=True,
            text=True,
        )

    def test_secure_fixture_passes(self):
        result = self.run_cli(
            "fixtures/secure.json"
        )

        self.assertEqual(
            result.returncode,
            0,
        )

        self.assertIn(
            "SECURITY POSTURE PASSED",
            result.stdout,
        )

    def test_secure_fixture_shows_coverage(self):
        result = self.run_cli(
            "fixtures/secure.json"
        )

        self.assertEqual(
            result.returncode,
            0,
        )

        self.assertIn(
            "ASSESSMENT COVERAGE",
            result.stdout,
        )

        self.assertIn(
            "Assessment confidence: COMPLETE",
            result.stdout,
        )

        self.assertIn(
            "Collection errors:     0",
            result.stdout,
        )

    def test_insecure_fixture_fails(self):
        result = self.run_cli(
            "fixtures/insecure.json"
        )

        self.assertEqual(
            result.returncode,
            1,
        )

        self.assertIn(
            "SECURITY ISSUES DETECTED",
            result.stdout,
        )

    def test_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "aws_posture.py",
                "--version",
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(
            result.returncode,
            0,
        )

        self.assertIn(
            "1.0.0",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()


class TestLiveCLIArguments(unittest.TestCase):

    def run_command(self, *arguments):
        return subprocess.run(
            [
                sys.executable,
                "aws_posture.py",
                *arguments,
            ],
            capture_output=True,
            text=True,
        )

    def test_fixture_and_live_rejected(self):
        result = self.run_command(
            "--fixture",
            "fixtures/secure.json",
            "--live",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "cannot be used together",
            result.stderr,
        )

    def test_missing_mode_rejected(self):
        result = self.run_command()

        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "one assessment mode is required",
            result.stderr,
        )

    def test_region_without_live_rejected(self):
        result = self.run_command(
            "--region",
            "us-east-1",
        )

        self.assertEqual(result.returncode, 2)

    def test_profile_without_live_rejected(self):
        result = self.run_command(
            "--profile",
            "security-audit",
        )

        self.assertEqual(result.returncode, 2)
