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
