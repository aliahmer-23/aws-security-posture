import unittest
from unittest.mock import MagicMock, patch

from collectors.session import (
    AWS_SERVICES,
    create_aws_clients,
)


class TestAWSSession(unittest.TestCase):

    @patch("boto3.Session")
    def test_creates_required_clients(self, session_class):
        session = MagicMock()
        session_class.return_value = session

        session.client.side_effect = (
            lambda service, **kwargs:
            f"{service}-client"
        )

        clients = create_aws_clients(
            region="us-east-1"
        )

        self.assertEqual(
            set(clients),
            set(AWS_SERVICES),
        )

        for service in AWS_SERVICES:
            self.assertEqual(
                clients[service],
                f"{service}-client",
            )

    @patch("boto3.Session")
    def test_region_passed_to_session(self, session_class):
        session_class.return_value = MagicMock()

        create_aws_clients(
            region="us-east-1"
        )

        session_class.assert_called_once_with(
            region_name="us-east-1"
        )

    @patch("boto3.Session")
    def test_profile_passed_to_session(self, session_class):
        session_class.return_value = MagicMock()

        create_aws_clients(
            profile="security-audit"
        )

        session_class.assert_called_once_with(
            profile_name="security-audit"
        )

    @patch("boto3.Session")
    def test_no_profile_or_region_supported(
        self,
        session_class,
    ):
        session_class.return_value = MagicMock()

        create_aws_clients()

        session_class.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
