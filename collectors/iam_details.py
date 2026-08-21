from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError


DEFAULT_UNUSED_DAYS = 90


def _error(
    operation: str,
    exc: ClientError,
) -> Dict[str, str]:
    error = exc.response.get("Error", {})

    return {
        "operation": operation,
        "code": error.get("Code", "Unknown"),
    }


def _password_policy(
    iam: Any,
    errors: List[Dict[str, str]],
) -> Optional[Dict[str, Any]]:
    try:
        response = iam.get_account_password_policy()

        policy = response.get(
            "PasswordPolicy",
            {},
        )

        return {
            "minimum_length": policy.get(
                "MinimumPasswordLength",
                0,
            ),
        }

    except ClientError as exc:
        code = exc.response.get(
            "Error",
            {},
        ).get(
            "Code",
            "Unknown",
        )

        # AWS returns NoSuchEntity when an account-level
        # IAM password policy has not been configured.
        if code == "NoSuchEntity":
            return {
                "minimum_length": 0,
            }

        errors.append(
            _error(
                "get_account_password_policy",
                exc,
            )
        )

        return None


def _list_users(
    iam: Any,
    errors: List[Dict[str, str]],
) -> Optional[List[Dict[str, Any]]]:
    users = []
    marker = None

    try:
        while True:
            kwargs = {}

            if marker:
                kwargs["Marker"] = marker

            response = iam.list_users(**kwargs)

            users.extend(
                response.get("Users", [])
            )

            if not response.get(
                "IsTruncated",
                False,
            ):
                break

            marker = response.get("Marker")

            if not marker:
                break

        return users

    except ClientError as exc:
        errors.append(
            _error("list_users", exc)
        )
        return None


def _count_unused_access_keys(
    iam: Any,
    users: List[Dict[str, Any]],
    errors: List[Dict[str, str]],
    unused_days: int,
    now: datetime,
) -> Optional[int]:
    unused = 0
    complete = True

    for user in users:
        username = user.get("UserName")

        if not username:
            continue

        try:
            response = iam.list_access_keys(
                UserName=username
            )

        except ClientError as exc:
            errors.append(
                _error(
                    "list_access_keys",
                    exc,
                )
            )
            complete = False
            continue

        for key in response.get(
            "AccessKeyMetadata",
            [],
        ):
            if key.get("Status") != "Active":
                continue

            key_id = key.get("AccessKeyId")

            if not key_id:
                continue

            try:
                last_used_response = (
                    iam.get_access_key_last_used(
                        AccessKeyId=key_id
                    )
                )

            except ClientError as exc:
                errors.append(
                    _error(
                        "get_access_key_last_used",
                        exc,
                    )
                )
                complete = False
                continue

            last_used = last_used_response.get(
                "AccessKeyLastUsed",
                {},
            ).get(
                "LastUsedDate"
            )

            if last_used is None:
                unused += 1
                continue

            if last_used.tzinfo is None:
                last_used = last_used.replace(
                    tzinfo=timezone.utc
                )

            age = now - last_used

            if age.days >= unused_days:
                unused += 1

    if not complete:
        return None

    return unused


def _count_admin_users(
    iam: Any,
    users: List[Dict[str, Any]],
    errors: List[Dict[str, str]],
) -> Optional[int]:
    """
    Conservative direct-user administrator detection.

    This checks managed policies directly attached to IAM
    users. Group/role-derived effective privilege analysis
    can be added as a later enhancement.
    """

    admin_users = 0
    complete = True

    for user in users:
        username = user.get("UserName")

        if not username:
            continue

        try:
            response = iam.list_attached_user_policies(
                UserName=username
            )

        except ClientError as exc:
            errors.append(
                _error(
                    "list_attached_user_policies",
                    exc,
                )
            )
            complete = False
            continue

        policies = response.get(
            "AttachedPolicies",
            [],
        )

        if any(
            policy.get("PolicyArn")
            == "arn:aws:iam::aws:policy/AdministratorAccess"
            for policy in policies
        ):
            admin_users += 1

    if not complete:
        return None

    return admin_users


def collect_iam_security_details(
    iam: Any,
    account_summary: Dict[str, Any],
    unused_days: int = DEFAULT_UNUSED_DAYS,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Collect additional read-only IAM security posture data.

    No IAM users, roles, policies, credentials, or other
    AWS resources are created, modified, or deleted.
    """

    if now is None:
        now = datetime.now(timezone.utc)

    summary = account_summary.get(
        "SummaryMap",
        {},
    )

    errors: List[Dict[str, str]] = []

    result = {
        "root_access_keys": summary.get(
            "AccountAccessKeysPresent",
            0,
        ),
        "root_mfa_enabled": bool(
            summary.get(
                "AccountMFAEnabled",
                0,
            )
        ),
        "unused_access_keys": None,
        "admin_users": None,
        "password_policy": None,
        "collection_errors": errors,
    }

    result["password_policy"] = _password_policy(
        iam,
        errors,
    )

    users = _list_users(
        iam,
        errors,
    )

    if users is None:
        return result

    result["unused_access_keys"] = (
        _count_unused_access_keys(
            iam,
            users,
            errors,
            unused_days,
            now,
        )
    )

    result["admin_users"] = _count_admin_users(
        iam,
        users,
        errors,
    )

    return result
