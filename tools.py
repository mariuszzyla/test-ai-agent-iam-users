import csv
import io
import json
import time
import boto3

from langchain_core.tools import Tool, StructuredTool
from pydantic import BaseModel
from langchain_community.tools import DuckDuckGoSearchRun

search_ddg = DuckDuckGoSearchRun()

search_duckduckgo = Tool(
    name = "search_duckduckgo",
    func=search_ddg.run,
    description="Search the web for information"
)

def _fetch_credential_report(iam) -> dict:
    """Generates IAM credential report and returns it as a dict keyed by username."""
    for _ in range(10):
        response = iam.generate_credential_report()
        if response["State"] == "COMPLETE":
            break
        time.sleep(2)

    report = iam.get_credential_report()
    reader = csv.DictReader(io.StringIO(report["Content"].decode("utf-8")))
    return {row["user"]: row for row in reader}


def _get_user_security_info(iam, username: str, credential_row: dict) -> dict:
    mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

    access_keys = []
    for key in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
        last_used_resp = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
        last_used = last_used_resp.get("AccessKeyLastUsed", {})
        access_keys.append({
            "key_id": key["AccessKeyId"],
            "status": key["Status"],
            "created": key["CreateDate"].isoformat(),
            "last_used": last_used.get("LastUsedDate", "never"),
            "last_used_service": last_used.get("ServiceName"),
            "last_used_region": last_used.get("Region"),
        })

    n = lambda v: None if v in ("N/A", "no_information", "", "not_supported") else v

    return {
        "mfa_enabled": len(mfa_devices) > 0,
        "mfa_devices": [d["SerialNumber"] for d in mfa_devices],
        "access_keys": access_keys,
        "password_last_used": n(credential_row.get("password_last_used")),
        "password_last_changed": n(credential_row.get("password_last_changed")),
    }


def _get_user_permissions(iam, username: str) -> dict:
    permissions = {
        "managed_policies": [],
        "inline_policies": [],
        "groups": [],
    }

    # Managed policies directly attached to user
    paginator = iam.get_paginator("list_attached_user_policies")
    for page in paginator.paginate(UserName=username):
        for policy in page["AttachedPolicies"]:
            policy_detail = {"name": policy["PolicyName"], "arn": policy["PolicyArn"], "document": None}
            try:
                version_id = iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]["DefaultVersionId"]
                doc = iam.get_policy_version(PolicyArn=policy["PolicyArn"], VersionId=version_id)
                policy_detail["document"] = doc["PolicyVersion"]["Document"]
            except Exception:
                pass
            permissions["managed_policies"].append(policy_detail)

    # Inline policies embedded in user
    paginator = iam.get_paginator("list_user_policies")
    for page in paginator.paginate(UserName=username):
        for policy_name in page["PolicyNames"]:
            try:
                doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)
                permissions["inline_policies"].append({
                    "name": policy_name,
                    "document": doc["PolicyDocument"],
                })
            except Exception:
                permissions["inline_policies"].append({"name": policy_name, "document": None})

    # Groups and their policies
    paginator = iam.get_paginator("list_groups_for_user")
    for page in paginator.paginate(UserName=username):
        for group in page["Groups"]:
            group_name = group["GroupName"]
            group_entry = {
                "name": group_name,
                "managed_policies": [],
                "inline_policies": [],
            }

            # Managed policies attached to group
            gp_paginator = iam.get_paginator("list_attached_group_policies")
            for gp_page in gp_paginator.paginate(GroupName=group_name):
                for policy in gp_page["AttachedPolicies"]:
                    policy_detail = {"name": policy["PolicyName"], "arn": policy["PolicyArn"], "document": None}
                    try:
                        version_id = iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]["DefaultVersionId"]
                        doc = iam.get_policy_version(PolicyArn=policy["PolicyArn"], VersionId=version_id)
                        policy_detail["document"] = doc["PolicyVersion"]["Document"]
                    except Exception:
                        pass
                    group_entry["managed_policies"].append(policy_detail)

            # Inline policies embedded in group
            gip_paginator = iam.get_paginator("list_group_policies")
            for gip_page in gip_paginator.paginate(GroupName=group_name):
                for policy_name in gip_page["PolicyNames"]:
                    try:
                        doc = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                        group_entry["inline_policies"].append({
                            "name": policy_name,
                            "document": doc["PolicyDocument"],
                        })
                    except Exception:
                        group_entry["inline_policies"].append({"name": policy_name, "document": None})

            permissions["groups"].append(group_entry)

    return permissions


def _list_iam_users_with_permissions(_: str = "") -> str:
    iam = boto3.client("iam")
    credential_report = _fetch_credential_report(iam)
    users = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            entry = {
                "username": username,
                "arn": user["Arn"],
                "created": user["CreateDate"].isoformat(),
                "security": _get_user_security_info(iam, username, credential_report.get(username, {})),
                "permissions": _get_user_permissions(iam, username),
            }
            users.append(entry)

    return json.dumps(users, indent=2, default=str)


list_iam_users_with_permissions = Tool(
    name="list_iam_users_with_permissions",
    func=_list_iam_users_with_permissions,
    description=(
        "Returns a JSON list of all AWS IAM users with their assigned permissions and security posture. "
        "For each user includes: MFA status, API access keys (IDs, status, last used), "
        "last console login, last password change, "
        "directly attached managed policies (with full policy documents), "
        "inline policies, and policies inherited through group membership. "
        "Use this tool to analyse who has access to what in the AWS account."
    ),
)


def _get_iam_user_permissions(username: str) -> str:
    iam = boto3.client("iam")
    try:
        user = iam.get_user(UserName=username)["User"]
    except iam.exceptions.NoSuchEntityException:
        return json.dumps({"error": f"User '{username}' not found."})

    credential_report = _fetch_credential_report(iam)
    entry = {
        "username": username,
        "arn": user["Arn"],
        "created": user["CreateDate"].isoformat(),
        "security": _get_user_security_info(iam, username, credential_report.get(username, {})),
        "permissions": _get_user_permissions(iam, username),
    }
    return json.dumps(entry, indent=2, default=str)


get_iam_user_permissions = Tool(
    name="get_iam_user_permissions",
    func=_get_iam_user_permissions,
    description=(
        "Returns a JSON object with permissions and security posture of a single AWS IAM user. "
        "Input must be the exact IAM username. "
        "Includes: MFA status, API access keys (IDs, status, last used), "
        "last console login, last password change, "
        "directly attached managed policies (with full policy documents), "
        "inline policies, and policies inherited through group membership. "
        "Use this tool when you need to inspect a specific user."
    ),
)

class ModifyIamResourceInput(BaseModel):
    method_name: str
    parameters: dict


def _modify_iam_resource(method_name: str, parameters: dict) -> str:
    iam = boto3.client("iam")
    method = getattr(iam, method_name, None)
    if method is None:
        return f"Error: '{method_name}' is not a valid IAM boto3 method."
    response = method(**parameters)
    response.pop("ResponseMetadata", None)
    return json.dumps(response, default=str) if response else f"'{method_name}' executed successfully."

modify_iam_resource = StructuredTool(
    name="modify_iam_resource",
    func=_modify_iam_resource,
    args_schema=ModifyIamResourceInput,
    description=(
        "Executes any AWS IAM boto3 write operation. "
        "ALWAYS provide both 'method_name' and 'parameters' — 'parameters' is REQUIRED and must never be omitted. "
        "The 'parameters' dict must contain exactly the arguments required by the boto3 IAM method as per AWS documentation. "
        "Common operations and their required parameters:\n"
        "- create_user: {\"UserName\": \"alice\"}\n"
        "- delete_user: {\"UserName\": \"alice\"}\n"
        "- update_access_key (deactivate): {\"UserName\": \"alice\", \"AccessKeyId\": \"AKIA...\", \"Status\": \"Inactive\"}\n"
        "- delete_access_key: {\"UserName\": \"alice\", \"AccessKeyId\": \"AKIA...\"}\n"
        "- add_user_to_group: {\"UserName\": \"alice\", \"GroupName\": \"Developers\"}\n"
        "- remove_user_from_group: {\"UserName\": \"alice\", \"GroupName\": \"Developers\"}\n"
        "- attach_user_policy: {\"UserName\": \"alice\", \"PolicyArn\": \"arn:aws:iam::aws:policy/ReadOnlyAccess\"}\n"
        "- detach_user_policy: {\"UserName\": \"alice\", \"PolicyArn\": \"arn:aws:iam::aws:policy/ReadOnlyAccess\"}\n"
        "- create_group: {\"GroupName\": \"Developers\"}\n"
        "- delete_group: {\"GroupName\": \"Developers\"}\n"
        "If unsure about required parameters, check boto3 IAM documentation before calling."
    ),
)


class SaveToFileInput(BaseModel):
    file_name: str
    content: str


def _save_to_file(file_name: str, content: str) -> str:
    with open(file_name, "w", encoding="utf-8") as f:
        f.write(content)
    return f"Report saved to {file_name}"


save_to_file = StructuredTool(
    name="save_to_file",
    func=_save_to_file,
    args_schema=SaveToFileInput,
    description=(
        "Saves the provided text content to a file. "
        "Provide a descriptive file_name including extension (e.g. 'iam_report.md', 'remediation.sh'). "
        "Accepts any text-based format: markdown, bash scripts, JSON, etc."
    ),
)
