import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from botocore.exceptions import ClientError

logger = logging.getLogger("AWSAuditor.IAM")

class IAMAuditor:
    def __init__(self, session: Any, config: Dict[str, Any]) -> None:
        self.client = session.client("iam")
        self.threshold_days = config.get("thresholds", {}).get("access_key_expiry_days", 90)

    def audit(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            paginator = self.client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username: str = user["UserName"]
                    user_arn: str = user["Arn"]
                    
                    if not self._is_mfa_enabled(username):
                        findings.append({
                            "Resource": user_arn,
                            "Type": "IAM User",
                            "Severity": "CRITICAL",
                            "Description": f"User '{username}' lacks Multi-Factor Authentication (MFA) privileges."
                        })
                    
                    findings.extend(self._audit_access_keys(username, user_arn))
        except ClientError as e:
            logger.error(f"Failed to scan IAM user directory: {str(e)}")
        return findings

    def _is_mfa_enabled(self, username: str) -> bool:
        try:
            mfa_devices = self.client.list_mfa_devices(UserName=username)
            return len(mfa_devices.get("MFADevices", [])) > 0
        except ClientError as e:
            logger.error(f"Error checking MFA devices for user {username}: {str(e)}")
            return False

    def _audit_access_keys(self, username: str, user_arn: str) -> List[Dict[str, Any]]:
        key_findings: List[Dict[str, Any]] = []
        try:
            keys_data = self.client.list_access_keys(UserName=username)
            now = datetime.now(timezone.utc)
            for metadata in keys_data.get("AccessKeyMetadata", []):
                if metadata["Status"] == "Active":
                    create_date: datetime = metadata["CreateDate"]
                    age_days = (now - create_date).days
                    if age_days > self.threshold_days:
                        key_findings.append({
                            "Resource": f"{user_arn}/accesskey/{metadata['AccessKeyId']}",
                            "Type": "IAM Access Key",
                            "Severity": "HIGH",
                            "Description": f"Active key {metadata['AccessKeyId']} is stale ({age_days} days old). Rotation required."
                        })
        except ClientError as e:
            logger.error(f"Error checking access keys for user {username}: {str(e)}")
        return key_findings