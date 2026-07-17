import time
import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

logger = logging.getLogger("AWSAuditor.RootUser")

class RootUserAuditor:
    def __init__(self, session: Any) -> None:
        self.client = session.client("iam")

    def audit(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            # Request delivery context of account structural access report records
            logger.info("Requesting latest AWS account IAM authorization tracking credential record snapshot...")
            while True:
                report_status = self.client.generate_credential_report()
                if report_status.get("State") == "COMPLETE":
                    break
                time.sleep(1)

            report_payload = self.client.get_credential_report()
            content: bytes = report_payload.get("Content", b"")
            lines = content.decode("utf-8").split("\n")
            
            if len(lines) > 1:
                headers = lines[0].split(",")
                for line in lines[1:]:
                    if not line.strip():
                        continue
                    columns = line.split(",")
                    row = dict(zip(headers, columns))
                    
                    if row.get("user") == "<root_account>":
                        if row.get("mfa_active") != "true":
                            findings.append({
                                "Resource": "arn:aws:iam::account:root",
                                "Type": "Root Account Profile",
                                "Severity": "CRITICAL",
                                "Description": "The master AWS root console access path does not utilize MFA security constraints."
                            })
                        if row.get("access_key_1_active") == "true" or row.get("access_key_2_active") == "true":
                            findings.append({
                                "Resource": "arn:aws:iam::account:root-keys",
                                "Type": "Root Account Profile",
                                "Severity": "CRITICAL",
                                "Description": "Active access keys were discovered for the root user account. These must be deleted immediately."
                            })
        except ClientError as e:
            logger.error(f"Failed to access administrative billing credentials context layers: {str(e)}")
        return findings