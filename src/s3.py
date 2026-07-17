import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

logger = logging.getLogger("AWSAuditor.S3")

class S3Auditor:
    def __init__(self, session: Any) -> None:
        self.client = session.client("s3")

    def audit(self, bucket_names: List[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for name in bucket_names:
            bucket_arn = f"arn:aws:s3:::{name}"
            try:
                if self._has_public_access_allowed(name):
                    findings.append({
                        "Resource": bucket_arn,
                        "Type": "S3 Bucket",
                        "Severity": "HIGH",
                        "Description": f"Bucket '{name}' is public or is missing rigid Public Access Block protections."
                    })
            except ClientError as e:
                logger.error(f"Failed to parse target security policy blocks on bucket {name}: {str(e)}")
        return findings

    def _has_public_access_allowed(self, bucket_name: str) -> bool:
        try:
            pab = self.client.get_public_access_block(Bucket=bucket_name)
            config = pab.get("PublicAccessBlockConfiguration", {})
            return not all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False)
            ])
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return True
            logger.error(f"Could not read public configuration block configurations for {bucket_name}: {str(e)}")
            return True