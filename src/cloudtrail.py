import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

logger = logging.getLogger("AWSAuditor.CloudTrail")

class CloudTrailAuditor:
    def __init__(self, session: Any, region_name: str) -> None:
        self.client = session.client("cloudtrail", region_name=region_name)
        self.region = region_name

    def audit(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            response = self.client.describe_trails(includeShadowTrails=False)
            trails = response.get("trailList", [])
            
            if not trails and self.region == "us-east-1":
                findings.append({
                    "Resource": f"AccountGlobal [{self.region}]",
                    "Type": "CloudTrail",
                    "Severity": "CRITICAL",
                    "Description": f"No active operational CloudTrail auditing configurations discovered inside base region context {self.region}."
                })
                
            for trail in trails:
                trail_arn: str = trail["TrailARN"]
                if not trail.get("IsMultiRegionTrail", False):
                    findings.append({
                        "Resource": trail_arn,
                        "Type": "CloudTrail",
                        "Severity": "MEDIUM",
                        "Description": f"Trail '{trail['Name']}' is localized and does not record cross-region tracking events."
                    })
                if not trail.get("LogFileValidationEnabled", False):
                    findings.append({
                        "Resource": trail_arn,
                        "Type": "CloudTrail",
                        "Severity": "HIGH",
                        "Description": f"Log file cryptographic integrity verification validation checks are disabled on trail '{trail['Name']}'."
                    })
        except ClientError as e:
            logger.error(f"Failed to query diagnostic logs inside CloudTrail clusters in region {self.region}: {str(e)}")
        return findings