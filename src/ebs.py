import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

logger = logging.getLogger("AWSAuditor.EBS")

class EBSAuditor:
    def __init__(self, session: Any, region_name: str) -> None:
        self.client = session.client("ec2", region_name=region_name)
        self.region = region_name

    def audit(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            response = self.client.describe_volumes()
            for volume in response.get("Volumes", []):
                volume_id: str = volume["VolumeId"]
                
                # Check 1: Encryption Status
                if not volume.get("Encrypted", False):
                    findings.append({
                        "Resource": f"{volume_id} [{self.region}]",
                        "Type": "EBS Volume",
                        "Severity": "HIGH",
                        "Description": f"Block storage volume '{volume_id}' is not encrypted at rest."
                    })
                
                # Check 2: Unattached Volume Accumulations
                if volume.get("State") == "available":
                    findings.append({
                        "Resource": f"{volume_id} [{self.region}]",
                        "Type": "EBS Volume",
                        "Severity": "MEDIUM",
                        "Description": f"Orphaned storage cluster footprint volume '{volume_id}' is unattached to any instance."
                    })
        except ClientError as e:
            logger.error(f"Failed to scan block storage nodes inside region {self.region}: {str(e)}")
        return findings