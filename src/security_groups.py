import logging
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError

logger = logging.getLogger("AWSAuditor.SecurityGroups")

class SecurityGroupAuditor:
    def __init__(self, session: Any, region_name: str) -> None:
        self.client = session.client("ec2", region_name=region_name)
        self.region = region_name
        self.dangerous_ports = [22, 3389, 5432, 27017, 3306]

    def audit(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            paginator = self.client.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    group_id: str = sg["GroupId"]
                    group_name: str = sg["GroupName"]
                    
                    for perm in sg.get("IpPermissions", []):
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")
                        
                        for ip_range in perm.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0" and self._is_hazardous(from_port, to_port):
                                findings.append({
                                    "Resource": f"{group_id} ({group_name}) [{self.region}]",
                                    "Type": "Security Group",
                                    "Severity": "HIGH",
                                    "Description": f"Inbound rule allows global world access (0.0.0.0/0) to admin port scope [{from_port}-{to_port}]."
                                })
        except ClientError as e:
            logger.error(f"Failed to process network groups inside region {self.region}: {str(e)}")
        return findings

    def _is_hazardous(self, from_port: Optional[int], to_port: Optional[int]) -> bool:
        if from_port is None or to_port is None:
            return True
        return any(from_port <= dp <= to_port for dp in self.dangerous_ports)