import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

logger = logging.getLogger("AWSAuditor.EC2")

class EC2Auditor:
    def __init__(self, session: Any, region_name: str) -> None:
        self.client = session.client("ec2", region_name=region_name)
        self.region = region_name

    def audit_instances(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            response = self.client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id: str = instance["InstanceId"]
                    
                    # Audit detailed monitoring enablement status
                    monitoring_state = instance.get("Monitoring", {}).get("State", "")
                    if monitoring_state != "enabled":
                        findings.append({
                            "Resource": f"{instance_id} [{self.region}]",
                            "Type": "EC2 Instance",
                            "Severity": "LOW",
                            "Description": f"Detailed CloudWatch metric tracking is disabled for running instance {instance_id}."
                        })
        except ClientError as e:
            logger.error(f"Failed to execute EC2 cluster scans inside region {self.region}: {str(e)}")
        return findings