import sys
import os
import logging
from typing import List, Dict, Any
import yaml
import boto3

from utils import get_aws_session, get_active_regions
from iam import IAMAuditor
from s3 import S3Auditor
from ec2 import EC2Auditor
from security_groups import SecurityGroupAuditor
from cloudtrail import CloudTrailAuditor
from cloudwatch import CloudWatchAuditor
from password_policy import PasswordPolicyAuditor
from root_user import RootUserAuditor
from ebs import EBSAuditor
from report import ReportCompiler

def load_config() -> Dict[str, Any]:
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        # Graceful baseline fallbacks if configuration is physically unreadable
        return {"global": {"output_dir": "reports", "enable_multi_region": True}}

config = load_config()
logging.basicConfig(
    level=config.get("global", {}).get("log_level", "INFO"),
    format='{"timestamp":"%(asctime)s", "service":"AuditorCore", "level":"%(levelname)s", "message":"%(message)s"}',
    stream=sys.stdout
)
logger = logging.getLogger("AWSAuditor.Main")

def run_scanners() -> None:
    logger.info("Initializing configuration rules extraction paths...")
    
    try:
        session = get_aws_session()
    except Exception as e:
        logger.critical(f"Aborting execution run block. AWS credential lookup failed: {str(e)}")
        sys.exit(1)

    all_findings: List[Dict[str, Any]] = []

    # -----------------------------------------------------------------------
    # 1. Global Scan Blocks
    # -----------------------------------------------------------------------
    logger.info("Running global configurations inspection metrics layer...")
    all_findings.extend(PasswordPolicyAuditor(session).audit())
    all_findings.extend(RootUserAuditor(session).audit())
    all_findings.extend(IAMAuditor(session, config).audit())

    # Map S3 identifiers ahead of loops to decouple and save networking resources
    try:
        s3_global = session.client("s3")
        buckets = [b["Name"] for b in s3_global.list_buckets().get("Buckets", [])]
    except Exception as e:
        logger.error(f"Global account bucket fetching block failed: {str(e)}")
        buckets = []

    # -----------------------------------------------------------------------
    # 2. Regional Scan Multi-Threading Blocks
    # -----------------------------------------------------------------------
    regions = get_active_regions(session) if config.get("global", {}).get("enable_multi_region", True) else [session.region_name or "us-east-1"]
    
    for current_region in regions:
        logger.info(f"==> Initiating regional framework evaluation loops on target region: [{current_region}]")
        
        # S3 Scanning
        all_findings.extend(S3Auditor(session).audit(buckets))
        
        # EC2 Monitoring State Check
        all_findings.extend(EC2Auditor(session, current_region).audit_instances())
        
        # Network Firewalls
        all_findings.extend(SecurityGroupAuditor(session, current_region).audit())
        
        # Audit Logs & Trails
        all_findings.extend(CloudTrailAuditor(session, current_region).audit())
        all_findings.extend(CloudWatchAuditor(session, current_region).audit())
        
        # Block Storage Volumes
        all_findings.extend(EBSAuditor(session, current_region).audit())

    # -----------------------------------------------------------------------
    # 3. Compile Reports Output Matrix
    # -----------------------------------------------------------------------
    output_directory = config.get("global", {}).get("output_dir", "reports")
    logger.info(f"Compiling tracking logs matrix data into target layout output mapping directory: {output_directory}")
    ReportCompiler.output_all(all_findings, output_directory)
    logger.info("Fleet infrastructure operational scan successfully executed.")

if __name__ == "__main__":
    run_scanners()