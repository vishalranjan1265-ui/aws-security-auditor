import time
import logging
from typing import List, Dict, Any, Callable
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("AWSAuditor.Utils")

def get_aws_session(profile: Optional[str] = None, region: Optional[str] = None) -> boto3.Session:
    try:
        return boto3.Session(profile_name=profile, region_name=region)
    except Exception as e:
        logger.critical(f"Failed to generate valid AWS core session tracking layer: {str(e)}")
        raise

def get_active_regions(session: boto3.Session) -> List[str]:
    try:
        ec2_client = session.client("ec2", region_name="us-east-1")
        regions_response = ec2_client.describe_regions(AllRegions=False)
        return [r["RegionName"] for r in regions_response.get("Regions", [])]
    except ClientError as e:
        logger.error(f"Failed to dynamically query active AWS regions via global EC2 descriptor: {str(e)}")
        return ["us-east-1", "us-west-2", "eu-west-1"]

def with_retry(func: Callable[..., Any], max_retries: int = 3, backoff_factor: float = 2.0) -> Callable[..., Any]:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        retries = 0
        while retries < max_retries:
            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in ["Throttling", "RequestLimitExceeded", "ProvisionedThroughputExceededException"]:
                    retries += 1
                    sleep_time = backoff_factor ** retries
                    logger.warning(f"Throttling detected during AWS call. Retrying in {sleep_time} seconds...")
                    time.sleep(sleep_time)
                else:
                    raise e
        return func(*args, **kwargs)
    return wrapper