import boto3
import json
import datetime
import time
import logging
from botocore.exceptions import ClientError

# -------------------
# LOGGING (for ECS)
# -------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
log = logging.getLogger()

# ----- CONFIG -----
BUCKET = "cf-backup-bucket-paras"  # backup bucket - DO NOT DELETE
SAFE_MODE = False  # Set to False to actually delete resources

with open("config.json") as f:
    config = json.load(f)

# ------------------


def now_ts():
    return datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")


# -------------------------
# Utility / S3 helpers
# -------------------------
def empty_and_delete_bucket(s3_client, bucket_name):
    """Empty (including versions) then delete a bucket."""
    log.info(f"[S3] Emptying & deleting bucket: {bucket_name}")

    if SAFE_MODE:
        log.info("[S3] SAFE_MODE ON — would empty & delete bucket")
        return True

    # Remove versions
    try:
        paginator = s3_client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [
                {"Key": key["Key"], "VersionId": key["VersionId"]}
                for key in (page.get("Versions", []) + page.get("DeleteMarkers", []))
            ]
            if objs:
                s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": objs})
    except ClientError:
        pass  # versioning may not be enabled

    # Remove normal objects
    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": objs})
    except ClientError as e:
        log.error(f"[S3] Error while emptying bucket {bucket_name}: {e}")
        return False

    # Finally delete bucket
    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        log.info(f"[S3] Deleted bucket: {bucket_name}")
        return True
    except ClientError as e:
        log.error(f"[S3] Failed to delete bucket {bucket_name}: {e}")
        return False


# -------------------------
# S3 cleanup
# -------------------------
def cleanup_s3(region):
    s3 = boto3.client("s3", region_name=region)
    all_buckets = s3.list_buckets().get("Buckets", [])

    deleted = []
    for b in all_buckets:
        name = b["Name"]
        if name == BUCKET:
            log.info(f"[S3] Skipping backup bucket: {name}")
            continue

        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            bucket_region = loc if loc else "us-east-1"
        except ClientError as e:
            log.error(f"[S3] Could not get location for {name}: {e}")
            continue

        if bucket_region == region:
            log.info(f"[S3] Found bucket in region {region}: {name}")
            if SAFE_MODE or empty_and_delete_bucket(s3, name):
                deleted.append(name)

    return deleted


# -------------------------
# ELB cleanup
# -------------------------
def cleanup_elb(region):
    elb = boto3.client("elb", region_name=region)
    deleted = []

    try:
        lbs = elb.describe_load_balancers().get("LoadBalancerDescriptions", [])
    except ClientError as e:
        log.error(f"[ELB] Error listing LB: {e}")
        return deleted

    for l in lbs:
        name = l["LoadBalancerName"]
        log.info(f"[ELB] Found classic LB: {name}")

        if SAFE_MODE:
            deleted.append(name)
            continue

        try:
            elb.delete_load_balancer(LoadBalancerName=name)
            deleted.append(name)
            log.info(f"[ELB] Deleted: {name}")
        except ClientError as e:
            log.error(f"[ELB] Failed delete {name}: {e}")

    return deleted


# -------------------------
# ELBv2 cleanup
# -------------------------
def cleanup_elbv2(region):
    elbv2 = boto3.client("elbv2", region_name=region)

    deleted_lbs = []
    deleted_tg = []

    try:
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
    except ClientError as e:
        log.error(f"[ELBV2] Error listing: {e}")
        return deleted_lbs, deleted_tg

    for lb in lbs:
        arn = lb["LoadBalancerArn"]
        log.info(f"[ELBV2] Found LB: {arn}")

        if SAFE_MODE:
            deleted_lbs.append(arn)
            continue

        try:
            elbv2.delete_load_balancer(LoadBalancerArn=arn)
            deleted_lbs.append(arn)
        except ClientError as e:
            log.error(f"[ELBV2] Failed delete {arn}: {e}")

    # Target groups
    try:
        tgroups = elbv2.describe_target_groups().get("TargetGroups", [])
    except ClientError:
        tgroups = []

    for tg in tgroups:
        arn = tg["TargetGroupArn"]
        log.info(f"[ELBV2] Found TG: {arn}")

        if SAFE_MODE:
            deleted_tg.append(arn)
            continue

        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            deleted_tg.append(arn)
        except ClientError as e:
            log.error(f"[ELBV2] Failed TG delete {arn}: {e}")

    return deleted_lbs, deleted_tg


# -------------------------
# ASG cleanup
# -------------------------
def cleanup_asg(region):
    asg = boto3.client("autoscaling", region_name=region)
    deleted = []

    try:
        paginator = asg.get_paginator("describe_auto_scaling_groups")
        pages = paginator.paginate()
    except ClientError:
        return deleted

    for page in pages:
        for g in page.get("AutoScalingGroups", []):
            name = g["AutoScalingGroupName"]
            log.info(f"[ASG] Found ASG: {name}")

            if SAFE_MODE:
                deleted.append(name)
                continue

            try:
                asg.update_auto_scaling_group(
                    AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
                )
                asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
                deleted.append(name)
            except ClientError as e:
                log.error(f"[ASG] Failed delete {name}: {e}")

    return deleted


# -------------------------
# RDS cleanup
# -------------------------
def cleanup_rds(region):
    rds = boto3.client("rds", region_name=region)
    deleted = []

    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
    except ClientError as e:
        log.error(f"[RDS] Error listing: {e}")
        return deleted

    for inst in instances:
        dbid = inst["DBInstanceIdentifier"]
        log.info(f"[RDS] Found DB: {dbid}")

        if SAFE_MODE:
            deleted.append(dbid)
            continue

        try:
            snap = f"{dbid}-final-{now_ts()}"
            rds.create_db_snapshot(DBSnapshotIdentifier=snap, DBInstanceIdentifier=dbid)

            waiter = rds.get_waiter("db_snapshot_available")
            waiter.wait(DBSnapshotIdentifier=snap)

            rds.delete_db_instance(DBInstanceIdentifier=dbid, SkipFinalSnapshot=True)
            deleted.append(dbid)
        except ClientError as e:
            log.error(f"[RDS] Delete failed: {e}")

    return deleted


# -------------------------
# VPC cleanup
# -------------------------
def cleanup_vpcs(region):
    ec2_res = boto3.resource("ec2", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    deleted = []

    try:
        vpcs = list(ec2_res.vpcs.all())
    except ClientError:
        return deleted

    for v in vpcs:
        if v.is_default:
            continue

        vpc_id = v.id
        log.info(f"[VPC] Found VPC: {vpc_id}")

        if SAFE_MODE:
            deleted.append(vpc_id)
            continue

        try:
            # Simplified delete flow
            for subnet in v.subnets.all():
                try: subnet.delete()
                except: pass

            ec2.delete_vpc(VpcId=vpc_id)
            deleted.append(vpc_id)
        except ClientError as e:
            log.error(f"[VPC] Failed delete {vpc_id}: {e}")

    return deleted


# -------------------------
# MAIN EXECUTION
# -------------------------
def run_cleanup():
    results = {}
    timestamp = now_ts()

    for region in config["regions"]:
        log.info(f"\n===== REGION: {region} =====")

        region_res = {
            "s3_deleted": cleanup_s3(region),
            "elb_deleted": cleanup_elb(region),
            "elbv2_deleted": cleanup_elbv2(region)[0],
            "target_groups_deleted": cleanup_elbv2(region)[1],
            "asg_deleted": cleanup_asg(region),
            "rds_deleted": cleanup_rds(region),
            "vpcs_deleted": cleanup_vpcs(region)
        }

        results[region] = region_res

    return results


# -------------------------
# ENTRYPOINT for ECS
# -------------------------
def main():
    log.info("Starting cleanup job...")
    out = run_cleanup()
    log.info("Cleanup completed.")
    log.info(json.dumps(out, indent=4))


if __name__ == "__main__":
    main()
