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
    log.info(f"[S3] Emptying & deleting bucket: {bucket_name}")

    if SAFE_MODE:
        log.info("[S3] SAFE_MODE ON — would empty & delete bucket")
        return True

    # Delete object versions if enabled
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
        pass

    # Delete normal objects
    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": objs})
    except ClientError as e:
        log.error(f"[S3] Error while emptying bucket {bucket_name}: {e}")
        return False

    # Delete the bucket
    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        log.info(f"[S3] Deleted bucket: {bucket_name}")
        return True
    except ClientError as e:
        log.error(f"[S3] Failed to delete bucket {bucket_name}: {e}")
        return False


def cleanup_s3(region):
    s3 = boto3.client("s3", region_name=region)
    all_buckets = s3.list_buckets().get("Buckets", [])

    deleted = []
    for b in all_buckets:
        name = b["Name"]

        if name == BUCKET:
            continue

        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            bucket_region = loc if loc else "us-east-1"
        except Exception:
            continue

        if bucket_region == region:
            if SAFE_MODE or empty_and_delete_bucket(s3, name):
                deleted.append(name)

    return deleted


# ===============================================================
# EC2 Cleanup (Instances + Volumes + EIPs)
# ===============================================================
def cleanup_ec2(region):
    ec2 = boto3.client("ec2", region_name=region)
    deleted_instances = []
    deleted_volumes = []
    released_eips = []

    log.info(f"[EC2] Starting EC2 cleanup in region {region}")

    # -------- EC2 INSTANCES --------
    try:
        instances = ec2.describe_instances()
        for reservation in instances["Reservations"]:
            for inst in reservation["Instances"]:
                inst_id = inst["InstanceId"]
                state = inst["State"]["Name"]
                log.info(f"[EC2] Found instance {inst_id} ({state})")

                if SAFE_MODE:
                    deleted_instances.append(inst_id)
                    continue

                if state not in ["terminated", "shutting-down"]:
                    try:
                        ec2.terminate_instances(InstanceIds=[inst_id])
                        deleted_instances.append(inst_id)
                        log.info(f"[EC2] Terminated instance: {inst_id}")
                    except ClientError as e:
                        log.error(f"[EC2] Failed to delete {inst_id}: {e}")

    except Exception as e:
        log.error(f"[EC2] Error listing instances: {e}")

    # -------- UNATTACHED VOLUMES --------
    try:
        volumes = ec2.describe_volumes()
        for vol in volumes["Volumes"]:
            vol_id = vol["VolumeId"]
            if len(vol["Attachments"]) == 0:
                log.info(f"[EC2] Unattached volume found: {vol_id}")

                if SAFE_MODE:
                    deleted_volumes.append(vol_id)
                    continue

                try:
                    ec2.delete_volume(VolumeId=vol_id)
                    deleted_volumes.append(vol_id)
                except ClientError as e:
                    log.error(f"[EC2] Failed to delete volume {vol_id}: {e}")
    except Exception as e:
        log.error(f"[EC2] Error listing volumes: {e}")

    # -------- UNASSOCIATED ELASTIC IPs --------
    try:
        eips = ec2.describe_addresses()
        for eip in eips["Addresses"]:
            if "AssociationId" not in eip:
                alloc_id = eip["AllocationId"]
                log.info(f"[EC2] Unused EIP: {alloc_id}")

                if SAFE_MODE:
                    released_eips.append(alloc_id)
                    continue

                try:
                    ec2.release_address(AllocationId=alloc_id)
                    released_eips.append(alloc_id)
                except ClientError as e:
                    log.error(f"[EC2] Failed to release EIP {alloc_id}: {e}")
    except Exception as e:
        log.error(f"[EC2] Error listing EIPs: {e}")

    return {
        "instances_deleted": deleted_instances,
        "volumes_deleted": deleted_volumes,
        "eips_released": released_eips
    }


# ===============================================================
# Lambda Cleanup
# ===============================================================
def cleanup_lambda(region):
    lam = boto3.client("lambda", region_name=region)
    deleted_functions = []

    log.info(f"[Lambda] Starting Lambda cleanup in region {region}")

    try:
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                fn_name = fn["FunctionName"]
                log.info(f"[Lambda] Found function: {fn_name}")

                if SAFE_MODE:
                    deleted_functions.append(fn_name)
                    continue

                try:
                    lam.delete_function(FunctionName=fn_name)
                    deleted_functions.append(fn_name)
                    log.info(f"[Lambda] Deleted function: {fn_name}")
                except ClientError as e:
                    log.error(f"[Lambda] Failed to delete {fn_name}: {e}")

    except Exception as e:
        log.error(f"[Lambda] Error listing Lambda functions: {e}")

    return deleted_functions

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


# ===============================================================
# EKS Cleanup (Cluster, Nodegroups, Fargate Profiles)
# ===============================================================
def cleanup_eks(region):
    eks = boto3.client("eks", region_name=region)
    deleted_clusters = []
    deleted_nodegroups = []
    deleted_fargate = []

    log.info(f"[EKS] Starting EKS cleanup in region {region}")

    try:
        clusters = eks.list_clusters().get("clusters", [])
    except Exception as e:
        log.error(f"[EKS] Error listing clusters: {e}")
        return {
            "clusters_deleted": deleted_clusters,
            "nodegroups_deleted": deleted_nodegroups,
            "fargate_deleted": deleted_fargate
        }

    for cluster in clusters:
        log.info(f"[EKS] Found cluster: {cluster}")

        # ------------------------------------
        # 1) Delete Nodegroups
        # ------------------------------------
        try:
            nodegroups = eks.list_nodegroups(clusterName=cluster).get("nodegroups", [])
            for ng in nodegroups:
                log.info(f"[EKS] Deleting nodegroup: {ng}")

                if SAFE_MODE:
                    deleted_nodegroups.append(ng)
                    continue

                try:
                    eks.delete_nodegroup(clusterName=cluster, nodegroupName=ng)
                    deleted_nodegroups.append(ng)
                except Exception as e:
                    log.error(f"[EKS] Failed to delete nodegroup {ng}: {e}")

        except Exception:
            pass

        # ------------------------------------
        # 2) Delete Fargate Profiles
        # ------------------------------------
        try:
            fargate_profiles = eks.list_fargate_profiles(clusterName=cluster).get("fargateProfileNames", [])
            for fp in fargate_profiles:
                log.info(f"[EKS] Deleting Fargate profile: {fp}")

                if SAFE_MODE:
                    deleted_fargate.append(fp)
                    continue

                try:
                    eks.delete_fargate_profile(clusterName=cluster, fargateProfileName=fp)
                    deleted_fargate.append(fp)
                except Exception as e:
                    log.error(f"[EKS] Failed to delete Fargate profile {fp}: {e}")

        except Exception:
            pass

        # ------------------------------------
        # 3) Delete Main EKS Cluster
        # ------------------------------------
        if SAFE_MODE:
            deleted_clusters.append(cluster)
            continue

        try:
            log.info(f"[EKS] Deleting EKS cluster: {cluster}")
            eks.delete_cluster(name=cluster)
            deleted_clusters.append(cluster)
        except Exception as e:
            log.error(f"[EKS] Failed to delete cluster {cluster}: {e}")

    return {
        "clusters_deleted": deleted_clusters,
        "nodegroups_deleted": deleted_nodegroups,
        "fargate_deleted": deleted_fargate
    }

# ===============================================================
# CloudFormation Cleanup (EKS ONLY)
# ===============================================================
def cleanup_cloudformation_eks_only(region):
    cfn = boto3.client("cloudformation", region_name=region)
    deleted = []

    log.info(f"[CFN] Starting EKS-only CloudFormation cleanup in region {region}")

    try:
        stacks = cfn.describe_stacks().get("Stacks", [])
    except ClientError as e:
        log.error(f"[CFN] Error listing stacks: {e}")
        return deleted

    # Filter ONLY EKS-related stacks
    eks_stacks = []

    for st in stacks:
        name = st["StackName"]
        status = st["StackStatus"]

        # Ignore already deleted or failed stacks
        if status.endswith("FAILED") or "DELETE" in status:
            continue

        # Match patterns of EKS stacks
        if (
            "EKS" in name.upper()
            or "NODEGROUP" in name.upper()
            or "FARGATE" in name.upper()
            or "EKSCLUSTER" in name.upper()
        ):
            eks_stacks.append(name)

    # Delete ONLY EKS stacks
    for name in eks_stacks:
        log.info(f"[CFN] Found EKS stack: {name}")

        if SAFE_MODE:
            deleted.append(name)
            continue

        try:
            cfn.delete_stack(StackName=name)
            log.info(f"[CFN] Deleting EKS stack: {name}")

            waiter = cfn.get_waiter("stack_delete_complete")
            waiter.wait(StackName=name)
            deleted.append(name)
            log.info(f"[CFN] Deleted EKS stack: {name}")

        except ClientError as e:
            log.error(f"[CFN] Failed to delete {name}: {e}")

    return deleted


# -------------------------
# MAIN EXECUTION
# -------------------------
def run_cleanup():
    results = {}
    for region in config["regions"]:
        log.info(f"\n===== REGION: {region} =====")

        results[region] = {
            "s3_deleted": cleanup_s3(region),
            "lambda_deleted": cleanup_lambda(region),
            "elb_deleted": cleanup_elb(region),
            "elbv2_deleted": cleanup_elbv2(region)[0],
            "target_groups_deleted": cleanup_elbv2(region)[1],
            "asg_deleted": cleanup_asg(region),
            "rds_deleted": cleanup_rds(region),
             # 🟦 NEW — Full EKS Cleanup
            "eks_deleted": cleanup_eks(region),

            # 🟦 Delete ONLY EKS CloudFormation stacks
            "cloudformation_eks_deleted": cleanup_cloudformation_eks_only(region),
            "ec2_deleted": cleanup_ec2(region),
            "vpcs_deleted": cleanup_vpcs(region),
        }
    return results


def main():
    log.info("Starting cleanup job...")
    output = run_cleanup()
    log.info("Cleanup completed.")
    log.info(json.dumps(output, indent=4))

if __name__ == "__main__":
    main()
