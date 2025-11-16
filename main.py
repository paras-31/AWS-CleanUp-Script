import boto3
import json
import datetime
import time
from botocore.exceptions import ClientError

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
    print(f"[S3] Emptying & deleting bucket: {bucket_name}")
    if SAFE_MODE:
        print("[S3] SAFE_MODE ON — would empty & delete bucket")
        return True

    # Remove object versions (if versioned)
    try:
        paginator = s3_client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = []
            for key in page.get("Versions", []) + page.get("DeleteMarkers", []):
                objs.append({"Key": key["Key"], "VersionId": key["VersionId"]})
            if objs:
                s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": objs})
    except ClientError as e:
        # list_object_versions may fail if not versioned — ignore and continue
        pass
    # Remove remaining objects (non-versioned)
    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": objs})
    except ClientError as e:
        print(f"[S3] Error while emptying bucket {bucket_name}: {e}")
        return False

    # Finally delete bucket
    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        print(f"[S3] Deleted bucket: {bucket_name}")
        return True
    except ClientError as e:
        print(f"[S3] Failed to delete bucket {bucket_name}: {e}")
        return False


# -------------------------
# S3 cleanup (exclude BUCKET)
# -------------------------
def cleanup_s3(region):
    s3 = boto3.client("s3", region_name=region)
    all_buckets = s3.list_buckets()["Buckets"]
    deleted = []
    for b in all_buckets:
        name = b["Name"]
        if name == BUCKET:
            print(f"[S3] Skipping backup bucket: {name}")
            continue
        # find bucket region
        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            # AWS returns None or 'us-east-1' differences; treat None as us-east-1
            bucket_region = loc if loc else "us-east-1"
        except ClientError as e:
            print(f"[S3] Could not get location for {name}: {e}")
            continue

        if bucket_region == region:
            print(f"[S3] Found bucket in region {region}: {name}")
            if not SAFE_MODE:
                ok = empty_and_delete_bucket(s3, name)
                if ok:
                    deleted.append(name)
            else:
                print(f"[S3] SAFE_MODE — would delete {name}")
                deleted.append(name)
    return deleted


# -------------------------
# ELB (classic) cleanup
# -------------------------
def cleanup_elb(region):
    elb = boto3.client("elb", region_name=region)
    deleted = []
    try:
        lbs = elb.describe_load_balancers()["LoadBalancerDescriptions"]
    except ClientError as e:
        print(f"[ELB] Error listing classic ELBs: {e}")
        return deleted
    for l in lbs:
        name = l["LoadBalancerName"]
        print(f"[ELB] Found classic LB: {name}")
        if not SAFE_MODE:
            try:
                elb.delete_load_balancer(LoadBalancerName=name)
                deleted.append(name)
                print(f"[ELB] Deleted classic LB: {name}")
            except ClientError as e:
                print(f"[ELB] Failed delete {name}: {e}")
        else:
            print(f"[ELB] SAFE_MODE — would delete {name}")
            deleted.append(name)
    return deleted


# -------------------------
# ELBv2 (ALB/NLB) + target groups
# -------------------------
def cleanup_elbv2(region):
    elbv2 = boto3.client("elbv2", region_name=region)
    deleted_lbs = []
    deleted_tg = []
    try:
        lbs = elbv2.describe_load_balancers()["LoadBalancers"]
    except ClientError as e:
        print(f"[ELBV2] Error listing LBs: {e}")
        return deleted_lbs, deleted_tg

    for lb in lbs:
        name = lb["LoadBalancerArn"]
        print(f"[ELBV2] Found LB ARN: {name}")
        # delete LB
        if not SAFE_MODE:
            try:
                elbv2.delete_load_balancer(LoadBalancerArn=name)
                deleted_lbs.append(name)
                print(f"[ELBV2] Deleted LB {name}")
            except ClientError as e:
                print(f"[ELBV2] Failed to delete LB {name}: {e}")
        else:
            print(f"[ELBV2] SAFE_MODE — would delete LB {name}")
            deleted_lbs.append(name)

    # Target groups
    try:
        tgs = elbv2.describe_target_groups()["TargetGroups"]
    except ClientError as e:
        print(f"[ELBV2] Error listing target groups: {e}")
        tgs = []

    for tg in tgs:
        arn = tg["TargetGroupArn"]
        print(f"[ELBV2] Found target group: {arn}")
        if not SAFE_MODE:
            try:
                elbv2.delete_target_group(TargetGroupArn=arn)
                deleted_tg.append(arn)
                print(f"[ELBV2] Deleted TG {arn}")
            except ClientError as e:
                print(f"[ELBV2] Failed deleting TG {arn}: {e}")
        else:
            print(f"[ELBV2] SAFE_MODE — would delete TG {arn}")
            deleted_tg.append(arn)

    return deleted_lbs, deleted_tg


# -------------------------
# AutoScaling Groups cleanup
# -------------------------
def cleanup_asg(region):
    asg_client = boto3.client("autoscaling", region_name=region)
    deleted_asgs = []
    try:
        paginator = asg_client.get_paginator("describe_auto_scaling_groups")
        for page in paginator.paginate():
            for g in page["AutoScalingGroups"]:
                name = g["AutoScalingGroupName"]
                print(f"[ASG] Found ASG: {name}")
                if not SAFE_MODE:
                    try:
                        # set desired capacity to 0
                        asg_client.update_auto_scaling_group(
                            AutoScalingGroupName=name, DesiredCapacity=0, MinSize=0, MaxSize=0
                        )
                        # attempt delete (ForceDelete deletes instances)
                        asg_client.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
                        deleted_asgs.append(name)
                        print(f"[ASG] Deleted ASG: {name}")
                    except ClientError as e:
                        print(f"[ASG] Failed deleting ASG {name}: {e}")
                else:
                    print(f"[ASG] SAFE_MODE — would delete {name}")
                    deleted_asgs.append(name)
    except ClientError as e:
        print(f"[ASG] Error listing ASGs: {e}")
    return deleted_asgs


# -------------------------
# RDS cleanup (create snapshot then delete)
# -------------------------
def cleanup_rds(region):
    rds = boto3.client("rds", region_name=region)
    deleted = []
    try:
        instances = rds.describe_db_instances()["DBInstances"]
    except ClientError as e:
        print(f"[RDS] Error listing instances: {e}")
        return deleted

    for inst in instances:
        dbid = inst["DBInstanceIdentifier"]
        print(f"[RDS] Found RDS instance: {dbid}")
        if not SAFE_MODE:
            try:
                snap_name = f"{dbid}-final-snap-{now_ts()}"
                print(f"[RDS] Creating final snapshot {snap_name} for {dbid}")
                rds.create_db_snapshot(DBSnapshotIdentifier=snap_name, DBInstanceIdentifier=dbid)
                # wait for snapshot to complete (optional) - here we poll existence
                waiter = rds.get_waiter("db_snapshot_available")
                print("[RDS] Waiting for snapshot to become available (may take time)...")
                waiter.wait(DBSnapshotIdentifier=snap_name)
                print(f"[RDS] Snapshot {snap_name} available.")
                # delete instance
                rds.delete_db_instance(DBInstanceIdentifier=dbid, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
                deleted.append(dbid)
                print(f"[RDS] Deleted instance {dbid}")
            except ClientError as e:
                print(f"[RDS] Failed to backup/delete {dbid}: {e}")
        else:
            print(f"[RDS] SAFE_MODE — would snapshot & delete {dbid}")
            deleted.append(dbid)
    return deleted


# -------------------------
# VPC cleanup (attempt common dependency cleanup)
# -------------------------
def cleanup_vpcs(region):
    ec2 = boto3.resource("ec2", region_name=region)
    client = boto3.client("ec2", region_name=region)
    deleted = []
    try:
        vpcs = list(ec2.vpcs.all())
    except ClientError as e:
        print(f"[VPC] Error listing VPCs: {e}")
        return deleted

    for vpc in vpcs:
        vpc_id = vpc.id
        # skip default VPC
        is_default = vpc.is_default
        print(f"[VPC] Found VPC {vpc_id} (default={is_default})")
        if is_default:
            print(f"[VPC] Skipping default VPC {vpc_id}")
            continue

        # Attempt to remove common dependencies
        try:
            # Delete NAT Gateways
            nat_gws = client.describe_nat_gateways(Filters=[{"Name":"vpc-id","Values":[vpc_id]}])["NatGateways"]
            for nat in nat_gws:
                nat_id = nat["NatGatewayId"]
                print(f"[VPC] Deleting NAT GW {nat_id}")
                if not SAFE_MODE:
                    client.delete_nat_gateway(NatGatewayId=nat_id)
            # Detach and delete IGWs
            igws = list(vpc.internet_gateways.all())
            for igw in igws:
                igw_id = igw.id
                print(f"[VPC] Detaching & deleting IGW {igw_id}")
                if not SAFE_MODE:
                    vpc.detach_internet_gateway(InternetGatewayId=igw_id)
                    igw.delete()
            # Delete route table associations (non-main)
            for rt in vpc.route_tables.all():
                for assoc in rt.associations:
                    if not assoc.main:
                        try:
                            print(f"[VPC] Disassociating route table assoc {assoc.id}")
                            if not SAFE_MODE:
                                assoc.delete()
                        except Exception:
                            pass
            # Delete subnets
            for subnet in vpc.subnets.all():
                sid = subnet.id
                print(f"[VPC] Deleting subnet {sid}")
                if not SAFE_MODE:
                    try:
                        subnet.delete()
                    except ClientError as e:
                        print(f"[VPC] Failed to delete subnet {sid}: {e}")
            # Delete security groups (except default)
            for sg in vpc.security_groups.all():
                if sg.group_name != "default":
                    print(f"[VPC] Deleting SG {sg.id}")
                    if not SAFE_MODE:
                        try:
                            sg.delete()
                        except ClientError as e:
                            print(f"[VPC] Failed to delete SG {sg.id}: {e}")
            # Delete network interfaces
            enis = client.describe_network_interfaces(Filters=[{"Name":"vpc-id","Values":[vpc_id]}])["NetworkInterfaces"]
            for eni in enis:
                eni_id = eni["NetworkInterfaceId"]
                print(f"[VPC] Deleting ENI {eni_id}")
                if not SAFE_MODE:
                    try:
                        client.delete_network_interface(NetworkInterfaceId=eni_id)
                    except ClientError as e:
                        print(f"[VPC] Failed to delete ENI {eni_id}: {e}")
            # Finally delete VPC
            print(f"[VPC] Deleting VPC {vpc_id}")
            if not SAFE_MODE:
                try:
                    client.delete_vpc(VpcId=vpc_id)
                    deleted.append(vpc_id)
                    print(f"[VPC] Deleted VPC {vpc_id}")
                except ClientError as e:
                    print(f"[VPC] Failed to delete VPC {vpc_id}: {e}")
            else:
                print(f"[VPC] SAFE_MODE — would delete VPC {vpc_id}")
                deleted.append(vpc_id)
        except ClientError as e:
            print(f"[VPC] Error processing VPC {vpc_id}: {e}")

    return deleted


# -------------------------
# Top-level cleanup per region
# -------------------------
def run_cleanup():
    timestamp = now_ts()
    results = {}

    for region in config["regions"]:
        print(f"\n\n===== REGION: {region} =====")
        region_res = {}

        # S3 (global) - delete buckets in this region except BUCKET
        try:
            s3_deleted = cleanup_s3(region)
            region_res["s3_deleted"] = s3_deleted
        except Exception as e:
            print(f"[S3] Error in cleanup for region {region}: {e}")

        # ELB classic
        try:
            elb_deleted = cleanup_elb(region)
            region_res["elb_deleted"] = elb_deleted
        except Exception as e:
            print(f"[ELB] Error: {e}")

        # ELBv2 (ALB/NLB) + TG
        try:
            elbv2_lbs, elbv2_tgs = cleanup_elbv2(region)
            region_res["elbv2_deleted"] = elbv2_lbs
            region_res["target_groups_deleted"] = elbv2_tgs
        except Exception as e:
            print(f"[ELBV2] Error: {e}")

        # ASG
        try:
            asgs = cleanup_asg(region)
            region_res["asgs_deleted"] = asgs
        except Exception as e:
            print(f"[ASG] Error: {e}")

        # RDS
        try:
            rds_deleted = cleanup_rds(region)
            region_res["rds_deleted"] = rds_deleted
        except Exception as e:
            print(f"[RDS] Error: {e}")

        # EC2 and EBS & EKS (your previous logic)
        ec2 = boto3.client("ec2", region_name=region)
        eks = boto3.client("eks", region_name=region)
        cf = boto3.client("cloudformation", region_name=region)

        # EC2 running instances
        try:
            instances = ec2.describe_instances(Filters=[{"Name":"instance-state-name","Values":["running"]}])
            ec2_ids = [i["InstanceId"] for r in instances["Reservations"] for i in r["Instances"]]
        except ClientError as e:
            print(f"[EC2] Error listing instances: {e}")
            ec2_ids = []

        print(f"[EC2] Running instances: {ec2_ids}")
        if not SAFE_MODE and ec2_ids:
            try:
                ec2.terminate_instances(InstanceIds=ec2_ids)
            except ClientError as e:
                print(f"[EC2] Failed terminating: {e}")
        region_res["ec2_terminated"] = ec2_ids

        # EBS available volumes
        try:
            vols = ec2.describe_volumes(Filters=[{"Name":"status","Values":["available"]}])["Volumes"]
            ebs_ids = [v["VolumeId"] for v in vols]
        except ClientError as e:
            print(f"[EBS] Error listing volumes: {e}")
            ebs_ids = []
        print(f"[EBS] Available volumes: {ebs_ids}")
        if not SAFE_MODE:
            for vol in ebs_ids:
                try:
                    ec2.delete_volume(VolumeId=vol)
                except ClientError as e:
                    print(f"[EBS] Failed delete {vol}: {e}")
        region_res["ebs_deleted"] = ebs_ids

        # EKS clusters (backup CF stacks then delete)
        try:
            clusters = eks.list_clusters()["clusters"]
        except ClientError as e:
            print(f"[EKS] Error listing clusters: {e}")
            clusters = []

        region_res["eks"] = []
        for cluster in clusters:
            # find related CF stacks
            try:
                stacks = cf.list_stacks(StackStatusFilter=["CREATE_COMPLETE","UPDATE_COMPLETE"])["StackSummaries"]
                eks_stacks = [s["StackName"] for s in stacks if cluster in s["StackName"]]
            except ClientError as e:
                print(f"[CF] Error listing stacks: {e}")
                eks_stacks = []

            print(f"[EKS] Cluster {cluster} related stacks: {eks_stacks}")

            backups = []
            for stack in eks_stacks:
                b = backup_cloudformation(region, stack, timestamp)
                backups.append(b)
            region_res["cf_backup"] = backups

            # delete nodegroups & cluster
            try:
                nodegroups = eks.list_nodegroups(clusterName=cluster)["nodegroups"]
                for ng in nodegroups:
                    print(f"[EKS] Deleting nodegroup {ng} in {cluster}")
                    if not SAFE_MODE:
                        eks.delete_nodegroup(clusterName=cluster, nodegroupName=ng)
                print(f"[EKS] Deleting cluster {cluster}")
                if not SAFE_MODE:
                    eks.delete_cluster(name=cluster)
                region_res["eks"].append({"cluster": cluster, "nodegroups": nodegroups})
            except ClientError as e:
                print(f"[EKS] Error deleting cluster {cluster}: {e}")

        # VPC cleanup (attempt)
        try:
            vpcs_deleted = cleanup_vpcs(region)
            region_res["vpcs_deleted"] = vpcs_deleted
        except Exception as e:
            print(f"[VPC] Error cleaning VPCs: {e}")

        results[region] = region_res

    return results


def lambda_handler(event, context):
    return run_cleanup()


if __name__ == "__main__":
    print("Running locally...")
    out = run_cleanup()
    print(json.dumps(out, indent=4))
