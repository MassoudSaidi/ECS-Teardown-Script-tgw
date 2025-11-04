import boto3
from botocore.exceptions import ClientError
import os
import sys

desktop = os.path.join(os.path.expanduser("~"), "Desktop")
log_path = os.path.join(desktop, "sg-check-python.txt")

# Redirect to log file
sys.stdout = open(log_path, "w", encoding="utf-8")
sys.stderr = sys.stdout


ec2 = boto3.resource('ec2', region_name='ca-central-1')

# ←←← PUT NRCan TWO IDs HERE (from earlier)
alb_sg = 'sg-0b2950d57f00aba77'
ec2_sg = 'sg-09cdd258c11bcfd78'

for sg_id in [alb_sg, ec2_sg]:
    try:
        sg = ec2.SecurityGroup(sg_id)
        print(f"\n=== {sg_id} ({sg.group_name}) ===")
        print("INGRESS:")
        for rule in sg.ip_permissions:
            ports = f"{rule.get('FromPort','*')}-{rule.get('ToPort','*')}"
            srcs = [g['GroupId'] for g in rule.get('UserIdGroupPairs',[])] + \
                   [c['CidrIp'] for c in rule.get('IpRanges',[])]
            print(f"  {rule['IpProtocol']:>3} {ports:>10} ← {', '.join(srcs) or 'nothing'}")

        print("EGRESS:")
        egress = sg.ip_permissions_egress
        if any(r['IpProtocol']=='-1' for r in egress):
            print("  ALL OUTBOUND ALLOWED (internet works)")
        else:
            print("  WARNING: Outbound locked → TGW/NAT will fail")

    except ClientError as e:
        print("AWS Error:", e.response['Error']['Message'])

# Restore stdout
sys.stdout.close()
sys.stdout = sys.__stdout__

print(f"Security group info logged to: {log_path}")