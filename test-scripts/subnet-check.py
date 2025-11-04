import boto3
from botocore.exceptions import ClientError
import os
import sys

desktop = os.path.join(os.path.expanduser("~"), "Desktop")
log_path = os.path.join(desktop, "subnet-check-python.txt")

# Redirect to log file
sys.stdout = open(log_path, "w", encoding="utf-8")
sys.stderr = sys.stdout


ec2 = boto3.client('ec2', region_name='ca-central-1')
vpc_id = 'vpc-07b1f23b14acf19b1'    # NRCan per doc: 'vpc-0809102c90503ef2d'

try:
    subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
    azs = set(sub['AvailabilityZone'] for sub in subnets)
    print("\nSubnets:", subnets)
    if len(azs) < 2:
        print("\nWarning: Only", len(azs), "AZs—HA risk; 2 AZs per doc.")
except ClientError as e:
    print("\nError:", e.response['Error']['Message'])


# Restore stdout
sys.stdout.close()
sys.stdout = sys.__stdout__

print(f"\nSecurity group info logged to: {log_path}")    