## Test Scripts

Switch to consumer profile
```powershell
$env:AWS_CONFIG_FILE = ".\.aws\config" ; $env:AWS_SHARED_CREDENTIALS_FILE = ".\.aws\credentials" ; $env:AWS_PROFILE = "dev"
```

#### 1. SCP Blocks on Required Resources (e.g., Deny API Gateway, VPC Link, ALB Creation)

```powershell
aws organizations list-policies --filter SERVICE_CONTROL_POLICY  --query "Policies[?contains(Name,'network') || contains(Name,'Network') || contains(Name,'NETWORK') || contains(Name,'deny') || contains(Name,'Deny') || contains(Name,'DENY')].{Id:Id,Name:Name,Description:Description}" | Tee-Object -FilePath "$HOME\Desktop\scp-describe.txt"
```

#### 2a. TGW Route Misconfig (e.g., No Outbound Route, No Return Path for Replies)
Doc says `"automatic via TGW," but if 0.0.0.0/0 → tgw-0368e0eab67d69402` missing, outbound fails (e.g., ECR pulls, SSM). No propagation = no cross-VPC (if using NLB).
Get subnet Ids (NRCan  vpc-0809102c90503ef2d):
```powershell
 aws ec2 describe-subnets  --filters "Name=vpc-id,Values=vpc-07b1f23b14acf19b1"  --query "Subnets[].SubnetId"  --output text  | Tee-Object -FilePath "$HOME\Desktop\subnetIDs-describe.txt"  
```

Check (workload vpc) private subnet route tables (use subnet IDs from above)

```powershell
aws ec2 describe-route-tables --filters "Name=association.subnet-id,Values=subnet-0fefc01038658ab1b,subnet-0d5b1c0ee609cf781" --query "RouteTables[].{RTB:RouteTableId, Routes:Routes[?DestinationCidrBlock=='0.0.0.0/0']}" --output table | Tee-Object -FilePath "$HOME\Desktop\tgw-describe.txt"
```
Expected output:
|-----------------------------------------------------------------------------|
|                             DescribeRouteTables                            |
+----------------------------------------------------------------------------+
|                                     RTB                                    |
+----------------------------------------------------------------------------+
|  rtb-06615485f3f495c54                                                     |
+----------------------------------------------------------------------------+
||                                  Routes                                  ||
|+-----------------------+--------------+---------+-------------------------+|
|| DestinationCidrBlock  |   Origin     |  State  |    TransitGatewayId     ||
|+-----------------------+--------------+---------+-------------------------+|
||  0.0.0.0/0            |  CreateRoute |  active |  tgw-05e4571a273ef229e  ||
|+-----------------------+--------------+---------+-------------------------+|

```powershell
aws ec2 describe-route-tables --filters "Name=association.subnet-id,Values=subnet-0fefc01038658ab1b,subnet-0d5b1c0ee609cf781" --query "RouteTables[].Routes[?DestinationCidrBlock=='0.0.0.0/0'].{TGW:TransitGatewayId, Peer:VpcPeeringConnectionId}" --output table  | Tee-Object -FilePath "$HOME\Desktop\rt-describe.txt"
```
Boto3 Script (Verify TGW routes and propagations) you can find the file in: ./test-scripts/tgw-check.py

```python
import boto3
from botocore.exceptions import ClientError
import os
import sys

desktop = os.path.join(os.path.expanduser("~"), "Desktop")
log_path = os.path.join(desktop, "tgw-check-python.txt")

# Redirect to log file
sys.stdout = open(log_path, "w", encoding="utf-8")
sys.stderr = sys.stdout


ec2 = boto3.client('ec2', region_name='ca-central-1')
tgw_id = 'tgw-05e4571a273ef229e'    #'tgw-0368e0eab67d69402'  # From doc or above command

try:
    # The DEFAULT route table ID
    # ────── FIXED: works even if there is no default route table ──────
    all_rts = ec2.describe_transit_gateway_route_tables(
        Filters=[{'Name': 'transit-gateway-id', 'Values': [tgw_id]}]
    )['TransitGatewayRouteTables']

    if not all_rts:
        raise Exception("TGW not found or zero permissions")
    rt_id = all_rts[0]['TransitGatewayRouteTableId']   # pick the first one
    print(f"Using route table {rt_id}")

    # Internet traffic outflow
    routes = ec2.search_transit_gateway_routes(
        TransitGatewayRouteTableId=rt_id,
        Filters=[{'Name': 'route-search.exact-match', 'Values': ['0.0.0.0/0']}]
    )
    print("\nTGW 0.0.0.0/0 route →")
    print(routes.get('Routes', 'No default route found'))

    # What pushes routes back?
    props = ec2.get_transit_gateway_route_table_propagations(
        TransitGatewayRouteTableId=rt_id
    )
    print("\nVPCs that propagate routes back:")
    for p in props.get('TransitGatewayRouteTablePropagations', []):
        print(f"  • {p['ResourceId']}  ({p['State']})")

except ClientError as e:
    print("AWS Error:", e.response['Error']['Message'])
    if 'AccessDenied' in str(e):
        print("Permission Issue - Possible SCP.")
except Exception as exc:
    print("Python Error:", exc)

# Restore stdout
sys.stdout.close()
sys.stdout = sys.__stdout__

print(f"tgw info logged to: {log_path}")
```

##### 2b. Subnet route tables
```powershell
aws ec2 describe-route-tables --filters "Name=association.subnet-id,Values=subnet-0fefc01038658ab1b,subnet-0d5b1c0ee609cf781" | Tee-Object -FilePath "$HOME\Desktop\sbnet-rt-describe.txt" 

```
Check the VPC ID (NRCan  vpc-0809102c90503ef2d)
```powershell
aws ec2 describe-route-tables  --filters "Name=vpc-id,Values=vpc-0809102c90503ef2d"  --query 'RouteTables[?Associations[0].SubnetId].{   
 Subnet:Associations[0].SubnetId,    Route:"Routes[?DestinationCidrBlock==`0.0.0.0/0`].{Target:GatewayId||TransitGatewayId||NatGatewayId}"  }'itGatewayId||NatGatewayId}"  }'  | Tee-Object -FilePath "$HOME\Desktop\sbnet2-rt-describe.txt" 
```

#### 3. VPC Endpoints (e.g., for SSM, CloudWatch,...)

List vpc endpoints:
```powershell
aws ec2 describe-vpc-endpoints --query "VpcEndpoints[].{ID:VpcEndpointId, Service:ServiceName, State:State}" --output table | Tee-Object -FilePath "$HOME\Desktop\vpce-describe.txt"
```

NRCan AWS Services: VPC Endpoint (vpce-066ce0c2c7f5d4a55)
List endpoints and services
```powershell
aws ec2 describe-vpc-endpoints --vpc-endpoint-ids vpce-066ce0c2c7f5d4a55 --query "VpcEndpoints[].{Service:ServiceName,State:State}"  | Tee-Object -FilePath "$HOME\Desktop\vpce-service-describe.txt"
```

#### 4. Security Groups/NACLs Blocking Traffic (e.g., ALB → Backend, VPC Link → ALB)
Doc mentions "Check security group outbound rules" in troubleshooting.
list Security Group ID + Name in VPC
```powershell
aws ec2 describe-security-groups --query "SecurityGroups[].{ID:GroupId, Name:GroupName}" --output table | Tee-Object -FilePath "$HOME\Desktop\sg-nacl-describe.txt"
```
Describe SG for ALB/EC2
from above find: `<alb-sg-id> <ec2-sg-id>` and replace in below:

```powershell
aws ec2 describe-security-groups --group-ids <alb-sg-id> <ec2-sg-id> --query "SecurityGroups[].{Id:GroupId,Ingress:IpPermissions[].{FromPort:FromPort,ToPort:ToPort,IpProtocol:IpProtocol,SG:UserIdGroupPairs[].GroupId},Egress:EgressIpPermissions[].{FromPort:FromPort,ToPort:ToPort,IpProtocol:IpProtocol,Cidr:IpRanges[].CidrIp}}" --region ca-central-1 --output json | Tee-Object -FilePath "$HOME\Desktop\sg-describe.txt" 
```
Sample output:

```json
IpPermissions[].{FromPort:FromPort,ToPort:ToPort,IpProtocol:IpProtocol,Cidr:IpRanges[].CidrIp}}" --region ca-central-1[
    {
        "Id": "sg-0b2950d57f00aba77",
        "Ingress": [
            {
                "FromPort": 80,
                "ToPort": 80,
                "IpProtocol": "tcp",
                "SG": [
                    "sg-09cdd258c11bcfd78"
                ]
            }
        ],
        "Egress": null
    },
    {
        "Id": "sg-09cdd258c11bcfd78",
        "Ingress": [
            {
                "FromPort": 80,
                "ToPort": 80,
                "IpProtocol": "tcp",
                "SG": []
            }
        ],
        "Egress": null
    }
]
```

Validating SG rules (you can find the file in ./test-scripts/sg-check.py):

```python
import boto3
from botocore.exceptions import ClientError

ec2 = boto3.resource('ec2', region_name='ca-central-1')

# ←←← PUT NRCan SG TWO IDs HERE (from above)
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
```
sample output:

```
=== sg-0b2950d57f00aba77 (test-ec2-sg) ===
INGRESS:
  tcp      80-80 ← sg-09cdd258c11bcfd78
EGRESS:
  ALL OUTBOUND ALLOWED (internet works)

=== sg-09cdd258c11bcfd78 (test-alb-sg) ===
INGRESS:
  tcp      80-80 ← 0.0.0.0/0
EGRESS:
  ALL OUTBOUND ALLOWED (internet works)
```

#### 5. Subnet/AZ or VPC Config Issues (e.g., No HA, Wrong CIDR)

check vpc_id according to doc. vpc-07b1f23b14acf19b1
```powershell
aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-0809102c90503ef2d" --query "Subnets\[].{Id:SubnetId,AZ:AvailabilityZone,Cidr:CidrBlock,Private:MapPublicIpOnLaunch}" --region ca-central-1
```
