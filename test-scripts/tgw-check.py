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
tgw_id = 'tgw-05e4571a273ef229e'    #'tgw-0368e0eab67d69402'  # From doc

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