import boto3
import time
import os
import argparse
import json
import subprocess

def get_boto_clients(region):
    """
    Initializes and returns a dictionary of boto3 clients.
    """
    return {
        'ecs': boto3.client('ecs', region_name=region),
        'ec2': boto3.client('ec2', region_name=region),
        'autoscaling': boto3.client('autoscaling', region_name=region),
        'elbv2': boto3.client('elbv2', region_name=region),
        'iam': boto3.client('iam', region_name=region),
        'application-autoscaling': boto3.client('application-autoscaling', region_name=region),
        'apigatewayv2': boto3.client('apigatewayv2', region_name=region), # NEW: Added API Gateway V2 client
    }

# ######################################################################################
# #          NEW FUNCTIONS TO DELETE API GATEWAY RESOURCES                           #
# ######################################################################################

def delete_api_gateway_integrations(clients, config):
    """ Deletes all integrations for a given API Gateway API. """
    api_id = config.get('API_ID')
    if not api_id:
        print("--- No API_ID found, skipping API Gateway integration deletion ---")
        return

    print(f"--- Deleting integrations for API Gateway: {api_id} ---")
    try:
        response = clients['apigatewayv2'].get_integrations(ApiId=api_id)
        integrations = response.get('Items', [])
        if not integrations:
            print("No integrations found.")
            return

        for integration in integrations:
            integration_id = integration['IntegrationId']
            print(f"Deleting integration: {integration_id}")
            clients['apigatewayv2'].delete_integration(ApiId=api_id, IntegrationId=integration_id)
        print("All integrations deleted successfully.")
    except clients['apigatewayv2'].exceptions.NotFoundException:
        print(f"API Gateway {api_id} not found. Skipping integration deletion.")
    except Exception as e:
        print(f"An error occurred while deleting API Gateway integrations: {e}")

def delete_api_gateway_routes(clients, config):
    """ Deletes all routes for a given API Gateway API. """
    api_id = config.get('API_ID')
    if not api_id:
        print("--- No API_ID found, skipping API Gateway route deletion ---")
        return

    print(f"--- Deleting routes for API Gateway: {api_id} ---")
    try:
        response = clients['apigatewayv2'].get_routes(ApiId=api_id)
        routes = response.get('Items', [])
        if not routes:
            print("No routes found.")
            return

        for route in routes:
            route_id = route['RouteId']
            print(f"Deleting route: {route_id}")
            clients['apigatewayv2'].delete_route(ApiId=api_id, RouteId=route_id)
        print("All routes deleted successfully.")
    except clients['apigatewayv2'].exceptions.NotFoundException:
        print(f"API Gateway {api_id} not found. Skipping route deletion.")
    except Exception as e:
        print(f"An error occurred while deleting API Gateway routes: {e}")


def disassociate_capacity_providers_from_cluster(clients, config):
    """ Disassociates all capacity providers from the ECS cluster. """
    cluster_name = config.get('CLUSTER_NAME')
    print(f"--- Disassociating capacity providers from cluster: {cluster_name} ---")
    try:
        # This action effectively detaches the aws_ecs_cluster_capacity_providers resource
        clients['ecs'].put_cluster_capacity_providers(
            cluster=cluster_name,
            capacityProviders=[],
            defaultCapacityProviderStrategy=[]
        )
        print(f"Successfully disassociated all capacity providers from {cluster_name}.")
        # Give it a moment to process the update before deleting the provider
        time.sleep(15)
    except clients['ecs'].exceptions.ClusterNotFoundException:
        print(f"Cluster {cluster_name} not found. Skipping disassociation.")
    except Exception as e:
        print(f"An error occurred while disassociating capacity providers: {e}")


def delete_api_gateway(clients, config):
    """ Deletes the API Gateway API. """
    api_id = config.get('API_ID')
    if not api_id:
        print("--- No API_ID found in config, skipping API Gateway deletion ---")
        return

    print(f"--- Deleting API Gateway API: {api_id} ---")
    try:
        clients['apigatewayv2'].delete_api(ApiId=api_id)
        print(f"API Gateway {api_id} deleted successfully.")
    except clients['apigatewayv2'].exceptions.NotFoundException:
        print(f"API Gateway {api_id} not found. Skipping.")
    except Exception as e:
        print(f"An error occurred while deleting API Gateway: {e}")


def delete_vpc_link(clients, config):
    """ Deletes the API Gateway VPC Link. """
    vpc_link_id = config.get('VPC_LINK_ID')
    if not vpc_link_id:
        print("--- No VPC_LINK_ID found in config, skipping VPC Link deletion ---")
        return

    print(f"--- Deleting API Gateway VPC Link: {vpc_link_id} ---")
    try:
        clients['apigatewayv2'].delete_vpc_link(VpcLinkId=vpc_link_id)
        # Deletion can take a moment, let's add a small pause
        print("Waiting for VPC Link to be deleted...")
        time.sleep(20)
        print(f"VPC Link {vpc_link_id} deleted successfully.")
    except clients['apigatewayv2'].exceptions.NotFoundException:
        print(f"VPC Link {vpc_link_id} not found. Skipping.")
    except Exception as e:
        print(f"An error occurred while deleting VPC Link: {e}")


# --- (No changes to the functions below until delete_security_groups) ---


def delete_appautoscaling_policies_and_targets(clients, config):
    """
    Finds and deletes Application Auto Scaling policies and the target
    associated with the ECS service. This MUST be done before deleting the service.
    """
    print(f"--- Handling App Auto Scaling for service: {config['SERVICE_NAME']} ---")
    service_namespace = 'ecs'
    # The resource ID is in a predictable format for an ECS service
    resource_id = f"service/{config['CLUSTER_NAME']}/{config['SERVICE_NAME']}"
    
    try:
        # Step 1: Find and delete all scaling policies attached to the service.
        print(f"Looking for scaling policies attached to resource: {resource_id}")
        paginator = clients['application-autoscaling'].get_paginator('describe_scaling_policies')
        pages = paginator.paginate(ServiceNamespace=service_namespace, ResourceId=resource_id)
        
        policy_names = []
        for page in pages:
            for policy in page.get('ScalingPolicies', []):
                policy_names.append(policy['PolicyName'])

        if not policy_names:
            print("No App Auto Scaling policies found. Skipping policy deletion.")
        else:
            for policy_name in policy_names:
                print(f"Deleting scaling policy: {policy_name}...")
                clients['application-autoscaling'].delete_scaling_policy(
                    ServiceNamespace=service_namespace,
                    ResourceId=resource_id,
                    PolicyName=policy_name
                )
            print("All scaling policies deleted successfully.")

        # Step 2: Find and delete the scalable target itself.
        print(f"Deregistering scalable target for resource: {resource_id}...")
        clients['application-autoscaling'].deregister_scalable_target(
            ServiceNamespace=service_namespace,
            ResourceId=resource_id,
            ScalableDimension='ecs:service:DesiredCount'
        )
        print("Scalable target deregistered successfully.")

    except clients['application-autoscaling'].exceptions.ObjectNotFoundException:
        print("Scalable target or policies not found. They may have already been deleted. Skipping.")
    except Exception as e:
        print(f"An error occurred while deleting App Auto Scaling resources: {e}")


def delete_ecs_service(clients, config):
    print(f"--- Handling ECS Service: {config['SERVICE_NAME']} in cluster {config['CLUSTER_NAME']} ---")
    try:
        clients['ecs'].describe_clusters(clusters=[config['CLUSTER_NAME']])
        print(f"Scaling down service {config['SERVICE_NAME']} to 0 desired tasks...")
        clients['ecs'].update_service(cluster=config['CLUSTER_NAME'], service=config['SERVICE_NAME'], desiredCount=0)
        waiter = clients['ecs'].get_waiter('services_stable')
        waiter.wait(cluster=config['CLUSTER_NAME'], services=[config['SERVICE_NAME']], WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
        print("Service scaled down successfully.")
        clients['ecs'].delete_service(cluster=config['CLUSTER_NAME'], service=config['SERVICE_NAME'], force=True)
        print(f"Service {config['SERVICE_NAME']} deleted successfully.")
    except clients['ecs'].exceptions.ClusterNotFoundException:
        print(f"Cluster {config['CLUSTER_NAME']} not found, cannot delete service. Skipping.")
    except clients['ecs'].exceptions.ServiceNotFoundException:
        print(f"Service {config['SERVICE_NAME']} not found. Skipping.")
    except Exception as e:
        print(f"An error occurred while deleting ECS service: {e}")


def delete_autoscaling_group_and_instances(clients, config, max_wait_minutes=5): # CHANGED TO 5
    print(f"--- Handling Auto Scaling Group starting with: {config['ASG_NAME_PREFIX']} ---")
    try:
        # 1. Find the ASG
        response = clients['autoscaling'].describe_auto_scaling_groups()
        asg_details = next((asg for asg in response['AutoScalingGroups'] 
                            if asg['AutoScalingGroupName'].startswith(config['ASG_NAME_PREFIX'])), None)
        
        if not asg_details:
            print("No matching Auto Scaling Group found. Skipping.")
            return
            
        asg_name = asg_details['AutoScalingGroupName']
        print(f"Found ASG: {asg_name}")

        # 2. Remove Scale-In Protection
        instance_ids = [i['InstanceId'] for i in asg_details.get('Instances', [])]
        if instance_ids:
            try:
                clients['autoscaling'].set_instance_protection(
                    AutoScalingGroupName=asg_name, InstanceIds=instance_ids, ProtectedFromScaleIn=False
                )
            except Exception:
                pass # Ignore if already terminating

        # 3. Delete Lifecycle Hooks (Pre-emptive)
        try:
            hooks = clients['autoscaling'].describe_lifecycle_hooks(AutoScalingGroupName=asg_name)['LifecycleHooks']
            for hook in hooks:
                clients['autoscaling'].delete_lifecycle_hook(
                    AutoScalingGroupName=asg_name, LifecycleHookName=hook['LifecycleHookName']
                )
        except Exception:
            pass

        # 4. Update ASG to size 0
        print("Setting ASG min/max/desired to 0...")
        clients['autoscaling'].update_auto_scaling_group(
            AutoScalingGroupName=asg_name, MinSize=0, MaxSize=0, DesiredCapacity=0, NewInstancesProtectedFromScaleIn=False
        )

        # 5. Wait for termination
        print("Waiting for all instances in the ASG to terminate...")
        start_time = time.time()
        
        while True:
            try:
                asg_desc_list = clients['autoscaling'].describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])['AutoScalingGroups']
            except Exception:
                break # ASG Gone
                
            if not asg_desc_list: break
                
            current_instances = asg_desc_list[0].get('Instances', [])
            active_instances = [i for i in current_instances if i['LifecycleState'] not in ['Terminated']]

            if not active_instances:
                print("All instances have been terminated.")
                break

            # HANDLE STUCK HOOKS
            for inst in active_instances:
                if inst['LifecycleState'] == 'Terminating:Wait':
                    print(f"Instance {inst['InstanceId']} stuck in Wait. Forcing CONTINUE...")
                    try:
                        hooks_resp = clients['autoscaling'].describe_lifecycle_hooks(AutoScalingGroupName=asg_name)
                        for hook in hooks_resp.get('LifecycleHooks', []):
                            clients['autoscaling'].complete_lifecycle_action(
                                LifecycleHookName=hook['LifecycleHookName'],
                                AutoScalingGroupName=asg_name,
                                LifecycleActionResult='CONTINUE',
                                InstanceId=inst['InstanceId']
                            )
                    except Exception:
                        pass

            elapsed = time.time() - start_time
            if elapsed > max_wait_minutes * 60:
                print(f" Timeout reached ({max_wait_minutes} min). Proceeding to force delete the ASG...")
                break

            print(f"{len(active_instances)} instance(s) still active... waiting 15 seconds.")
            time.sleep(15)

        # 6. Delete the ASG
        print("Deleting the ASG...")
        clients['autoscaling'].delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
        print(f"Auto Scaling Group {asg_name} deleted successfully.")
        
    except Exception as e:
        print(f"An error occurred during ASG deletion: {e}")



def delete_launch_template(clients, config):
    print(f"--- Deleting Launch Templates starting with: {config['LAUNCH_TEMPLATE_PREFIX']} ---")
    try:
        response = clients['ec2'].describe_launch_templates()
        for lt in response['LaunchTemplates']:
            if lt['LaunchTemplateName'].startswith(config['LAUNCH_TEMPLATE_PREFIX']):
                print(f"Deleting Launch Template: {lt['LaunchTemplateName']} ({lt['LaunchTemplateId']})")
                clients['ec2'].delete_launch_template(LaunchTemplateId=lt['LaunchTemplateId'])
    except Exception as e:
        print(f"An error occurred: {e}")


def delete_load_balancer_and_target_group(clients, config):
    print(f"--- Handling Load Balancer and Target Group ---")
    try:
        response = clients['elbv2'].describe_load_balancers(Names=[config['ALB_NAME']])
        lb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
        print(f"Deleting Load Balancer: {config['ALB_NAME']} ({lb_arn})")
        clients['elbv2'].delete_load_balancer(LoadBalancerArn=lb_arn)
        waiter = clients['elbv2'].get_waiter('load_balancers_deleted')
        waiter.wait(LoadBalancerArns=[lb_arn])
        print("Load Balancer deleted successfully.")
    except clients['elbv2'].exceptions.LoadBalancerNotFoundException:
        print(f"Load Balancer {config['ALB_NAME']} not found. Skipping.")
    except Exception as e:
        print(f"An error occurred deleting LB: {e}")
    try:
        response = clients['elbv2'].describe_target_groups(Names=[config['TARGET_GROUP_NAME']])
        tg_arn = response['TargetGroups'][0]['TargetGroupArn']
        print(f"Deleting Target Group: {config['TARGET_GROUP_NAME']} ({tg_arn})")
        clients['elbv2'].delete_target_group(TargetGroupArn=tg_arn)
        print("Target Group deleted successfully.")
    except clients['elbv2'].exceptions.TargetGroupNotFoundException:
        print(f"Target Group {config['TARGET_GROUP_NAME']} not found. Skipping.")
    except Exception as e:
        print(f"An error occurred deleting TG: {e}")


def delete_capacity_providers(clients, config):
    cp_name = config.get('CAPACITY_PROVIDER_NAME') # Assumes a naming convention
    if not cp_name:
      # Fallback naming convention if BASE_NAME is used
      base_name = config.get('BASE_NAME', 'default')
      cp_name = f"{base_name}-capacity-provider"
        
    print(f"--- Handling ECS Capacity Provider: {cp_name} ---")
    try:
        # This part remains the same
        clients['ecs'].delete_capacity_provider(capacityProvider=cp_name)
        print(f"Capacity Provider {cp_name} deleted successfully.")
    except Exception as e:
        print(f"An error occurred deleting capacity provider {cp_name}: {e}")

def delete_ecs_cluster(clients, config):
    print(f"--- Deleting ECS Cluster: {config['CLUSTER_NAME']} ---")
    try:
        # Check if services exist (safety check)
        services_response = clients['ecs'].list_services(cluster=config['CLUSTER_NAME'])
        if services_response.get('serviceArns'):
            print(f"ERROR: Cluster {config['CLUSTER_NAME']} still has active services. Aborting cluster deletion.")
            return

        print(f"Proceeding with deletion of cluster: {config['CLUSTER_NAME']}")
        clients['ecs'].delete_cluster(cluster=config['CLUSTER_NAME'])
        
        # Manually wait for deletion since 'clusters_deleted' waiter doesn't exist
        print("Cluster delete request sent. Waiting 20 seconds for propagation...")
        time.sleep(20)
        
        # Verification
        try:
            clients['ecs'].describe_clusters(clusters=[config['CLUSTER_NAME']])
            print("Warning: Cluster might still exist (AWS is slow to delete). It should disappear shortly.")
        except clients['ecs'].exceptions.ClusterNotFoundException:
            print(f"Cluster {config['CLUSTER_NAME']} deleted successfully.")

    except clients['ecs'].exceptions.ClusterNotFoundException:
        print(f"Cluster {config['CLUSTER_NAME']} not found. Skipping.")
    except Exception as e:
        print(f"An error occurred while deleting ECS cluster: {e}")


def delete_security_groups(clients, vpc_id, config):
    # UPDATED: This function now only deletes SGs created by our Terraform script.
    # It does NOT touch the client's VPC or other pre-existing resources.
    print(f"--- Deleting Terraform-Managed Security Groups in VPC {vpc_id} ---")
    # REMOVED: 'redis-sg' is no longer created.
    sg_names = [config['ALB_SG_NAME'], config['ECS_SG_NAME']]
    for sg_name in sg_names:
        try:
            response = clients['ec2'].describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': [sg_name]}, {'Name': 'vpc-id', 'Values': [vpc_id]}]
            )
            if response['SecurityGroups']:
                sg_id = response['SecurityGroups'][0]['GroupId']
                print(f"Deleting Security Group: {sg_name} ({sg_id})")
                time.sleep(5)
                clients['ec2'].delete_security_group(GroupId=sg_id)
            else:
                print(f"Security Group {sg_name} not found.")
        except Exception as e:
            print(f"Could not delete SG {sg_name}. It might be in use or already gone. Error: {e}")

# REMOVED: get_vpc_id_by_name is no longer needed as we get the ID directly.

def get_config_from_terraform(folder_path, use_terragrunt=True): # Defaulting use_terragrunt to False
    command_name = "terragrunt" if use_terragrunt else "terraform"
    # command_name = "terragrunt"
    print(f"--- Getting configuration from {command_name} output in: {folder_path} ---")
    try:
        if not use_terragrunt:
            print("Running 'terraform init'...")
            subprocess.run(["terraform", "init", "-upgrade"], cwd=folder_path, capture_output=True, text=True, check=True)
        
        print(f"Running '{command_name} output -json nuke_script_config'...")
        process = subprocess.run(
            [command_name, "output", "-json", "nuke_script_config"],
            cwd=folder_path, capture_output=True, text=True, check=True
        )
        return json.loads(process.stdout)

    except FileNotFoundError:
        print(f"\nFATAL: '{command_name}' command not found. Please ensure it's installed and in your PATH.")
        return None
    except subprocess.CalledProcessError as e:
        if "The installed provider plugins are not consistent" in e.stderr:
            print("\nProvider mismatch detected. Reinitializing Terraform to fix plugin cache...")
            subprocess.run(["terraform", "init", "-upgrade"], cwd=folder_path, capture_output=True, text=True, check=True)
            print("Re-run terraform output after reinitialization...")
            process = subprocess.run(
                [command_name, "output", "-json", "nuke_script_config"],
                cwd=folder_path, capture_output=True, text=True, check=True
            )
            return json.loads(process.stdout)
        else:
            print(f"\nFATAL: A {command_name} command failed.")
            print(f"Return Code: {e.returncode}\n----- {command_name.upper()} STDERR -----\n{e.stderr}\n--------------------------")
            return None
    except Exception as e:
        print(f"\nFATAL: An unexpected error occurred. {e}")
        return None

# ##################################################################
# #                     MAIN EXECUTION BLOCK (Updated)             #
# ##################################################################

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Programmatically destroy AWS resources for a Terraform project.")
    parser.add_argument("path", help="The relative or absolute path to the Terraform project directory.")    
    parser.add_argument("--manual-config", action="store_true", help="Use hardcoded/manual resource names.")
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Error: The provided path '{args.path}' is not a valid directory.")
        exit(1)



    # LOGIC TO SWITCH BETWEEN MODES
    if args.manual_config:
        print("!!! RUNNING IN MANUAL RECOVERY MODE !!!")
        config = {
            "AWS_REGION": "ca-central-1",
                        
            "CLUSTER_NAME": "btap-app-test3-dev-tgw-3-cluster",
            "ASG_NAME_PREFIX": "btap-app-test3-dev-tgw-3-asg-",
            "LAUNCH_TEMPLATE_PREFIX": "btap-app-test3-dev-tgw-3-lt-",
            # IMPORTANT:  "vpc-0809102c90503ef2d"  # From NRCan's info; confirm if needed. "vpc-0c095736cf65241cb" is BSUPs resource
            "VPC_ID": "vpc-0809102c90503ef2d",
            "ALB_SG_NAME": "btap-app-test3-dev-tgw-3-alb-sg",
            "ECS_SG_NAME": "btap-app-test3-dev-tgw-3-ecs-sg",
            
            "SERVICE_NAME": "btap-app-test3-dev-tgw-3-service", 
            "ALB_NAME": "btap-app-test3-dev-tgw-3-alb",
            "TARGET_GROUP_NAME": "btap-app-test3-dev-tgw-3-tg",
            
            # Set these to empty strings if unknown; 
            # the script will try to delete them
            "API_ID": "", 
            "VPC_LINK_ID": "",
            "CAPACITY_PROVIDER_NAME": "btap-app-test3-dev-tgw-3-capacity-provider"
        }
    else:        
        # config = get_config_from_terraform(args.path, use_terragrunt=args.use_terragrunt)
        config = get_config_from_terraform(args.path, True)
        if not config:
            print("\nAborting due to configuration errors.")
            exit(1)        
    
    # This config is no longer needed as we have a direct name.
    # config['CAPACITY_PROVIDER_NAME'] = f"{config.get('BASE_NAME')}-capacity-provider"
    
    print("\n>>> Discovered Configuration <<<")
    print(json.dumps(config, indent=2))
    input("\n>>> Press Enter to continue with the destruction of the above resources, or Ctrl+C to abort. <<<")

    clients = get_boto_clients(config['AWS_REGION'])
    
    print("\n>>> Starting AWS Resource Destruction Script <<<")
    
    # ----------------- REVISED AND CORRECTED DESTRUCTION ORDER -----------------
    
    # 1. Remove service auto-scaling dependencies first.
    delete_appautoscaling_policies_and_targets(clients, config)
    
    # 2. Scale down and delete the ECS service. This detaches it from the Target Group.
    delete_ecs_service(clients, config)
    
    # 3. NEW: Delete API Gateway components that depend on the ALB Listener.
    # The integration is the key dependency on the listener.
    delete_api_gateway_integrations(clients, config)
    delete_api_gateway_routes(clients, config)
    delete_api_gateway(clients, config)
    
    # 4. Now that the API Gateway is gone, delete the ALB and its Target Group.
    delete_load_balancer_and_target_group(clients, config)

    # 5. The VPC Link is no longer in use by the API Gateway.
    delete_vpc_link(clients, config)

    # 6. Scale down and delete the ASG, terminating all EC2 instances.
    delete_autoscaling_group_and_instances(clients, config)
    
    # 7. Delete the Launch Template.
    delete_launch_template(clients, config)
    
    # 8. NEW: Disassociate the Capacity Provider from the Cluster BEFORE deleting it.
    disassociate_capacity_providers_from_cluster(clients, config)
    
    # 9. Now delete the Capacity Provider itself.
    delete_capacity_providers(clients, config)
    
    # 10. Delete the now-empty and un-associated ECS Cluster.
    delete_ecs_cluster(clients, config)
    
    print("\n--- SKIPPING IAM ROLE DELETION BY DEFAULT (This is a safe practice) ---")
    
    # 11. Clean up networking resources created by this stack.
    vpc_id = config.get('VPC_ID')
    if vpc_id:
        print("\nWaiting 60 seconds for network interfaces to detach before deleting security groups...")
        time.sleep(60)
        delete_security_groups(clients, vpc_id, config)
    else:
        print(f"\nCould not find VPC_ID in the configuration to delete SGs from.")
        
    print("\n>>> Destruction Script Finished <<<")
    print("NOTE: This script does not delete the VPC, Subnets, or IAM Roles.")
    print("You can now run 'terragrunt destroy' to safely remove any remaining resources (like CloudWatch resources).")