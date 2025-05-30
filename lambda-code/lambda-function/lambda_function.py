## Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: MIT-0

import boto3
import json

# Create EC2 client and AWS Config client
ec2_client = boto3.client('ec2')
config_client = boto3.client('config')
ec2_resource = boto3.resource('ec2')

def check_non_compliant_instances(config_rule_name):
    """
    Function to check non-compliant EC2 instances based on a Config rule.
    :param config_rule_name: Name of the AWS Config rule to check
    :return: List of non-compliant instance IDs
    """
    non_compliant_instances = []
    print("--------INSIDE CHECK NON COMPLIANT INSTANCES FUNCTION---------")
    # Get the non-compliant resources from AWS Config
    response = config_client.get_compliance_details_by_config_rule(
        ConfigRuleName=config_rule_name,
        ComplianceTypes=['NON_COMPLIANT']
    )
    # Extract the instance IDs from the non-compliant resources
    for result in response.get('EvaluationResults', []):
        resource_id = result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
        non_compliant_instances.append(resource_id)
        
    return non_compliant_instances

def get_desired_instance_type(config_rule_name):
    """
    Function to fetch the desired instance type from the AWS Config rule.
    :param config_rule_name: Name of the AWS Config rule
    :return: Desired instance type
    """
    print("--------INSIDE GET DESIRED INSTANCE TYPE FUNCTION---------")
    try:
        response = config_client.describe_config_rules(
            ConfigRuleNames=[config_rule_name]
        )
        print(response)
        # Assuming the desired instance type is stored in 'InputParameters' field
        rule_parameters = response['ConfigRules'][0].get('InputParameters', '{}')
        desired_instance_type = json.loads(rule_parameters).get('instanceType', None)
        return desired_instance_type
    except Exception as e:
        print(f"Error fetching instance type from config rule: {e}")
        return None

def remediate_instances(instance_ids, config_rule_name):
    """
    Function to remediate non-compliant EC2 instances by changing the instance type and restarting them.
    :param instance_ids: List of non-compliant EC2 instance IDs to remediate
    :param config_rule_name: AWS Config rule name to fetch the desired instance type
    :return: List of instance remediation status messages
    """
    print("--------INSIDE REMEDIATE INSTANCES FUNCTION---------")
    instance_messages = []
    
    # Get the desired instance type from the config rule
    desired_instance_type = get_desired_instance_type(config_rule_name)
    print(desired_instance_type)
    if not desired_instance_type:
        return ["Error: Unable to retrieve desired instance type from the Config rule."]
    
    # ec2_client.stop_instances(InstanceIds=instance_ids)
    for instance_id in instance_ids:
        stop_response = ec2_client.stop_instances(InstanceIds=[instance_id])
        print(f"Stop Response for {instance_id}: {stop_response}")
        waiter = ec2_client.get_waiter('instance_stopped')
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 60, 'MaxAttempts': 40})
    
    print("Going into the main instance modification loop")
    # # Wait for the instances to be stopped
    # waiter = ec2_client.get_waiter('instance_stopped')
    # waiter.wait(InstanceIds=instance_ids, WaiterConfig={'Delay': 120, 'MaxAttempts': 40})
    # print("before for loop")
    # print(instance_ids)
    
    # for instance_id in instance_ids:
    #         ec2_client.stop_instances(InstanceIds=[instance_id])
    #         instance = ec2_resource.Instance(instance_id)
    #         instance.wait_until_stopped()
    
    for instance_id in instance_ids:
        try:
            #print(instance_id)
            # Modify the instance type
            # instance = ec2_resource.Instance(instance_id)
            # instance.wait_until_stopped()
            execution = ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                InstanceType={'Value': desired_instance_type}
            )
            print(execution)
            # Start the instance again
            ec2_client.start_instances(InstanceIds=[instance_id])
            instance_messages.append(f"Instance {instance_id} type changed to {desired_instance_type} and restarted.")
        except Exception as e:
            instance_messages.append(f"Error remediating instance {instance_id}: {str(e)}")
    
    return instance_messages

def pause_instances(non_compliant_instance_ids):
    """
    Function to pause non-compliant EC2 instances (stop the instances).
    :param non_compliant_instance_ids: List of non-compliant EC2 instance IDs to pause
    :return: List of instance state messages
    """
    print("--------INSIDE PAUSE INSTANCES FUNCTION---------")
    print(non_compliant_instance_ids)
    cleaned_instance_ids = []

    for instance_ids_str in non_compliant_instance_ids:
        instance_ids = instance_ids_str.strip('[]').split('", "')
        cleaned_instance_ids.extend([instance_id.strip('"') for instance_id in instance_ids])
    print(cleaned_instance_ids) 
    
    instance_messages = []
    
    # Describe instance statuses to check their current state
    instance_status = ec2_client.describe_instances(InstanceIds=cleaned_instance_ids)
    print(instance_status)
    
    for reservation in instance_status['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_state = instance['State']['Name']
            
            if instance_state == 'stopped':
                instance_messages.append(f"Instance {instance_id} already paused")
            else:
                # Stop (pause) the non-compliant instance
                ec2_client.stop_instances(InstanceIds=[instance_id])
                instance_messages.append(f"Instance {instance_id} paused")
    
    return instance_messages

def lambda_handler(event, context):
    # Extract the action group, API path, and parameters from the input event
    print(event)
    action_group = event.get('actionGroup', 'security-bot-action-group')
    api_path = event.get('apiPath', None)
    parameters = event.get('parameters', [])
    request_body_content = event.get('requestBody', {}).get('content', {})
    print("--------INSIDE MAIN LAMBDA FUNCTION---------")

    # Parse parameters and request body to extract useful values
    config_rule_name = None
    instance_ids=[]
    # Check parameters for config rule name or instance IDs
    for param in parameters:
        if param['name'] == 'config_rule':
            config_rule_name = param['value']
        if param['name'] == 'instance_ids':
            instance_ids = param['value'].split(',')

    # Check request body content for config rule or instance IDs
    for content_type, content_data in request_body_content.items():
        for prop in content_data.get('properties', []):
            if prop['name'] == 'config_rule':
                config_rule_name = prop['value']
            if prop['name'] == 'instance_ids':
                instance_ids = prop['value'].split(',')

    if api_path == "/check-non-compliant-instances":
        # Handle check non-compliant instances
        if config_rule_name is None:
            config_rule_name = 'desired-instance-type'  # Default value

        non_compliant_instances = check_non_compliant_instances(config_rule_name)
        
        if not non_compliant_instances:
            response_body = {
                "message": "All instances are compliant."
            }
        else:
            response_body = {
                "message": "Non-compliant instances found.",
                "instance_ids": non_compliant_instances
            }

    elif api_path == "/pause-non-compliant-instances":
        # Handle pause non-compliant instances
        if not instance_ids:
            response_body = {
                "message": "No instance IDs provided."
            }
        else:
            pause_instance_ids=[]
            for prop in request_body_content['application/json']['properties']:
                if prop['name'] == 'instance_ids':
                # The 'value' contains a JSON-formatted string, so we need to parse it
                    instance_ids_str = prop['value']
                    instance_ids = json.loads(instance_ids_str)
                    pause_instance_ids.extend(instance_ids)
            #pause_instance_ids = request_body_content['application/json']['properties']['value']
            print("***********")
            # pause_instance_ids=["i-06eb1ac54a25ba3c1", "i-0d494435cc8d1dea1"]
            print(pause_instance_ids)
            instance_messages = pause_instances(pause_instance_ids)
            response_body = {
                "message": "Non-compliant instances have been processed for pausing.",
                "instance_status": instance_messages
            }
    elif api_path == "/remediate-instances":
        # Handle remediation of non-compliant instances
        if not instance_ids:
            response_body = {
                "message": "No instance IDs provided."
            }
        else:
            instance_ids=check_non_compliant_instances(config_rule_name)
            instance_messages = remediate_instances(instance_ids, config_rule_name)
            response_body = {
                "message": "Non-compliant instances have been remediated.",
                "instance_status": instance_messages
            }
    else:
        response_body = {
            "message": "Invalid API path provided."
        }

    # Format the response according to the Bedrock requirements
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "apiPath": api_path,
            "httpMethod": event.get('httpMethod', 'POST'),
            "httpStatusCode": 200,
            "responseBody": {
                "application/json": {
                    "body": json.dumps(response_body)
                }
            }
        },
        "sessionAttributes": event.get('sessionAttributes', {}),
        "promptSessionAttributes": event.get('promptSessionAttributes', {}),
        "knowledgeBasesConfiguration": []
    }