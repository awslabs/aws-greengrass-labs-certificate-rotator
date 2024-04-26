# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Deploys a component version to a Thing group. This should be
called after "gdk component build" and "gdk component publish".

Example execution:
python3 deploy_component_version.py 1.1.0 GreengrassEC2DeviceFarm
"""

import argparse
import sys
import time
import boto3
from libs.gdk_config import GdkConfig

ACCOUNT = boto3.client('sts').get_caller_identity().get('Account')

def get_deployment():
    """ Gets the details of the existing deployment """
    target_arn = f'arn:aws:iot:{gdk_config.region()}:{ACCOUNT}:thinggroup/{args.thingGroupName}'

    print(f'Searching for existing Thing group deployment for {args.thingGroupName}')

    try:
        # Get the latest deployment for the specified target ARN
        response = greengrassv2_client.list_deployments(
            targetArn=target_arn,
            historyFilter='LATEST_ONLY',
            maxResults=1
        )
    except Exception as e:
        print(f'Failed to list deployments\nException: {e}')
        sys.exit(1)

    # We expect to update an existing deployment, not create a new one
    if len(response['deployments']) == 0:
        print('No existing deployment for this target ARN. Abort.')
        sys.exit(1)

    # We expect at most one result in the list
    deployment_id = response['deployments'][0]['deploymentId']

    try:
        response = greengrassv2_client.get_deployment(deploymentId=deployment_id)

        if 'deploymentName' in response:
            print(f'Found existing named deployment "{response["deploymentName"]}"')
        else:
            print(f'Found existing unnamed deployment {deployment_id}')
    except Exception as e:
        print(f'Failed to get deployment\nException: {e}')
        sys.exit(1)

    return response

def update_deployment(deployment):
    """ Updates the current deplyment with the desired versions of the components """

    # Add or update our component to the specified version
    if gdk_config.name() not in deployment['components']:
        print(f'Adding {gdk_config.name()} {args.version} to the deployment')
    else:
        print(f'Updating deployment with {gdk_config.name()} {args.version}')
    deployment['components'].update({gdk_config.name(): {'componentVersion': args.version}})

def create_deployment(deployment):
    """ Creates a deployment of the component to the given target ARN """

    # Give the deployment a name if it doesn't already have one
    if 'deploymentName' in deployment:
        deployment_name = deployment['deploymentName']
    else:
        deployment_name = f'Deployment for {args.thingGroupName}'
        print(f'Renaming deployment to "{deployment_name}"')

    try:
        # Deploy with default deployment policies and no tags
        response = greengrassv2_client.create_deployment(
            targetArn=deployment['targetArn'],
            deploymentName=deployment_name,
            components=deployment['components']
        )
    except Exception as e:
        print(f'Failed to create deployment\nException: {e}')
        sys.exit(1)

    return response['deploymentId']

def wait_for_deployment_to_finish(deploy_id):
    """ Waits for the deployment to complete """
    done = False
    snapshot = time.time()

    while not done and (time.time() - snapshot) < 900:
        try:
            response = greengrassv2_client.get_deployment(deploymentId=deploy_id)
            deployment_status = response['deploymentStatus']
            iot_job_id = response['iotJobId']

            try:
                job_process_details = iot_client.describe_job(jobId=iot_job_id)['job']['jobProcessDetails']
                started = job_process_details['numberOfQueuedThings'] > 0 or\
                            job_process_details['numberOfInProgressThings'] > 0 or\
                            job_process_details['numberOfFailedThings'] > 0 or\
                            job_process_details['numberOfRejectedThings'] > 0 or\
                            job_process_details['numberOfTimedOutThings'] > 0 or\
                            job_process_details['numberOfSucceededThings'] > 0
                done = started and job_process_details['numberOfQueuedThings'] == 0 and\
                        job_process_details['numberOfInProgressThings'] == 0
                succeeded = done and job_process_details['numberOfFailedThings'] == 0 and\
                            job_process_details['numberOfRejectedThings'] == 0 and\
                            job_process_details['numberOfTimedOutThings'] == 0
            except Exception as e:
                print(f'Failed to describe job\nException: {e}')
                sys.exit(1)
        except Exception as e:
            print(f'Failed to get deployment\nException: {e}')
            sys.exit(1)

    if succeeded:
        print(f'Deployment completed successfully in {time.time() - snapshot:.1f} seconds')
    elif not done:
        print('Deployment timed out')
        sys.exit(1)
    else:
        print(f'Deployment error: {deployment_status}')
        sys.exit(1)


gdk_config = GdkConfig()

parser = argparse.ArgumentParser(description=f'Deploy a version of the {gdk_config.name()} component')
parser.add_argument('version', help='Version of the component to be deployed (Example: 1.1.0)')
parser.add_argument('thingGroupName', help='Name of the Thing group of Greengrass core device(s) to deploy to')
args = parser.parse_args()

greengrassv2_client = boto3.client('greengrassv2', region_name=gdk_config.region())
iot_client = boto3.client('iot', region_name=gdk_config.region())

print(f'Attempting deployment of version {args.version} to {args.thingGroupName}')

# Get the latest deployment for the specified target ARN
current_deployment = get_deployment()

# Update the components of the current deployment
update_deployment(current_deployment)

# Create a new deployment
new_deployment_id = create_deployment(current_deployment)
print(f'Deployment {new_deployment_id} successfully created. Waiting for completion ...')
wait_for_deployment_to_finish(new_deployment_id)
