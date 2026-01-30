# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Verifies the new device certificate
"""
# pylint: disable=duplicate-code

import json
import os
import boto3

# Global clients initialized lazily to avoid breaking unit tests
iot = None
iot_jobs_data = None
iot_data = None

def initialize_boto3_clients():
    """Lazy initialization of clients"""
    # pylint: disable=global-statement
    global iot, iot_jobs_data, iot_data
    if iot is None:
        iot = boto3.client('iot')
    if iot_jobs_data is None:
        iot_jobs_endpoint = iot.describe_endpoint(endpointType='iot:Jobs')['endpointAddress']
        iot_jobs_data = boto3.client('iot-jobs-data', endpoint_url=f'https://{iot_jobs_endpoint}')
    if iot_data is None:
        iot_data_endpoint = iot.describe_endpoint(endpointType='iot:Data-ATS')['endpointAddress']
        iot_data = boto3.client('iot-data', endpoint_url=f'https://{iot_data_endpoint}')


def valid_job_execution(event):
    """ Validates the job execution """
    try:
        job_execution = iot_jobs_data.describe_job_execution(jobId=event['jobId'],
                                                    thingName=event['thingName'],
                                                    includeJobDocument=True)['execution']
        print(job_execution)
    except Exception as error:
        print(f'No valid job execution for this Thing: {error}')
        job_execution = None

    # The Thing should have an IN_PROGRESS job execution
    return job_execution is not None and job_execution['status'] == 'IN_PROGRESS' and\
            job_execution['jobDocument'] == os.environ.get('JOB_DOCUMENT')


def valid_shadow(shadow):
    """ Validates that the shadow has the expected fields """
    return shadow is not None and\
            'newCertificateId' in shadow and\
            'oldCertificateId' in shadow and\
            'progress' in shadow and\
            shadow['progress'] == 'created'


def valid_thing_principals(thing_principal_objects):
    """ Validates the thing principals """
    # The Thing should have two principals and they should both be certificates
    return len(thing_principal_objects) == 2 and\
            'cert' in thing_principal_objects[0]['principal'] and\
            'cert' in thing_principal_objects[1]['principal']


def valid_client(event, thing_principal_objects, new_cert_id):
    """ Validates the MQTT client """
    # The MQTT client should have authenticated using the new certificate and this should
    # be one of the Thing principals. And we demand that the client ID match the Thing name.
    # (Being mindful that Greengrass can append a suffix to the client ID.)
    return event['principal'] == new_cert_id and\
            (thing_principal_objects[0]['principal'].endswith(event['principal']) or\
            thing_principal_objects[1]['principal'].endswith(event['principal'])) and\
            event['clientId'].startswith(event['thingName'])


def handler(event, context):
    """ Lambda handler """
    # pylint: disable=unused-argument
    print(f'request: {json.dumps(event)}')

    initialize_boto3_clients()

    # The create Lambda should have created a shadow
    try:
        shadow_response = iot_data.get_thing_shadow(thingName=event['thingName'],
                                            shadowName=os.environ.get('SHADOW_NAME'))
        shadow = json.loads(shadow_response['payload'].read())['state']['reported']
        print(f'shadow: {shadow}')
    except Exception as error:
        print(f'No valid shadow for this Thing: {error}')
        shadow = None

    # Get only those thing principals that are associated exclusively (our certificates should be)
    thing_principal_objects = iot.list_thing_principals_v2(thingName=event['thingName'],
                                                 thingPrincipalType='EXCLUSIVE_THING')['thingPrincipalObjects']
    print(thing_principal_objects)

    # If all the pre-conditions are met, we can proceed
    if valid_job_execution(event) and\
        valid_shadow(shadow) and\
        valid_thing_principals(thing_principal_objects) and\
        valid_client(event, thing_principal_objects, shadow['newCertificateId']):

        # Update shadow to mark committed
        iot_data.update_thing_shadow(
            thingName=event['thingName'],
            shadowName=os.environ.get('SHADOW_NAME'),
            payload=json.dumps({
                'state': {
                    'reported': {
                        'progress': 'committed'
                    }
                }
            })
        )

        # Respond with success
        topic = f'{event["topic"]}/accepted'
        reply = {}

    else:
        error_msg = 'Pre-conditions not met'
        print(error_msg)
        topic = f'{event["topic"]}/rejected'
        reply = { 'errorMsg': error_msg }

    iot_data.publish(topic=topic, qos=0, payload=json.dumps(reply))

    return { 'status': 200, 'reply': reply }
