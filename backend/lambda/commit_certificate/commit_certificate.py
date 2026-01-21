# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Verifies the new device certificate
"""
# pylint: disable=duplicate-code

import json
import os
import boto3

def publish_reply(iot, topic, message):
    """ Publishes a reply back to the device """
    endpoint = iot.describe_endpoint(endpointType='iot:Data-ATS')['endpointAddress']
    iot_data = boto3.client('iot-data', endpoint_url=f'https://{endpoint}')
    iot_data.publish(topic=topic, qos=0, payload=message)


def valid_job_execution(job_execution):
    """ Validates the job execution """
    # The Thing should have an IN_PROGRESS job execution and the status details should
    # contain the IDs of the new and old certificates.
    return job_execution is not None and job_execution['status'] == 'IN_PROGRESS' and\
            job_execution['jobDocument'] == os.environ.get('JOB_DOCUMENT') and\
            'statusDetails' in job_execution and len(job_execution['statusDetails']) == 3 and\
            'certificateRotationProgress' in job_execution['statusDetails'] and\
            job_execution['statusDetails']['certificateRotationProgress'] == 'created' and\
            'oldCertificateId' in job_execution['statusDetails'] and\
            'newCertificateId' in job_execution['statusDetails']


def valid_thing_principals(thing_principal_objects):
    """ Validates the thing principals """
    # The Thing should have two principals and they should both be certificates
    return len(thing_principal_objects) == 2 and\
            'cert' in thing_principal_objects[0]['principal'] and\
            'cert' in thing_principal_objects[1]['principal']


def valid_client(event, job_execution, thing_principal_objects):
    """ Validates the MQTT client """
    # The MQTT client should have authenticated using the new certificate and this should
    # be one of the Thing principals. And we demand that the client ID match the Thing name.
    # (Being mindful that Greengrass can append a suffix to the client ID.)
    return event['principal'] == job_execution['statusDetails']['newCertificateId'] and\
            (thing_principal_objects[0]['principal'].endswith(event['principal']) or\
            thing_principal_objects[1]['principal'].endswith(event['principal'])) and\
            event['clientId'].startswith(event['thingName'])


def handler(event, context):
    """ Lambda handler """
    # pylint: disable=unused-argument
    print(f'request: {json.dumps(event)}')

    iot = boto3.client('iot')
    endpoint = iot.describe_endpoint(endpointType='iot:Jobs')['endpointAddress']
    iot_jobs_data = boto3.client('iot-jobs-data', endpoint_url=f'https://{endpoint}')

    # We should only be here if this Thing has a job execution IN_PROGRESS
    try:
        job_execution = iot_jobs_data.describe_job_execution(jobId=event['jobId'],
                                                    thingName=event['thingName'],
                                                    includeJobDocument=True)['execution']
        print(job_execution)
    except Exception as error:
        print(f'No valid job execution for this Thing: {error}')
        job_execution = None

    # Get only those thing principals that are associated exclusively (our certificates should be)
    thing_principal_objects = iot.list_thing_principals_v2(thingName=event['thingName'],
                                                 thingPrincipalType='EXCLUSIVE_THING')['thingPrincipalObjects']
    print(thing_principal_objects)

    # If all the pre-conditions are met, we can proceed
    if valid_job_execution(job_execution) and\
        valid_thing_principals(thing_principal_objects) and\
        valid_client(event, job_execution, thing_principal_objects):

        # Mark in the status details that we committed to the new certificate
        status_details = job_execution['statusDetails']
        status_details['certificateRotationProgress'] = 'committed'

        # Update the job execution with the committed status
        iot_jobs_data.update_job_execution(jobId=event['jobId'],
                                            thingName=event['thingName'],
                                            status='IN_PROGRESS',
                                            statusDetails=status_details)

        # Formulate the reply message
        topic = f'{event["topic"]}/accepted'
        reply = {}

        error_msg = None

    else:
        error_msg = 'Pre-conditions not met'
        print(error_msg)
        topic = f'{event["topic"]}/rejected'
        reply = { 'errorMsg': error_msg }

    publish_reply(iot, topic, json.dumps(reply))

    return { 'status': 200, 'reply': reply }
