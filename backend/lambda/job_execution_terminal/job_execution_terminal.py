# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Handles job execution reaching terminal status. Detaches and deletes the
old certificate on job execution succeeded.
"""

import json
import os
from enum import Enum
import boto3

class Certificate(Enum):
    """ Certificate types """
    OLD = 1
    NEW = 2


def send_notification(message):
    """ Sends a message as an SNS notification """
    sns = boto3.client('sns')

    print(message)

    sns.publish(TopicArn=os.environ.get('SNS_TOPIC_ARN'),
                Message=message,
                Subject='AWS Labs Certificate Rotator Notification')


def delete_certificate(certificate, event):
    """ Deletes either the new or old certificate """
    iot = boto3.client('iot')

    thing_name = event['thingArn'].split('thing/')[-1]

    certificate_age = 'new' if certificate == Certificate.NEW else 'old'

    print(f'Deleting {thing_name} {certificate_age} certificate')

    certificate_key = f'{certificate_age}CertificateId'

    # The job execution status details should exist and contain the certificate ID.
    has_cert_details = 'statusDetails' in event and\
                            certificate_key in event['statusDetails']

    # We can't proceed if the certificate details are absent
    if not has_cert_details:
        print('Did not delete certificate because certificate details missing from job status')
        return

    certificate_id = event['statusDetails'][certificate_key]

    # Get only those thing principals that are associated exclusively (our certificates should be)
    thing_principal_objects = iot.list_thing_principals_v2(thingName=thing_name,
                                                 thingPrincipalType='EXCLUSIVE_THING')['thingPrincipalObjects']
    print(thing_principal_objects)

    # The Thing should have two principals and they should both be certificates
    valid_thing_principals = len(thing_principal_objects) == 2 and\
                                'cert' in thing_principal_objects[0]['principal'] and\
                                'cert' in thing_principal_objects[1]['principal']

    # We should have thing principals. The certificate should be one of the Thing principals.
    if valid_thing_principals and\
        (thing_principal_objects[0]['principal'].endswith(certificate_id) or\
        thing_principal_objects[1]['principal'].endswith(certificate_id)):

        # Get the certificcate and extract its details
        certificate = iot.describe_certificate(certificateId=certificate_id)
        certificate_status = certificate['certificateDescription']['status']
        certificate_arn = certificate['certificateDescription']['certificateArn']

        # Deactivate the certificate (it should be active)
        if certificate_status == 'ACTIVE':
            iot.update_certificate(certificateId=certificate_id, newStatus='INACTIVE')

        # Detach the certificate from the Thing
        iot.detach_thing_principal(thingName=thing_name, principal=certificate_arn)

        # Get the policies attached to the certificate
        policies = iot.list_principal_policies(principal=certificate_arn)['policies']
        print(policies)

        # Detach all policies from the certificate
        for policy in policies:
            iot.detach_policy(policyName=policy['policyName'], target=certificate_arn)

        print(f'Deleting certificate {certificate_id}')

        # And finally, delete it
        iot.delete_certificate(certificateId=certificate_id)

    else:
        print('Did not delete certificate because of invalid thing state')


def get_rotation_progress(event):
    """ Gets the progress indicator from the status details of the job execution """
    progress = None

    if 'statusDetails' in event and 'certificateRotationProgress' in event['statusDetails']:
        progress = event['statusDetails']['certificateRotationProgress']

    return progress


def valid_job(event):
    """ Validates that the event is from a certificate rotation job """
    iot = boto3.client('iot')

    try:
        job_document = iot.get_job_document(jobId=event['jobId'])['document']
        print(job_document)
    except Exception as error:
        print(f'No valid job document for this job ID: {error}')
        job_document = None

    # There should be a job execution and it should be a certificate rotation
    return job_document is not None and job_document == os.environ.get('JOB_DOCUMENT')


def handler(event, context):
    """ Lambda handler """
    # pylint: disable=unused-argument
    print(f'request: {json.dumps(event)}')

    # Ensure we are processing a valid certificate rotation job
    if valid_job(event):
        msg_prefix = f'Certificate rotation job execution for {event["thingArn"].split("thing/")[-1]}'
        rotation_progress = get_rotation_progress(event)

        if event['status'] == 'SUCCEEDED':
            # Is the success after the commit (as it should)?
            if rotation_progress == 'committed':
                # With the rotation successfully completed, we can delete the old certificate
                delete_certificate(Certificate.OLD, event)
                print(f'{msg_prefix} SUCCEEDED')
            else:
                # This should not happen. Do not delete a certficiate. Just notify.
                send_notification(f'{msg_prefix} SUCCEEDED but rotation progress was '
                                    'contradicting. Check core device logs for details. '
                                    'Old certificate is still active.')

        elif event['status'] == 'FAILED':
            # Is the failure after the create (and before the commit)?
            if rotation_progress == 'created':
                # The device will have rolled back to the old certificate. Delete the new one.
                delete_certificate(Certificate.NEW, event)

            send_notification(f'{msg_prefix} FAILED. Core device detected an error. '
                                'Check core device logs for details. Old certificate is '
                                'still active.')

        elif event['status'] == 'TIMED_OUT':
            # Handle the unlikely event that we suffered a comms error after receiving the commit,
            # but before the job execution was updated to SUCCEEDED. In this situaion, we can't
            # know if the device received the certificate/commit/accepted message. Hence we don't
            # know if the device is using the new or old certificate. In this case we retain both
            # the old and new certificate and request operator attention.
            if rotation_progress == 'committed':

                # We send an SNS because we can't know what certificate the device is using
                send_notification(f'{msg_prefix} TIMED OUT after commit. It is indeterminate '
                                    'whether the device rotated to the new certificate or rolled '
                                    'back to the old. Both certificates retained in the cloud. '
                                    'Manual intervention required to identify and delete the '
                                    'unused certificate.')

            # This is a timeout before the commit.
            else:
                # Is the timeout after the create (and before the commit)?
                if rotation_progress == 'created':
                    # The device will have rolled back to the old certificate. Delete the new one.
                    delete_certificate(Certificate.NEW, event)

                send_notification(f'{msg_prefix} TIMED OUT. Likely due to intermittent '
                                    'connectivity. Rotation cancelled. Old '
                                    'certificate is still active.')

    result = {
        'status': 200
    }

    return result
