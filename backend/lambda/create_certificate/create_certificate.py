# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Creates a new device certificate, using a Certificate Signing Request (CSR)
from a device, and publishes it back to the device.
"""
# pylint: disable=duplicate-code

import json
import os
import boto3

def valid_job_execution(iot_jobs_data, event):
    """ Validates the job execution """
    try:
        job_execution = iot_jobs_data.describe_job_execution(jobId=event['jobId'],
                                                    thingName=event['thingName'],
                                                    includeJobDocument=True)['execution']
        print(job_execution)
    except Exception as error:
        print(f'No valid job execution for this Thing: {error}')
        job_execution = None

    # The Thing should have an IN_PROGRESS job execution with no status details
    return job_execution is not None and job_execution['status'] == 'IN_PROGRESS' and\
            job_execution['jobDocument'] == os.environ.get('JOB_DOCUMENT') and\
            'statusDetails' in job_execution and len(job_execution['statusDetails']) == 1 and\
            'certificateRotationProgress' in job_execution['statusDetails'] and\
            job_execution['statusDetails']['certificateRotationProgress'] == 'started'


def valid_thing_principals(thing_principal_objects):
    """ Validates the thing principals """
    # The Thing should have just one principal and it should be a certificate
    return len(thing_principal_objects) == 1 and 'cert' in thing_principal_objects[0]['principal']


def valid_client(event, thing_principal_objects):
    """ Validates the MQTT client """
    # The MQTT client should have authenticated using the certificate attached to the Thing.
    # And we demand that the client ID match the Thing name (being mindful that Greengrass
    # can append a suffix to the client ID.)
    return thing_principal_objects[0]['principal'].endswith(event['principal']) and\
        event['clientId'].startswith(event['thingName'])


def create_iot_certificate(iot, csr):
    """ Uses AWS IoT to create a device certificate """
    cert_response = None
    error_msg = None

    print('Using AWS IoT to create the certificate')

    # Use the CSR to create a new certificate, setting it ACTIVE immediately
    try:
        cert_response = iot.create_certificate_from_csr(certificateSigningRequest=csr,
                                                        setAsActive=True)
        print(cert_response)

    except Exception as error:
        error_msg = f'Failed to create certificate from CSR: {error}'

    return (cert_response, error_msg)


def create_pca_certificate(iot, csr, ca_arn):
    """ Uses AWS Private Certificate Authority to create a device certificate """
    cert_response = None
    error_msg = None

    print('Using Private CA to create the certificate')

    pca = boto3.client('acm-pca')

    signing_algorithm = os.environ.get('PCA_SIGNING_ALGORITHM')
    validity_in_days = os.environ.get('PCA_VALIDITY_IN_DAYS')

    # Use the CSR to get Private CA to issue a new certificate
    try:
        response = pca.issue_certificate(CertificateAuthorityArn=ca_arn,
                                            Csr=csr.encode('utf-8'),
                                            SigningAlgorithm=signing_algorithm,
                                            Validity={
                                                'Value': int(validity_in_days),
                                                'Type': 'DAYS'
                                            })
        print(response)

        waiter = pca.get_waiter('certificate_issued')

        waiter.wait(CertificateAuthorityArn=ca_arn,
                    CertificateArn=response['CertificateArn'],
                    WaiterConfig={'Delay': 1, 'MaxAttempts': 30})

        print('Certificate is ready')

        # Get the new certificate from Private CA
        response = pca.get_certificate(CertificateAuthorityArn=ca_arn,
                                        CertificateArn=response['CertificateArn'])

        # Register it in AWS IoT. We register it without a CA because we don't require
        # that the Private CA be registered in AWS IoT.
        cert_response = iot.register_certificate_without_ca(certificatePem=response['Certificate'],
                                                            status='ACTIVE')

        # Add the PEM to the response to emulate the IoT create_certificate_from_csr() response
        cert_response['certificatePem'] = response['Certificate']

    except Exception as error:
        error_msg = f'Failed to create certificate from CSR: {error}'

    return (cert_response, error_msg)


def create_certificate(iot, iot_jobs_data, event, thing_principal_objects):
    """ Create and register a new device certificate """
    pca_ca_arn = os.environ.get('PCA_CA_ARN')

    # We use Private CA for certificate creation if a Private CA ARN is defined
    if pca_ca_arn is None or pca_ca_arn == '':
        cert_response, error_msg = create_iot_certificate(iot, event['csr'])
    else:
        cert_response, error_msg = create_pca_certificate(iot, event['csr'], pca_ca_arn)

    # Proceed if no errors. We have validated everything from the Thing, so we expect
    # no further errors.
    if error_msg is None:

        # Get the policies that are attached to the existing certificate
        policies = iot.list_principal_policies(principal=thing_principal_objects[0]['principal'])['policies']
        print(policies)

        # Policies attached to the existing certificate should be attached to the new one
        for policy in policies:
            iot.attach_policy(policyName=policy['policyName'],
                                target=cert_response['certificateArn'])

        # Attach the new device certificate to the Thing with exclusive association
        iot.attach_thing_principal(thingName=event['thingName'],
                                    principal=cert_response['certificateArn'],
                                    thingPrincipalType='EXCLUSIVE_THING')

        # We'll remember the certificate IDs in the job execution status details
        status_details = {
            'certificateRotationProgress': 'created',
            'oldCertificateId': event['principal'],
            'newCertificateId': cert_response['certificateId']
        }

        # Update the job execution to remember the certificate IDs
        iot_jobs_data.update_job_execution(jobId=event['jobId'],
                                            thingName=event['thingName'],
                                            status='IN_PROGRESS',
                                            statusDetails=status_details)

        certificate = cert_response['certificatePem']
    else:
        certificate = None

    return (certificate, error_msg)


def publish_reply(iot, topic, message):
    """ Publishes a reply back to the device """
    endpoint = iot.describe_endpoint(endpointType='iot:Data-ATS')['endpointAddress']
    iot_data = boto3.client('iot-data', endpoint_url=f'https://{endpoint}')
    iot_data.publish(topic=topic, qos=0, payload=message)


def handler(event, context):
    """ Lambda handler """
    # pylint: disable=unused-argument
    print(f'request: {json.dumps(event)}')

    iot = boto3.client('iot')
    endpoint = iot.describe_endpoint(endpointType='iot:Jobs')['endpointAddress']
    iot_jobs_data = boto3.client('iot-jobs-data', endpoint_url=f'https://{endpoint}')

    # Get only those thing principals that are associated exclusively (our certificates should be)
    thing_principal_objects = iot.list_thing_principals_v2(thingName=event['thingName'],
                                                 thingPrincipalType='EXCLUSIVE_THING')['thingPrincipalObjects']
    print(thing_principal_objects)

    # If all the pre-conditions are met, we can proceed
    if valid_job_execution(iot_jobs_data, event) and\
        valid_thing_principals(thing_principal_objects) and\
        valid_client(event, thing_principal_objects):

        certificate, error_msg = create_certificate(iot, iot_jobs_data, event, thing_principal_objects)
    else:
        certificate = None
        error_msg = 'Pre-conditions not met'


    if error_msg is not None:
        print(error_msg)
        topic = f'{event["topic"]}/rejected'
        reply = { 'errorMsg': error_msg }
    else:
        topic = f'{event["topic"]}/accepted'
        reply = { 'certificatePem': certificate }

    publish_reply(iot, topic, json.dumps(reply))

    return { 'status': 200, 'reply': reply }
