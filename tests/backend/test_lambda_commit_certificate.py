# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for backend.lambda.commit_certificate.py
"""

import json
from unittest.mock import call
import pytest
from commit_certificate import handler

JOB_ID = 'redpill'
NEW_CERT_ID = 'choice is an illusion'
OLD_CERT_ID = 'how deep the rabbit hole goes'
THING_NAME = 'Nebuchadnezzar'
JOB_DOCUMENT = '{"operation":"ROTATE_CERTIFICATE"}'
TOPIC = f'awslabs/things/{THING_NAME}/certificate/commit'

@pytest.fixture(name='job_execution')
def fixture_job_execution():
    """ Fake job execution state """
    return {
        'execution' : {
            'jobId': JOB_ID,
            'status': 'IN_PROGRESS',
            'statusDetails': {
                'newCertificateId': NEW_CERT_ID,
                'oldCertificateId': OLD_CERT_ID,
                'progress': 'created'
            },
            'jobDocument': JOB_DOCUMENT
        }
    }

@pytest.fixture(name='principals')
def fixture_principals():
    """ Fake thing principals """
    return {
        'principals': [
            f'arn:aws:iot:us-east-1:000011112222:cert/{NEW_CERT_ID}',
            f'arn:aws:iot:us-east-1:000011112222:cert/{OLD_CERT_ID}'
        ]
    }

@pytest.fixture(name='event')
def fixture_event(mocker, boto3_client, job_execution, principals):
    """ Lambda event with associated setup and checks """
    event = {
        'jobId': JOB_ID,
        'thingName': THING_NAME,
        'topic': TOPIC,
        'clientId': THING_NAME,
        'principal': NEW_CERT_ID
    }

    boto3_client.describe_job_execution.return_value = job_execution
    boto3_client.list_thing_principals.return_value = principals
    mocker.patch('commit_certificate.os.environ.get', return_value=JOB_DOCUMENT)

    yield event

    calls = [call(endpointType='iot:Jobs'), call(endpointType='iot:Data-ATS')]
    boto3_client.describe_endpoint.assert_has_calls(calls, any_order=True)
    boto3_client.describe_job_execution.assert_called_once_with(jobId=JOB_ID, thingName=THING_NAME,
                                                                includeJobDocument=True)
    boto3_client.list_thing_principals.assert_called_once_with(thingName=THING_NAME)

def confirm_succeeded(boto3_client):
    """ Checks that the commit succeeded """
    boto3_client.update_job_execution.assert_called_once_with(jobId=JOB_ID, thingName=THING_NAME,
                                                              status='IN_PROGRESS',
                                                              statusDetails={
                                                                    'newCertificateId': NEW_CERT_ID,
                                                                    'oldCertificateId': OLD_CERT_ID,
                                                                    'progress': 'committed'
                                                                })
    boto3_client.publish.assert_called_once_with(topic=f'{TOPIC}/accepted', qos=0, payload=json.dumps({}))

def confirm_failed(boto3_client):
    """ Checks that the commit failed """
    boto3_client.publish.assert_called_once_with(topic=f'{TOPIC}/rejected', qos=0,
                                                 payload=json.dumps({ 'errorMsg': 'Pre-conditions not met' }))

def test_commit_succeeded(boto3_client, event):
    """ Commit succeeds if all necessary conditions are in place """
    handler(event, None)
    confirm_succeeded(boto3_client)

def test_commit_failed_no_job_execution_for_thing(boto3_client, event):
    """ Commit fails if describe_job_execution throws an exception """
    boto3_client.describe_job_execution.side_effect = Exception('mocked error')
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_job_execution_wrong_status(boto3_client, event, job_execution):
    """ Commit fails if the job execution is in the wrong state """
    job_execution['execution']['status'] = 'QUEUED'
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_job_execution_wrong_document(boto3_client, event, job_execution):
    """ Commit fails if the job execution has the wrong job document """
    job_execution['execution']['jobDocument'] = 'something else'
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_job_execution_no_status_details(boto3_client, event, job_execution):
    """ Commit fails if the job execution has no status details """
    del job_execution['execution']['statusDetails']
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_job_execution_status_details_no_progress(boto3_client, event, job_execution):
    """ Commit fails if the job execution status details is missing the progress field """
    del job_execution['execution']['statusDetails']['progress']
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_job_execution_wrong_progress(boto3_client, event, job_execution):
    """ Commit fails if the job execution has status details with wrong progress """
    job_execution['execution']['statusDetails']['progress'] = 'something else'
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_job_execution_status_details_no_old(boto3_client, event, job_execution):
    """ Commit fails if the job execution status details is missing the old certificate ID """
    del job_execution['execution']['statusDetails']['oldCertificateId']
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_job_execution_status_details_no_new(boto3_client, event, job_execution):
    """ Commit fails if the job execution status details is missing the new certificate ID """
    del job_execution['execution']['statusDetails']['newCertificateId']
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_thing_principals_too_few(boto3_client, event, principals):
    """ Commit fails if the thing has fewer principals than expected """
    del principals['principals'][0]
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_thing_principals_too_many(boto3_client, event, principals):
    """ Commit fails if the thing has more principals than expected """
    principals['principals'].append('arn:aws:iot:us-east-1:000011112222:cert/bonus')
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_thing_principal_not_cert(boto3_client, event, principals):
    """ Commit fails if the thing has principals other than a certificate """
    principals['principals'][0]='wrong type of principal'
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_auth_wrong_principal(boto3_client, event):
    """ Commit fails if the thing authenticated with a principal other than the new certificate """
    event['principal'] = f'arn:aws:iot:us-east-1:000011112222:cert/{OLD_CERT_ID}'
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_auth_wrong_client(boto3_client, event):
    """ Commit fails if the device authenticated with a client name other than the Thing name """
    event['clientId'] = 'Metacortex'
    handler(event, None)
    confirm_failed(boto3_client)
