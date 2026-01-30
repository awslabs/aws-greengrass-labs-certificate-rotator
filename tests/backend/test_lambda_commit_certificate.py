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
SHADOW_NAME = "he's beginning to believe"
TOPIC = f'awslabs/things/{THING_NAME}/certificate/commit'

@pytest.fixture(name='job_execution')
def fixture_job_execution():
    """ Fake job execution state """
    return {
        'execution' : {
            'jobId': JOB_ID,
            'status': 'IN_PROGRESS',
            'statusDetails': {
                'Operation': 'ROTATE_CERTIFICATE'
            },
            'jobDocument': JOB_DOCUMENT
        }
    }

@pytest.fixture(name='principals')
def fixture_principals():
    """ Fake thing principals """
    return {
        'thingPrincipalObjects': [
            {
                'principal': f'arn:aws:iot:us-east-1:000011112222:cert/{OLD_CERT_ID}',
                'thingPrincipalType': 'EXCLUSIVE_THING'
            },
            {
                'principal': f'arn:aws:iot:us-east-1:000011112222:cert/{NEW_CERT_ID}',
                'thingPrincipalType': 'EXCLUSIVE_THING'
            }
        ]
    }

@pytest.fixture(name='shadow_document')
def fixture_shadow_document():
    """ Fake shadow document """
    return {
        'state': {
            'reported': {
                'newCertificateId': NEW_CERT_ID,
                'oldCertificateId': OLD_CERT_ID,
                'progress': 'created'
            }
        }
    }

@pytest.fixture(name='event')
def fixture_event(mocker, boto3_client, job_execution, principals, shadow_document):
    """ Lambda event with associated setup and checks """
    event = {
        'jobId': JOB_ID,
        'thingName': THING_NAME,
        'topic': TOPIC,
        'clientId': THING_NAME,
        'principal': NEW_CERT_ID
    }

    boto3_client.describe_job_execution.return_value = job_execution
    boto3_client.list_thing_principals_v2.return_value = principals
    boto3_client.get_thing_shadow.return_value = mock_shadow_response(shadow_document)
    mocker.patch('commit_certificate.os.environ.get', side_effect=mock_os_environ_get)

    yield event

    calls = [call(endpointType='iot:Jobs'), call(endpointType='iot:Data-ATS')]
    boto3_client.describe_endpoint.assert_has_calls(calls, any_order=True)
    boto3_client.get_thing_shadow.assert_called_once_with(thingName=THING_NAME,
                                                            shadowName=SHADOW_NAME)
    boto3_client.describe_job_execution.assert_called_once_with(jobId=JOB_ID, thingName=THING_NAME,
                                                                includeJobDocument=True)
    boto3_client.list_thing_principals_v2.assert_called_once_with(thingName=THING_NAME,
                                                                   thingPrincipalType='EXCLUSIVE_THING')

def mock_os_environ_get(name):
    """ Mock environment """
    environment = {
        'JOB_DOCUMENT': JOB_DOCUMENT,
        'SHADOW_NAME': SHADOW_NAME
    }

    return environment.get(name, None)

def mock_shadow_response(shadow_document):
    """ Mock shadow response with payload """
    class MockPayload:
        """ Mock payload object """
        def read(self):
            """ Read mock shadow """
            return json.dumps(shadow_document).encode('utf-8')

    return {'payload': MockPayload()}

def confirm_succeeded(boto3_client):
    """ Checks that the commit succeeded """
    boto3_client.update_thing_shadow.assert_called_once_with(
        thingName=THING_NAME,
        shadowName=SHADOW_NAME,
        payload=json.dumps({
            'state': {
                'reported': {
                    'progress': 'committed'
                }
            }
        })
    )
    boto3_client.publish.assert_called_once_with(topic=f'{TOPIC}/accepted', qos=0, payload=json.dumps({}))

def confirm_failed(boto3_client):
    """ Checks that the commit failed """
    boto3_client.publish.assert_called_once_with(topic=f'{TOPIC}/rejected', qos=0,
                                                 payload=json.dumps({ 'errorMsg': 'Pre-conditions not met' }))

def test_initialize_boto3_clients_idempotent(boto3_client, event):
    """ Confirm that boto3 clients are initialized once and reused """
    handler(event, None)
    assert boto3_client.call_count == 3

    boto3_client.get_thing_shadow.reset_mock()
    boto3_client.describe_job_execution.reset_mock()
    boto3_client.list_thing_principals_v2.reset_mock()
    handler(event, None)
    assert boto3_client.call_count == 3

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

def test_commit_failed_shadow_exception(boto3_client, event):
    """ Commit fails if get_thing_shadow throws an exception """
    boto3_client.get_thing_shadow.side_effect = Exception('mocked error')
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_shadow_no_progress(boto3_client, event, shadow_document):
    """ Commit fails if the shadow is missing the progress field """
    del shadow_document['state']['reported']['progress']
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_shadow_wrong_progress(boto3_client, event, shadow_document):
    """ Commit fails if the shadow has wrong progress """
    shadow_document['state']['reported']['progress'] = 'committed'
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_shadow_no_new_cert(boto3_client, event, shadow_document):
    """ Commit fails if the shadow is missing the new certificate ID """
    del shadow_document['state']['reported']['newCertificateId']
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_shadow_no_old_cert(boto3_client, event, shadow_document):
    """ Commit fails if the shadow is missing the old certificate ID """
    del shadow_document['state']['reported']['oldCertificateId']
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_thing_principals_too_few(boto3_client, event, principals):
    """ Commit fails if the thing has fewer principals than expected """
    del principals['thingPrincipalObjects'][0]
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_thing_principals_too_many(boto3_client, event, principals):
    """ Commit fails if the thing has more principals than expected """
    principals['thingPrincipalObjects'].append({
        'principal': 'arn:aws:iot:us-east-1:000011112222:cert/bonus',
        'thingPrincipalType': 'EXCLUSIVE_THING'
    })
    handler(event, None)
    confirm_failed(boto3_client)

def test_commit_failed_thing_principal_not_cert(boto3_client, event, principals):
    """ Commit fails if the thing has principals other than a certificate """
    principals['thingPrincipalObjects'][0]['principal']='wrong type of principal'
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
