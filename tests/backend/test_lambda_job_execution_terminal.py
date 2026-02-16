# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=R0903,R0801  # Single-method test classes and duplicate code acceptable in tests

"""
Unit tests for backend.lambda.job_execution_terminal.py
"""

import json
from unittest.mock import call
import pytest
from job_execution_terminal import handler

JOB_ID = 'redpill'
NEW_CERT_ID = 'choice is an illusion'
OLD_CERT_ID = 'how deep the rabbit hole goes'
THING_NAME = 'Nebuchadnezzar'
JOB_DOCUMENT = '{"operation":"ROTATE_CERTIFICATE"}'
SNS_TOPIC_ARN = "Not a real ARN"
SHADOW_NAME = "he's beginning to believe"
NEW_CERT_ARN = f'arn:aws:iot:us-east-1:000011112222:cert/{NEW_CERT_ID}'
OLD_CERT_ARN = f'arn:aws:iot:us-east-1:000011112222:cert/{OLD_CERT_ID}'
POLICIES = {'policies': [{'policyName': 'morpheus'}, {'policyName': 'smith'}]}

@pytest.fixture(name='principals')
def fixture_principals():
    """ Fake thing principals """
    return {
        'thingPrincipalObjects': [
            {
                'principal': f'arn:aws:iot:us-east-1:000011112222:cert/{NEW_CERT_ID}',
                'thingPrincipalType': 'EXCLUSIVE_THING'
            },
            {
                'principal': f'arn:aws:iot:us-east-1:000011112222:cert/{OLD_CERT_ID}',
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
                'progress': 'committed',
                'oldCertificateId': OLD_CERT_ID
            }
        }
    }

@pytest.fixture(name='event')
def fixture_event(mocker, boto3_client, principals, shadow_document):
    """ Lambda event with associated setup and checks """
    event = {
        'eventType': 'JOB_EXECUTION',
        'jobId': JOB_ID,
        'thingArn': f'arn:aws:iot:us-east-1:000011112222:thing/{THING_NAME}',
        'status': 'SUCCEEDED'
    }

    boto3_client.get_job_document.return_value = {'document': JOB_DOCUMENT}
    boto3_client.get_thing_shadow.return_value = mock_shadow_response(shadow_document)
    mocker.patch('job_execution_terminal.os.environ.get', side_effect=mock_os_environ_get)

    # This setup section only does anything useful when status is SUCCEEDED
    boto3_client.list_thing_principals_v2.return_value = principals
    cert_desc = {'certificateDescription': {'status': 'ACTIVE', 'certificateArn': OLD_CERT_ARN}}
    boto3_client.describe_certificate.return_value = cert_desc
    boto3_client.list_principal_policies.return_value = POLICIES

    yield event

    boto3_client.describe_endpoint.assert_called_once_with(endpointType='iot:Data-ATS')
    boto3_client.get_thing_shadow.assert_called_once_with(thingName=THING_NAME,
                                                            shadowName=SHADOW_NAME)
    # Delete will execute every time, unless we create an exception on get_thing_shadow
    if not boto3_client.get_thing_shadow.side_effect:
        boto3_client.delete_thing_shadow.assert_called_once_with(thingName=THING_NAME,
                                                                shadowName=SHADOW_NAME)
    boto3_client.get_job_document.assert_called_once_with(jobId=JOB_ID)

def mock_os_environ_get(name):
    """ Mock environment """
    environment = {
        'JOB_DOCUMENT': JOB_DOCUMENT,
        'SNS_TOPIC_ARN': SNS_TOPIC_ARN,
        'SHADOW_NAME': SHADOW_NAME
    }

    return environment.get(name, None)

def mock_shadow_response(shadow_document):
    """ Mock shadow response with payload """
    class MockPayload:
        """ Mock payload object """
        def read(self):
            """ Read mock shadow """
            return json.dumps(shadow_document)

    return {'payload': MockPayload()}

def confirm_certificate_deleted(boto3_client, cert_id, cert_arn, cert_status):
    """ Checks that all certificate deletion actions occur """
    boto3_client.list_thing_principals_v2.assert_called_once_with(thingName=THING_NAME,
                                                                   thingPrincipalType='EXCLUSIVE_THING')
    boto3_client.describe_certificate.assert_called_once_with(certificateId=cert_id)

    if cert_status == 'ACTIVE':
        boto3_client.update_certificate.assert_called_once_with(certificateId=cert_id, newStatus='INACTIVE')
    else:
        boto3_client.update_certificate.assert_not_called()
    boto3_client.detach_thing_principal.assert_called_once_with(thingName=THING_NAME, principal=cert_arn)
    boto3_client.list_principal_policies.assert_called_once_with(principal=cert_arn)
    calls = [call(policyName=POLICIES['policies'][0]['policyName'], target=cert_arn),
             call(policyName=POLICIES['policies'][1]['policyName'], target=cert_arn)]
    boto3_client.detach_policy.assert_has_calls(calls)
    boto3_client.delete_certificate.assert_called_once_with(certificateId=cert_id)

def confirm_certificate_not_deleted(boto3_client):
    """ Checks that no certificate deletion actions occur """
    boto3_client.update_certificate.assert_not_called()
    boto3_client.detach_thing_principal.assert_not_called()
    boto3_client.list_principal_policies.assert_not_called()
    boto3_client.detach_policy.assert_not_called()
    boto3_client.delete_certificate.assert_not_called()

def test_initialize_boto3_clients_idempotent(boto3_client, event):
    """ Confirm that boto3 clients are initialized once and reused """
    handler(event, None)
    assert boto3_client.call_count == 3

    boto3_client.get_thing_shadow.reset_mock()
    boto3_client.delete_thing_shadow.reset_mock()
    boto3_client.get_job_document.reset_mock()
    handler(event, None)
    assert boto3_client.call_count == 3

def test_job_succeeded_deletes_active_cert(boto3_client, event):
    """ Confirm that a successful job deletes the old certificate that is active """
    handler(event, None)
    confirm_certificate_deleted(boto3_client, OLD_CERT_ID, OLD_CERT_ARN, 'ACTIVE')
    boto3_client.publish.assert_not_called()

def test_job_succeeded_deletes_inactive_cert(boto3_client, event):
    """ Confirm that a successful job deletes the old certificate that is inactive """
    cert_desc = {'certificateDescription': {'status': 'INACTIVE', 'certificateArn': OLD_CERT_ARN}}
    boto3_client.describe_certificate.return_value = cert_desc
    handler(event, None)
    confirm_certificate_deleted(boto3_client, OLD_CERT_ID, OLD_CERT_ARN, 'INACTIVE')
    boto3_client.publish.assert_not_called()

def test_job_succeeded_thing_principals_too_few(boto3_client, event, principals):
    """ Handle succeeded job but the thing has fewer principals than expected """
    del principals['thingPrincipalObjects'][0]
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_not_called()

def test_job_succeeded_thing_principals_too_many(boto3_client, event, principals):
    """ Handle succeeded job but the thing has more principals than expected """
    principals['thingPrincipalObjects'].append({
        'principal': 'arn:aws:iot:us-east-1:000011112222:cert/bonus',
        'thingPrincipalType': 'EXCLUSIVE_THING'
    })
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_not_called()

def test_job_succeeded_thing_principal_not_cert(boto3_client, event, principals):
    """ Handle succeeded job but the thing has principals other than a certificate """
    principals['thingPrincipalObjects'][0]['principal']='wrong type of principal'
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_not_called()

def test_job_succeeded_no_shadow(boto3_client, event):
    """ Handle succeeded job but shadow is missing """
    boto3_client.get_thing_shadow.side_effect = Exception('mocked error')
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_succeeded_no_old_certificate_key(boto3_client, event, shadow_document):
    """ Handle succeeded job but the shadow is missing the old certificate key """
    del shadow_document['state']['reported']['oldCertificateId']
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_succeeded_no_new_certificate_key(boto3_client, event, shadow_document):
    """ Handle succeeded job but the shadow is missing the new certificate key """
    del shadow_document['state']['reported']['newCertificateId']
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_succeeded_no_progress_key(boto3_client, event, shadow_document):
    """ Handle succeeded job but the shadow is missing the progress key """
    del shadow_document['state']['reported']['progress']
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_succeeded_wrong_progress(boto3_client, event, shadow_document):
    """ Handle succeeded job but progress is not committed """
    shadow_document['state']['reported']['progress'] = 'created'
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_no_job_document(boto3_client, event):
    """ We should not do anything if there's no job or job document """
    boto3_client.get_job_document.side_effect = Exception('mocked error')
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_wrong_job_document(boto3_client, event):
    """ We should not do anything if the job document is wrong """
    boto3_client.get_job_document.return_value = {'document': 'whatever'}
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_failed_after_create(boto3_client, event, shadow_document):
    """ This is a standard rollback. The new certificate should be deleted """
    event['status'] = 'FAILED'
    shadow_document['state']['reported']['progress'] = 'created'
    cert_desc = {'certificateDescription': {'status': 'ACTIVE', 'certificateArn': NEW_CERT_ARN}}
    boto3_client.describe_certificate.return_value = cert_desc
    handler(event, None)
    confirm_certificate_deleted(boto3_client, NEW_CERT_ID, NEW_CERT_ARN, 'ACTIVE')
    boto3_client.publish.assert_called_once()

def test_job_failed_after_commit(boto3_client, event, shadow_document):
    """ We should not delete any certificate, but should send a notification """
    event['status'] = 'FAILED'
    shadow_document['state']['reported']['progress'] = 'committed'
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_timed_out_before_create(boto3_client, event, shadow_document):
    """ We should not delete any certificate, but should send a notification """
    event['status'] = 'TIMED_OUT'
    del shadow_document['state']['reported']['progress']
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_timed_out_after_create(boto3_client, event, shadow_document):
    """ This is a rollback. The new certificate should be deleted """
    event['status'] = 'TIMED_OUT'
    shadow_document['state']['reported']['progress'] = 'created'
    cert_desc = {'certificateDescription': {'status': 'ACTIVE', 'certificateArn': NEW_CERT_ARN}}
    boto3_client.describe_certificate.return_value = cert_desc
    handler(event, None)
    confirm_certificate_deleted(boto3_client, NEW_CERT_ID, NEW_CERT_ARN, 'ACTIVE')
    boto3_client.publish.assert_called_once()

def test_job_timed_out_after_commit(boto3_client, event, shadow_document):
    """ We should not delete any certificate, but should send a notification """
    event['status'] = 'TIMED_OUT'
    shadow_document['state']['reported']['progress'] = 'committed'
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_invalid_status(boto3_client, event):
    """ We should not do anything """
    event['status'] = 'JUNK'
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_not_called()
