# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for backend.lambda.job_execution_terminal.py
"""

from unittest.mock import call
import pytest
from job_execution_terminal import handler

JOB_ID = 'redpill'
NEW_CERT_ID = 'choice is an illusion'
OLD_CERT_ID = 'how deep the rabbit hole goes'
THING_NAME = 'Nebuchadnezzar'
JOB_DOCUMENT = '{"operation":"ROTATE_CERTIFICATE"}'
SNS_ARN = "Not a real ARN"
NEW_CERT_ARN = f'arn:aws:iot:us-east-1:000011112222:cert/{NEW_CERT_ID}'
OLD_CERT_ARN = f'arn:aws:iot:us-east-1:000011112222:cert/{OLD_CERT_ID}'
POLICIES = {'policies': [{'policyName': 'morpheus'}, {'policyName': 'smith'}]}

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
def fixture_event(mocker, boto3_client, principals):
    """ Lambda event with associated setup and checks """
    event = {
        'eventType': 'JOB_EXECUTION',
        'jobId': JOB_ID,
        'thingArn': f'arn:aws:iot:us-east-1:000011112222:thing/{THING_NAME}',
        'status': 'SUCCEEDED',
        'statusDetails': {
            'newCertificateId': NEW_CERT_ID,
            'progress': 'committed',
            'oldCertificateId': OLD_CERT_ID
        }
    }

    boto3_client.get_job_document.return_value = {'document': JOB_DOCUMENT}
    mocker.patch('job_execution_terminal.os.environ.get', side_effect=mock_os_environ_get)

    # This setup section only does anything useful when status is SUCCEEDED
    boto3_client.list_thing_principals.return_value = principals
    cert_desc = {'certificateDescription': {'status': 'ACTIVE', 'certificateArn': OLD_CERT_ARN}}
    boto3_client.describe_certificate.return_value = cert_desc
    boto3_client.list_principal_policies.return_value = POLICIES

    yield event

    boto3_client.get_job_document.assert_called_once_with(jobId=JOB_ID)

def mock_os_environ_get(name):
    """ Mock environment for the case of AWS IoT CA """
    environment = {
        'JOB_DOCUMENT': JOB_DOCUMENT,
        'SNS_ARN': SNS_ARN
    }

    return environment.get(name, None)

def confirm_certificate_deleted(boto3_client, cert_id, cert_arn, cert_status):
    """ Checks that all certificate deletion actions occur """
    boto3_client.list_thing_principals.assert_called_once_with(thingName=THING_NAME)
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
    del principals['principals'][0]
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_not_called()

def test_job_succeeded_thing_principals_too_many(boto3_client, event, principals):
    """ Handle succeeded job but the thing has more principals than expected """
    principals['principals'].append('arn:aws:iot:us-east-1:000011112222:cert/bonus')
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_not_called()

def test_job_succeeded_thing_principal_not_cert(boto3_client, event, principals):
    """ Handle succeeded job but the thing has principals other than a certificate """
    principals['principals'][0]='wrong type of principal'
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_not_called()

def test_job_succeeded_no_status_details(boto3_client, event):
    """ Handle succeeded job but the event is missing the status details """
    del event['statusDetails']
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_succeeded_no_certificate_key(boto3_client, event):
    """ Handle succeeded job but the event is missing the certificate key in the status details """
    del event['statusDetails']['oldCertificateId']
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_not_called()

def test_no_job_document(boto3_client, event):
    """ We should not do anything if there's no job or job document """
    boto3_client.get_job_document.side_effect = Exception('mocked error')
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_not_called()

def test_wrong_job_document(boto3_client, event):
    """ We should not do anything if the job document is wrong """
    boto3_client.get_job_document.return_value = {'document': 'whatever'}
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_not_called()

def test_job_failed_after_create(boto3_client, event):
    """ This is a standard rollback. The new certificate should be deleted """
    event['status'] = 'FAILED'
    event['statusDetails']['progress'] = 'created'
    cert_desc = {'certificateDescription': {'status': 'ACTIVE', 'certificateArn': NEW_CERT_ARN}}
    boto3_client.describe_certificate.return_value = cert_desc
    handler(event, None)
    confirm_certificate_deleted(boto3_client, NEW_CERT_ID, NEW_CERT_ARN, 'ACTIVE')
    boto3_client.publish.assert_called_once()

def test_job_failed_after_commit(boto3_client, event):
    """ We should not delete any certificate, but should send a notification """
    event['status'] = 'FAILED'
    event['statusDetails']['progress'] = 'committed'
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_timed_out_before_create(boto3_client, event):
    """ We should not delete any certificate, but should send a notification """
    event['status'] = 'TIMED_OUT'
    del event['statusDetails']['progress']
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_timed_out_after_create(boto3_client, event):
    """ This is a rollback. The new certificate should be deleted """
    event['status'] = 'TIMED_OUT'
    event['statusDetails']['progress'] = 'created'
    cert_desc = {'certificateDescription': {'status': 'ACTIVE', 'certificateArn': NEW_CERT_ARN}}
    boto3_client.describe_certificate.return_value = cert_desc
    handler(event, None)
    confirm_certificate_deleted(boto3_client, NEW_CERT_ID, NEW_CERT_ARN, 'ACTIVE')
    boto3_client.publish.assert_called_once()

def test_job_timed_out_after_commit(boto3_client, event):
    """ We should not delete any certificate, but should send a notification """
    event['status'] = 'TIMED_OUT'
    event['statusDetails']['progress'] = 'committed'
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_called_once()

def test_job_invalid_status(boto3_client, event):
    """ We should not do anything """
    event['status'] = 'JUNK'
    handler(event, None)
    confirm_certificate_not_deleted(boto3_client)
    boto3_client.publish.assert_not_called()
