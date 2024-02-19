# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for backend.lambda.create_certificate.py
"""

import json
from unittest.mock import call, ANY
import pytest
from create_certificate import handler

JOB_ID = 'redpill'
NEW_CERT_ID = 'choice is an illusion'
OLD_CERT_ID = 'how deep the rabbit hole goes'
THING_NAME = 'Nebuchadnezzar'
JOB_DOCUMENT = '{"operation":"ROTATE_CERTIFICATE"}'
TOPIC = f'awslabs/things/{THING_NAME}/certificate/commit'
NEW_CERT_PEM = '-----BEGIN CERTIFICATE-----\nNot a real certificate\n-----END CERTIFICATE-----\n'
NEW_CERT_ARN = f'arn:aws:iot:us-east-1:000011112222:cert/{NEW_CERT_ID}'
POLICIES = {'policies': [{'policyName': 'morpheus'}, {'policyName': 'smith'}]}
PCA_CA_ARN = 'arn:aws:acm-pca:us-east-1:000011112222:certificate-authority/cipher'
PCA_SIGNING_ALGORITHM = 'SHA256WITHRSA'
PCA_VALIDITY_IN_DAYS = 7

@pytest.fixture(name='job_execution')
def fixture_job_execution():
    """ Fake job execution state """
    return {
        'execution' : {
            'jobId': JOB_ID,
            'status': 'IN_PROGRESS',
            'statusDetails': {
                'certificateRotationProgress': 'started'
            },
            'jobDocument': JOB_DOCUMENT
        }
    }

@pytest.fixture(name='principals')
def fixture_principals():
    """ Fake thing principals """
    return {
        'principals': [
            f'arn:aws:iot:us-east-1:000011112222:cert/{OLD_CERT_ID}'
        ]
    }

@pytest.fixture(name='event')
def fixture_event(mocker, boto3_client, job_execution, principals):
    """ Lambda event with associated setup and checks """
    event = {
        'jobId': JOB_ID,
        'csr': '-----BEGIN CERTIFICATE REQUEST-----\nNot a real CSR\n-----END CERTIFICATE REQUEST-----\n',
        'thingName': THING_NAME,
        'topic': TOPIC,
        'clientId': THING_NAME,
        'principal': OLD_CERT_ID
    }

    boto3_client.describe_job_execution.return_value = job_execution
    boto3_client.list_thing_principals.return_value = principals
    mocker.patch('create_certificate.os.environ.get', side_effect=mock_os_environ_get)

    yield event

    calls = [call(endpointType='iot:Jobs'), call(endpointType='iot:Data-ATS')]
    boto3_client.describe_endpoint.assert_has_calls(calls, any_order=True)
    boto3_client.list_thing_principals.assert_called_once_with(thingName=THING_NAME)
    boto3_client.describe_job_execution.assert_called_once_with(jobId=JOB_ID, thingName=THING_NAME,
                                                                includeJobDocument=True)

def mock_os_environ_get(name):
    """ Mock environment for the case of AWS IoT CA """
    environment = {
        'JOB_DOCUMENT': JOB_DOCUMENT
    }

    return environment.get(name, None)

def mock_os_environ_get_pca(name):
    """ Mock environment for the case of PCA enabled """
    environment = {
        'JOB_DOCUMENT': JOB_DOCUMENT,
        'PCA_CA_ARN': PCA_CA_ARN,
        'PCA_SIGNING_ALGORITHM': PCA_SIGNING_ALGORITHM,
        'PCA_VALIDITY_IN_DAYS': f'{PCA_VALIDITY_IN_DAYS}'
    }

    return environment.get(name, None)

def confirm_succeeded(boto3_client, event, principals):
    """ Checks that the create succeeded """
    boto3_client.list_principal_policies.assert_called_once_with(principal=principals['principals'][0])
    calls = [call(policyName=POLICIES['policies'][0]['policyName'], target=NEW_CERT_ARN),
             call(policyName=POLICIES['policies'][1]['policyName'], target=NEW_CERT_ARN)]
    boto3_client.attach_policy.assert_has_calls(calls)
    boto3_client.attach_thing_principal.assert_called_once_with(thingName=event['thingName'],
                                                                principal=NEW_CERT_ARN)
    boto3_client.update_job_execution.assert_called_once_with(jobId=JOB_ID, thingName=THING_NAME,
                                                              status='IN_PROGRESS',
                                                              statusDetails={
                                                                    'newCertificateId': NEW_CERT_ID,
                                                                    'oldCertificateId': OLD_CERT_ID,
                                                                    'certificateRotationProgress': 'created'
                                                                })
    boto3_client.publish.assert_called_once_with(topic=f'{TOPIC}/accepted', qos=0,
                                                 payload=json.dumps({ 'certificatePem': NEW_CERT_PEM }))

def confirm_failed(boto3_client):
    """ Checks that the commit failed """
    boto3_client.publish.assert_called_once_with(topic=f'{TOPIC}/rejected', qos=0, payload=ANY)

def test_create_succeeded_iot(boto3_client, event, principals):
    """ Create, with AWS IoT CA, succeeds if all necessary conditions are in place """
    NEW_CERT = {
        'certificateArn': NEW_CERT_ARN,
        'certificateId': NEW_CERT_ID,
        'certificatePem': NEW_CERT_PEM
    }
    boto3_client.create_certificate_from_csr.return_value = NEW_CERT
    boto3_client.list_principal_policies.return_value = POLICIES

    handler(event, None)

    boto3_client.create_certificate_from_csr.assert_called_once_with(certificateSigningRequest=event['csr'],
                                                                     setAsActive=True)
    confirm_succeeded(boto3_client, event, principals)

def test_create_succeeded_pca(mocker, boto3_client, event, principals):
    """ Create, with AWS PCA, succeeds if all necessary conditions are in place """
    PCA_CERT_ARN = f'{PCA_CA_ARN}/certificate/switch'
    boto3_client.issue_certificate.return_value = {'CertificateArn': PCA_CERT_ARN}
    boto3_client.get_certificate.return_value = {'Certificate': NEW_CERT_PEM}
    boto3_client.register_certificate_without_ca.return_value = {
        'certificateArn': NEW_CERT_ARN,
        'certificateId': NEW_CERT_ID
    }
    boto3_client.list_principal_policies.return_value = POLICIES
    mocker.patch('create_certificate.os.environ.get', side_effect=mock_os_environ_get_pca)

    handler(event, None)

    boto3_client.issue_certificate.assert_called_once_with(CertificateAuthorityArn=PCA_CA_ARN,
                                                           Csr=event['csr'].encode('utf-8'),
                                                           SigningAlgorithm=PCA_SIGNING_ALGORITHM,
                                                           Validity={
                                                                'Value': PCA_VALIDITY_IN_DAYS,
                                                                'Type': 'DAYS'
                                                            })
    boto3_client.get_waiter.assert_called_once()
    boto3_client.get_waiter.return_value.wait.assert_called_once_with(CertificateAuthorityArn=PCA_CA_ARN,
                                                                      CertificateArn=PCA_CERT_ARN,
                                                                      WaiterConfig=ANY)
    boto3_client.get_certificate.assert_called_once_with(CertificateAuthorityArn=PCA_CA_ARN,
                                                         CertificateArn=PCA_CERT_ARN)
    boto3_client.register_certificate_without_ca(certificatePem=NEW_CERT_PEM, status='ACTIVE')
    confirm_succeeded(boto3_client, event, principals)

def test_create_failed_error_on_iot(boto3_client, event):
    """ Create fails if create_certificate_from_csr throws an exception """
    boto3_client.create_certificate_from_csr.side_effect = Exception('mocked error')
    handler(event, None)
    confirm_failed(boto3_client)

def test_create_failed_error_on_pca(mocker, boto3_client, event):
    """ Create fails if issue_certificate throws an exception """
    boto3_client.issue_certificate.side_effect = Exception('mocked error')
    mocker.patch('create_certificate.os.environ.get', side_effect=mock_os_environ_get_pca)
    handler(event, None)
    confirm_failed(boto3_client)

def test_create_failed_no_job_execution_for_thing(boto3_client, event):
    """ Create fails if describe_job_execution throws an exception """
    boto3_client.describe_job_execution.side_effect = Exception('mocked error')
    handler(event, None)
    confirm_failed(boto3_client)

def test_create_failed_job_execution_wrong_status(boto3_client, event, job_execution):
    """ Create fails if the job execution is in the wrong state """
    job_execution['execution']['status'] = 'QUEUED'
    handler(event, None)
    confirm_failed(boto3_client)

def test_create_failed_job_execution_wrong_document(boto3_client, event, job_execution):
    """ Create fails if the job execution has the wrong job document """
    job_execution['execution']['jobDocument'] = 'something else'
    handler(event, None)
    confirm_failed(boto3_client)

def test_create_failed_job_execution_has_status_details(boto3_client, event, job_execution):
    """ Commit fails if the job execution has status details already """
    job_execution['execution']['statusDetails'] = 'anything'
    handler(event, None)
    confirm_failed(boto3_client)

def test_create_failed_thing_principals_too_few(boto3_client, event, principals):
    """ Create fails if the thing has fewer principals than expected """
    del principals['principals'][0]
    handler(event, None)
    confirm_failed(boto3_client)

def test_create_failed_thing_principals_too_many(boto3_client, event, principals):
    """ Create fails if the thing has more principals than expected """
    principals['principals'].append('arn:aws:iot:us-east-1:000011112222:cert/bonus')
    handler(event, None)
    confirm_failed(boto3_client)

def test_create_failed_thing_principal_not_cert(boto3_client, event, principals):
    """ Create fails if the thing has principals other than a certificate """
    principals['principals'][0]='wrong type of principal'
    handler(event, None)
    confirm_failed(boto3_client)

def test_create_failed_auth_wrong_principal(boto3_client, event):
    """ Create fails if the thing authenticated with a principal other than the old certificate """
    event['principal'] = f'arn:aws:iot:us-east-1:000011112222:cert/{NEW_CERT_ID}'
    handler(event, None)
    confirm_failed(boto3_client)

def test_create_failed_auth_wrong_client(boto3_client, event):
    """ Create fails if the device authenticated with a client name other than the Thing name """
    event['clientId'] = 'Metacortex'
    handler(event, None)
    confirm_failed(boto3_client)
