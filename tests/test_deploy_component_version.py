# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for deploy_component_version.py
"""

from unittest.mock import call
import runpy
import sys
import pytest

COMPONENT_NAME = 'Maynard'
COMPONENT_VERSION = 'Aenima'
THING_GROUP_NAME = 'Tool'
DEPLOYMENT_ID = 'jambi'
DEPLOYMENT_NAME = f'Deployment for {THING_GROUP_NAME}'
TARGET_ARN = f'arn:aws:iot:us-east-1:000011112222:thinggroup/{THING_GROUP_NAME}'
NEW_DEPLOYMENT_ID = 'the pot'
JOB_ID = 'lateralus'
COMPONENTS = {COMPONENT_NAME: {}}

@pytest.fixture(name='boto3_client')
def fixture_boto3_client(mocker, job_description):
    """ Mocked boto3 client object """
    boto3_client = mocker.patch('boto3.client')
    # Make our mock get returned by the client() method call
    boto3_client.return_value = boto3_client

    # Mock the GDK configuration
    gdk_config_class = mocker.patch('libs.gdk_config.GdkConfig')
    gdk_config = gdk_config_class.return_value
    gdk_config.name.return_value = COMPONENT_NAME

    boto3_client.get_caller_identity.return_value.get.return_value = '000011112222'
    boto3_client.list_deployments.return_value = {'deployments': [{'deploymentId': DEPLOYMENT_ID}]}
    boto3_client.get_deployment.return_value = {'deploymentName': DEPLOYMENT_NAME, 'components': COMPONENTS,
                                                'targetArn': TARGET_ARN, 'deploymentStatus': 'whatever',
                                                'iotJobId': JOB_ID}
    boto3_client.create_deployment.return_value = {'deploymentId': NEW_DEPLOYMENT_ID}
    boto3_client.describe_job.return_value = job_description

    yield boto3_client

    gdk_config_class.assert_called_once()
    boto3_client.list_deployments.assert_called_once()

@pytest.fixture(name='job_description')
def fixture_job():
    """ Mocked job description object """
    return {
        'job': {
            'jobProcessDetails' : {
                'numberOfQueuedThings': 0,
                'numberOfInProgressThings': 0,
                'numberOfFailedThings': 0,
                'numberOfRejectedThings': 0,
                'numberOfTimedOutThings': 0,
                'numberOfSucceededThings': 0
            }
        }
    }

def confirm_exit():
    """ Confirm program hits sys.exit(1) """
    sys.argv[1:] = [COMPONENT_VERSION, THING_GROUP_NAME]
    with pytest.raises(SystemExit) as system_exit:
        runpy.run_module('deploy_component_version')
    assert system_exit.type == SystemExit
    assert system_exit.value.code == 1

def confirm_success(boto3_client):
    """ Confirm program exit with no error """
    sys.argv[1:] = [COMPONENT_VERSION, THING_GROUP_NAME]
    runpy.run_module('deploy_component_version')
    calls=[call(deploymentId=DEPLOYMENT_ID), call(deploymentId=NEW_DEPLOYMENT_ID)]
    boto3_client.get_deployment.assert_has_calls(calls)
    boto3_client.create_deployment.assert_called_once_with(targetArn=TARGET_ARN, deploymentName=DEPLOYMENT_NAME,
                                                           components=COMPONENTS)
    boto3_client.describe_job.assert_called_once_with(jobId=JOB_ID)

def test_fails_if_list_deployments_exception(boto3_client):
    """ Should exit abruptly if list_deployments throws an exception """
    boto3_client.list_deployments.side_effect = Exception('mocked error')
    confirm_exit()

def test_fails_if_no_existing_deployments(boto3_client):
    """ Should exit abruptly if there are zero deployments """
    boto3_client.list_deployments.return_value = {'deployments': []}
    confirm_exit()

def test_fails_if_get_deployment_exception(boto3_client):
    """ Should exit abruptly if get_deployment throws an exception """
    boto3_client.get_deployment.side_effect = Exception('mocked error')
    confirm_exit()
    boto3_client.get_deployment.assert_called_once_with(deploymentId=DEPLOYMENT_ID)

def test_fails_if_create_deployment_exception(boto3_client):
    """ Should exit abruptly if create_deployment throws an exception """
    boto3_client.create_deployment.side_effect = Exception('mocked error')
    confirm_exit()
    boto3_client.get_deployment.assert_called_once_with(deploymentId=DEPLOYMENT_ID)
    boto3_client.create_deployment.assert_called_once_with(targetArn=TARGET_ARN, deploymentName=DEPLOYMENT_NAME,
                                                           components=COMPONENTS)

def test_fails_if_second_get_deployment_exception(boto3_client):
    """ Should exit abruptly if the second get_deployment throws an exception """
    boto3_client.get_deployment.side_effect = [boto3_client.get_deployment.return_value, Exception('mocked error')]
    confirm_exit()
    calls=[call(deploymentId=DEPLOYMENT_ID), call(deploymentId=NEW_DEPLOYMENT_ID)]
    boto3_client.get_deployment.assert_has_calls(calls)
    boto3_client.create_deployment.assert_called_once_with(targetArn=TARGET_ARN, deploymentName=DEPLOYMENT_NAME,
                                                           components=COMPONENTS)

def test_fails_if_describe_job_exception(boto3_client):
    """ Should exit abruptly if describe_job throws an exception """
    boto3_client.describe_job.side_effect = [Exception('mocked error')]
    confirm_exit()
    calls=[call(deploymentId=DEPLOYMENT_ID), call(deploymentId=NEW_DEPLOYMENT_ID)]
    boto3_client.get_deployment.assert_has_calls(calls)
    boto3_client.create_deployment.assert_called_once_with(targetArn=TARGET_ARN, deploymentName=DEPLOYMENT_NAME,
                                                           components=COMPONENTS)
    boto3_client.describe_job.assert_called_once_with(jobId=JOB_ID)

def test_fails_if_job_execution_failed(boto3_client, job_description):
    """ Should exit abruptly if any job execution fails """
    job_description['job']['jobProcessDetails']['numberOfSucceededThings'] = 10
    job_description['job']['jobProcessDetails']['numberOfFailedThings'] = 1
    confirm_exit()
    calls=[call(deploymentId=DEPLOYMENT_ID), call(deploymentId=NEW_DEPLOYMENT_ID)]
    boto3_client.get_deployment.assert_has_calls(calls)
    boto3_client.create_deployment.assert_called_once_with(targetArn=TARGET_ARN, deploymentName=DEPLOYMENT_NAME,
                                                           components=COMPONENTS)
    boto3_client.describe_job.assert_called_once_with(jobId=JOB_ID)

def test_fails_if_job_execution_timed_out(boto3_client, job_description):
    """ Should exit abruptly if any job execution times out """
    job_description['job']['jobProcessDetails']['numberOfSucceededThings'] = 10
    job_description['job']['jobProcessDetails']['numberOfTimedOutThings'] = 1
    confirm_exit()
    calls=[call(deploymentId=DEPLOYMENT_ID), call(deploymentId=NEW_DEPLOYMENT_ID)]
    boto3_client.get_deployment.assert_has_calls(calls)
    boto3_client.create_deployment.assert_called_once_with(targetArn=TARGET_ARN, deploymentName=DEPLOYMENT_NAME,
                                                           components=COMPONENTS)
    boto3_client.describe_job.assert_called_once_with(jobId=JOB_ID)

def test_fails_if_deployment_times_out(mocker, boto3_client, job_description):
    """ Should exit abruptly if the deployment times out """
    job_description['job']['jobProcessDetails']['numberOfInProgressThings'] = 10
    mocker.patch('time.time', side_effect=[0, 0, 900])
    job_description['job']['jobProcessDetails']['numberOfTimedOutThings'] = 1
    confirm_exit()
    calls=[call(deploymentId=DEPLOYMENT_ID), call(deploymentId=NEW_DEPLOYMENT_ID)]
    boto3_client.get_deployment.assert_has_calls(calls)
    boto3_client.create_deployment.assert_called_once_with(targetArn=TARGET_ARN, deploymentName=DEPLOYMENT_NAME,
                                                           components=COMPONENTS)
    boto3_client.describe_job.assert_called_once_with(jobId=JOB_ID)

def test_succeeds_named_add(boto3_client, job_description):
    """ Successful deployment to a named deployment, first time adding the component """
    job_description['job']['jobProcessDetails']['numberOfSucceededThings'] = 10
    boto3_client.get_deployment.return_value['components'] = {}
    confirm_success(boto3_client)

def test_succeeds_named_exists(boto3_client, job_description):
    """ Successful deployment to a named deployment, component already in the deployment """
    job_description['job']['jobProcessDetails']['numberOfSucceededThings'] = 10
    confirm_success(boto3_client)

def test_succeeds_unnamed_add(boto3_client, job_description):
    """ Successful deployment to an unnamed deployment, first time adding the component """
    del boto3_client.get_deployment.return_value['deploymentName']
    job_description['job']['jobProcessDetails']['numberOfSucceededThings'] = 10
    boto3_client.get_deployment.return_value['components'] = {}
    confirm_success(boto3_client)

def test_succeeds_unnamed_exists(boto3_client, job_description):
    """ Successful deployment to an unnamed deployment, component already in the deployment """
    del boto3_client.get_deployment.return_value['deploymentName']
    job_description['job']['jobProcessDetails']['numberOfSucceededThings'] = 10
    confirm_success(boto3_client)
