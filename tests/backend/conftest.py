# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Shared fixtures for backend lambda tests
"""

import pytest
import create_certificate
import commit_certificate
import job_execution_terminal

@pytest.fixture(name='boto3_client')
def fixture_boto3_client(mocker):
    """ Mocked boto3 client object """
    mock_boto3_client = mocker.patch('boto3.client')
    # Make our mock get returned by the client() method call
    mock_boto3_client.return_value = mock_boto3_client

    # Reset global clients in Lambda modules to ensure clean state
    create_certificate.iot = None
    create_certificate.iot_jobs_data = None
    create_certificate.iot_data = None
    commit_certificate.iot = None
    commit_certificate.iot_jobs_data = None
    commit_certificate.iot_data = None
    job_execution_terminal.iot = None
    job_execution_terminal.iot_data = None
    job_execution_terminal.sns = None

    return mock_boto3_client
