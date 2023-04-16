# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Shared fixtures for backend lambda tests
"""

import pytest

@pytest.fixture(name='boto3_client')
def fixture_boto3_client(mocker):
    """ Mocked boto3 client object """
    mock_boto3_client = mocker.patch('boto3.client')
    # Make our mock get returned by the client() method call
    mock_boto3_client.return_value = mock_boto3_client
    return mock_boto3_client
