# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.config.py
"""

import copy
from unittest.mock import call
import pytest
from config import Config
from pki_file import KEY_ALGORITHMS, SIGNING_ALGORITHMS
from awsiot.greengrasscoreipc.model import (
    GetConfigurationResponse,
    ConfigurationValidityReport,
    ConfigurationValidityStatus
)

DEPLOYMENT_ID = 'foobar'

@pytest.fixture(name='default_config')
def fixture_default_config():
    """ Default configuration """
    return { 'keyAlgorithm': 'RSA-2048', 'signingAlgorithm': 'SHA256WITHRSA' }

@pytest.fixture(name='ipc_client')
def fixture_ipc_client(mocker, default_config):
    """ Create a mocked IPC client object with default component configuration """
    ipc_client = mocker.Mock()
    configuration_response = GetConfigurationResponse(component_name='foobar', value=default_config)
    ipc_client.get_configuration.return_value = configuration_response
    return ipc_client

@pytest.fixture(name='config')
def fixture_config(ipc_client):
    """ Create a Config object with mocked IPC client """
    return Config(ipc_client, KEY_ALGORITHMS, SIGNING_ALGORITHMS)

@pytest.fixture(name='event')
def fixture_event(mocker, default_config):
    """ Create an event object with default component configuration """
    event = mocker.patch('awsiot.greengrasscoreipc.model.ValidateConfigurationUpdateEvents')
    event.validate_configuration_update_event.deployment_id = DEPLOYMENT_ID
    event.validate_configuration_update_event.configuration = copy.deepcopy(default_config)
    return event

def test_configuration_accepted_if_valid(ipc_client, config, event):
    """ Configuration is accepted if valid """
    calls = []
    # Check all valid combinations
    for key_algorithm, key_value in KEY_ALGORITHMS.items():
        for signing_algorithm, signing_value in SIGNING_ALGORITHMS.items():
            if key_value['type'] == signing_value['type']:
                event.validate_configuration_update_event.configuration['keyAlgorithm'] = key_algorithm
                event.validate_configuration_update_event.configuration['signingAlgorithm'] = signing_algorithm
                config.on_stream_event(event)
                report = ConfigurationValidityReport(status=ConfigurationValidityStatus.ACCEPTED,
                                                        deployment_id=DEPLOYMENT_ID,
                                                        message='Valid key and signing algorithm configuration')
                calls.append(call(configuration_validity_report=report))
                assert config.key_algorithm == key_algorithm
                assert config.signing_algorithm == signing_algorithm

    ipc_client.send_configuration_validity_report.assert_has_calls(calls, any_order=True)

def test_configuration_rejected_if_invalid_key_algorithm(ipc_client, config, event, default_config):
    """ Configuration is rejected if the key algorithm is invalid """
    event.validate_configuration_update_event.configuration['keyAlgorithm'] = 'nonsense'
    config.on_stream_event(event)
    report = ConfigurationValidityReport(status=ConfigurationValidityStatus.REJECTED,
                                            deployment_id=DEPLOYMENT_ID,
                                            message='Invalid key algorithm')
    ipc_client.send_configuration_validity_report.assert_called_once_with(configuration_validity_report=report)
    assert config.key_algorithm == default_config['keyAlgorithm']
    assert config.signing_algorithm == default_config['signingAlgorithm']

def test_configuration_rejected_if_invalid_signing_algorithm(ipc_client, config, event, default_config):
    """ Configuration is rejected if the signing algorithm is invalid """
    event.validate_configuration_update_event.configuration['signingAlgorithm'] = 'nonsense'
    config.on_stream_event(event)
    report = ConfigurationValidityReport(status=ConfigurationValidityStatus.REJECTED,
                                            deployment_id=DEPLOYMENT_ID,
                                            message='Invalid signing algorithm')
    ipc_client.send_configuration_validity_report.assert_called_once_with(configuration_validity_report=report)
    assert config.key_algorithm == default_config['keyAlgorithm']
    assert config.signing_algorithm == default_config['signingAlgorithm']

def test_configuration_rejected_if_key_and_signing_type_mismatched(ipc_client, config, event, default_config):
    """ Configuration is rejected if key and signing algorithms have mismatched types """
    calls = []
    # Check all mismatched combinations
    for key_algorithm, key_value in KEY_ALGORITHMS.items():
        for signing_algorithm, signing_value in SIGNING_ALGORITHMS.items():
            if key_value['type'] != signing_value['type']:
                event.validate_configuration_update_event.configuration['keyAlgorithm'] = key_algorithm
                event.validate_configuration_update_event.configuration['signingAlgorithm'] = signing_algorithm
                config.on_stream_event(event)
                report = ConfigurationValidityReport(status=ConfigurationValidityStatus.REJECTED,
                                                deployment_id=DEPLOYMENT_ID,
                                                message='Key algorithm and signing algorithm have mismatched types')
                calls.append(call(configuration_validity_report=report))

    ipc_client.send_configuration_validity_report.assert_has_calls(calls, any_order=True)
    assert config.key_algorithm == default_config['keyAlgorithm']
    assert config.signing_algorithm == default_config['signingAlgorithm']

def test_exception_is_caught(ipc_client, config, event):
    """ Confirm that exceptions are caught """
    ipc_client.send_configuration_validity_report.side_effect = Exception('mocked error')
    config.on_stream_event(event)
    report = ConfigurationValidityReport(status=ConfigurationValidityStatus.ACCEPTED,
                                            deployment_id=DEPLOYMENT_ID,
                                            message='Valid key and signing algorithm configuration')
    ipc_client.send_configuration_validity_report.assert_called_once_with(configuration_validity_report=report)

def test_on_stream_error():
    """ Always returns false so the stream is not closed """
    assert Config.on_stream_error(Exception()) is False

def test_on_stream_closed():
    """ Calls it - nothing to check """
    Config.on_stream_closed()
