# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.state_creating_certificate.py
"""

import json
import pytest
from state_creating_certificate import StateCreatingCertificate
from topic_base import TOPIC_BASE_CERT

@pytest.fixture(name='state_creating_certificate')
def fixture_state_getting_job(state_machine):
    """ Instantiation of a single state """
    return StateCreatingCertificate(state_machine)

def test_rotate_if_create_accepted(state_machine, state_creating_certificate):
    """ Confirm that we rotate the certificate if the cloud backend accepts the create """
    message = { 'certificatePem': 'foobar' }
    state_machine.pki.rotate.return_value = True
    state_creating_certificate.on_rx_message(f'{TOPIC_BASE_CERT}/create/accepted', message)
    state_machine.pki.rotate.assert_called_once_with(message['certificatePem'])
    state_machine.stop.assert_called_once()

def test_restarts_occurs_even_if_rotate_fails(state_machine, state_creating_certificate):
    """ Confirm that we fail the job and restart if the rotate fails """
    message = { 'certificatePem': 'foobar' }
    state_machine.pki.rotate.return_value = False
    state_creating_certificate.on_rx_message(f'{TOPIC_BASE_CERT}/create/accepted', message)
    state_machine.pki.rotate.assert_called_once_with(message['certificatePem'])
    state_machine.fail_the_job.assert_called_once_with()
    state_machine.stop.assert_called_once()

def test_rollback_if_commit_rejected(state_machine, state_creating_certificate):
    """ Confirm that we fail the job if the cloud backend rejects the create """
    state_creating_certificate.on_rx_message(f'{TOPIC_BASE_CERT}/create/rejected', json.dumps({}))
    state_machine.fail_the_job.assert_called_once()

def test_timeout_triggers_failure(state_machine, state_creating_certificate):
    """ Confirm that we return to Idle if the update times out """
    state_creating_certificate.on_timeout()
    state_machine.fail_the_job.assert_called_once()

def test_non_job_topic_is_ignored(state_machine, state_creating_certificate):
    """ Confirm that non-jobs topics are ignored """
    state_creating_certificate.on_rx_message('foobar', json.dumps({}))
    state_machine.pki.rotate.assert_not_called()
    state_machine.stop.assert_not_called()
    state_machine.fail_the_job.assert_not_called()
