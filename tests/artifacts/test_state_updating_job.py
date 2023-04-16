# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.state_updating_job.py
"""

import json
import pytest
from state_updating_job import StateUpdatingJob
from state_creating_certificate import StateCreatingCertificate
from topic_base import TOPIC_BASE_JOBS, TOPIC_BASE_CERT

@pytest.fixture(name='state_updating_job')
def fixture_state_getting_job(state_machine):
    """ Instantiation of a single state """
    return StateUpdatingJob(state_machine)

def test_transition_to_state_creating_certificate(state_machine, state_updating_job):
    """ Confirm that transition to StateCreatingCertificate occurs """
    job_id = 'john'
    csr = 'paul'
    state_machine.pki.create_csr.return_value = csr

    state_updating_job.on_rx_message(f'{TOPIC_BASE_JOBS}/{job_id}/update/accepted', json.dumps({}))

    state_machine.pki.create_csr.assert_called_once()
    state_machine.publish.assert_called_once_with(f'{TOPIC_BASE_CERT}/create',
                                                    json.dumps({ 'jobId': job_id, 'csr': csr }))
    state_machine.change_state.assert_called_once_with(StateCreatingCertificate)

def test_csr_creation_fails(state_machine, state_updating_job):
    """ Confirm that job fails if CSR creation fails """
    state_machine.pki.create_csr.return_value = None
    state_updating_job.on_rx_message(f'{TOPIC_BASE_JOBS}/foobar/update/accepted', json.dumps({}))
    state_machine.pki.create_csr.assert_called_once()
    state_machine.fail_the_job.assert_called_once()

def test_rejection_transitions_to_idle(state_machine, state_updating_job):
    """ Confirm that we return to Idle if the update is rejected """
    state_updating_job.on_rx_message(f'{TOPIC_BASE_JOBS}/foobar/update/rejected', json.dumps({}))
    state_machine.change_state_idle.assert_called_once()

def test_timeout_transitions_to_idle(state_machine, state_updating_job):
    """ Confirm that we return to Idle if the update times out """
    state_updating_job.on_timeout()
    state_machine.change_state_idle.assert_called_once()

def test_non_job_topic_is_ignored(state_machine, state_updating_job):
    """ Confirm that non-jobs topics are ignored """
    state_updating_job.on_rx_message('foobar', json.dumps({}))
    state_machine.publish.assert_not_called()
    state_machine.change_state.assert_not_called()

def test_non_job_topic_response_is_ignored(state_machine, state_updating_job):
    """ Confirm that non-jobs topics are ignored """
    state_updating_job.on_rx_message(f'{TOPIC_BASE_JOBS}/foobar/update/unexpected', json.dumps({}))
    state_machine.publish.assert_not_called()
    state_machine.change_state.assert_not_called()
