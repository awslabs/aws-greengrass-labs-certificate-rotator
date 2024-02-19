# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.state_getting_job.py
"""

import json
import pytest
from state_getting_job import StateGettingJob
from state_updating_job import StateUpdatingJob
from state_committing_certificate import StateCommittingCertificate
from topic_base import TOPIC_BASE_JOBS, TOPIC_BASE_CERT

@pytest.fixture(name='state_getting_job')
def fixture_state_getting_job(state_machine):
    """ Instantiation of a single state """
    return StateGettingJob(state_machine)

def create_message(status):
    """ Creates a canned job message """
    message = {}
    message['execution'] = {}
    message['execution']['status'] = status
    message['execution']['jobDocument'] = {}
    message['execution']['jobDocument']['operation'] = 'ROTATE_CERTIFICATE'
    message['execution']['jobId'] = 'foobar'
    return message

def test_transition_to_state_updating_job(state_machine, state_getting_job):
    """ Confirm that transition to StateUpdatingJob occurs """
    message = create_message('QUEUED')
    state_getting_job.on_rx_message(f'{TOPIC_BASE_JOBS}/{message["execution"]["jobId"]}/get/accepted', message)
    expected_publish_msg = { 'status': 'IN_PROGRESS', 'statusDetails': { 'certificateRotationProgress': 'started' } }
    state_machine.publish.assert_called_once_with(f'{TOPIC_BASE_JOBS}/{message["execution"]["jobId"]}/update',
                                                    json.dumps(expected_publish_msg))
    state_machine.change_state.assert_called_once_with(StateUpdatingJob)

def test_transition_to_state_creating_certificate(state_machine, state_getting_job):
    """ Confirm that transition to StateCommittingCertificate occurs """
    message = create_message('IN_PROGRESS')
    job_id = message["execution"]["jobId"]
    state_machine.pki.backup_exists.return_value = True
    state_getting_job.on_rx_message(f'{TOPIC_BASE_JOBS}/{job_id}/get/accepted', message)
    state_machine.pki.backup_exists.assert_called_once()
    state_machine.publish.assert_called_once_with(f'{TOPIC_BASE_CERT}/commit', json.dumps({ 'jobId': job_id }))
    state_machine.change_state.assert_called_once_with(StateCommittingCertificate)

def test_unexpected_job_states_ignored(state_machine, state_getting_job):
    """ Confirm that we only process the desired job execution states """
    message = create_message('THER')
    state_getting_job.on_rx_message(f'{TOPIC_BASE_JOBS}/{message["execution"]["jobId"]}/get/accepted', message)
    state_machine.publish.assert_not_called()
    state_machine.change_state.assert_not_called()

def test_fail_job_if_no_backup(state_machine, state_getting_job):
    """ Confirm that the job is failed if there's no backup for an in-progress job """
    message = create_message('IN_PROGRESS')
    state_machine.pki.backup_exists.return_value = False
    state_getting_job.on_rx_message(f'{TOPIC_BASE_JOBS}/{message["execution"]["jobId"]}/get/accepted', message)
    state_machine.pki.backup_exists.assert_called_once()
    state_machine.fail_the_job.assert_called_once()

def test_rejection_transitions_to_idle(state_machine, state_getting_job):
    """ Confirm that we return to Idle if the get is rejected """
    state_getting_job.on_rx_message(f'{TOPIC_BASE_JOBS}/foobar/get/rejected', json.dumps({}))
    state_machine.change_state_idle.assert_called_once()

def test_non_job_topic_is_ignored(state_machine, state_getting_job):
    """ Confirm that non-jobs topics are ignored """
    state_getting_job.on_rx_message('foobar', json.dumps({}))
    state_machine.publish.assert_not_called()
    state_machine.change_state.assert_not_called()

def test_timeout_triggers_rollback(state_machine, state_getting_job):
    """ Confirm that we rollback if the get times out (and there's a backup) """
    state_machine.pki.backup_exists.return_value = True
    state_getting_job.on_timeout()
    state_machine.pki.backup_exists.assert_called_once()
    state_machine.pki.rollback.assert_called_once()
    state_machine.stop.assert_called_once()

def test_timeout_transitions_to_idle(state_machine, state_getting_job):
    """ Confirm that we return to Idle if the get times out (if there's no backup) """
    state_machine.pki.backup_exists.return_value = False
    state_getting_job.on_timeout()
    state_machine.pki.backup_exists.assert_called_once()
    state_machine.change_state_idle.assert_called_once()
