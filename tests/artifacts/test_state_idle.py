# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.state_idle.py
"""

import json
import pytest
from state_idle import StateIdle
from state_updating_job import StateUpdatingJob
from topic_base import TOPIC_BASE_JOBS

@pytest.fixture(name='state_idle')
def fixture_state_getting_job(state_machine):
    """ Instantiation of a single state """
    return StateIdle(state_machine)

def test_transition_to_state_updating_job(state_machine, state_idle):
    """ Confirm that transition to StateUpdatingJob occurs """
    message = {}
    message['execution'] = {}
    message['execution']['status'] = 'QUEUED'
    message['execution']['jobDocument'] = {}
    message['execution']['jobDocument']['operation'] = 'ROTATE_CERTIFICATE'
    message['execution']['jobId'] = 'foobar'

    state_idle.on_rx_message(f'{TOPIC_BASE_JOBS}/notify-next', message)

    state_machine.publish.assert_called_once_with(f'{TOPIC_BASE_JOBS}/{message["execution"]["jobId"]}/update',
                                                    json.dumps({ 'status': 'IN_PROGRESS' }))
    state_machine.change_state.assert_called_once_with(StateUpdatingJob)

def test_non_job_topic_is_ignored(state_machine, state_idle):
    """ Confirm that non-jobs topics are ignored """
    state_idle.on_rx_message('foobar', json.dumps({}))
    state_machine.publish.assert_not_called()
    state_machine.change_state.assert_not_called()

def test_non_rotation_document_is_ignored(state_machine, state_idle):
    """ Confirm that non-certificate rotation jobs documents are ignored """
    message = {}
    message['execution'] = {}
    message['execution']['status'] = 'QUEUED'
    message['execution']['jobDocument'] = {}

    state_idle.on_rx_message('foobar', json.dumps({}))

    state_machine.publish.assert_not_called()
    state_machine.change_state.assert_not_called()

def test_timeout_has_no_effect(state_machine, state_idle):
    """ Confirm that timeout has no effect """
    state_idle.on_timeout()
    state_machine.publish.assert_not_called()
    state_machine.change_state.assert_not_called()
