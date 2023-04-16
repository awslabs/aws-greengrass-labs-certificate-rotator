# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.state_committing_certificate.py
"""

import json
import pytest
from state_committing_certificate import StateCommittingCertificate
from topic_base import TOPIC_BASE_JOBS, TOPIC_BASE_CERT

@pytest.fixture(name='state_committing_certificate')
def fixture_state_getting_job(state_machine):
    """ Instantiation of a single state """
    return StateCommittingCertificate(state_machine)

def test_certificate_committed_if_commit_accepted(state_machine, state_committing_certificate):
    """ Confirm that we commit to the certificate if the cloud backend accepts the commit """
    state_machine.job_id = 'john'
    state_committing_certificate.on_rx_message(f'{TOPIC_BASE_CERT}/commit/accepted', json.dumps({}))
    state_machine.pki.delete_backup.assert_called_once()
    state_machine.publish.assert_called_once_with(f'{TOPIC_BASE_JOBS}/{state_machine.job_id}/update',
                                                json.dumps({ 'status': 'SUCCEEDED' }))
    state_machine.change_state_idle.assert_called_once()

def test_rollback_if_commit_rejected(state_machine, state_committing_certificate):
    """ Confirm that we rollback if the cloud backend rejects the commit """
    state_committing_certificate.on_rx_message(f'{TOPIC_BASE_CERT}/commit/rejected', json.dumps({}))
    state_machine.fail_the_job.assert_called_once()
    state_machine.pki.rollback.assert_called_once()
    state_machine.stop.assert_called_once()

def test_timeout_triggers_rollback(state_machine, state_committing_certificate):
    """ Confirm that we rollback if the commit times out """
    state_committing_certificate.on_timeout()
    state_machine.change_state_idle.assert_called_once()
    state_machine.pki.rollback.assert_called_once()
    state_machine.stop.assert_called_once()

def test_non_job_topic_is_ignored(state_machine, state_committing_certificate):
    """ Confirm that non-jobs topics are ignored """
    state_committing_certificate.on_rx_message('foobar', json.dumps({}))
    state_machine.pki.delete_backup.assert_not_called()
    state_machine.publish.assert_not_called()
    state_machine.change_state_idle.assert_not_called()
    state_machine.fail_the_job.assert_not_called()
    state_machine.pki.rollback.assert_not_called()
    state_machine.stop.assert_not_called()
