# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for state_machine.py
"""

import json
import pytest
from state_machine import StateMachine
from pki_file import PKIFile
from topic_base import TOPIC_BASE_JOBS
from state import State

@pytest.fixture(name='state_machine')
def fixture_state_machine(mocker):
    """ Mock the classes instantiated by the state machine constructor """
    # Make the client creation always retry
    mocker.patch('state_machine.GreengrassCoreIPCClientV2.__init__',
                 return_value=None, side_effect=[Exception('mocked error'), None])
    mocker.patch('state_machine.PubSub.__init__', return_value=None)
    mocker.patch('state_machine.PubSub.subscribe', return_value=True)
    mocker.patch('state_machine.PubSub.publish')
    mocker.patch('state_machine.EffectiveConfig.__init__', return_value=None)
    mocker.patch('state_machine.EffectiveConfig.private_key_path', return_value='whatever')
    mocker.patch('state_machine.PKIHSM.__init__', return_value=None)
    mocker.patch('state_machine.PKIFile.__init__', return_value=None)
    mocker.patch('state_machine.PKIFile.backup_exists', return_value=False)
    mocker.patch('state_machine.Timer.__init__', return_value=None)
    mocker.patch('state_machine.Timer.start', return_value=None)
    return StateMachine()

@pytest.fixture(name='mock_state')
def fixture_mock_state(mocker):
    """ A mock state to change to """
    mock_state = mocker.Mock(spec=State)
    mock_state.return_value = mock_state
    mock_state.__name__ = 'StateMock'
    return mock_state

def test_pki(state_machine):
    """ Check the PKI getter """
    state_machine.start()
    assert isinstance(state_machine.pki, PKIFile)

def test_start(mocker, state_machine):
    """ State machine should start up """
    publish = mocker.patch('state_machine.PubSub.publish')
    timer_start = mocker.patch('state_machine.Timer.start', return_value=None)
    state_init = mocker.patch('state_machine.StateGettingJob.__init__', return_value=None)
    state_machine.start()
    assert state_machine.running() is True
    publish.assert_called_once_with(f'{TOPIC_BASE_JOBS}/$next/get','{}')
    timer_start.assert_called_once()
    state_init.assert_called_once()

def test_start_with_retried_subscriptions(mocker, state_machine):
    """ State machine should start up after retrying subscriptions """
    # We make the first subscribe fail but the next 9 succeed
    subscribe = mocker.patch('state_machine.PubSub.subscribe')
    subscribe.side_effect = [False, True, True, True, True, True, True, True, True, True]
    publish = mocker.patch('state_machine.PubSub.publish')
    timer_start = mocker.patch('state_machine.Timer.start', return_value=None)
    state_init = mocker.patch('state_machine.StateGettingJob.__init__', return_value=None)
    sleep = mocker.patch('time.sleep')
    state_machine.start()
    assert state_machine.running() is True
    publish.assert_called_once_with(f'{TOPIC_BASE_JOBS}/$next/get','{}')
    timer_start.assert_called_once()
    sleep.assert_called_once()
    state_init.assert_called_once()

def test_start_subscription_failure_rollback(mocker, state_machine):
    """ State machine rollback if subscribe fails at startup and there's a rotation in progress """
    mocker.patch('state_machine.PubSub.subscribe', return_value=False)
    mocker.patch('state_machine.PKIFile.backup_exists', return_value=True)
    rollback = mocker.patch('state_machine.PKIFile.rollback')
    state_machine.start()
    assert state_machine.running() is False
    rollback.assert_called_once()

def test_stop(state_machine):
    """ Confirm we can stop the state machine """
    state_machine.start()
    assert state_machine.running() is True
    state_machine.stop()
    assert state_machine.running() is False

def test_change_state(mocker, state_machine, mock_state):
    """ Confirm we can change state """
    state_machine.start()
    timer_start = mocker.patch('state_machine.Timer.start', return_value=None)
    timer_cancel = mocker.patch('state_machine.Timer.cancel', return_value=None)
    state_machine.change_state(mock_state)
    timer_cancel.assert_called_once()
    timer_start.assert_called_once()
    assert mock_state.call_count == 1

def test_change_state_again(mocker, state_machine, mock_state):
    """ Confirm we can change state to a state we created previously (without re-creating it) """
    state_machine.start()
    timer_start = mocker.patch('state_machine.Timer.start', return_value=None)
    timer_cancel = mocker.patch('state_machine.Timer.cancel', return_value=None)
    state_machine.change_state(mock_state)
    state_machine.change_state_idle()
    state_machine.change_state(mock_state)
    assert timer_cancel.call_count == 2
    assert timer_start.call_count == 2
    assert mock_state.call_count == 1

def test_change_state_idle(mocker, state_machine):
    """ Confirm we can change state to idle """
    state_machine.start()
    timer_start = mocker.patch('state_machine.Timer.start', return_value=None)
    timer_cancel = mocker.patch('state_machine.Timer.cancel', return_value=None)
    idle_init = mocker.patch('state_machine.StateIdle.__init__', return_value=None)
    state_machine.change_state_idle()
    timer_cancel.assert_called_once()
    timer_start.assert_not_called()
    idle_init.assert_called_once()

def test_publish(mocker, state_machine):
    """ Confirm that publish() publishes """
    publish = mocker.patch('state_machine.PubSub.publish')
    state_machine.publish('topic', 'message')
    publish.assert_called_once_with('topic', 'message')

def test_on_rx_message(mocker, state_machine, mock_state):
    """ Test that received messages go to the current state """
    state_machine.start()
    mocker.patch('state_machine.Timer.cancel', return_value=None)
    state_machine.change_state(mock_state)
    state_machine.on_rx_message('my_topic', 'my_message')
    mock_state.on_rx_message.assert_called_once_with('my_topic', 'my_message')

def test_on_rx_message_not_processed(state_machine, mock_state):
    """ Received messages not processed if state machine not running """
    state_machine.change_state(mock_state)
    state_machine.on_rx_message('my_topic', 'my_message')
    mock_state.on_rx_message.assert_not_called()

def test_on_timeout(mocker, state_machine, mock_state):
    """ Test that timeouts go to the current state """
    state_machine.start()
    mocker.patch('state_machine.Timer.cancel', return_value=None)
    state_machine.change_state(mock_state)
    state_machine.on_timeout()
    mock_state.on_timeout.assert_called_once()

def test_on_timeout_not_processed(state_machine, mock_state):
    """ Timeouts not processed if state machine not running """
    state_machine.change_state(mock_state)
    state_machine.on_timeout()
    mock_state.on_timeout.assert_not_called()

def test_fail_the_job(mocker, state_machine):
    """ Failing the job should send a message to IoT Core and change state to Idle """
    state_machine.start()
    publish = mocker.patch('state_machine.PubSub.publish')
    timer_start = mocker.patch('state_machine.Timer.start', return_value=None)
    timer_cancel = mocker.patch('state_machine.Timer.cancel', return_value=None)
    idle_init = mocker.patch('state_machine.StateIdle.__init__', return_value=None)
    state_machine.job_id = 'whatever'
    state_machine.fail_the_job()
    publish.assert_called_once_with(f'{TOPIC_BASE_JOBS}/{state_machine.job_id}/update',
                                    json.dumps({ 'status': 'FAILED' }))
    timer_cancel.assert_called_once()
    timer_start.assert_not_called()
    idle_init.assert_called_once()
