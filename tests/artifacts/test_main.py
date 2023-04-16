# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.main.py
"""

import runpy

def test_main(mocker):
    """ Main can sleep and exit when state machine stops running """
    init = mocker.patch('state_machine.StateMachine.__init__', return_value=None)
    start = mocker.patch('state_machine.StateMachine.start')
    # Stop running on the second call
    running = mocker.patch('state_machine.StateMachine.running')
    running.side_effect = [True, False]
    time_sleep = mocker.patch('time.sleep')

    runpy.run_module('main')

    init.assert_called_once()
    start.assert_called_once()
    assert running.call_count == 2
    time_sleep.assert_called_once()
