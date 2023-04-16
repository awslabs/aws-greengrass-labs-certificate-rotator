# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.state.py
"""

import json
import pytest
from state import State

@pytest.fixture(name="state")
def fixture_state(mocker, state_machine):
    """ Instantiation of a single state """
    mocker.patch.multiple(State, __abstractmethods__=set())
    # pylint: disable-msg=abstract-class-instantiated
    return State(state_machine)

def test_on_rx_message(state):
    """ Test that we get an exception """
    with pytest.raises(NotImplementedError):
        state.on_rx_message('foobar', json.dumps({}))

def test_on_timeout(state):
    """ Test that we get an exception """
    with pytest.raises(NotImplementedError):
        state.on_timeout()
