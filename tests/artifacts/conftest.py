# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Shared fixtures for artifacts tests
"""

import pytest

@pytest.fixture(name='state_machine')
def fixture_state_machine(mocker):
    """ Mocked state machine object """
    return mocker.patch('state_machine.StateMachine')
