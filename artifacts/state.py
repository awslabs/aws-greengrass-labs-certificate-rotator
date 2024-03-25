# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Abstract base class for the states in the state machine
"""

from abc import ABC, abstractmethod
import typing
if typing.TYPE_CHECKING:
    from state_machine import StateMachine # pragma: no cover

class State(ABC):
    """ Abstract base class for certificate rotator states """
    def __init__(self, context: 'StateMachine'):
        self._context = context

    @abstractmethod
    def on_rx_message(self, topic: str, message: dict) -> None:
        """ Handles a message received on our subscribed topics """
        raise NotImplementedError

    @abstractmethod
    def on_timeout(self) -> None:
        """ Handles a state timeout """
        raise NotImplementedError
