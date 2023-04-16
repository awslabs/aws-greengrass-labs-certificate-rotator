# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Abstract base class for the states in the state machine
"""

from abc import ABC, abstractmethod

class State(ABC):
    """ Abstract base class for certificate rotator states """
    def __init__(self, context):
        self._context = context

    @abstractmethod
    def on_rx_message(self, topic, message):
        """ Handles a message received on our subscribed topics """
        raise NotImplementedError

    @abstractmethod
    def on_timeout(self):
        """ Handles a state timeout """
        raise NotImplementedError
