# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Event handler for the CreatingCertificate state
"""

from state import State
from topic_base import TOPIC_BASE_CERT

class StateCreatingCertificate(State):
    """ Certificate rotator state: Creating Certificate """
    def on_rx_message(self, topic, message):
        if topic == f'{TOPIC_BASE_CERT}/create/accepted':
            print('Got new certificate. Backing up old certificate and private key, and switching to new.')
            rotated = self._context.pki.rotate(message['certificatePem'])
            if not rotated:
                print('Error rotating the certificate and private key.')
            print('Restarting to activate new certificate and private key.')
            self._context.stop()
        elif topic == f'{TOPIC_BASE_CERT}/create/rejected':
            print('Create rejected.')
            self._context.fail_the_job()

    def on_timeout(self):
        print('Comms failure creating new certificate.')
        self._context.fail_the_job()
