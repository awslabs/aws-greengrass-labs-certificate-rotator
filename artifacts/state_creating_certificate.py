# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Event handler for the CreatingCertificate state
"""

from state import State
from topic_base import TOPIC_BASE_CERT

class StateCreatingCertificate(State):
    """ Certificate rotator state: Creating Certificate """
    def on_rx_message(self, topic: str, message: dict) -> None:
        if topic == f'{TOPIC_BASE_CERT}/create/accepted':
            print('Got new certificate. Backing up old certificate and private key, and switching to new.')
            rotated = self._context.pki.rotate(message['certificatePem'])
            if rotated:
                print('Restarting to activate new certificate and private key.')
            else:
                # The PKI rotation should not fail. If it does, it's an indication that the
                # PKI module is perhaps not in a sane state, so we can't safely rollback
                # here. Fail the job and let the restart handle rollback with freshly booted software.
                print('Error rotating the certificate and private key.')
                self._context.fail_the_job()
            self._context.stop()
        elif topic == f'{TOPIC_BASE_CERT}/create/rejected':
            print('Create rejected.')
            self._context.fail_the_job()

    def on_timeout(self) -> None:
        print('Comms failure creating new certificate.')
        self._context.fail_the_job()
