# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Event handler for the CommittingCertificate state
"""

import json
from state import State
from topic_base import TOPIC_BASE_JOBS, TOPIC_BASE_CERT

class StateCommittingCertificate(State):
    """ Certificate rotator state: Committing Certificate """
    def on_rx_message(self, topic: str, message: dict) -> None:
        if topic == f'{TOPIC_BASE_CERT}/commit/accepted':
            print('Certificate committed. Removing backup.')
            self._context.pki.delete_backup()
            topic = f'{TOPIC_BASE_JOBS}/{self._context.job_id}/update'
            request = { 'status': 'SUCCEEDED' }
            self._context.publish(topic, json.dumps(request))
            self._context.change_state_idle()
        elif topic == f'{TOPIC_BASE_CERT}/commit/rejected':
            print('New certificate rejected. Rollback and restart.')
            self._context.fail_the_job()
            self._context.pki.rollback()
            self._context.stop()

    def on_timeout(self) -> None:
        print('Comms failure with new certificate. Rollback and restart.')
        self._context.change_state_idle()
        self._context.pki.rollback()
        self._context.stop()
