# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Event handler for the UpdatingJob state
"""

import json
from state import State
from state_creating_certificate import StateCreatingCertificate
from topic_base import TOPIC_BASE_JOBS, TOPIC_BASE_CERT

class StateUpdatingJob(State):
    """ Certificate rotator state: Updating Job """
    def on_rx_message(self, topic, message):
        if topic.startswith(TOPIC_BASE_JOBS):
            if topic.endswith('update/rejected'):
                self._context.change_state_idle()
            elif topic.endswith('update/accepted'):
                # Remember the job ID
                self._context.job_id = topic.split('/')[-3]

                csr = self._context.pki.create_csr()

                if csr is not None:
                    response = {
                                    'jobId': self._context.job_id,
                                    'csr': csr
                                }
                    self._context.change_state(StateCreatingCertificate)
                    self._context.publish(f'{TOPIC_BASE_CERT}/create',json.dumps(response))
                else:
                    # Fail the job if the CSR is not created
                    print('Error creating the CSR.')
                    self._context.fail_the_job()

    def on_timeout(self):
        self._context.change_state_idle()
