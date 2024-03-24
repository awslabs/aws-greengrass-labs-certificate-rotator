# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Event handler for the GettingJob state
"""

import json
from state import State
from state_updating_job import StateUpdatingJob
from state_committing_certificate import StateCommittingCertificate
from topic_base import TOPIC_BASE_JOBS, TOPIC_BASE_CERT

class StateGettingJob(State):
    """ Certificate rotator state: Getting Job """
    def on_rx_message(self, topic: str, message: dict) -> None:
        if topic.startswith(TOPIC_BASE_JOBS) and topic.endswith('get/accepted') and\
            'execution' in message and\
            'operation' in message['execution']['jobDocument'] and\
            message['execution']['jobDocument']['operation'] == 'ROTATE_CERTIFICATE':

            # Remember the job ID
            self._context.job_id = message['execution']['jobId']

            if message['execution']['status'] == 'QUEUED':
                # There is a new rotation job (created before we started up)
                topic = f'{TOPIC_BASE_JOBS}/{message["execution"]["jobId"]}/update'
                request = { 'status': 'IN_PROGRESS', 'statusDetails': { 'certificateRotationProgress': 'started' } }
                self._context.change_state(StateUpdatingJob)
                self._context.publish(topic, json.dumps(request))
            elif message['execution']['status'] == 'IN_PROGRESS':
                if self._context.pki.backup_exists():
                    # We have an in progress job and a backup. Therefore we
                    # just restarted after rotating to the new certificate.
                    response = { 'jobId': message['execution']['jobId'] }
                    self._context.change_state(StateCommittingCertificate)
                    self._context.publish(f'{TOPIC_BASE_CERT}/commit', json.dumps(response))
                else:
                    # We have an in progress job but no backup. Therefore we
                    # just restarted after rolling back a failed rotation.
                    print('ROLLBACK: In progress certificate rotation job, but no backup exists')
                    self._context.fail_the_job()
        else:
            # Ignore (reset to idle) if 'get/rejected' or or 'get/accepted'
            # but no job, or job type is not a certificate rotation, (or we
            # got some other unexpected topic)
            self._context.change_state_idle()

    def on_timeout(self) -> None:
        # We timed out trying to get the next job. It means we don't have
        # comms with IoT Core, just after Greengrass has started up. If we
        # have a certificate backup, it means we are trying to rotate the
        # certificate, but it appears the new certificate is not working.
        if self._context.pki.backup_exists():
            # Rollback and restart
            print('Comms failure with new certificate. Rollback and restart.')
            self._context.pki.rollback()
            self._context.stop()
        else:
            # If there's no backup, we can just return to idle.
            self._context.change_state_idle()
