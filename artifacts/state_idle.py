# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Event handler for the Idle state
"""

import json
from state import State
from state_updating_job import StateUpdatingJob
from topic_base import TOPIC_BASE_JOBS

class StateIdle(State):
    """ Certificate rotator state: Idle """
    def on_rx_message(self, topic: str, message: dict) -> None:
        if topic == f'{TOPIC_BASE_JOBS}/notify-next'\
            and 'execution' in message and message['execution']['status'] == 'QUEUED'\
            and 'operation' in message['execution']['jobDocument']\
            and message['execution']['jobDocument']['operation'] == 'ROTATE_CERTIFICATE':

            topic = f'{TOPIC_BASE_JOBS}/{message["execution"]["jobId"]}/update'
            request = { 'status': 'IN_PROGRESS', 'statusDetails': { 'certificateRotationProgress': 'started' } }
            self._context.change_state(StateUpdatingJob)
            self._context.publish(topic, json.dumps(request))

    def on_timeout(self) -> None:
        pass
