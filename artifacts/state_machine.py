# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
State machine for the certificate rotation process - Context role in the pattern
"""

import json
from threading import Timer
import time
from awsiot.greengrasscoreipc.clientv2 import GreengrassCoreIPCClientV2
from effective_config import EffectiveConfig
from pubsub import PubSub
from pki_hsm import PKIHSM
from pki_file import PKIFile
from state_idle import StateIdle
from state_getting_job import StateGettingJob
from topic_base import TOPIC_BASE_JOBS, TOPIC_BASE_CERT

class StateMachine():
    """ State machine for managing the certificate rotation process """
    def __init__(self):
        self._running = False
        self._states = {}
        self._state = None
        self._timer = None

        ipc_client = self._create_ipc_client()

        self._pubsub_client = PubSub(ipc_client, self.on_rx_message)

        # Instantiate the correct PKI based on the configuration
        effective_config = EffectiveConfig()
        pkcs = effective_config.private_key_path().startswith('pkcs11:object=')
        self._pki = PKIHSM(ipc_client) if pkcs else PKIFile(ipc_client)

        self._job_id = None

    @property
    def pki(self):
        """ Getter for the PKI """
        return self._pki

    @property
    def job_id(self):
        """ Getter for the job ID """
        return self._job_id

    @job_id.setter
    def job_id(self, value):
        """ Setter for the job ID """
        self._job_id = value

    def start(self):
        """ Starts the state machine """
        print('Starting the state machine')

        rollback = False

        while not self._create_subscriptions() and not rollback:
            # We failed to subscribe. It means we don't have
            # comms with IoT Core, just after Greengrass has started up. If we
            # have a certificate backup, it means we are trying to rotate the
            # certificate, but it appears the new certificate is not working.
            if self._pki.backup_exists():
                # Rollback and restart
                print('Subscription failure with new certificate. Rollback and restart.')
                self._pki.rollback()
                rollback = True
            else:
                # Not trying to rotate. So we just wait a while before
                # re-attempting our subscriptions.
                time.sleep(10)
                print('Retrying subscriptions')

        # Except for the rare case of a rollback, we proceed to getting the next job
        if not rollback:
            # We start by getting the next/current job
            self.change_state(StateGettingJob)
            self._running = True
            self._pubsub_client.publish(f'{TOPIC_BASE_JOBS}/$next/get','{}')

    def stop(self):
        """ Stops the state machine """
        print('Stopping the state machine')
        self._running = False

    def running(self):
        """ Indicates whether state machine is running"""
        return self._running

    def change_state_idle(self):
        """ Changes the state of the state machine to Idle """
        self.change_state(StateIdle)

    def change_state(self, new_state_class):
        """ Changes the state of the state machine """
        print(f'Changing state to {new_state_class.__name__}')

        if self._timer is not None:
            self._timer.cancel()

        if new_state_class is not StateIdle:
            self._timer = Timer(30, self.on_timeout)
            self._timer.start()
        else:
            self._timer = None

        if new_state_class.__name__ not in self._states:
            self._states[new_state_class.__name__] = new_state_class(self)

        self._state = self._states[new_state_class.__name__]

    def publish(self, topic, message):
        """ Publishes a message to IoT Core """
        self._pubsub_client.publish(topic, message)

    def on_rx_message(self, topic, message):
        """ Handles a message received on our subscribed topics """
        if self._running:
            self._state.on_rx_message(topic, message)

    def on_timeout(self):
        """ Handles a state timeout """
        if self._running:
            self._state.on_timeout()

    def fail_the_job(self):
        """ Marks the job as failed """
        print('Failing the certificate rotation job.')
        topic = f'{TOPIC_BASE_JOBS}/{self._job_id}/update'
        request = { 'status': 'FAILED' }
        self.publish(topic, json.dumps(request))
        self.change_state_idle()

    def _create_ipc_client(self):
        """ Instantiates the IPC client """
        ipc_client = None

        # The call to GreengrassCoreIPCClientV2() can timeout if other
        # components on the device are trying to communicate to IoT Core.
        # So we retry until we succeed.
        while ipc_client is None:
            try:
                print('Creating IPC client')
                ipc_client = GreengrassCoreIPCClientV2()
            except Exception as error:
                print(f'Error creating IPC client: {repr(error)}.')

        return ipc_client

    def _create_subscriptions(self):
        """ Subscribes to all the required topics """
        SUBSCRIPTION_TOPICS = [
            f'{TOPIC_BASE_JOBS}/notify-next',
            f'{TOPIC_BASE_JOBS}/+/get/accepted',
            f'{TOPIC_BASE_JOBS}/+/get/rejected',
            f'{TOPIC_BASE_JOBS}/+/update/accepted',
            f'{TOPIC_BASE_JOBS}/+/update/rejected',
            f'{TOPIC_BASE_CERT}/create/accepted',
            f'{TOPIC_BASE_CERT}/create/rejected',
            f'{TOPIC_BASE_CERT}/commit/accepted',
            f'{TOPIC_BASE_CERT}/commit/rejected'
        ]

        rval = True

        for topic in SUBSCRIPTION_TOPICS:
            if not self._pubsub_client.subscribe(topic):
                rval = False
                break

        # Indicate whether all subscriptions succeeded or not
        return rval
