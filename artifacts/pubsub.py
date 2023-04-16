# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Thin wrapper around the IPC V2 client IoT Core publish/subscribe APIs
"""

import json
import sys
import traceback

from awsiot.greengrasscoreipc.model import (
    IoTCoreMessage,
    QOS,
)

class PubSub():
    """ Minimal IoT Core publish/subscribe wrapper """
    def __init__(self, ipc_client, subscription_callback):
        self._ipc_client = ipc_client
        self._subscription_callback = subscription_callback

    def publish(self, topic, message) -> bool:
        """ Publishes a message to IoT Core """
        print(f'Publishing message on topic {topic}: {message}')
        try:
            self._ipc_client.publish_to_iot_core(topic_name=topic, qos=QOS.AT_MOST_ONCE, payload=message)
            rval = True
        except Exception:
            traceback.print_exc()
            rval = False

        return rval

    def subscribe(self, topic) -> bool:
        """ Subscribes to an IoT Core topic """
        print(f'Subscribing to topic {topic}')
        try:
            self._ipc_client.subscribe_to_iot_core(topic_name=topic,
                                                    qos=QOS.AT_LEAST_ONCE,
                                                    on_stream_event=self.on_stream_event,
                                                    on_stream_error=self.on_stream_error,
                                                    on_stream_closed=self.on_stream_closed)
            rval = True
        except Exception:
            traceback.print_exc()
            rval = False

        return rval

    def on_stream_event(self, event: IoTCoreMessage) -> None:
        """ Handles an incoming message from subscriptions """
        try:
            message = str(event.message.payload, 'utf-8')
            topic = event.message.topic_name
            print(f'Received new message on topic {topic}: {message}')
            self._subscription_callback(topic, json.loads(message))
        except Exception:
            traceback.print_exc()

    @staticmethod
    def on_stream_error(error: Exception) -> bool:
        """ Handles a stream error """
        print(f'Received a stream error: {error}', file=sys.stderr)
        traceback.print_exc()
        return False  # Return True to close stream, False to keep stream open.

    @staticmethod
    def on_stream_closed() -> None:
        """ Handles a stream closure """
        print('Subscribe to topic stream closed.')
