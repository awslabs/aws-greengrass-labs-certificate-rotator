# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.pubsub.py
"""

import json
from unittest.mock import ANY
import pytest
from pubsub import PubSub
from awsiot.greengrasscoreipc.model import (
    IoTCoreMessage,
    MQTTMessage,
    QOS
)

TOPIC = 'foobar'
PAYLOAD = {'value': 'yeehah'}

@pytest.fixture(name='ipc_client')
def fixture_ipc_client(mocker):
    """ Create a mocked IPC client object with default component configuration """
    return mocker.Mock()

@pytest.fixture(name='callback')
def fixture_callback(mocker):
    """ Create a mock callback function for the subscription callback """
    return mocker.Mock()

@pytest.fixture(name='pubsub')
def fixture_pubsub(ipc_client, callback):
    """ Create a PubSub object with mocked IPC client and mocked subscription callback """
    return PubSub(ipc_client, callback)

@pytest.fixture(name='event')
def fixture_event():
    """ Create an event object with default component configuration """
    return IoTCoreMessage(message=MQTTMessage(topic_name=TOPIC, payload=json.dumps(PAYLOAD)))

def test_publish(ipc_client, pubsub):
    """ Confirm publish """
    assert pubsub.publish(TOPIC, PAYLOAD) is True
    ipc_client.publish_to_iot_core.assert_called_once_with(topic_name=TOPIC, qos=QOS.AT_MOST_ONCE, payload=PAYLOAD)

def test_publish_exception(ipc_client, pubsub):
    """ Confirm publish catches exception"""
    ipc_client.publish_to_iot_core.side_effect=Exception('mocked error')
    assert pubsub.publish(TOPIC, PAYLOAD) is False
    ipc_client.publish_to_iot_core.assert_called_once_with(topic_name=TOPIC, qos=QOS.AT_MOST_ONCE, payload=PAYLOAD)

def test_subscribe(ipc_client, pubsub):
    """ Confirm subscribe """
    assert pubsub.subscribe(TOPIC) is True
    ipc_client.subscribe_to_iot_core.assert_called_once_with(topic_name=TOPIC, qos=QOS.AT_LEAST_ONCE,
                                                    on_stream_event=ANY,
                                                    on_stream_error=ANY,
                                                    on_stream_closed=ANY)

def test_subscribe_exception(ipc_client, pubsub):
    """ Confirm subscribe catches exception """
    ipc_client.subscribe_to_iot_core.side_effect=Exception('mocked error')
    assert pubsub.subscribe(TOPIC) is False
    ipc_client.subscribe_to_iot_core.assert_called_once_with(topic_name=TOPIC, qos=QOS.AT_LEAST_ONCE,
                                                    on_stream_event=ANY,
                                                    on_stream_error=ANY,
                                                    on_stream_closed=ANY)

def test_rx_message_triggers_callback(callback, pubsub, event):
    """ Confirm that a received message triggers the subscription callback """
    pubsub.on_stream_event(event)
    callback.assert_called_once_with(TOPIC, PAYLOAD)

def test_rx_message_exception(mocker, ipc_client, event):
    """ Confirm that a received message exception in the callback is caught """
    callback = mocker.Mock(side_effect=Exception('mocked error'))
    pubsub = PubSub(ipc_client, callback)
    pubsub.on_stream_event(event)
    callback.assert_called_once_with(TOPIC, PAYLOAD)

def test_on_stream_error():
    """ Always returns false so the stream is not closed """
    assert PubSub.on_stream_error(Exception()) is False

def test_on_stream_closed():
    """ Calls it - nothing to check """
    PubSub.on_stream_closed()
