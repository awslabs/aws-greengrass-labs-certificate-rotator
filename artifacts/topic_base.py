# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Define the base of the MQTT topics used by this component
"""

import os

TOPIC_BASE_JOBS = f'$aws/things/{os.environ.get("AWS_IOT_THING_NAME")}/jobs'
TOPIC_BASE_CERT = f'awslabs/things/{os.environ.get("AWS_IOT_THING_NAME")}/certificate'
