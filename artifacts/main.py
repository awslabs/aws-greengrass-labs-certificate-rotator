# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Runs the Certificate Rotator component on the Greengrass edge runtime.
"""

import time
from state_machine import StateMachine

state_machine = StateMachine()
state_machine.start()

# The process will exit if the state machine stops running. The
# state machine stops running when the certificate changes and
# a Greengrass restart is therefore required.
while state_machine.running():
    time.sleep(5)
