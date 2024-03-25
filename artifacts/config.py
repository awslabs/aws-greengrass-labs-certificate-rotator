# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Component configuration management
"""

import sys
import traceback
from awsiot.greengrasscoreipc.clientv2 import GreengrassCoreIPCClientV2
from awsiot.greengrasscoreipc.model import (
    ValidateConfigurationUpdateEvents,
    ConfigurationValidityReport,
    ConfigurationValidityStatus
)

class Config():
    """ Component configuration management """
    def __init__(self, ipc_client: GreengrassCoreIPCClientV2, key_algorithms: dict, signing_algorithms: dict):
        self._ipc_client = ipc_client
        self._key_algorithms = key_algorithms
        self._signing_algorithms = signing_algorithms
        self._ipc_client.subscribe_to_validate_configuration_updates(
                                                    on_stream_event=self.on_stream_event,
                                                    on_stream_error=self.on_stream_error,
                                                    on_stream_closed=self.on_stream_closed)

        print('Getting configuration')
        response = self._ipc_client.get_configuration()
        self._key_algorithm = response.value['keyAlgorithm']
        self._signing_algorithm = response.value['signingAlgorithm']
        print(f'Configured key algorithm is {self._key_algorithm}')
        print(f'Configured signing algorithm is {self._signing_algorithm}')

    @property
    def key_algorithm(self) -> str:
        """ Getter for the key algorithm """
        return self._key_algorithm

    @property
    def signing_algorithm(self) -> str:
        """ Getter for the signing algorithm """
        return self._signing_algorithm

    def on_stream_event(self, event: ValidateConfigurationUpdateEvents) -> None:
        """ Handles an incoming message from subscriptions """
        try:
            deployment_id = event.validate_configuration_update_event.deployment_id
            new_key_algorithm = event.validate_configuration_update_event.configuration['keyAlgorithm']
            new_signing_algorithm = event.validate_configuration_update_event.configuration['signingAlgorithm']
            print(f'Validating new configuration for deployment ID {deployment_id}')
            print(f'Proposed key algorithm is {new_key_algorithm}')
            print(f'Proposed signing algorithm is {new_signing_algorithm}')

            status = ConfigurationValidityStatus.REJECTED

            if new_key_algorithm not in self._key_algorithms:
                message = 'Invalid key algorithm'
            elif new_signing_algorithm not in self._signing_algorithms:
                message = 'Invalid signing algorithm'
            elif self._key_algorithms[new_key_algorithm]['type'] !=\
                    self._signing_algorithms[new_signing_algorithm]['type']:
                message = 'Key algorithm and signing algorithm have mismatched types'
            else:
                status = ConfigurationValidityStatus.ACCEPTED
                message = 'Valid key and signing algorithm configuration'
                self._key_algorithm = new_key_algorithm
                self._signing_algorithm = new_signing_algorithm

            print(f'New configuration is {status}: {message}')
            report = ConfigurationValidityReport(status=status,
                                                    deployment_id=deployment_id,
                                                    message=message)
            self._ipc_client.send_configuration_validity_report(configuration_validity_report=report)
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
