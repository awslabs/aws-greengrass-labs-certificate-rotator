# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Abstract base class for the minimal Public Key Infrastructure (PKI)
"""

import typing
from abc import ABC, abstractmethod
from config import Config
from effective_config import EffectiveConfig
from awsiot.greengrasscoreipc.clientv2 import GreengrassCoreIPCClientV2

class PKI(ABC):
    """ Minimal Public Key Infrastructure (PKI) """
    def __init__(self, ipc_client: GreengrassCoreIPCClientV2, key_algorithms: typing.Dict,
                 signing_algorithms: typing.Dict):
        self._config = Config(ipc_client, key_algorithms, signing_algorithms)
        self._effective_config = EffectiveConfig()

    @abstractmethod
    def create_csr(self) -> typing.Optional[str]:
        """ Creates a certificate signing request from a new private key """
        raise NotImplementedError

    @abstractmethod
    def rotate(self, new_cert_pem: str) -> bool:
        """ Rotates from the old to new certificate and private key """
        raise NotImplementedError

    @abstractmethod
    def rollback(self) -> bool:
        """ Rolls back to the old certificate and private key """
        raise NotImplementedError

    @abstractmethod
    def backup_exists(self) -> bool:
        """ Indicates whether the backup certificate and private key exists """
        raise NotImplementedError

    @abstractmethod
    def delete_backup(self) -> None:
        """ Deletes the backup certificate and private key """
        raise NotImplementedError
