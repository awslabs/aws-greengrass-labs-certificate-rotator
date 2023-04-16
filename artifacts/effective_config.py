# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Greengrass effective configuration
"""

import os
import platform
import yaml

class EffectiveConfig():
    """ Greengrass effective configuration """
    def __init__(self):
        # Get the Greengrass root path from our working directory
        if platform.system() == 'Windows':
            gg_root_path = os.getcwd().split('\\work')[0]
            file_path = '\\config\\effectiveConfig.yaml'
        else:
            gg_root_path = os.getcwd().split('/work')[0]
            file_path = '/config/effectiveConfig.yaml'

        with open(f'{gg_root_path}{file_path}', encoding='utf-8') as effective_config_file:
            self._yaml = yaml.safe_load(effective_config_file)

    def certificate_file_path(self):
        """ Certificate file path configuration """
        return self._yaml['system']['certificateFilePath']

    def private_key_path(self):
        """ Private key path configuration """
        return self._yaml['system']['privateKeyPath']
