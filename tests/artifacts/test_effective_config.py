# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.effective_config.py
"""

from effective_config import EffectiveConfig

ROOT_DIR = 'rocinante'
CONFIG_FILE =\
"""
system:
    certificateFilePath: cartman
    privateKeyPath: stan
"""

def do_load_and_checks(mocker, platform, working_directory, config_path):
    """ Common steps """
    platform_system = mocker.patch('effective_config.platform.system', return_value=platform)
    os_getcwd = mocker.patch('effective_config.os.getcwd', return_value=f'{ROOT_DIR}{working_directory}')
    file_open = mocker.patch('effective_config.open', mocker.mock_open(read_data=CONFIG_FILE))

    config = EffectiveConfig()

    platform_system.assert_called_once()
    os_getcwd.assert_called_once()
    file_open.assert_called_once_with(f'{ROOT_DIR}{config_path}', encoding='utf-8')

    assert config.certificate_file_path() == 'cartman'
    assert config.private_key_path() == 'stan'

def test_effective_config_loads_under_linux(mocker):
    """ Test under Linux """
    do_load_and_checks(mocker, 'Linux', '/work', '/config/effectiveConfig.yaml')

def test_effective_config_loads_under_windows(mocker):
    """ Test under Windows """
    do_load_and_checks(mocker, 'Windows', '\\work', '\\config\\effectiveConfig.yaml')
