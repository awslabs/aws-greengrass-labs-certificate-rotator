# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.effective_config.py
"""

import json
from effective_config import EffectiveConfig

ROOT_DIR = 'rocinante'

EFFECTIVE_CONFIG_WITH_PATHS =\
"""
system:
    certificateFilePath: cartman
    privateKeyPath: stan
"""

EFFECTIVE_CONFIG_EMPTY_PATHS =\
"""
system:
    certificateFilePath: ""
    privateKeyPath: ""
"""

def mock_config_files(mocker, platform_name, working_directory,
                      effective_config, transaction_log=None):
    """ Mocks the platform, working directory and config file reads.

    open() is dispatched by file name: the effective configuration snapshot
    returns `effective_config`; the transaction log returns `transaction_log`,
    or raises FileNotFoundError when it is None, standing in for an absent log.
    """
    mocker.patch('effective_config.platform.system', return_value=platform_name)
    mocker.patch('effective_config.os.getcwd', return_value=f'{ROOT_DIR}{working_directory}')

    def dispatch(file_path, *args, **kwargs):
        if str(file_path).endswith('config.tlog'):
            if transaction_log is None:
                raise FileNotFoundError(file_path)
            return mocker.mock_open(read_data=transaction_log)(file_path, *args, **kwargs)
        return mocker.mock_open(read_data=effective_config)(file_path, *args, **kwargs)

    mocker.patch('effective_config.open', side_effect=dispatch)

def transaction_log(entries):
    """ Builds a transaction log body from (topic_path, value, timestamp) tuples """
    lines = [json.dumps({'TS': timestamp, 'TP': topic_path, 'V': value})
             for topic_path, value, timestamp in entries]
    return '\n'.join(lines) + '\n'

def test_effective_config_loads_under_linux(mocker):
    """ Manually provisioned device, Linux: the snapshot value is used """
    mock_config_files(mocker, 'Linux', '/work', EFFECTIVE_CONFIG_WITH_PATHS)

    config = EffectiveConfig()

    assert config.certificate_file_path() == 'cartman'
    assert config.private_key_path() == 'stan'

def test_effective_config_loads_under_windows(mocker):
    """ Manually provisioned device, Windows: the snapshot value is used """
    mock_config_files(mocker, 'Windows', '\\work', EFFECTIVE_CONFIG_WITH_PATHS)

    config = EffectiveConfig()

    assert config.certificate_file_path() == 'cartman'
    assert config.private_key_path() == 'stan'

def test_transaction_log_overrides_empty_snapshot(mocker):
    """ Fleet provisioned device: the snapshot holds empty paths, so the newest
    transaction log entry decides. Stale, blank and malformed lines are ignored. """
    log = (
        json.dumps({'TS': 1, 'TP': ['system', 'certificateFilePath'], 'V': ''}) + '\n'
        + json.dumps({'TS': 100, 'TP': ['system', 'certificateFilePath'], 'V': '/gg/old.crt'}) + '\n'
        + 'this is not json\n'
        + '\n'
        + json.dumps({'TS': 100, 'TP': ['system'], 'V': {'nested': 'ignored'}}) + '\n'
        + transaction_log([
            (['system', 'certificateFilePath'], '/gg/thingCert.crt', 200),
            (['system', 'privateKeyPath'], '/gg/privKey.key', 200),
        ])
    )
    mock_config_files(mocker, 'Linux', '/work', EFFECTIVE_CONFIG_EMPTY_PATHS, log)

    config = EffectiveConfig()

    assert config.certificate_file_path() == '/gg/thingCert.crt'
    assert config.private_key_path() == '/gg/privKey.key'

def test_file_uri_scheme_is_stripped(mocker):
    """ A file URI value is reduced to a plain path that open() can use """
    effective_config = (
        'system:\n'
        '    certificateFilePath: file:///x/y.crt\n'
        '    privateKeyPath: file:///x/y.key\n'
    )
    mock_config_files(mocker, 'Linux', '/work', effective_config)

    config = EffectiveConfig()

    assert config.certificate_file_path() == '/x/y.crt'
    assert config.private_key_path() == '/x/y.key'

def test_greengrass_defaults_when_nothing_configured(mocker):
    """ Neither source holds a value, so the Greengrass defaults are used """
    mock_config_files(mocker, 'Linux', '/work', EFFECTIVE_CONFIG_EMPTY_PATHS)

    config = EffectiveConfig()

    assert config.certificate_file_path() == f'{ROOT_DIR}/thingCert.crt'
    assert config.private_key_path() == f'{ROOT_DIR}/privKey.key'

def test_pkcs11_uris_are_preserved(mocker):
    """ HSM configuration: PKCS#11 URIs must survive resolution unchanged """
    effective_config = (
        'system:\n'
        "    certificateFilePath: 'pkcs11:object=iotcert;type=cert'\n"
        "    privateKeyPath: 'pkcs11:object=iotkey;type=private'\n"
    )
    mock_config_files(mocker, 'Linux', '/work', effective_config)

    config = EffectiveConfig()

    assert config.certificate_file_path() == 'pkcs11:object=iotcert;type=cert'
    assert config.private_key_path().startswith('pkcs11:object=')
