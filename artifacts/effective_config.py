# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Greengrass effective configuration
"""

import json
import os
import platform

import yaml

# Certificate and private key paths may be recorded with a file URI scheme.
# Strip it so that the value can be passed to open().
FILE_SCHEME = 'file://'

# Topic paths of the values we resolve, in both the transaction log and the
# effective configuration.
TP_CERTIFICATE_FILE_PATH = ['system', 'certificateFilePath']
TP_PRIVATE_KEY_PATH = ['system', 'privateKeyPath']

# Greengrass default file names, relative to the Greengrass root path. Used as a
# last resort when neither the transaction log nor the effective configuration
# holds a value.
DEFAULT_CERTIFICATE_FILE_NAME = 'thingCert.crt'
DEFAULT_PRIVATE_KEY_FILE_NAME = 'privKey.key'

class EffectiveConfig():
    """ Greengrass effective configuration.

    Resolves the certificate and private key paths using a three-tier fallback:

      1. The transaction log (config/config.tlog), which holds the authoritative
         running configuration. This is the only source that is correct on
         devices provisioned by Fleet Provisioning, where the effective
         configuration snapshot holds empty values.
      2. The effective configuration snapshot (config/effectiveConfig.yaml),
         which is correct on manually provisioned devices.
      3. The Greengrass defaults, relative to the Greengrass root path.
    """
    def __init__(self):
        # Get the Greengrass root path from our working directory
        if platform.system() == 'Windows':
            gg_root_path = os.getcwd().split('\\work')[0]
            effective_config_path = f'{gg_root_path}\\config\\effectiveConfig.yaml'
            transaction_log_path = f'{gg_root_path}\\config\\config.tlog'
        else:
            gg_root_path = os.getcwd().split('/work')[0]
            effective_config_path = f'{gg_root_path}/config/effectiveConfig.yaml'
            transaction_log_path = f'{gg_root_path}/config/config.tlog'

        self._gg_root_path = gg_root_path
        self._yaml = self._load_effective_config(effective_config_path)
        self._transaction_log = self._load_transaction_log(transaction_log_path)

    def certificate_file_path(self) -> str:
        """ Certificate file path configuration """
        return self._resolve(TP_CERTIFICATE_FILE_PATH, DEFAULT_CERTIFICATE_FILE_NAME)

    def private_key_path(self) -> str:
        """ Private key path configuration """
        return self._resolve(TP_PRIVATE_KEY_PATH, DEFAULT_PRIVATE_KEY_FILE_NAME)

    @staticmethod
    def _load_effective_config(file_path) -> dict:
        """ Loads the effective configuration snapshot.

        A missing or malformed snapshot is not fatal: the transaction log and the
        Greengrass defaults remain as sources.
        """
        try:
            with open(file_path, encoding='utf-8') as effective_config_file:
                loaded = yaml.safe_load(effective_config_file)
        except (OSError, yaml.YAMLError) as error:
            print(f'Could not read {file_path}: {repr(error)}.')
            loaded = None

        return loaded if isinstance(loaded, dict) else {}

    @staticmethod
    def _load_transaction_log(file_path) -> dict:
        """ Scans the Greengrass transaction log for the values we resolve.

        The log is newline delimited JSON: one object per line, appended to over
        the lifetime of the device. Each entry has a timestamp ('TS'), a topic
        path ('TP') and a value ('V'). Several entries may exist for one topic
        path, in which case the newest one is current.

        A missing, unreadable or partially malformed log is not fatal: blank and
        unparseable lines are skipped, and any topic path without a value simply
        falls through to the next source.
        """
        newest = {}

        try:
            with open(file_path, encoding='utf-8') as transaction_log_file:
                for line in transaction_log_file:
                    EffectiveConfig._collect_transaction_log_entry(line, newest)
        except OSError as error:
            print(f'Could not read {file_path}: {repr(error)}.')

        return { key: value for key, (_, value) in newest.items() }

    @staticmethod
    def _collect_transaction_log_entry(line, newest) -> None:
        """ Keeps the newest non-empty value per topic path of interest """
        line = line.strip()

        if not line:
            return

        try:
            entry = json.loads(line)
        except ValueError:
            # Truncated or otherwise malformed line. Greengrass owns this file,
            # so we skip whatever we don't understand.
            return

        if not isinstance(entry, dict):
            return

        topic_path = entry.get('TP')
        value = entry.get('V')
        timestamp = entry.get('TS')

        if topic_path not in (TP_CERTIFICATE_FILE_PATH, TP_PRIVATE_KEY_PATH):
            return
        if not isinstance(value, str) or not value:
            return
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            timestamp = 0

        key = EffectiveConfig._topic_path_key(topic_path)

        # On equal timestamps the later line wins, the log being append only.
        if key not in newest or timestamp >= newest[key][0]:
            newest[key] = (timestamp, value)

    @staticmethod
    def _topic_path_key(topic_path) -> str:
        """ Dictionary key for a topic path """
        return '/'.join(topic_path)

    def _resolve(self, topic_path, default_file_name) -> str:
        """ Resolves a configuration path from the transaction log, else the
        effective configuration snapshot, else the Greengrass default """
        value = self._transaction_log.get(EffectiveConfig._topic_path_key(topic_path), '')

        if not value:
            value = self._from_effective_config(topic_path)

        if not value:
            value = os.path.join(self._gg_root_path, default_file_name)

        return EffectiveConfig._strip_file_scheme(value)

    def _from_effective_config(self, topic_path) -> str:
        """ Reads a value from the effective configuration snapshot """
        node = self._yaml

        for key in topic_path:
            if not isinstance(node, dict):
                return ''
            node = node.get(key)

        return node if isinstance(node, str) else ''

    @staticmethod
    def _strip_file_scheme(value) -> str:
        """ Strips a leading file URI scheme, leaving a plain filesystem path.

        Values that are not file URIs, such as the PKCS#11 URIs of an HSM
        configuration, are returned unchanged.
        """
        if value.startswith(FILE_SCHEME):
            return value[len(FILE_SCHEME):]

        return value
