# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Backend operations
"""

import logging
import sys
import os
import time
import boto3
sys.path.append(f'{os.path.dirname(os.path.abspath(__file__))}/../..')
# pylint: disable=import-error
# pylint: disable=wrong-import-position
from libs.gdk_config import GdkConfig

COMMIT_RULE_NAME = 'AWSLabsCertificateRotatorCommitCertificate'
CREATE_LAMBDA_NAME = 'AWSLabsCertificateRotatorCreateCertificate'
CREATE_RULE_NAME = 'AWSLabsCertificateRotatorCreateCertificate'

class Backend():
    """ Backend operations """
    def __init__(self, pca_ca_id):
        self._logger = logging.getLogger( __name__ )
        self._gdk_config = GdkConfig()
        account = boto3.client('sts').get_caller_identity().get('Account')
        self._pca_ca_arn = f'arn:aws:acm-pca:{self._gdk_config.region()}:{account}:certificate-authority/{pca_ca_id}'
        self._lambda_client = boto3.client('lambda', region_name=self._gdk_config.region())
        self._acm_pca_client = boto3.client('acm-pca', region_name=self._gdk_config.region())
        self._iot_client = boto3.client('iot', region_name=self._gdk_config.region())

    def disable_create(self):
        """ Disable create by disabling the rule """
        self._iot_client.disable_topic_rule(ruleName=CREATE_RULE_NAME)

    def enable_create(self):
        """ Enable create by enabling the rule """
        self._iot_client.enable_topic_rule(ruleName=CREATE_RULE_NAME)

    def disable_commit(self):
        """ Disable commit by disabling the rule """
        self._iot_client.disable_topic_rule(ruleName=COMMIT_RULE_NAME)

    def enable_commit(self):
        """ Enable commit by enabling the rule """
        self._iot_client.enable_topic_rule(ruleName=COMMIT_RULE_NAME)

    def enable_private_ca(self):
        """ Enable AWS Private CA certificate issuance """
        self._update_environment_variable('PCA_CA_ARN', self._pca_ca_arn)

    def disable_private_ca(self):
        """ Disable AWS Private CA certificate issuance """
        self._update_environment_variable('PCA_CA_ARN', '')

    def set_private_ca_signing_algorithm(self, signing_algorithm):
        """ Sets AWS Private CA certificate issuance signing algorithm """
        self._update_environment_variable('PCA_SIGNING_ALGORITHM', signing_algorithm)

    def private_ca_key_and_signing_algorithms_match(self, signing_algorithm):
        """ Gets the family of the AWS Private CA key algorithm """
        response = self._acm_pca_client.describe_certificate_authority(CertificateAuthorityArn=self._pca_ca_arn)
        self._logger.info(response)
        family = response['CertificateAuthority']['CertificateAuthorityConfiguration']['KeyAlgorithm'].split('_')[0]
        return family in signing_algorithm

    def _update_environment_variable(self, key, value):
        """ Update a Lambda environment variable """
        configuration = self._lambda_client.get_function_configuration(FunctionName=CREATE_LAMBDA_NAME)
        self._logger.info(configuration)
        configuration['Environment']['Variables'][key] = value
        self._logger.info(configuration)
        self._lambda_client.update_function_configuration(FunctionName=CREATE_LAMBDA_NAME,
                                                            Environment=configuration['Environment'])

        configuration = self._lambda_client.get_function_configuration(FunctionName=CREATE_LAMBDA_NAME)
        self._logger.info(configuration['LastUpdateStatus'])
        while configuration['LastUpdateStatus'] == 'InProgress':
            time.sleep(0.1)
            configuration = self._lambda_client.get_function_configuration(FunctionName=CREATE_LAMBDA_NAME)
            self._logger.info(configuration['LastUpdateStatus'])
