# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=R0902  # Allow more instance attributes

"""
Greengrass operations
"""

import logging
import sys
import os
import time
import uuid
import json
import boto3
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import SignatureAlgorithmOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
sys.path.append(f'{os.path.dirname(os.path.abspath(__file__))}/../..')
# pylint: disable=import-error
# pylint: disable=wrong-import-position
from libs.gdk_config import GdkConfig

JOB_TEMPLATE_NAME = 'AWSLabsCertificateRotator'
SHADOW_NAME = 'AWSLabsCertificateRotator'

KEY_ALGORITHMS = {
    'RSA-2048': { 'size': 2048, 'type': rsa.RSAPublicKey },
    'RSA-3072': { 'size': 3072, 'type': rsa.RSAPublicKey },
    'ECDSA-P256': { 'size': 256, 'type': ec.EllipticCurvePublicKey },
    'ECDSA-P384': { 'size': 384, 'type': ec.EllipticCurvePublicKey },
    'ECDSA-P521': { 'size': 521, 'type': ec.EllipticCurvePublicKey }
}

SIGNATURE_ALGORITHMS = {
    'SHA256WITHRSA': SignatureAlgorithmOID.RSA_WITH_SHA256,
    'SHA384WITHRSA': SignatureAlgorithmOID.RSA_WITH_SHA384,
    'SHA512WITHRSA': SignatureAlgorithmOID.RSA_WITH_SHA512,
    'SHA256WITHECDSA': SignatureAlgorithmOID.ECDSA_WITH_SHA256,
    'SHA384WITHECDSA': SignatureAlgorithmOID.ECDSA_WITH_SHA384,
    'SHA512WITHECDSA': SignatureAlgorithmOID.ECDSA_WITH_SHA512
}

class Greengrass():
    """ Greengrass operations """
    def __init__(self, thing_group_name):
        self._thing_group_name = thing_group_name
        self._logger = logging.getLogger( __name__ )
        self._gdk_config = GdkConfig()
        account = boto3.client('sts').get_caller_identity().get('Account')
        self._target_arn = f'arn:aws:iot:{self._gdk_config.region()}:{account}:thinggroup/{thing_group_name}'
        self._greengrassv2_client = boto3.client('greengrassv2', region_name=self._gdk_config.region())
        self._iot_client = boto3.client('iot', region_name=self._gdk_config.region())
        endpoint = self._iot_client.describe_endpoint(endpointType='iot:Jobs')['endpointAddress']
        self._iot_jobs_data_client = boto3.client('iot-jobs-data', endpoint_url=f'https://{endpoint}',
                                                    region_name=self._gdk_config.region())
        endpoint = self._iot_client.describe_endpoint(endpointType='iot:Data-ATS')['endpointAddress']
        self._iot_data_client = boto3.client('iot-data', endpoint_url=f'https://{endpoint}',
                                              region_name=self._gdk_config.region())

    def merge_configuration(self, key_algorithm, signing_algorithm):
        """ Merges new configuration for the certificate rotator component """
        # We expect this test suite to only be run after a new component
        # version has been deployed to the target ARN. So we have high
        # confidence that a deployment exists for the target ARN. And
        # we are interested in the latest deployment only.
        # Get the latest deployment for the specified target ARN.
        deployment_id = self._greengrassv2_client.list_deployments(
            targetArn=self._target_arn,
            historyFilter='LATEST_ONLY',
            maxResults=1
        )['deployments'][0]['deploymentId']
        self._logger.info('Current deployment ID: %s', deployment_id)

        # Get the details of the deployment
        deployment = self._get_deployment(deployment_id)
        self._logger.info('Deployment details: %s', deployment)

        # Update with the configuration to merge
        deployment['components'][self._gdk_config.name()].update({
            'configurationUpdate': {
                'merge': '{"keyAlgorithm": "' + key_algorithm + '", "signingAlgorithm": "' + signing_algorithm + '"}'
            }
        })
        self._logger.info('Updated deployment details: %s', deployment)

        # Now create a deployment to send the configuration change to the target ARN
        deployment_id = self._greengrassv2_client.create_deployment(
            targetArn=deployment['targetArn'],
            deploymentName=deployment['deploymentName'],
            components=deployment['components']
        )['deploymentId']
        self._logger.info('Created deployment ID: %s', deployment_id)

        iot_job_id = self._get_deployment(deployment_id)['iotJobId']
        (succeeded, failed, timed_out) = self.wait_for_job_to_finish(iot_job_id)

        return succeeded > 0 and failed == 0 and timed_out == 0

    def create_rotation_job(self):
        """ Creates a job from the job template, to rotate the certificates of the devices in the group """
        job_template_arn = self._iot_client.describe_job_template(jobTemplateId=JOB_TEMPLATE_NAME)['jobTemplateArn']

        job_id = f'{JOB_TEMPLATE_NAME}-{uuid.uuid4().hex[:8].lower()}'
        self._iot_client.create_job(jobId=job_id,
                                    jobTemplateArn=job_template_arn,
                                    targets=[self._target_arn])
        self._logger.info('Created job ID: %s', job_id)

        return job_id

    def wait_for_job_to_finish(self, job_id):
        """ Waits for the job to complete """
        done = False
        job_process_details = None

        while not done:
            job_process_details = self._iot_client.describe_job(jobId=job_id)['job']['jobProcessDetails']
            started = job_process_details['numberOfQueuedThings'] > 0 or\
                        job_process_details['numberOfInProgressThings'] > 0 or\
                        job_process_details['numberOfFailedThings'] > 0 or\
                        job_process_details['numberOfRejectedThings'] > 0 or\
                        job_process_details['numberOfTimedOutThings'] > 0 or\
                        job_process_details['numberOfSucceededThings'] > 0
            done = started and job_process_details['numberOfQueuedThings'] == 0 and\
                    job_process_details['numberOfInProgressThings'] == 0

            time.sleep(2)

        self._logger.info('Last job process details: %s', job_process_details)

        return (job_process_details['numberOfSucceededThings'],
                    job_process_details['numberOfFailedThings'],
                    job_process_details['numberOfTimedOutThings'])

    def get_certificates(self):
        """ Gets the current core device certificates as a list of principals """
        certificates = []
        things = self._iot_client.list_things_in_thing_group(thingGroupName=self._thing_group_name)['things']

        for thing in things:
            self._logger.info('Getting certificates for Thing: %s', thing)
            principals = self._iot_client.list_thing_principals(thingName=thing)['principals']
            self._logger.info('Principals: %s', principals)

            if len(principals) == 1 and 'cert' in principals[0]:
                certificates.append(principals[0])
            else:
                self._logger.error('Invalid principals')

        return certificates

    def check_certificates(self, ca_is_aws_iot, key_algorithm, signature_algorithm):
        """ Checks the new certificates """
        things = self._iot_client.list_things_in_thing_group(thingGroupName=self._thing_group_name)['things']

        valid = True
        for thing in things:
            valid &= self._check_thing_certificate(thing, ca_is_aws_iot, key_algorithm, signature_algorithm)

        return valid

    def deactivate_new_certificates(self):
        """ Deactivates new certificates as they're created so reconnection will fail, triggering a rollback """
        things = self._iot_client.list_things_in_thing_group(thingGroupName=self._thing_group_name)['things']

        while len(things) > 0:
            self._logger.info('Things still processing: %s', len(things))

            for thing in things:
                try:
                    shadow_response = self._iot_data_client.get_thing_shadow(
                        thingName=thing,
                        shadowName=SHADOW_NAME
                    )
                except self._iot_data_client.exceptions.ResourceNotFoundException:
                    self._logger.info('Shadow not available yet for: %s', thing)
                    continue

                shadow = json.loads(shadow_response['payload'].read())

                # if the shadow exists, the progress should already be "created", but we confirm
                if shadow['state']['reported']['progress'] == 'created':
                    new_cert_id = shadow['state']['reported']['newCertificateId']

                    self._logger.info('Deactivating new certificate for: %s', thing)
                    self._iot_client.update_certificate(certificateId=new_cert_id, newStatus='INACTIVE')
                    things.remove(thing)

            # Pause so we can't hit API limits
            time.sleep(0.1)

    def remove_windows_devices_from_thing_group(self):
        """ Removes any Windows core devices from the thing group """
        core_devices = self._greengrassv2_client.list_core_devices(thingGroupArn=self._target_arn)['coreDevices']
        removed_things = []

        for device in core_devices:
            thing_name = device['coreDeviceThingName']
            platform = self._greengrassv2_client.get_core_device(coreDeviceThingName=thing_name)['platform']
            if 'windows' in platform:
                self._logger.info('Removing core device %s from Thing group', thing_name)
                self._iot_client.remove_thing_from_thing_group(thingGroupName=self._thing_group_name,
                                                                thingName=thing_name)
                removed_things.append(thing_name)

        return removed_things

    def remove_pkcs_devices_from_thing_group(self):
        """ Removes any core devices using PKCS/HSM/TPM from the thing group """
        core_devices = self._greengrassv2_client.list_core_devices(thingGroupArn=self._target_arn)['coreDevices']
        removed_things = []

        for device in core_devices:
            thing_name = device['coreDeviceThingName']
            response = self._greengrassv2_client.list_installed_components(coreDeviceThingName=thing_name)
            for component in response['installedComponents']:
                if component['componentName'] == 'aws.greengrass.crypto.Pkcs11Provider':
                    self._logger.info('Removing core device %s from Thing group', thing_name)
                    self._iot_client.remove_thing_from_thing_group(thingGroupName=self._thing_group_name,
                                                                    thingName=thing_name)
                    removed_things.append(thing_name)

        return removed_things

    def add_devices_to_thing_group(self, removed_things):
        """ Restores core devices to the thing group """
        for thing in removed_things:
            self._logger.info('Adding core device %s to Thing group', thing)
            self._iot_client.add_thing_to_thing_group(thingGroupName=self._thing_group_name,
                                                            thingName=thing)

    def _check_thing_certificate(self, thing_name, ca_is_aws_iot, key_algorithm, signature_algorithm):
        """ Checks the new certificate attached to a Thing """
        valid = False
        self._logger.info('Checking certificate for Thing: %s', thing_name)

        principals = self._iot_client.list_thing_principals(thingName=thing_name)['principals']
        self._logger.info('Principals: %s', principals)

        if len(principals) == 1 and 'cert' in principals[0]:
            cert_id = principals[0].split('/')[-1]
            cert = self._iot_client.describe_certificate(certificateId=cert_id)['certificateDescription']
            self._logger.info('Certificate: %s', cert)

            certificate = load_pem_x509_certificate(cert['certificatePem'].encode('utf-8'))

            issuer_is_aws_iot = False
            for attribute in certificate.issuer:
                self._logger.info('Certificate issuer attribute: %s', attribute)
                if 'Amazon Web Services' in attribute.value:
                    issuer_is_aws_iot = True

            self._logger.info('Signature algorithm: %s', certificate.signature_algorithm_oid)

            public_key = certificate.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                self._logger.info('Public key is RSA type with size %d', public_key.key_size)
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                self._logger.info('Public key is EC type with size %d', public_key.key_size)
            else:
                self._logger.info('Public key is UNKNOWN type')

            valid = ca_is_aws_iot == issuer_is_aws_iot and\
                    certificate.signature_algorithm_oid == SIGNATURE_ALGORITHMS[signature_algorithm] and\
                    isinstance(public_key, KEY_ALGORITHMS[key_algorithm]['type']) and\
                    (isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)) and\
                     public_key.key_size == KEY_ALGORITHMS[key_algorithm]['size'])

        return valid

    def _get_deployment(self, deployment_id):
        """ Gets the deployment, allowing for eventual consistency of the API """
        deployment = None
        snapshot = time.time()

        while deployment is None:
            try:
                deployment = self._greengrassv2_client.get_deployment(deploymentId=deployment_id)
            except self._greengrassv2_client.exceptions.ResourceNotFoundException as e:
                self._logger.info('Deployment %s not yet found', deployment_id)
                if (time.time() - snapshot) < 10:
                    time.sleep(1)
                else:
                    raise e

        return deployment
