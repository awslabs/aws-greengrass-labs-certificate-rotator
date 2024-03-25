# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Public Key Infrastructure (PKI) for file storage on disk
"""

import os
import shutil
import traceback
import typing
from cryptography.x509 import CertificateSigningRequestBuilder, load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from pki import PKI
from awsiot.greengrasscoreipc.clientv2 import GreengrassCoreIPCClientV2

class RsaKeyAlgorithm(typing.TypedDict):
    """ Types hints for RSA key algorithm dictionary """
    size: int
    type: typing.Type[rsa.RSAPrivateKey]

class EcKeyAlgorithm(typing.TypedDict):
    """ Types hints for EC key algorithm dictionary """
    curve: typing.Union[ec.SECP256R1, ec.SECP384R1, ec.SECP521R1]
    type: typing.Type[ec.EllipticCurvePrivateKey]

KEY_ALGORITHMS: typing.Dict[str, typing.Union[RsaKeyAlgorithm, EcKeyAlgorithm]] = {
    'RSA-2048': { 'size': 2048, 'type': rsa.RSAPrivateKey },
    'RSA-3072': { 'size': 3072, 'type': rsa.RSAPrivateKey },
    'ECDSA-P256': { 'curve': ec.SECP256R1(), 'type': ec.EllipticCurvePrivateKey },
    'ECDSA-P384': { 'curve': ec.SECP384R1(), 'type': ec.EllipticCurvePrivateKey },
    'ECDSA-P521': { 'curve': ec.SECP521R1(), 'type': ec.EllipticCurvePrivateKey }
}

class SigningAlgorithm(typing.TypedDict):
    """ Types hints for signing algorithms dictionary """
    hash: typing.Union[hashes.SHA256, hashes.SHA384, hashes.SHA512]
    type: typing.Union[typing.Type[rsa.RSAPrivateKey], typing.Type[ec.EllipticCurvePrivateKey]]
    padding: typing.Optional[padding.PSS]

SIGNING_ALGORITHMS: typing.Dict[str, SigningAlgorithm] = {
    'SHA256WITHRSA': { 'hash': hashes.SHA256(), 'type': rsa.RSAPrivateKey, 'padding': None },
    'SHA384WITHRSA': { 'hash': hashes.SHA384(), 'type': rsa.RSAPrivateKey, 'padding': None },
    'SHA512WITHRSA': { 'hash': hashes.SHA512(), 'type': rsa.RSAPrivateKey, 'padding': None },

    # Use the maximum salt length, that matches the hash length
    'SHA256WITHRSAANDMGF1': { 'hash': hashes.SHA256(), 'type': rsa.RSAPrivateKey,
                             'padding': padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32) },
    'SHA384WITHRSAANDMGF1': { 'hash': hashes.SHA384(), 'type': rsa.RSAPrivateKey,
                             'padding': padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48) },
    'SHA512WITHRSAANDMGF1': { 'hash': hashes.SHA512(), 'type': rsa.RSAPrivateKey,
                             'padding': padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64) },

    'ECDSA-WITH-SHA256': { 'hash': hashes.SHA256(), 'type': ec.EllipticCurvePrivateKey, 'padding': None },
    'ECDSA-WITH-SHA384': { 'hash': hashes.SHA384(), 'type': ec.EllipticCurvePrivateKey, 'padding': None },
    'ECDSA-WITH-SHA512': { 'hash': hashes.SHA512(), 'type': ec.EllipticCurvePrivateKey, 'padding': None }
}

class PKIFile(PKI):
    """ Public Key Infrastructure (PKI) for file storage on disk """

    PRIVATE_KEY_BAK = 'private_key.bak'
    CERTIFICATE_BAK = 'certificate.bak'

    def __init__(self, ipc_client: GreengrassCoreIPCClientV2):
        super().__init__(ipc_client, KEY_ALGORITHMS, SIGNING_ALGORITHMS)
        print('Using PKIFile')
        self._private_key_backup = f'{os.getcwd()}/{PKIFile.PRIVATE_KEY_BAK}'
        self._certificate_backup = f'{os.getcwd()}/{PKIFile.CERTIFICATE_BAK}'
        self._new_private_key_pem = ''

    def create_csr(self) -> typing.Optional[str]:
        """ Creates a certificate signing request from the private key """
        try:
            with open(self._effective_config.certificate_file_path(), 'rb') as certificate_file:
                certificate = load_pem_x509_certificate(certificate_file.read())

            print(f'Generating new private key using algorithm {self._config.key_algorithm}')

            # Generate a new private key. The private key family must match the signing algorithm.
            new_private_key: typing.Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
            if KEY_ALGORITHMS[self._config.key_algorithm]['type'] == rsa.RSAPrivateKey:
                size = KEY_ALGORITHMS[self._config.key_algorithm]['size'] # type: ignore
                new_private_key = rsa.generate_private_key(public_exponent=65537, key_size=size)
            else:
                curve = KEY_ALGORITHMS[self._config.key_algorithm]['curve'] # type: ignore
                new_private_key = ec.generate_private_key(curve)

            print(f'Signing the CSR using algorithm {self._config.signing_algorithm}')

            if not isinstance(new_private_key, SIGNING_ALGORITHMS[self._config.signing_algorithm]['type']):
                # pylint: disable=broad-exception-raised
                # We catch this exception ourselves
                raise Exception('Signing algorithm doesn\'t match private key family')

            # Generate a CSR and sign it with the private key. Use the same
            # subject name attributes as the existing certificate.
            new_csr = CertificateSigningRequestBuilder().\
                    subject_name(certificate.subject).\
                    sign(new_private_key, SIGNING_ALGORITHMS[self._config.signing_algorithm]['hash'],
                         rsa_padding=SIGNING_ALGORITHMS[self._config.signing_algorithm]['padding'])

            # Get the private key format. aws-crt-io demands PKCS#1 format for the private key when running
            # under Windows. A PKCS#1 RSA key is also what AWS IoT CreateKeysAndCertificate produces.
            if isinstance(new_private_key, rsa.RSAPrivateKey):
                # This produces PKCS#1 format
                key_format = serialization.PrivateFormat.TraditionalOpenSSL
            else:
                # This produces PCKS#8 format (the BEGIN header does not specify the encryption family)
                key_format = serialization.PrivateFormat.PKCS8

            # Serialize the private key and the CSR
            self._new_private_key_pem = new_private_key.private_bytes(
                                                                encoding=serialization.Encoding.PEM,
                                                                format=key_format,
                                                                encryption_algorithm=serialization.NoEncryption()
                                                                ).decode('utf-8')
            new_csr_pem = new_csr.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')

        except Exception as error:
            print(f'Error creating the CSR: {repr(error)}.')
            traceback.print_exc()
            new_csr_pem = None

        return new_csr_pem

    def rotate(self, new_cert_pem: str) -> bool:
        """ Rotates from the old to new certificate and private key """
        try:
            certificate_file_path = self._effective_config.certificate_file_path()
            private_key_path = self._effective_config.private_key_path()

            shutil.copy2(certificate_file_path, self._certificate_backup)
            shutil.copy2(private_key_path, self._private_key_backup)

            with open(certificate_file_path, 'w', encoding='utf-8') as cert_file:
                cert_file.write(new_cert_pem)
            with open(private_key_path, 'w', encoding='utf-8') as key_file:
                key_file.write(self._new_private_key_pem)

            success = True

        except Exception as error:
            print(f'Error rotating the certificate and private key: {repr(error)}.')
            traceback.print_exc()
            success = False

        return success

    def rollback(self) -> bool:
        """ Rolls back to the old certificate and private key """
        try:
            certificate_file_path = self._effective_config.certificate_file_path()
            private_key_path = self._effective_config.private_key_path()

            shutil.copy2(self._certificate_backup, certificate_file_path)
            shutil.copy2(self._private_key_backup, private_key_path)

            self.delete_backup()
            success = True

        except Exception as error:
            print(f'Error rolling back the certificate: {repr(error)}.')
            traceback.print_exc()
            success = False

        return success

    def backup_exists(self) -> bool:
        """ Indicates whether the backup certificate and private key exists """
        # We expect neither or both to exist. However, if we lost power, rebooted or restarted
        # at an inopportune moment, it may be that only one exists.
        return os.path.exists(self._certificate_backup) and os.path.exists(self._private_key_backup)

    def delete_backup(self) -> None:
        """ Deletes the backup certificate and private key """
        os.remove(self._certificate_backup)
        os.remove(self._private_key_backup)
