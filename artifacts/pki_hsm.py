# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Public Key Infrastructure (PKI) for HSM storage
"""

import platform
import sys
import traceback
import typing
from cryptography.hazmat.primitives import hashes
from pki import PKI
from awsiot.greengrasscoreipc.clientv2 import GreengrassCoreIPCClientV2

# Greengrass HSM/PKCS is only supported on Linux. And the python-pkcs11
# module requires Python 3.7 or above. So we don't import these
# packages unless we are in a system that can actually use them.
if platform.system() == 'Linux' and (sys.version_info.major > 3 or\
    (sys.version_info.major == 3 and sys.version_info.minor >= 7)):
    import pkcs11
    from pkcs11 import Attribute, ObjectClass, Mechanism, KeyType, MechanismFlag, MGF
    from pkcs11.util.x509 import decode_x509_certificate
    from pkcs11.util.rsa import encode_rsa_public_key
    from pkcs11.util.ec import encode_ecdsa_signature, encode_named_curve_parameters
    from asn1crypto import pem, x509, csr, keys, core, algos

    class RsaKeyAlgorithm(typing.TypedDict):
        """ Types hints for RSA key algorithm dictionary """
        size: int
        type: KeyType

    class EcKeyAlgorithm(typing.TypedDict):
        """ Types hints for EC key algorithm dictionary """
        curve: str
        type: KeyType

    KEY_ALGORITHMS: typing.Dict[str, typing.Union[RsaKeyAlgorithm, EcKeyAlgorithm]] = {
        'RSA-2048': { 'size': 2048, 'type': KeyType.RSA },
        'RSA-3072': { 'size': 3072, 'type': KeyType.RSA },
        'ECDSA-P256': { 'curve': 'secp256r1', 'type': KeyType.EC },
        'ECDSA-P384': { 'curve': 'secp384r1', 'type': KeyType.EC },
        'ECDSA-P521': { 'curve': 'secp521r1', 'type': KeyType.EC }
    }

    class Params(algos.RSASSAPSSParams):
        """ RSA PSS parameters for ASN.1 CSR creation """
        def __init__(self, hash_alg: str, salt_size: int):
            super().__init__({
                'hash_algorithm': algos.DigestAlgorithm({'algorithm': hash_alg}),
                'mask_gen_algorithm': algos.MaskGenAlgorithm({
                    'algorithm': algos.MaskGenAlgorithmId('mgf1'),
                    'parameters': {
                        'algorithm': algos.DigestAlgorithmId(hash_alg),
                    }
                }),
                'salt_length': algos.Integer(salt_size),
                'trailer_field': algos.TrailerField(1)
            })

    class SigningAlgorithm(typing.TypedDict):
        """ Types hints for signing algorithms dictionary """
        name: str
        params: typing.Optional[Params]
        mech: Mechanism
        mech_param: typing.Optional[typing.Tuple[Mechanism, MGF, int]]
        type: KeyType

    SIGNING_ALGORITHMS: typing.Dict[str, SigningAlgorithm] = {
        'SHA256WITHRSA': { 'name': 'sha256_rsa', 'params': None, 'mech': Mechanism.SHA256_RSA_PKCS,
                            'mech_param': None, 'type': KeyType.RSA },
        'SHA384WITHRSA': { 'name': 'sha384_rsa', 'params': None, 'mech': Mechanism.SHA384_RSA_PKCS,
                            'mech_param': None, 'type': KeyType.RSA },
        'SHA512WITHRSA': { 'name': 'sha512_rsa', 'params': None, 'mech': Mechanism.SHA512_RSA_PKCS,
                            'mech_param': None, 'type': KeyType.RSA },

        # Use the maximum salt length, that matches the hash length
        'SHA256WITHRSAANDMGF1': { 'name': 'rsassa_pss', 'params': Params('sha256', 32), 
                                    'mech': Mechanism.SHA256_RSA_PKCS_PSS,
                                    'mech_param': (Mechanism.SHA256, MGF.SHA256, 32),
                                    'type': KeyType.RSA },
        'SHA384WITHRSAANDMGF1': { 'name': 'rsassa_pss', 'params': Params('sha384', 48),
                                    'mech': Mechanism.SHA384_RSA_PKCS_PSS,
                                    'mech_param': (Mechanism.SHA384, MGF.SHA384, 48),
                                    'type': KeyType.RSA },
        'SHA512WITHRSAANDMGF1': { 'name': 'rsassa_pss', 'params': Params('sha512', 64),
                                    'mech': Mechanism.SHA512_RSA_PKCS_PSS,
                                    'mech_param': (Mechanism.SHA512, MGF.SHA512, 64),
                                    'type': KeyType.RSA },

        'ECDSA-WITH-SHA256': { 'name': 'sha256_ecdsa', 'params': None, 'mech': Mechanism.ECDSA,
                                'mech_param': None, 'type': KeyType.EC },
        'ECDSA-WITH-SHA384': { 'name': 'sha384_ecdsa', 'params': None, 'mech': Mechanism.ECDSA,
                                'mech_param': None, 'type': KeyType.EC },
        'ECDSA-WITH-SHA512': { 'name': 'sha512_ecdsa', 'params': None, 'mech': Mechanism.ECDSA,
                                'mech_param': None, 'type': KeyType.EC }
    }

    HASHES = { 'sha256_ecdsa': hashes.SHA256(), 'sha384_ecdsa': hashes.SHA384(), 'sha512_ecdsa': hashes.SHA512() }

class PKIHSM(PKI):
    """ Public Key Infrastructure (PKI) for HSM storage """

    SUFFIX_PENDING = 1
    SUFFIX_BACKUP = 2

    def __init__(self, ipc_client: GreengrassCoreIPCClientV2):
        super().__init__(ipc_client, KEY_ALGORITHMS, SIGNING_ALGORITHMS)
        self._label = self._effective_config.certificate_file_path().split('=')[1].split(';')[0]
        print(f'Using PKIHSM. PKCS object label = {self._label}')
        self._label_backup = f'{self._label}.bak'
        self._label_pending = f'{self._label}.pending'
        self._pkcs_config = PKIHSM.get_pkcs_configuration(ipc_client)

    def create_csr(self) -> typing.Optional[str]:
        """ Creates a certificate signing request from a new private key """
        # Read/write session since we will modify the token contents
        session = self._get_session(rw=True)

        try:
            # Before creating a new pending keypair, first we ensure to delete any vestige that might
            # exist if we lost power, rebooted or restarted at an inopportune moment.
            self._delete_pending_keypair(session)

            print(f'Generating a pending new key pair using algorithm {self._config.key_algorithm}')
            pending_pub_key, pending_priv_key = self._create_pending_keypair(session)

            print('Constructing the CSR information from the pending new public key')
            info = self._create_csr_info(session, pending_pub_key)

            print('Destroying the pending public key in the HSM token')
            pending_pub_key.destroy()

            # For an EC private key, SoftHSM and Microchip ATECC608B do not support SHA
            # hashing as part of a single signing call. In other words, they do not
            # support the mechanisms ECDSA_SHA256, ECDSA_SHA384 and ECDSA_SHA512. So we
            # hash externally and only ask the HSM to sign using ECDSA mechanism.
            if pending_priv_key.key_type == KeyType.EC:
                print('Hashing the CSR information prior to signing in the HSM')
                digest = hashes.Hash(HASHES[SIGNING_ALGORITHMS[self._config.signing_algorithm]['name']])
                digest.update(info.dump())
                data = digest.finalize()
            else:
                data = info.dump()

            # Sign the CSR information, by using the private key inside the HSM
            print(f'Signing the CSR using algorithm {self._config.signing_algorithm}')
            mech = SIGNING_ALGORITHMS[self._config.signing_algorithm]['mech']
            mech_param = SIGNING_ALGORITHMS[self._config.signing_algorithm]['mech_param']
            signature = pending_priv_key.sign(data, mechanism=mech, mechanism_param=mech_param)

            # For ECDSA keys, PKCS #11 outputs the two parameters (r & s)
            # as two concatenated biginteger of the same length. Encode them.
            if pending_priv_key.key_type == KeyType.EC:
                signature = encode_ecdsa_signature(signature)

            # Now build the final CSR
            algorithm = SIGNING_ALGORITHMS[self._config.signing_algorithm]['name']
            params = SIGNING_ALGORITHMS[self._config.signing_algorithm]['params']
            new_csr = csr.CertificationRequest({'certification_request_info': info,
                                                'signature_algorithm': {
                                                    'algorithm': algorithm,
                                                    'parameters': params
                                                },
                                                'signature': signature})

            new_csr_pem = pem.armor('CERTIFICATE REQUEST', new_csr.dump()).decode('utf-8')

        except Exception as error:
            print(f'Error creating the CSR: {repr(error)}.')
            traceback.print_exc()
            new_csr_pem = None

        session.close()

        return new_csr_pem

    def rotate(self, new_cert_pem: str) -> bool:
        """ Rotates from the old to new certificate and private key """
        # Read/write session since we will modify the token contents
        session = self._get_session(rw=True)

        try:
            # Get the objects of the current certificate and private key
            cert_object = self._get_cert_object(session, self._label)
            priv_key = self._get_key(session, ObjectClass.PRIVATE_KEY, self._label)

            # Remember the ID of the private key
            priv_key_id = priv_key.id

            # Get the pending private key
            pending_priv_key = self._get_key(session, ObjectClass.PRIVATE_KEY, self._label_pending)

            # Before creating new backups, first we ensure to delete any vestige backups that might
            # exist if we lost power, rebooted or restarted at an inopportune moment.
            self._delete_backup(session)

            print('Backing up the current certificate and private key objects in the HSM token')
            print(cert_object[Attribute.ID])
            cert_object.copy({Attribute.LABEL: self._label_backup,
                                Attribute.ID: self._get_temp_id(cert_object[Attribute.ID], PKIHSM.SUFFIX_BACKUP)})
            priv_key.copy({Attribute.LABEL: self._label_backup,
                            Attribute.ID: self._get_temp_id(priv_key.id, PKIHSM.SUFFIX_BACKUP)})

            # Setup a new object for the new certificate, preserving the label and ID of the old
            _, _, der_bytes = pem.unarmor(new_cert_pem.encode('utf-8'))
            new_cert_object = decode_x509_certificate(der_bytes)
            new_cert_object[Attribute.LABEL] = cert_object[Attribute.LABEL]
            new_cert_object[Attribute.ID] = cert_object[Attribute.ID]
            new_cert_object[Attribute.TOKEN] = True

            print('Destroying the old certificate and creating the new certificate in the HSM token')
            cert_object.destroy()
            session.create_object(new_cert_object)

            print('Destroying the old private key and the new private key in the HSM token')
            priv_key.destroy()
            pending_priv_key.copy({Attribute.LABEL: self._label, Attribute.ID: priv_key_id})

            print('Destroying the pending private key in the HSM token')
            pending_priv_key.destroy()

            success = True

        except Exception as error:
            print(f'Error rotating the certificate and private key: {repr(error)}.')
            traceback.print_exc()
            success = False

        session.close()

        return success

    def rollback(self) -> bool:
        """ Rolls back to the old certificate and private key """
        # Read/write session since we will modify the token contents
        session = self._get_session(rw=True)

        try:
            # Get the objects of the new and backup certificates and keys. The two backups
            # should exists because this method should only be called when they do.
            cert_object = self._get_cert_object(session, self._label)
            priv_key = self._get_key(session, ObjectClass.PRIVATE_KEY, self._label)
            backup_cert_object = self._get_cert_object(session, self._label_backup)
            backup_priv_key = self._get_key(session, ObjectClass.PRIVATE_KEY, self._label_backup)

            existing_id = None

            # Normally there should be a new certificate and a new private key.
            # However, it's possible to lose power, suffer an error, restart or
            # reboot during the rotation. Thus we might have the backups but be
            # missing one out of the new private certificate or new private key
            # (and this will have triggered this rollback attempt).
            if cert_object is not None:
                # Remember the ID of the certificate (which is also the ID of the private key)
                existing_id = cert_object[Attribute.ID]
                print('Destroying the new certificate object in the HSM token')
                cert_object.destroy()
            if priv_key is not None:
                # Remember the ID of the private key (which is also the ID of the private key)
                existing_id = priv_key.id
                print('Destroying the new private key object in the HSM token')
                priv_key.destroy()

            print('Copying the backup certificate and private key objects in the HSM token')
            backup_cert_object.copy({Attribute.LABEL: self._label, Attribute.ID: existing_id})
            backup_priv_key.copy({Attribute.LABEL: self._label, Attribute.ID: existing_id})

            print('Destroying the backup certificate and private key objects in the HSM token')
            backup_cert_object.destroy()
            backup_priv_key.destroy()

            success = True

        except Exception as error:
            print(f'Error rolling back the certificate and private key: {repr(error)}.')
            traceback.print_exc()
            success = False

        session.close()

        return success

    def backup_exists(self) -> bool:
        """ Indicates whether the backup certificate and private key exists """
        # Read-only session since we won't modify the token contents
        session = self._get_session(rw=False)

        # Try to load the backup certificate and private key
        backup_cert_object = self._get_cert_object(session, self._label_backup)
        backup_priv_key = self._get_key(session, ObjectClass.PRIVATE_KEY, self._label_backup)

        session.close()

        # We expect neither or both to exist. However, if we lost power, rebooted or restarted
        # at an inopportune moment, it may be that only one exists.
        return backup_cert_object is not None and backup_priv_key is not None

    def delete_backup(self) -> None:
        """ Deletes the backup certificate and private key """
        # Read/write session since we will modify the token contents
        session = self._get_session(rw=True)

        self._delete_backup(session)

        session.close()

    def _get_slot(self):
        """ Gets the configured PKCS slot """
        lib = pkcs11.lib(self._pkcs_config['library'])
        slots = lib.get_slots(token_present=True)
        found_slot = None

        # Find the slot identified in the PKCS component configuration
        for slot in slots:
            if slot.slot_id == self._pkcs_config['slot']:
                found_slot = slot
                break

        return found_slot

    def _get_session(self, rw=False):
        """ Gets a session to the token from the configured PKCS slot """
        slot = self._get_slot()
        token = slot.get_token()
        print(f'Found slot {slot}. Token = {token}')

        session = token.open(rw, user_pin=self._pkcs_config['userPin'])

        return session

    def _get_cert_object(self, session, label):
        """ Gets the certificate from the configured PKCS slot and token """
        # There should only ever be at most one certificate object in the token
        # that matches the given label.
        cert_object = None
        for cert_object in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE,
                                                Attribute.LABEL: label}):
            pass

        return cert_object

    def _get_key(self, session, object_class, label):
        try:
            key = session.get_key(object_class=object_class, label=label)
        except Exception:
            key = None

        return key

    def _create_pending_keypair(self, session):
        """ Creates a pending new key pair using the configured key algorithm """
        # Get the existing private key (there should only be one with this label)
        priv_key = self._get_key(session, ObjectClass.PRIVATE_KEY, self._label)

        # Derive an ID for the pending private key from the existing private key ID
        pending_id = self._get_temp_id(priv_key.id, PKIHSM.SUFFIX_PENDING)

        # Generate a pending new key pair, retaining the ID of the old key.
        if KEY_ALGORITHMS[self._config.key_algorithm]['type'] == KeyType.RSA:
            print('Creating RSA key pair')
            size = KEY_ALGORITHMS[self._config.key_algorithm]['size']
            public, private = session.generate_keypair(key_type=KeyType.RSA, key_length=size,
                                                        id=pending_id, label=self._label_pending, store=True)
        else:
            print('Creating EC key pair')
            curve = KEY_ALGORITHMS[self._config.key_algorithm]['curve']
            parameters = session.create_domain_parameters(KeyType.EC, {
                Attribute.EC_PARAMS: encode_named_curve_parameters(curve),
            }, local=True)
            cap = MechanismFlag.SIGN|MechanismFlag.DECRYPT|MechanismFlag.UNWRAP
            public, private = parameters.generate_keypair(id=pending_id, label=self._label_pending,
                                                                    store=True, capabilities=cap)

        return public, private

    def _delete_pending_keypair(self, session):
        """ Deletes the pending key pair """
        # Try to load the pending key pair
        pending_pub_key = self._get_key(session, ObjectClass.PUBLIC_KEY, self._label_pending)
        pending_priv_key = self._get_key(session, ObjectClass.PRIVATE_KEY, self._label_pending)

        if pending_pub_key is not None:
            print('Destroying the pending public key in the HSM token')
            pending_pub_key.destroy()
        if pending_priv_key is not None:
            print('Destroying the pending private key in the HSM token')
            pending_priv_key.destroy()

    def _create_csr_info(self, session, pending_pub_key):
        """ Constructs the CSR information from the pending new public key and the existing certificate """
        # Get the object of the current certificate
        cert_object = self._get_cert_object(session, self._label)

        # Load a certificate object from the DER-encoded value
        cert = x509.Certificate.load(cert_object[Attribute.VALUE])

        # Setup the public key information ready to create the CSR info.
        if pending_pub_key.key_type == KeyType.RSA:
            print('Constructing CSR with RSA public key')
            algorithm_name = 'rsa'
            parameters = core.Null
            public_key = keys.RSAPublicKey.load(encode_rsa_public_key(pending_pub_key))
        else:
            print('Constructing CSR with EC public key')
            algorithm_name = 'ec'
            parameters = keys.ECDomainParameters.load(pending_pub_key[Attribute.EC_PARAMS])
            public_key = bytes(core.OctetString.load(pending_pub_key[Attribute.EC_POINT]))

        # Create the CSR information with the same subject as the current certificate
        info = csr.CertificationRequestInfo({'version': 0,
                                                'subject': cert.subject,
                                                'subject_pk_info': {
                                                    'algorithm': {
                                                        'algorithm': algorithm_name,
                                                        'parameters': parameters
                                                    },
                                                    'public_key': public_key
                                                },
                                                'attributes': csr.CRIAttributes([])})

        return info

    def _get_temp_id(self, object_id, suffix):
        # Derive an object ID from an existing object ID. We have to use a different ID
        # for private keys else Greengrass will complain about two keys with the same ID.
        temp_id_int = (int.from_bytes(object_id, 'big') * 256) + suffix
        return temp_id_int.to_bytes(len(object_id) + 1, 'big')

    def _delete_backup(self, session):
        """ Deletes the backup certificate and private key """
        # Try to load the backup certificate and private key
        backup_cert_object = self._get_cert_object(session, self._label_backup)
        backup_priv_key = self._get_key(session, ObjectClass.PRIVATE_KEY, self._label_backup)

        if backup_cert_object is not None:
            print('Destroying the backup certificate object in the HSM token')
            backup_cert_object.destroy()
        if backup_priv_key is not None:
            print('Destroying the backup private key object in the HSM token')
            backup_priv_key.destroy()

    @staticmethod
    def get_pkcs_configuration(ipc_client):
        """ Gets the PKCS configuration """
        component_name = 'aws.greengrass.crypto.Pkcs11Provider'
        print(f'Getting {component_name} configuration')
        response = ipc_client.get_configuration(component_name=component_name)
        print(response)
        return response.value
