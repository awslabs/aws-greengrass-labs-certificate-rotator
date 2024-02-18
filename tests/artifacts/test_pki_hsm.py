# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.pki_hsm.py
"""

import runpy
from unittest.mock import call, ANY
import pytest
from pkcs11 import Attribute, ObjectClass, KeyType, MechanismFlag
from pki_hsm import PKIHSM, KEY_ALGORITHMS, SIGNING_ALGORITHMS
from awsiot.greengrasscoreipc.model import (
    GetConfigurationResponse
)

LABEL = 'Let It Bleed'
LABEL_BACKUP = f'{LABEL}.bak'
LABEL_PENDING = f'{LABEL}.pending'
ID = b'\xde\xad'
ID_BACKUP = b'\xde\xad\x02'
ID_PENDING = b'\xde\xad\x01'
CERTIFICATE_PEM = 'Ooh yeah I\'m gonna fade away'
CERTIFICATE_SUBJECT = 'War, children'
CSR_PEM = 'It\'s just a shot away'
PKCS_CONFIG = {
  "name": "fake_pkcs11",
  "library": "fake.so",
  "slot": 1,
  "userPin": "1234"
}
CSR_REQUEST_INFO_DATA = 'yankee doodle dandy'
CSR_SIGNATURE = 'I did it my way'

@pytest.fixture(name='config')
def fixture_config(mocker):
    """ A mocked PKI configuration """
    mock_config_class = mocker.patch('pki.Config')
    mock_config = mock_config_class.return_value
    return mock_config

@pytest.fixture(name='pkihsm')
def fixture_pkihsm(mocker, config):
    """ PKIHSM constructor with dependencies mocked """
    # Set a default configuration
    config.key_algorithm = 'RSA-2048'
    config.signing_algorithm = 'SHA256WITHRSA'

    # Mock out the other basic dependencies of the constructor
    mocker.patch('pki.EffectiveConfig.__init__', return_value=None)
    mocker.patch('pki.EffectiveConfig.certificate_file_path', return_value=f'pkcs11:object={LABEL};type=cert')

    ipc_client = mocker.Mock()
    ipc_client.get_configuration.return_value = GetConfigurationResponse(component_name='foobar', value=PKCS_CONFIG)
    return PKIHSM(ipc_client)

@pytest.fixture(name='pkcs11_session')
def fixture_pkcs11_session(mocker):
    """ Mock PKCS11 session with an HSM """
    pkcs11_lib_class = mocker.patch('pki_hsm.pkcs11.lib')
    pkcs11_lib = pkcs11_lib_class.return_value
    # Create two slots, with our second being the one of interest. This forces the
    # code to search for a match.
    slot1 = mocker.Mock()
    slot1.slot_id = PKCS_CONFIG['slot'] + 1
    slot2 = mocker.Mock()
    slot2.slot_id = PKCS_CONFIG['slot']
    pkcs11_lib.get_slots.return_value = [slot1, slot2]
    token = mocker.Mock()
    slot2.get_token.return_value = token
    session = mocker.Mock()
    token.open.return_value = session

    yield session

    pkcs11_lib_class.assert_called_once_with(PKCS_CONFIG['library'])
    pkcs11_lib.get_slots.assert_called_once_with(token_present=True)
    slot2.get_token.assert_called_once()
    token.open.assert_called_once_with(ANY, user_pin=PKCS_CONFIG['userPin'])
    session.close.assert_called_once()

@pytest.fixture(name='csr_request_info')
def fixture_csr_builder(mocker, pkcs11_session):
    """ Do CSR common bit setup and teardown """
    cert_object = mocker.MagicMock()
    pkcs11_session.get_objects.return_value = [cert_object]
    x509_cert_load = mocker.patch('pki_hsm.x509.Certificate.load', return_value=mocker.MagicMock())
    csr_request_info = mocker.patch('pki_hsm.csr.CertificationRequestInfo')

    yield csr_request_info

    key_calls = [call(object_class=ObjectClass.PUBLIC_KEY, label=LABEL_PENDING),
                 call(object_class=ObjectClass.PRIVATE_KEY, label=LABEL_PENDING),
                 call(object_class=ObjectClass.PRIVATE_KEY, label=LABEL)]
    pkcs11_session.get_key.assert_has_calls(key_calls, any_order=False)
    pkcs11_session.get_objects.assert_called_once_with({Attribute.CLASS: ObjectClass.CERTIFICATE,
                                                        Attribute.LABEL: LABEL})
    x509_cert_load.assert_called_once()
    csr_request_info.assert_called_once()

def test_create_csr_rsa(mocker, pkihsm, pkcs11_session, config, csr_request_info):
    """ Create CSR with RSA private key and signing algorithm """
    key_object = mocker.Mock()
    key_object.id = ID
    # No pending key pair key (so exceptions on the first and second calls)
    pkcs11_session.get_key.side_effect = [Exception('mocked error'), Exception('mocked error'), key_object]
    pending_priv_key_object = mocker.Mock()
    pending_pub_key_object = mocker.Mock()
    pkcs11_session.generate_keypair.return_value = (pending_pub_key_object, pending_priv_key_object)
    encode_rsa_public_key = mocker.patch('pki_hsm.encode_rsa_public_key')
    mocker.patch('pki_hsm.keys.RSAPublicKey.load')
    csr_request_info.return_value.dump.return_value = CSR_REQUEST_INFO_DATA
    csr_request = mocker.patch('pki_hsm.csr.CertificationRequest')
    pending_priv_key_object.sign.return_value = CSR_SIGNATURE
    mocker.patch('pki_hsm.pem.armor', return_value=CSR_PEM.encode('utf-8'))

    config.key_algorithm = 'RSA-2048'
    config.signing_algorithm = 'SHA256WITHRSA'
    pending_pub_key_object.key_type = KeyType.RSA
    pending_priv_key_object.key_type = KeyType.RSA

    assert pkihsm.create_csr() == CSR_PEM

    pkcs11_session.generate_keypair.assert_called_once_with(key_type=KeyType.RSA,
                                                            key_length=KEY_ALGORITHMS[config.key_algorithm]['size'],
                                                            id=ID_PENDING, label=LABEL_PENDING, store=True)
    encode_rsa_public_key.assert_called_once_with(pending_pub_key_object)
    pending_pub_key_object.destroy.assert_called_once()
    mech = SIGNING_ALGORITHMS[config.signing_algorithm]['mech']
    mech_param = SIGNING_ALGORITHMS[config.signing_algorithm]['mech_param']
    pending_priv_key_object.sign.assert_called_once_with(CSR_REQUEST_INFO_DATA, mechanism=mech,
                                                         mechanism_param=mech_param)
    params = SIGNING_ALGORITHMS[config.signing_algorithm]['params']
    csr_request.assert_called_once_with({'certification_request_info': csr_request_info.return_value,
                                                'signature_algorithm': {
                                                    'algorithm': SIGNING_ALGORITHMS[config.signing_algorithm]['name'],
                                                    'parameters': params,
                                                },
                                                'signature': CSR_SIGNATURE})

def test_create_csr_ec(mocker, pkihsm, pkcs11_session, config, csr_request_info):
    """ Create CSR with EC private key and signing algorithm """
    key_object = mocker.Mock()
    key_object.id = ID
    # No pending key pair key (so exceptions on the first and second calls)
    pkcs11_session.get_key.side_effect = [Exception('mocked error'), Exception('mocked error'), key_object]
    encode_named_curve_parameters = mocker.patch('pki_hsm.encode_named_curve_parameters')
    parameters = mocker.Mock()
    pkcs11_session.create_domain_parameters.return_value = parameters
    pending_priv_key_object = mocker.Mock()
    pending_pub_key_object = mocker.MagicMock()
    parameters.generate_keypair.return_value = (pending_pub_key_object, pending_priv_key_object)
    mocker.patch('pki_hsm.keys.ECDomainParameters.load')
    mocker.patch('pki_hsm.core.OctetString.load')
    csr_request_info.return_value.dump.return_value = CSR_REQUEST_INFO_DATA
    hash_class = mocker.patch('pki_hsm.hashes.Hash')
    digest = hash_class.return_value
    digest.finalize.return_value = CSR_REQUEST_INFO_DATA
    csr_request = mocker.patch('pki_hsm.csr.CertificationRequest')
    pending_priv_key_object.sign.return_value = CSR_SIGNATURE
    encode_ecdsa_signature = mocker.patch('pki_hsm.encode_ecdsa_signature', return_value=CSR_SIGNATURE)
    mocker.patch('pki_hsm.pem.armor', return_value=CSR_PEM.encode('utf-8'))

    config.key_algorithm = 'ECDSA-P256'
    config.signing_algorithm = 'ECDSA-WITH-SHA256'
    pending_pub_key_object.key_type = KeyType.EC
    pending_priv_key_object.key_type = KeyType.EC

    assert pkihsm.create_csr() == CSR_PEM

    encode_named_curve_parameters.assert_called_once_with(KEY_ALGORITHMS[config.key_algorithm]['curve'])
    pkcs11_session.create_domain_parameters.assert_called_once()
    parameters.generate_keypair.assert_called_once_with(id=ID_PENDING, label=LABEL_PENDING, store=True,
                                            capabilities=MechanismFlag.SIGN|MechanismFlag.DECRYPT|MechanismFlag.UNWRAP)
    pending_pub_key_object.destroy.assert_called_once()
    mech = SIGNING_ALGORITHMS[config.signing_algorithm]['mech']
    mech_param = SIGNING_ALGORITHMS[config.signing_algorithm]['mech_param']
    pending_priv_key_object.sign.assert_called_once_with(CSR_REQUEST_INFO_DATA, mechanism=mech,
                                                         mechanism_param=mech_param)
    encode_ecdsa_signature.assert_called_once_with(CSR_SIGNATURE)
    params = SIGNING_ALGORITHMS[config.signing_algorithm]['params']
    csr_request.assert_called_once_with({'certification_request_info': csr_request_info.return_value,
                                                'signature_algorithm': {
                                                    'algorithm': SIGNING_ALGORITHMS[config.signing_algorithm]['name'],
                                                    'parameters': params,
                                                },
                                                'signature': CSR_SIGNATURE})

def test_create_csr_pending_cleaup(mocker, pkihsm, pkcs11_session):
    """ Create CSR should delete old pending key pair if it exists """
    pending_pub_key_object = mocker.Mock()
    pending_priv_key_object = mocker.Mock()
    # We make the normal private key absent just so this test case terminates straight
    # after the pending key pair deleted
    pkcs11_session.get_key.side_effect = [pending_pub_key_object, pending_priv_key_object, Exception('mocked error')]
    assert pkihsm.create_csr() is None
    pending_pub_key_object.destroy.assert_called_once()
    pending_priv_key_object.destroy.assert_called_once()

def test_create_csr_exception(pkihsm, pkcs11_session):
    """ Create CSR should handle exceptions """
    pkcs11_session.get_key.side_effect = Exception('mocked error')
    assert pkihsm.create_csr() is None

def test_rotate(mocker, pkihsm, pkcs11_session):
    """ Rotate should copy to backups and write new cert and key """
    cert_object = mocker.MagicMock()
    cert_object[Attribute.ID] = ID
    cert_object[Attribute.LABEL] = LABEL
    # No backup certificate (empty list on the second call)
    pkcs11_session.get_objects.side_effect = [[cert_object], []]
    key_object = mocker.Mock()
    key_object.id = ID
    pending_key_object = mocker.Mock()
    # No backup key (exception on the third call)
    pkcs11_session.get_key.side_effect = [key_object, pending_key_object, Exception('mocked error')]
    new_cert_object = mocker.MagicMock()
    DER = b'\xde\xad\xbe\xef'
    pem_unarmour = mocker.patch('pki_hsm.pem.unarmor', return_value=(0, 0, DER))
    decode_x509_cert = mocker.patch('pki_hsm.decode_x509_certificate', return_value=new_cert_object)

    assert pkihsm.rotate(CERTIFICATE_PEM)

    cert_calls = [call({Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: LABEL}),
                  call({Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: LABEL_BACKUP})]
    pkcs11_session.get_objects.assert_has_calls(cert_calls, any_order=False)
    key_calls = [call(object_class=ObjectClass.PRIVATE_KEY, label=LABEL),
                 call(object_class=ObjectClass.PRIVATE_KEY, label=LABEL_PENDING),
                 call(object_class=ObjectClass.PRIVATE_KEY, label=LABEL_BACKUP)]
    pkcs11_session.get_key.assert_has_calls(key_calls, any_order=False)
    # Couldn't figure out how to make the MagicMock return ID and LABEL values instead
    # of another MagicMock. Hence the ANY here because the ID is not correctly injected.
    cert_object.copy.assert_called_once_with({Attribute.LABEL: LABEL_BACKUP, Attribute.ID: ANY})
    key_object.copy.assert_called_once_with({Attribute.LABEL: LABEL_BACKUP, Attribute.ID: ID_BACKUP})
    pem_unarmour.assert_called_once()
    decode_x509_cert.assert_called_once_with(DER)
    cert_object.destroy.assert_called_once()
    key_object.destroy.assert_called_once()
    pkcs11_session.create_object.assert_called_once_with(new_cert_object)
    pending_key_object.copy.assert_called_once_with({Attribute.LABEL: LABEL, Attribute.ID: ID})
    pending_key_object.destroy.assert_called_once()

def test_rotate_exception(pkihsm, pkcs11_session):
    """ Rotate should handle exceptions """
    pkcs11_session.get_objects.side_effect = Exception('mocked error')
    assert not pkihsm.rotate(CERTIFICATE_PEM)

def test_rollback(mocker, pkihsm, pkcs11_session):
    """ Rollback should restore from backups and delete new """
    cert_object = mocker.MagicMock()
    cert_object[Attribute.ID] = ID
    backup_cert_object = mocker.Mock()
    pkcs11_session.get_objects.side_effect = [[cert_object], [backup_cert_object]]
    key_object = mocker.Mock()
    key_object.id = ID
    backup_key_object = mocker.Mock()
    pkcs11_session.get_key.side_effect = [key_object, backup_key_object]

    assert pkihsm.rollback()

    cert_calls = [call({Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: LABEL}),
                  call({Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: LABEL_BACKUP})]
    pkcs11_session.get_objects.assert_has_calls(cert_calls, any_order=False)
    key_calls = [call(object_class=ObjectClass.PRIVATE_KEY, label=LABEL),
                 call(object_class=ObjectClass.PRIVATE_KEY, label=LABEL_BACKUP)]
    pkcs11_session.get_key.assert_has_calls(key_calls, any_order=False)
    cert_object.destroy.assert_called_once()
    key_object.destroy.assert_called_once()
    backup_cert_object.copy.assert_called_once_with({Attribute.LABEL: LABEL, Attribute.ID: ID})
    backup_key_object.copy.assert_called_once_with({Attribute.LABEL: LABEL, Attribute.ID: ID})
    backup_cert_object.destroy.assert_called_once()
    backup_key_object.destroy.assert_called_once()

def test_rollback_handles_missing_key(mocker, pkihsm, pkcs11_session):
    """ Rollback should handle a situation in which the new key was not created before restart """
    cert_object = mocker.MagicMock()
    cert_object[Attribute.ID] = ID
    backup_cert_object = mocker.Mock()
    pkcs11_session.get_objects.side_effect = [[cert_object], [backup_cert_object]]
    backup_key_object = mocker.Mock()
    pkcs11_session.get_key.side_effect = [None, backup_key_object]

    assert pkihsm.rollback()

    cert_object.destroy.assert_called_once()
    backup_cert_object.copy.assert_called_once_with({Attribute.LABEL: LABEL, Attribute.ID: cert_object[Attribute.ID]})
    backup_key_object.copy.assert_called_once_with({Attribute.LABEL: LABEL, Attribute.ID: cert_object[Attribute.ID]})
    backup_cert_object.destroy.assert_called_once()
    backup_key_object.destroy.assert_called_once()

def test_rollback_handles_missing_cert(mocker, pkihsm, pkcs11_session):
    """ Rollback should handle a situation in which the new certificate was not created before restart """
    backup_cert_object = mocker.Mock()
    pkcs11_session.get_objects.side_effect = [[], [backup_cert_object]]
    key_object = mocker.Mock()
    key_object.id = ID
    backup_key_object = mocker.Mock()
    pkcs11_session.get_key.side_effect = [key_object, backup_key_object]

    assert pkihsm.rollback()

    key_object.destroy.assert_called_once()
    backup_cert_object.copy.assert_called_once_with({Attribute.LABEL: LABEL, Attribute.ID: ID})
    backup_key_object.copy.assert_called_once_with({Attribute.LABEL: LABEL, Attribute.ID: ID})
    backup_cert_object.destroy.assert_called_once()
    backup_key_object.destroy.assert_called_once()

def test_rollback_exception(pkihsm, pkcs11_session):
    """ Rollback should handle exceptions """
    pkcs11_session.get_objects.side_effect = Exception('mocked error')
    assert not pkihsm.rollback()

def test_backup_exists(mocker, pkihsm, pkcs11_session):
    """ Backup should exist if both objects exist """
    pkcs11_session.get_objects.return_value = [mocker.Mock()]
    pkcs11_session.get_key.return_value = mocker.Mock()
    assert pkihsm.backup_exists()
    pkcs11_session.get_objects.assert_called_once_with({Attribute.CLASS: ObjectClass.CERTIFICATE,
                                                 Attribute.LABEL: LABEL_BACKUP})
    pkcs11_session.get_key.assert_called_once_with(object_class=ObjectClass.PRIVATE_KEY, label=LABEL_BACKUP)

def test_backup_not_exists_if_neither(pkihsm, pkcs11_session):
    """ Backup should not exist if neither object exists """
    pkcs11_session.get_objects.return_value = []
    pkcs11_session.get_key.side_effect = Exception('mocked error')
    assert not pkihsm.backup_exists()
    pkcs11_session.get_objects.assert_called_once_with({Attribute.CLASS: ObjectClass.CERTIFICATE,
                                                 Attribute.LABEL: LABEL_BACKUP})
    pkcs11_session.get_key.assert_called_once_with(object_class=ObjectClass.PRIVATE_KEY, label=LABEL_BACKUP)

def test_backup_not_exists_if_no_cert(mocker, pkihsm, pkcs11_session):
    """ Backup should not exist if just the cert backup is missing """
    pkcs11_session.get_objects.return_value = []
    pkcs11_session.get_key.return_value = mocker.Mock()
    assert not pkihsm.backup_exists()
    pkcs11_session.get_objects.assert_called_once_with({Attribute.CLASS: ObjectClass.CERTIFICATE,
                                                 Attribute.LABEL: LABEL_BACKUP})
    pkcs11_session.get_key.assert_called_once_with(object_class=ObjectClass.PRIVATE_KEY, label=LABEL_BACKUP)

def test_backup_not_exists_if_no_key(mocker, pkihsm, pkcs11_session):
    """ Backup should not exist if just the key is missing """
    pkcs11_session.get_objects.return_value = [mocker.Mock()]
    pkcs11_session.get_key.side_effect = Exception('mocked error')
    assert not pkihsm.backup_exists()
    pkcs11_session.get_objects.assert_called_once_with({Attribute.CLASS: ObjectClass.CERTIFICATE,
                                                 Attribute.LABEL: LABEL_BACKUP})
    pkcs11_session.get_key.assert_called_once_with(object_class=ObjectClass.PRIVATE_KEY, label=LABEL_BACKUP)

def test_delete_backup(mocker, pkihsm, pkcs11_session):
    """ Backup should be deleted """
    cert_object = mocker.Mock()
    pkcs11_session.get_objects.return_value = [cert_object]
    key_object = mocker.Mock()
    pkcs11_session.get_key.return_value = key_object

    pkihsm.delete_backup()

    pkcs11_session.get_objects.assert_called_once_with({Attribute.CLASS: ObjectClass.CERTIFICATE,
                                                 Attribute.LABEL: LABEL_BACKUP})
    pkcs11_session.get_key.assert_called_once_with(object_class=ObjectClass.PRIVATE_KEY, label=LABEL_BACKUP)
    cert_object.destroy.assert_called_once()
    key_object.destroy.assert_called_once()

def test_handle_no_slots(mocker, pkihsm):
    """ Confirm we get an exception if the HSM doesn't have a slot we want """
    pkcs11_lib_class = mocker.patch('pki_hsm.pkcs11.lib')
    pkcs11_lib = pkcs11_lib_class.return_value
    pkcs11_lib.get_slots.return_value = []

    with pytest.raises(Exception):
        pkihsm.backup_exists()

def test_platform_no_import(mocker):
    """ Confirm we don't import PKCS when running under Windows """
    mocker.patch('platform.system', return_value='Windows')
    runpy.run_module('pki_hsm')
