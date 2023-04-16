# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.pki_file.py
"""

from unittest.mock import call, ANY
import pytest
from pki_file import PKIFile, KEY_ALGORITHMS, SIGNING_ALGORITHMS
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

CWD = 'zion'
CERT_FILE_PATH = 'matrix/trinity'
PRIV_KEY_PATH = 'matrix/neo'
CERTIFICATE_PEM = 'Ooh, a storm is threatening'
CERTIFICATE_SUBJECT = 'My very life today'
CSR_PEM = 'If I don\'t get some shelter'

@pytest.fixture(name='config')
def fixture_config(mocker):
    """ A mocked PKI configuration """
    mock_config_class = mocker.patch('pki.Config')
    mock_config = mock_config_class.return_value
    return mock_config

@pytest.fixture(name='pkifile')
def fixture_pkifile(mocker, config):
    """ PKIFile constructor with dependencies mocked """
    # Set a default configuration
    config.key_algorithm = 'RSA-2048'
    config.signing_algorithm = 'SHA256WITHRSA'

    # Mock out the other basic dependencies of the constructor
    mocker.patch('pki.EffectiveConfig.__init__', return_value=None)
    mocker.patch('pki.EffectiveConfig.certificate_file_path', return_value=CERT_FILE_PATH)
    mocker.patch('pki.EffectiveConfig.private_key_path', return_value=PRIV_KEY_PATH)
    mocker.patch('pki_file.os.getcwd', return_value=CWD)
    return PKIFile(mocker.Mock())

@pytest.fixture(name='csr_builder')
def fixture_csr_builder(mocker):
    """ Do CSR builder setup and tear down """
    file = mocker.patch('pki_file.open', mocker.mock_open(read_data=CERTIFICATE_PEM))
    certificate = mocker.Mock()
    certificate.subject = CERTIFICATE_SUBJECT
    load_pem = mocker.patch('pki_file.load_pem_x509_certificate', return_value=certificate)
    csr_builder_class = mocker.patch('pki_file.CertificateSigningRequestBuilder')
    csr_builder = csr_builder_class.return_value
    csr_builder.subject_name.return_value.sign.return_value.public_bytes.return_value.decode.return_value = CSR_PEM

    yield csr_builder

    file.assert_called_once_with(CERT_FILE_PATH, 'rb')
    load_pem.assert_called_once_with(CERTIFICATE_PEM)
    csr_builder_class.assert_called_once()
    csr_builder.subject_name.return_value.sign.return_value.public_bytes\
                .assert_called_once_with(encoding=serialization.Encoding.PEM)

def test_create_csr_rsa(mocker, pkifile, config, csr_builder):
    """ Create CSR with RSA private key and signing algorithm """
    private_key = mocker.MagicMock(spec=rsa.RSAPrivateKey)
    gen_priv_key = mocker.patch('pki_file.rsa.generate_private_key', return_value=private_key)

    config.key_algorithm = 'RSA-2048'
    config.signing_algorithm = 'SHA256WITHRSA'

    assert pkifile.create_csr() == CSR_PEM

    gen_priv_key.assert_called_once_with(public_exponent=65537, key_size=KEY_ALGORITHMS[config.key_algorithm]['size'])
    private_key.private_bytes.assert_called_once_with(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                      encryption_algorithm=ANY)
    csr_builder.subject_name.assert_called_once_with(CERTIFICATE_SUBJECT)
    csr_builder.subject_name().sign.assert_called_once_with(private_key,
                                                            SIGNING_ALGORITHMS[config.signing_algorithm]['hash'])

def test_create_csr_ec(mocker, pkifile, config, csr_builder):
    """ Create CSR with EC private key and signing algorithm """
    private_key = mocker.MagicMock(spec=ec.EllipticCurvePrivateKey)
    gen_priv_key = mocker.patch('pki_file.ec.generate_private_key', return_value=private_key)

    config.key_algorithm = 'ECDSA-P256'
    config.signing_algorithm = 'ECDSA-WITH-SHA256'

    assert pkifile.create_csr() == CSR_PEM

    gen_priv_key.assert_called_once_with(KEY_ALGORITHMS[config.key_algorithm]['curve'])
    private_key.private_bytes.assert_called_once_with(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.PKCS8,
                                                      encryption_algorithm=ANY)
    csr_builder.subject_name.assert_called_once_with(CERTIFICATE_SUBJECT)
    csr_builder.subject_name().sign.assert_called_once_with(private_key,
                                                            SIGNING_ALGORITHMS[config.signing_algorithm]['hash'])

def test_create_csr_mismatched_family(mocker, pkifile, config):
    """ Mismatched encryption family for key and signing algorithms results in no CSR """
    mocker.patch('pki_file.open', mocker.mock_open(read_data=CERTIFICATE_PEM))
    certificate = mocker.Mock()
    certificate.subject = CERTIFICATE_SUBJECT
    mocker.patch('pki_file.load_pem_x509_certificate', return_value=certificate)
    config.key_algorithm = 'RSA-2048'
    config.signing_algorithm = 'ECDSA-WITH-SHA256'
    assert pkifile.create_csr() is None

def test_create_csr_exception(mocker, pkifile):
    """ Create CSR should handle exceptions """
    mocker.patch('pki_file.open', side_effect=Exception('mocked error'))
    assert pkifile.create_csr() is None

def test_rotate(mocker, pkifile):
    """ Rotate should copy to backups and write new cert and key """
    shutil_copy2 = mocker.patch('pki_file.shutil.copy2')
    file = mocker.patch('pki_file.open', mocker.mock_open())
    assert pkifile.rotate(CERTIFICATE_PEM)
    calls = [call(f'{CERT_FILE_PATH}', f'{CWD}/{PKIFile.CERTIFICATE_BAK}'),
             call(f'{PRIV_KEY_PATH}', f'{CWD}/{PKIFile.PRIVATE_KEY_BAK}')]
    shutil_copy2.assert_has_calls(calls, any_order=False)
    calls = [call(f'{CERT_FILE_PATH}', 'w', encoding='utf-8'), call(f'{PRIV_KEY_PATH}', 'w', encoding='utf-8')]
    file.assert_has_calls(calls, any_order=True)
    calls = [call(CERTIFICATE_PEM), call(None)]
    file().write.assert_has_calls(calls, any_order=True)

def test_rotate_exception(mocker, pkifile):
    """ Rotate should handle exceptions """
    mocker.patch('pki_file.shutil.copy2', side_effect=Exception('mocked error'))
    assert not pkifile.rotate(CERTIFICATE_PEM)

def test_rollback(mocker, pkifile):
    """ Rollback should restore from backups and delete new """
    shutil_copy2 = mocker.patch('pki_file.shutil.copy2')
    os_remove = mocker.patch('pki_file.os.remove')
    assert pkifile.rollback()
    calls = [call(f'{CWD}/{PKIFile.CERTIFICATE_BAK}', f'{CERT_FILE_PATH}'),
             call(f'{CWD}/{PKIFile.PRIVATE_KEY_BAK}', f'{PRIV_KEY_PATH}')]
    shutil_copy2.assert_has_calls(calls, any_order=False)
    calls = [call(f'{CWD}/{PKIFile.CERTIFICATE_BAK}'), call(f'{CWD}/{PKIFile.PRIVATE_KEY_BAK}')]
    os_remove.assert_has_calls(calls, any_order=False)

def test_rollback_exception(mocker, pkifile):
    """ Rollback should handle exceptions """
    mocker.patch('pki_file.shutil.copy2', side_effect=Exception('mocked error'))
    assert not pkifile.rollback()

def test_backup_exists(mocker, pkifile):
    """ Backup should exist if both files exist """
    os_path_exists = mocker.patch('pki_file.os.path.exists', return_value=True)
    assert pkifile.backup_exists()
    calls = [call(f'{CWD}/{PKIFile.CERTIFICATE_BAK}'), call(f'{CWD}/{PKIFile.PRIVATE_KEY_BAK}')]
    os_path_exists.assert_has_calls(calls, any_order=False)

def test_backup_not_exists_if_neither(mocker, pkifile):
    """ Backup should not exist if neither file exists """
    os_path_exists = mocker.patch('pki_file.os.path.exists', return_value=False)
    assert not pkifile.backup_exists()
    os_path_exists.assert_called_once_with(f'{CWD}/{PKIFile.CERTIFICATE_BAK}')

def test_backup_not_exists_if_no_cert(mocker, pkifile):
    """ Backup should not exist if just the cert backup is missing """
    os_path_exists = mocker.patch('pki_file.os.path.exists', return_value=False)
    os_path_exists.side_effect = [False, True]
    assert not pkifile.backup_exists()
    os_path_exists.assert_called_once_with(f'{CWD}/{PKIFile.CERTIFICATE_BAK}')

def test_backup_not_exists_if_no_key(mocker, pkifile):
    """ Backup should not exist if just the key backup is missing """
    os_path_exists = mocker.patch('pki_file.os.path.exists', return_value=False)
    os_path_exists.side_effect = [True, False]
    assert not pkifile.backup_exists()
    calls = [call(f'{CWD}/{PKIFile.CERTIFICATE_BAK}'), call(f'{CWD}/{PKIFile.PRIVATE_KEY_BAK}')]
    os_path_exists.assert_has_calls(calls, any_order=False)

def test_delete_backup(mocker, pkifile):
    """ Backup should be deleted """
    os_remove = mocker.patch('pki_file.os.remove')
    pkifile.delete_backup()
    calls = [call(f'{CWD}/{PKIFile.CERTIFICATE_BAK}'), call(f'{CWD}/{PKIFile.PRIVATE_KEY_BAK}')]
    os_remove.assert_has_calls(calls, any_order=False)
