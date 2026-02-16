# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for artifacts.pki.py
"""

import pytest
from pki import PKI

@pytest.fixture(name='pki')
def fixture_config(mocker):
    """ Mock the configuration classes in the PKI object """
    mocker.patch.multiple(PKI, __abstractmethods__=set())
    mocker.patch('pki.Config.__init__', return_value=None)
    mocker.patch('pki.EffectiveConfig.__init__', return_value=None)
    # pylint: disable-msg=abstract-class-instantiated
    return PKI(None, None, None)  # type: ignore[abstract,arg-type]

def test_create_csr(pki):
    """ Test that we get an exception """
    # pylint: disable-msg=abstract-class-instantiated
    with pytest.raises(NotImplementedError):
        pki.create_csr()

def test_rotate(pki):
    """ Test that we get an exception """
    with pytest.raises(NotImplementedError):
        pki.rotate('foobar')

def test_rollback(pki):
    """ Test that we get an exception """
    with pytest.raises(NotImplementedError):
        pki.rollback()

def test_backup_exists(pki):
    """ Test that we get an exception """
    with pytest.raises(NotImplementedError):
        pki.backup_exists()

def test_delete_backup(pki):
    """ Test that we get an exception """
    with pytest.raises(NotImplementedError):
        pki.delete_backup()
