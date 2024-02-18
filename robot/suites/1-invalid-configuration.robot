# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation   Component invalid configuration checks
Library         Greengrass  ${THING_GROUP_NAME}
Test Template   Invalid configuration should fail

*** Test Cases ***                              KEY         SIGNING
Invalid key algorithm                           Foobar      SHA256WITHRSA
Invalid signing algorithm                       RSA-2048    Foobar
Mismatch: RSA-2048 with ECDSA-WITH-SHA256       RSA-2048    ECDSA-WITH-SHA256
Mismatch: RSA-2048 with ECDSA-WITH-SHA384       RSA-2048    ECDSA-WITH-SHA384
Mismatch: RSA-2048 with ECDSA-WITH-SHA512       RSA-2048    ECDSA-WITH-SHA512
Mismatch: RSA-3072 with ECDSA-WITH-SHA256       RSA-3072    ECDSA-WITH-SHA256
Mismatch: RSA-3072 with ECDSA-WITH-SHA384       RSA-3072    ECDSA-WITH-SHA384
Mismatch: RSA-3072 with ECDSA-WITH-SHA512       RSA-3072    ECDSA-WITH-SHA512
Mismatch: ECDSA-P256 with SHA256WITHRSA         ECDSA-P256  SHA256WITHRSA
Mismatch: ECDSA-P256 with SHA384WITHRSA         ECDSA-P256  SHA384WITHRSA
Mismatch: ECDSA-P256 with SHA512WITHRSA         ECDSA-P256  SHA512WITHRSA
Mismatch: ECDSA-P256 with SHA256WITHRSAANDMGF1  ECDSA-P256  SHA256WITHRSAANDMGF1
Mismatch: ECDSA-P256 with SHA384WITHRSAANDMGF1  ECDSA-P256  SHA384WITHRSAANDMGF1
Mismatch: ECDSA-P256 with SHA512WITHRSAANDMGF1  ECDSA-P256  SHA512WITHRSAANDMGF1
Mismatch: ECDSA-P384 with SHA256WITHRSA         ECDSA-P384  SHA256WITHRSA
Mismatch: ECDSA-P384 with SHA384WITHRSA         ECDSA-P384  SHA384WITHRSA
Mismatch: ECDSA-P384 with SHA512WITHRSA         ECDSA-P384  SHA512WITHRSA
Mismatch: ECDSA-P384 with SHA256WITHRSAANDMGF1  ECDSA-P384  SHA256WITHRSAANDMGF1
Mismatch: ECDSA-P384 with SHA384WITHRSAANDMGF1  ECDSA-P384  SHA384WITHRSAANDMGF1
Mismatch: ECDSA-P384 with SHA512WITHRSAANDMGF1  ECDSA-P384  SHA512WITHRSAANDMGF1
Mismatch: ECDSA-P521 with SHA256WITHRSA         ECDSA-P521  SHA256WITHRSA
Mismatch: ECDSA-P521 with SHA384WITHRSA         ECDSA-P521  SHA384WITHRSA
Mismatch: ECDSA-P521 with SHA512WITHRSA         ECDSA-P521  SHA512WITHRSA
Mismatch: ECDSA-P521 with SHA256WITHRSAANDMGF1  ECDSA-P521  SHA256WITHRSAANDMGF1
Mismatch: ECDSA-P521 with SHA384WITHRSAANDMGF1  ECDSA-P521  SHA384WITHRSAANDMGF1
Mismatch: ECDSA-P521 with SHA512WITHRSAANDMGF1  ECDSA-P521  SHA512WITHRSAANDMGF1

*** Keywords ***
Invalid configuration should fail
    [Arguments]     ${key_algorithm}    ${signing_algorithm}
    ${result} =     Greengrass.Merge Configuration  ${key_algorithm}    ${signing_algorithm}
    Should Be True  ${result} == False
