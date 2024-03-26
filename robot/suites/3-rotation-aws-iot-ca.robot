# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation   Rotate with AWS IoT CA as issuer
Library         Greengrass  ${THING_GROUP_NAME}
Library         Backend  ${PCA_CA_ID}
Suite Setup     Setup
Test Template   Rotation Should Succeed

*** Variables ***
${windows_things}
${pkcs_things}

*** Test Cases ***                                          KEY         SIGNING
AWS IoT CA with RSA-2048 key and SHA256WITHRSA CSR          RSA-2048    SHA256WITHRSA
AWS IoT CA with RSA-2048 key and SHA384WITHRSA CSR          RSA-2048    SHA384WITHRSA
AWS IoT CA with RSA-2048 key and SHA512WITHRSA CSR          RSA-2048    SHA512WITHRSA
AWS IoT CA with RSA-2048 key and SHA256WITHRSAANDMGF1 CSR   RSA-2048    SHA256WITHRSAANDMGF1
AWS IoT CA with RSA-2048 key and SHA384WITHRSAANDMGF1 CSR   RSA-2048    SHA384WITHRSAANDMGF1
AWS IoT CA with RSA-2048 key and SHA512WITHRSAANDMGF1 CSR   RSA-2048    SHA512WITHRSAANDMGF1
AWS IoT CA with RSA-3072 key and SHA256WITHRSA CSR          RSA-3072    SHA256WITHRSA
AWS IoT CA with RSA-3072 key and SHA384WITHRSA CSR          RSA-3072    SHA384WITHRSA
AWS IoT CA with RSA-3072 key and SHA512WITHRSA CSR          RSA-3072    SHA512WITHRSA
AWS IoT CA with RSA-3072 key and SHA256WITHRSAANDMGF1 CSR   RSA-3072    SHA256WITHRSAANDMGF1
AWS IoT CA with RSA-3072 key and SHA384WITHRSAANDMGF1 CSR   RSA-3072    SHA384WITHRSAANDMGF1
AWS IoT CA with RSA-3072 key and SHA512WITHRSAANDMGF1 CSR   RSA-3072    SHA512WITHRSAANDMGF1
AWS IoT CA with ECDSA-P256 key and ECDSA-WITH-SHA256 CSR    ECDSA-P256  ECDSA-WITH-SHA256
AWS IoT CA with ECDSA-P256 key and ECDSA-WITH-SHA384 CSR    ECDSA-P256  ECDSA-WITH-SHA384
AWS IoT CA with ECDSA-P256 key and ECDSA-WITH-SHA512 CSR    ECDSA-P256  ECDSA-WITH-SHA512
AWS IoT CA with ECDSA-P384 key and ECDSA-WITH-SHA256 CSR    ECDSA-P384  ECDSA-WITH-SHA256
AWS IoT CA with ECDSA-P384 key and ECDSA-WITH-SHA384 CSR    ECDSA-P384  ECDSA-WITH-SHA384
AWS IoT CA with ECDSA-P384 key and ECDSA-WITH-SHA512 CSR    ECDSA-P384  ECDSA-WITH-SHA512
AWS IoT CA with ECDSA-P521 key and ECDSA-WITH-SHA256 CSR    ECDSA-P521  ECDSA-WITH-SHA256
AWS IoT CA with ECDSA-P521 key and ECDSA-WITH-SHA384 CSR    ECDSA-P521  ECDSA-WITH-SHA384
AWS IoT CA with ECDSA-P521 key and ECDSA-WITH-SHA512 CSR    ECDSA-P521  ECDSA-WITH-SHA512

*** Keywords ***
Setup
    # Ensure Private CA is disabled for all test cases in this suite
    Backend.Disable Private CA

Rotation Should Succeed
    [Arguments]     ${key_algorithm}    ${signing_algorithm}

    # The IoT Device SDK doesn't support PKCS#8 keys under Windows, and Greengrass
    # can only use EC keys in PKCS#8 format: https://github.com/awslabs/aws-c-io/issues/260
    IF  '${key_algorithm}' == 'ECDSA-P256' or '${key_algorithm}' == 'ECDSA-P384' or '${key_algorithm}' == 'ECDSA-P521'
        ${windows_things} =     Greengrass.Remove Windows Devices From Thing Group
    END

    # The IoT Device SDK doesn't support ECDSA-P521 with HSMs/PKCS#11: https://github.com/awslabs/aws-c-io/issues/591
    IF  '${key_algorithm}' == 'ECDSA-P521'
        ${pkcs_things} =    Greengrass.Remove PKCS Devices From Thing Group
    END

    ${result} =     Greengrass.Merge Configuration  ${key_algorithm}    ${signing_algorithm}
    Should Be True  ${result}
    ${job_id} =     Greengrass.Create Rotation Job
    ${counts} =     Greengrass.Wait For Job To Finish   ${job_id}
    # All job executions should succeed (no failures and no timeouts)
    Should Be True  ${counts}[0] > 0 and ${counts}[1] == 0 and ${counts}[2] == 0
    # AWS IoT CA will always issue certificates signed using SHA256WITHRSA 
    # regardless of what signing algorithm we use for the CSR.
    ${result} =     Greengrass.Check Certificates   ${True}     ${key_algorithm}    SHA256WITHRSA
    Should Be True  ${result}

    [Teardown]  Restore Devices     ${key_algorithm}    ${signing_algorithm}    ${windows_things}   ${pkcs_things}

Restore Devices
    [Arguments]     ${key_algorithm}    ${signing_algorithm}    ${windows_things}   ${pkcs_things}
    IF  '${key_algorithm}' == 'ECDSA-P256' or '${key_algorithm}' == 'ECDSA-P384' or '${key_algorithm}' == 'ECDSA-P521'
        Greengrass.Add Devices To Thing Group   ${windows_things}
    END
    IF  '${key_algorithm}' == 'ECDSA-P521'
        Greengrass.Add Devices To Thing Group   ${pkcs_things}
    END
