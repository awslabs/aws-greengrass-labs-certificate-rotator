# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation   Rotate with AWS Private CA as issuer
Library         Greengrass  ${THING_GROUP_NAME}
Library         Backend     ${PCA_CA_ID}
Suite Setup     Setup
Suite Teardown  Teardown
Test Template   Rotation Should Succeed

*** Test Cases ***                                          SIGNING
AWS Private CA with certificate signing SHA256WITHRSA       SHA256WITHRSA
AWS Private CA with certificate signing SHA384WITHRSA       SHA384WITHRSA
AWS Private CA with certificate signing SHA512WITHRSA       SHA512WITHRSA
AWS Private CA with certificate signing SHA256WITHECDSA     SHA256WITHECDSA
AWS Private CA with certificate signing SHA384WITHECDSA     SHA384WITHECDSA
AWS Private CA with certificate signing SHA512WITHECDSA     SHA512WITHECDSA

*** Keywords ***
Setup
    Backend.Enable Private CA
    # We use key algorithm RSA-2048 and CSR signing algorithm SHA256WITHRSA for all test 
    # cases in this suite. The CSR signing algorithm used on the Greengrass core device 
    # is not the same as the certificate signing algorithm we use with AWS Private CA
    # when issuing a certificate. The focus of this suite is to test that the Lambda backend
    # can use AWS Private CA with different certificate signing algorithms.
    ${result} =     Greengrass.Merge Configuration  RSA-2048    SHA256WITHRSA
    Should Be True  ${result}

Teardown
    Backend.Disable Private CA

Rotation Should Succeed
    [Arguments]     ${signing_algorithm}
    ${match} =  Backend.Private CA Key and Signing Algorithms Match     ${signing_algorithm}
    Skip If     ${match} == False   Signing algorithm doesn't match CA key algorithm family     
    Backend.Set Private CA Signing Algorithm    ${signing_algorithm}
    ${job_id} =     Greengrass.Create Rotation Job
    ${counts} =     Greengrass.Wait For Job To Finish   ${job_id}
    # All job executions should succeed (no failures and no timeouts)
    Should Be True  ${counts}[0] > 0 and ${counts}[1] == 0 and ${counts}[2] == 0
    # The component is using the one key algorithm for all test cases in this suite. Only
    # the AWS Private CA certificate signing algorithm is changing.
    ${result} =     Greengrass.Check Certificates   ${False}    RSA-2048    ${signing_algorithm}
    Should Be True  ${result}
