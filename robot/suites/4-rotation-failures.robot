# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation   Rotation failures and rollback
Library         Collections
Library         Greengrass  ${THING_GROUP_NAME}
Library         Backend     ${PCA_CA_ID}
Suite Setup     Setup

*** Test Cases ***
Failure if create times out
    Backend.Disable Create
    ${job_id} =     Greengrass.Create Rotation Job
    ${counts} =     Greengrass.Wait For Job To Finish   ${job_id}
    # All job executions should fail (no successes and no timeouts)
    Should Be True  ${counts}[0] == 0 and ${counts}[1] > 0 and ${counts}[2] == 0
    [Teardown]  Backend.Enable Create

Rollback if re-connection fails
    ${old_certs} =  Greengrass.Get Certificates
    ${job_id} =     Greengrass.Create Rotation Job
    Greengrass.Deactivate New Certificates
    ${counts} =     Greengrass.Wait For Job To Finish   ${job_id}
    # All job executions should fail (no successes and no timeouts)
    Should Be True  ${counts}[0] == 0 and ${counts}[1] > 0 and ${counts}[2] == 0
    ${new_certs} =  Greengrass.Get Certificates
    Lists Should Be Equal   ${new_certs}    ${old_certs}

Rollback if commit times out
    Backend.Disable Commit
    ${old_certs} =  Greengrass.Get Certificates
    ${job_id} =     Greengrass.Create Rotation Job
    ${counts} =     Greengrass.Wait For Job To Finish   ${job_id}
    # All job executions should fail (no successes and no timeouts)
    Should Be True  ${counts}[0] == 0 and ${counts}[1] > 0 and ${counts}[2] == 0
    ${new_certs} =  Greengrass.Get Certificates
    Lists Should Be Equal   ${new_certs}    ${old_certs}
    [Teardown]  Backend.Enable Commit

*** Keywords ***
Setup
    # Ensure Private CA is disabled for all test cases in this suite
    Backend.Disable Private CA

    # Set a baseline component configuration. Key algorithm and CSR signing
    # algorithm should be immaterial in the rollback process, but we at least
    # need certainty over what was tetsed.
    ${result} =     Greengrass.Merge Configuration  RSA-2048    SHA256WITHRSA
    Should Be True  ${result}
