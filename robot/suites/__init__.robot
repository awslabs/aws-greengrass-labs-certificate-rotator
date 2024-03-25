# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation    AWS Labs Greengrass Certificate Rotator test suite
Suite Setup      Setup
Suite Teardown   Teardown

*** Keywords ***
Setup
    Pass Execution  No suite-wide setup actions required

Teardown
    # Nothing to do
    Pass Execution  No suite-wide teardown actions required
