// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib/core';
import { Template, Match } from 'aws-cdk-lib/assertions';
import * as CertificateRotator from '../lib/certificate-rotator-stack';

const STACK_NAME = 'MyTestStack'

const JOB_DOCUMENT: string = '{"operation":"ROTATE_CERTIFICATE"}';

function checkBasicResources(template: Template) {
  // Four Lambda functions when including the custom resource
  template.resourceCountIs('AWS::Lambda::Function', 4);
  template.resourceCountIs('AWS::IoT::TopicRule', 3);
  template.resourceCountIs('AWS::IoT::JobTemplate', 1);
  template.resourceCountIs('AWS::SNS::Topic', 1);
  template.hasResourceProperties('AWS::Lambda::Function', { FunctionName: `${STACK_NAME}CreateCertificate` });
  template.hasResourceProperties('AWS::Lambda::Function', { FunctionName: `${STACK_NAME}CommitCertificate` });
  template.hasResourceProperties('AWS::Lambda::Function', { FunctionName: `${STACK_NAME}JobExecutionTerminal` });
  template.hasResourceProperties('AWS::IoT::TopicRule', { RuleName: `${STACK_NAME}CreateCertificate` });
  template.hasResourceProperties('AWS::IoT::TopicRule', { RuleName: `${STACK_NAME}CommitCertificate` });
  template.hasResourceProperties('AWS::IoT::TopicRule', { RuleName: `${STACK_NAME}JobExecutionTerminal` });
  template.hasResourceProperties('AWS::IoT::JobTemplate', { JobTemplateId: `${STACK_NAME}` });
  template.hasResourceProperties('AWS::SNS::Topic', { TopicName: `${STACK_NAME}Notification` });
}

test('Good stack with Private CA disabled', () => {
  const app = new cdk.App({
    context: {
      PcaCaId: '',
      PcaValidityInDays: 'beta',
      PcaSigningAlgorithm: 'delta'
    }
  });

  const stack = new CertificateRotator.CertificateRotatorStack(app, STACK_NAME);

  const template = Template.fromStack(stack);
  checkBasicResources(template);
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: {
        PCA_CA_ARN: '',
        PCA_VALIDITY_IN_DAYS: 'beta',
        PCA_SIGNING_ALGORITHM: 'delta',
        JOB_DOCUMENT: JOB_DOCUMENT
      }
    },
    FunctionName: `${STACK_NAME}CreateCertificate`
  });
});

test('Good stack with Private CA enabled', () => {
  const app = new cdk.App({
    context: {      
      PcaCaId: 'alpha',
      PcaValidityInDays: 'beta',
      PcaSigningAlgorithm: 'delta'
    }
  });

  const stack = new CertificateRotator.CertificateRotatorStack(app, STACK_NAME);

  const template = Template.fromStack(stack);
  checkBasicResources(template);
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: {
        JOB_DOCUMENT: JOB_DOCUMENT,
        PCA_CA_ARN: {
          "Fn::Join": [
            "",
            [
              "arn:aws:acm-pca:",
              {
                "Ref": "AWS::Region"
              },
              ":",
              {
                "Ref": "AWS::AccountId"
              },
              ":certificate-authority/alpha"
            ]
          ]
        },
        PCA_VALIDITY_IN_DAYS: 'beta',
        PCA_SIGNING_ALGORITHM: 'delta'
      }
    },
    FunctionName: `${STACK_NAME}CreateCertificate`
  });
});

test('Missing context variables', () => {
  const app = new cdk.App();
  expect(() => {
    new CertificateRotator.CertificateRotatorStack(app, STACK_NAME);
  }).toThrow();
});
