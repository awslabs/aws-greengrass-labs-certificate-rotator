// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib/core';
import { Template } from 'aws-cdk-lib/assertions';
import * as Cicd from '../lib/cicd-stack';

const STACK_NAME = 'MyTestStack'

function checkBasicResources(template: Template) {
  template.hasResourceProperties('AWS::CodePipeline::Pipeline', { Name: `${STACK_NAME}` });
  template.resourceCountIs('AWS::CodeBuild::Project', 3);
  template.hasResourceProperties('AWS::CodeBuild::Project', { Name: `${STACK_NAME}BuildBackend` });
  template.hasResourceProperties('AWS::CodeBuild::Project', { Name: `${STACK_NAME}BuildComponent` });
  template.hasResourceProperties('AWS::CodeBuild::Project', { Name: `${STACK_NAME}Test` });
  template.resourceCountIs('AWS::S3::Bucket', 1);
  template.resourceCountIs('AWS::CodeBuild::ReportGroup', 2);
  template.hasResourceProperties('AWS::SNS::Topic', { TopicName: `${STACK_NAME}Notification` });
}

test('Good Stack with CodeCommit repo', () => {
    const app = new cdk.App({
      context: {
        ConnectionId: '',
        OwnerName: '',
        RepositoryName: 'delta',
        BranchName: 'gamma',
        ThingGroupName: 'epsilon',
        PcaCaId: 'zeta',
      }
    });

    const stack = new Cicd.CicdStack(app, STACK_NAME);
    const template = Template.fromStack(stack)
    template.resourceCountIs('AWS::Events::Rule', 2);
    template.hasResourceProperties('AWS::Events::Rule', {
      EventPattern: { source: [ 'aws.codecommit' ] }
    });
});

test('Good Stack with CodeStar connection', () => {
  const app = new cdk.App({
    context: {
      ConnectionId: 'alpha',
      OwnerName: 'beta',
      RepositoryName: 'delta',
      BranchName: 'gamma',
      ThingGroupName: 'epsilon',
      PcaCaId: 'zeta',
    }
  });

  const stack = new Cicd.CicdStack(app, STACK_NAME);
  const template = Template.fromStack(stack)
  template.resourceCountIs('AWS::Events::Rule', 1);
});

test('Missing Context Variables', () => {
  const app = new cdk.App();
  expect(() => {
    new Cicd.CicdStack(app, STACK_NAME);
  }).toThrow();
});
