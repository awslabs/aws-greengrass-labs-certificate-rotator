// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib/core';
import * as codebuild from 'aws-cdk-lib/aws-codebuild';
import * as codecommit from 'aws-cdk-lib/aws-codecommit';
import * as codepipeline from 'aws-cdk-lib/aws-codepipeline';
import * as codepipeline_actions from 'aws-cdk-lib/aws-codepipeline-actions';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as events_targets from 'aws-cdk-lib/aws-events-targets';
import * as events from 'aws-cdk-lib/aws-events';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as gdkConfig from '../../gdk-config.json';
import { NagSuppressions } from 'cdk-nag'

type CicdStackContext = {
	connectionId: string,
  ownerName: string,
  repositoryName: string,
  branchName: string,
  thingGroupName: string,
  pcaCaId: string
}

export class CicdStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const context = this.getContext();

    // Extract configuration from GDK configuration to prevent mismatches
    const componentName = Object.keys(gdkConfig['component'])[0];
    const bucketName = gdkConfig['component'][componentName as keyof typeof gdkConfig['component']]['publish']['bucket'];

    const backendBuildProject = this.createPipelineProject('BuildBackend', 'backend', 10);
    const componentBuildProject = this.createPipelineProject('BuildComponent', 'component', 10);
    const testProject = this.createPipelineProject('Test', 'test', 120);

    const pipelineBucket = this.createBucket();

    const pipeline = this.createPipeline(backendBuildProject, componentBuildProject, testProject,
                                          pipelineBucket, context);

    this.createSnsTopic(pipeline);

    this.createTestReportGroup('Unit', componentBuildProject, pipelineBucket);
    this.createTestReportGroup('Integration', testProject, pipelineBucket);

    // The pipeline projects need some extra rights
    backendBuildProject.role?.attachInlinePolicy(this.createBackendBuildProjectPolicy())
    componentBuildProject.role?.attachInlinePolicy(this.createComponentBuildProjectPolicy(context.thingGroupName,
                                                                                          componentName, bucketName))
    testProject.role?.attachInlinePolicy(this.createTestProjectPolicy(context.thingGroupName, context.pcaCaId))
  }

  private createPipelineProject(name: string, specName: string, timeout: number): codebuild.PipelineProject {
    const project = new codebuild.PipelineProject(this, `${this.stackName}${name}`, {
      projectName: `${this.stackName}${name}`,
      buildSpec: codebuild.BuildSpec.fromSourceFilename(`cicd/buildspec-${specName}.yaml`),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_7_0
      },
      timeout: cdk.Duration.minutes(timeout),
      // This key specification should be redundant because it's the same as the default if it's
      // not specified. However CDK Nag complains if it's not here. Specifying is better than suppressing.
      encryptionKey: kms.Alias.fromAliasName(this, `${this.stackName}${name}S3Key`, 'alias/aws/s3')
    });

    NagSuppressions.addResourceSuppressions(project, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'The default policy created in the code build project role includes wildcards.'
      }
    ], true )

    return project;
  }

  private createBucket(): s3.Bucket {
    return new s3.Bucket(this, `${this.stackName}Bucket`, {
      bucketName: `${this.stackName.toLowerCase()}-${this.account}-${this.region}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: false,
      serverAccessLogsPrefix: 'access-logs',
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true
    });
  }

  private createPipeline(backendBuildProject: codebuild.PipelineProject,
                          componentBuildProject: codebuild.PipelineProject,
                          testProject: codebuild.PipelineProject,
                          pipelineBucket: s3.Bucket,
                          context: CicdStackContext): codepipeline.Pipeline {
    const sourceArtifact = new codepipeline.Artifact('Source');
    const backendBuildArtifact = new codepipeline.Artifact('BuildAndDeployBackend');
    const componentBuildArtifact = new codepipeline.Artifact('BuildAndDeployComponent');
    const testArtifact = new codepipeline.Artifact('Test');

    var sourceAction;

    if (context.connectionId !== '') {
        sourceAction = new codepipeline_actions.CodeStarConnectionsSourceAction({
            actionName: 'Source',
            output: sourceArtifact,
            connectionArn: `arn:aws:codestar-connections:${this.region}:${this.account}:connection/${context.connectionId}`,
            owner: context.ownerName,
            repo: context.repositoryName,
            branch: context.branchName
          });
    } else {
        // If no CodeStar connection ID is defined, we assume CodeCommit is being used.
        const codeCommitRepository = codecommit.Repository.fromRepositoryName(this, `${this.stackName}Repository`,
                                                                              context.repositoryName);
        sourceAction = new codepipeline_actions.CodeCommitSourceAction({
            actionName: 'Source',
            output: sourceArtifact,
            repository: codeCommitRepository,
            branch: context.branchName
        });    
    }

    const backendBuildAction = new codepipeline_actions.CodeBuildAction({
      actionName: 'BuildAndDeployBackend',
      project: backendBuildProject,
      input: sourceArtifact,
      outputs: [backendBuildArtifact]
    });

    const componentBuildAction = new codepipeline_actions.CodeBuildAction({
      actionName: 'BuildAndDeployComponent',
      project: componentBuildProject,
      input: sourceArtifact,
      outputs: [componentBuildArtifact],
      environmentVariables: {
        "THING_GROUP_NAME": { value: context.thingGroupName }
      }
    });

    const testAction = new codepipeline_actions.CodeBuildAction({
      actionName: 'Test',
      project: testProject,
      input: sourceArtifact,
      outputs: [testArtifact],
      environmentVariables: {
        "THING_GROUP_NAME": { value: context.thingGroupName },
        "PCA_CA_ID": { value: context.pcaCaId }
      }
    });

    const pipeline = new codepipeline.Pipeline(this, `${this.stackName}`, {
      pipelineName: `${this.stackName}`,
      pipelineType: codepipeline.PipelineType.V2,
      artifactBucket: pipelineBucket,
      stages: [
        {
          stageName: 'Source',
          actions: [sourceAction],
        },
        {
          stageName: 'BuildAndDeploy',
          actions: [backendBuildAction, componentBuildAction],
        },
        {
          stageName: 'Test',
          actions: [testAction],
        }
      ],
    });
  
    NagSuppressions.addResourceSuppressions(pipeline, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'The default policy created in the pipeline role includes wildcards.'
      }
    ], true )

    return pipeline;
  }

  private createSnsTopic(pipeline: codepipeline.Pipeline) {
    // We need a Customer Managed Key for this topic because we need to
    // define a KMS key policy that allows Event Bridge to use the
    // key when publishing to SNS. We can't achieve this with the default
    // AWS-managed SNS key.
    // https://repost.aws/knowledge-center/sns-not-getting-eventbridge-notification
    // https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-troubleshooting.html#eb-no-messages-published-sns
    const key = new kms.Key(this, `${this.stackName}Key`, {
      alias: `${this.stackName}/sns`,
      description: `${this.stackName} SNS Key`,
      enableKeyRotation: true,
      pendingWindow: cdk.Duration.days(7),
      removalPolicy: cdk.RemovalPolicy.DESTROY
    });

    key.addToResourcePolicy(new iam.PolicyStatement({
      principals: [new iam.ServicePrincipal('events.amazonaws.com')],
      actions: [
        'kms:Decrypt',
        'kms:GenerateDataKey'
      ],
      resources: ['*'],
    }));
  
    const topic = new sns.Topic(this, `${this.stackName}Notification`, {
      topicName: `${this.stackName}Notification`,
      displayName: `${this.stackName} CI/CD Notification`,
      masterKey: key
    });

    // Send only SUCCEEDED and FAILED states to the SNS topic, to give a pipeline execution result
    const notificationRule = pipeline.onStateChange(`${this.stackName}StateChange`);
    notificationRule.addEventPattern({ detail: { state: ['SUCCEEDED','FAILED'] } });
    const state = events.EventField.fromPath('$.detail.state')
    const executionId = events.EventField.fromPath('$.detail.execution-id')
    const account = events.EventField.fromPath('$.account')
    notificationRule.addTarget(new events_targets.SnsTopic(topic, {
      message: events.RuleTargetInput.fromText(`Account ${account} ${state} for execution ID ${executionId}`)
    }));
  }

  private createTestReportGroup(name: string, project: codebuild.PipelineProject, bucket: s3.Bucket) {
    // We create the unit tests report group explicitly, rather than let CodeBuild do it,
    // so that we can define the raw results export
    new codebuild.CfnReportGroup(this, `${this.stackName}${name}TestReportGroup`, {
      type: 'TEST',
      name: `${project.projectName}-${name}TestsReport`,
      exportConfig: {
        exportConfigType: 'S3',
         s3Destination: {
          bucket: bucket.bucketName,
          encryptionDisabled: true,
          packaging: 'NONE'
        }
      }
    });
  }

  private createBackendBuildProjectPolicy(): iam.Policy {
    const policy = new iam.Policy(this, `${this.stackName}BackendBuildProjectPolicy`, {
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['sts:AssumeRole'],
          resources: [
            `arn:aws:iam::${this.account}:role/cdk-*-deploy-role-${this.account}-${this.region}`,
            `arn:aws:iam::${this.account}:role/cdk-*-lookup-role-${this.account}-${this.region}`,
            `arn:aws:iam::${this.account}:role/cdk-*-file-publishing-role-${this.account}-${this.region}`,
          ]
        })
      ]
    })

    NagSuppressions.addResourceSuppressions(policy, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'The wildcards used above are least privilege.'
      }
    ], true )

    return policy;
  }

  private createComponentBuildProjectPolicy(thingGroupName: string, componentName: string,
                                            bucketName: string): iam.Policy {
    const policy = new iam.Policy(this, `${this.stackName}ComponentBuildProjectPolicy`, {
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['greengrass:CreateDeployment'],
          resources: ['*']
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:CreateJob'],
          resources: [
            `arn:aws:iot:${this.region}:${this.account}:job/*`,
            `arn:aws:iot:${this.region}:${this.account}:thing/*`,
            `arn:aws:iot:${this.region}:${this.account}:thinggroup/${thingGroupName}`,
            `arn:aws:iot:${this.region}:${this.account}:jobtemplate/*`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:DescribeJob', 'iot:CancelJob', 'iot:UpdateJob'],
          resources: [`arn:aws:iot:${this.region}:${this.account}:job/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:DescribeThingGroup'],
          resources: [`arn:aws:iot:${this.region}:${this.account}:thinggroup/${thingGroupName}`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['greengrass:CreateComponentVersion','greengrass:ListComponentVersions'],
          resources: [`arn:aws:greengrass:${this.region}:${this.account}:components:${componentName}`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['s3:CreateBucket','s3:GetBucketLocation'],
          resources: [`arn:aws:s3:::${bucketName}-${this.region}-${this.account}`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['s3:PutObject','s3:GetObject'],
          resources: [`arn:aws:s3:::${bucketName}-${this.region}-${this.account}/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['greengrass:GetDeployment', 'greengrass:ListDeployments'],
          resources: [`arn:aws:greengrass:${this.region}:${this.account}:deployments:*`]
        })
      ]
    })

    NagSuppressions.addResourceSuppressions(policy, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'The wildcards used above are least privilege.'
      }
    ], true )

    return policy;
  }

  private createTestProjectPolicy(thingGroupName: string, pcaCaId: string): iam.Policy {
    const policy = new iam.Policy(this, `${this.stackName}TestProjectPolicy`, {
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['greengrass:CreateDeployment'],
          resources: ['*']
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:CreateJob'],
          resources: [
            `arn:aws:iot:${this.region}:${this.account}:job/*`,
            `arn:aws:iot:${this.region}:${this.account}:thing/*`,
            `arn:aws:iot:${this.region}:${this.account}:thinggroup/${thingGroupName}`,
            `arn:aws:iot:${this.region}:${this.account}:jobtemplate/*`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:DescribeJob', 'iot:CancelJob', 'iot:UpdateJob'],
          resources: [`arn:aws:iot:${this.region}:${this.account}:job/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:DescribeThingGroup'],
          resources: [`arn:aws:iot:${this.region}:${this.account}:thinggroup/${thingGroupName}`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['greengrass:ListCoreDevices'],
          resources: ['*']
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['greengrass:GetDeployment', 'greengrass:ListDeployments'],
          resources: [`arn:aws:greengrass:${this.region}:${this.account}:deployments:*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['greengrass:GetCoreDevice', 'greengrass:ListInstalledComponents'],
          resources: [`arn:aws:greengrass:${this.region}:${this.account}:coreDevices:*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:DescribeEndpoint', 'iot:ListThingPrincipals'],
          resources: ['*']
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:ListThingsInThingGroup'],
          resources: [`arn:aws:iot:${this.region}:${this.account}:thinggroup/${thingGroupName}`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:AddThingToThingGroup', 'iot:RemoveThingFromThingGroup'],
          resources: [
            `arn:aws:iot:${this.region}:${this.account}:thing/*`,
            `arn:aws:iot:${this.region}:${this.account}:thinggroup/${thingGroupName}`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:DescribeJobTemplate' ],
          resources: [`arn:aws:iot:${this.region}:${this.account}:jobtemplate/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:DescribeCertificate', 'iot:UpdateCertificate'],
          resources: [`arn:aws:iot:${this.region}:${this.account}:cert/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:DisableTopicRule','iot:EnableTopicRule' ],
          resources: [`arn:aws:iot:${this.region}:${this.account}:rule/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iotjobsdata:DescribeJobExecution'],
          resources: [`arn:aws:iot:${this.region}:${this.account}:thing/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['lambda:GetFunctionConfiguration', 'lambda:UpdateFunctionConfiguration'],
          resources: [`arn:aws:lambda:${this.region}:${this.account}:function:*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['acm-pca:DescribeCertificateAuthority'],
          resources: [`arn:aws:acm-pca:${this.region}:${this.account}:certificate-authority/${pcaCaId}`]
        })
      ]
    })

    NagSuppressions.addResourceSuppressions(policy, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'The wildcards used above are least privilege.'
      }
    ], true )

    return policy;
  }

  private getContextVariable(name:string, desc:string): string {
    const contextVariable = this.node.tryGetContext(name);

    if (contextVariable === undefined) {
      throw new Error(`Variable undefined: ${name}\n${desc}`);
    }

    return contextVariable;
  }

  private getContext(): CicdStackContext {
    const connectionId    = this.getContextVariable('ConnectionId',   'CodeStar connection ID of the repo, if hosted in GitHub, BitBucket and GitHub Enterprise Server (Default: Empty string denoting CodeCommit as the host)');
    const ownerName       = this.getContextVariable('OwnerName',      'Name of the owner of the repo, if hosted in GitHub, BitBucket and GitHub Enterprise Server (Default: Empty string because CodeCommit is the default host)');
    const repositoryName  = this.getContextVariable('RepositoryName', 'Name of the repository containing the source code (Default: aws-greengrass-labs-certificate-rotator)');
    const branchName      = this.getContextVariable('BranchName',     'Name of the branch to use in the repository (Default: main)');
    const thingGroupName  = this.getContextVariable('ThingGroupName', 'Name of the Thing group of Greengrass core device(s) to which the component should be deployed and tested (Mandatory)');
    const pcaCaId         = this.getContextVariable('PcaCaId',        'ID of the AWS Private CA certificate to use for issuing device certificates (Default: Empty string denoting no AWS Private CA)');

    return {
      connectionId,
      ownerName,
      repositoryName,
      branchName,
      thingGroupName,
      pcaCaId
    }
  }
}
