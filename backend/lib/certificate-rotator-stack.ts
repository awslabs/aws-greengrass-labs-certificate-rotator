// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as iot from 'aws-cdk-lib/aws-iot';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as cr from 'aws-cdk-lib/custom-resources';
import { NagSuppressions } from 'cdk-nag'

const JOB_DOCUMENT: string = '{"operation":"ROTATE_CERTIFICATE"}';

type CertificateRotatorStackContext = {
  pcaCaId: string,
  pcaValidityInDays: string,
  pcaSigningAlgorithm: string
}

export class CertificateRotatorStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const context = this.getContext();

    const topic = this.createSnsTopic();
    this.createJobTemplate();    

    // Create the environment variables needed by the lambdas
    const createCertEnv = this.createCreateCertEnv(context);
    const commitCertEnv = this.createCommitCertEnv();
    const jobTerminalEnv = this.createJobTerminalEnv(topic)

    const createCertificateLambda = this.createLambda('CreateCertificate', 'create_certificate', 60, createCertEnv);
    const commitCertificateLambda = this.createLambda('CommitCertificate', 'commit_certificate', 10, commitCertEnv);
    const jobExecutionTerminalLambda = this.createLambda('JobExecutionTerminal', 'job_execution_terminal', 10, jobTerminalEnv);

    // The lambdas need some extra rights
    createCertificateLambda.role?.attachInlinePolicy(this.createCertificateLambdaPolicy())
    commitCertificateLambda.role?.attachInlinePolicy(this.commitCertificateLambdaPolicy())
    jobExecutionTerminalLambda.role?.attachInlinePolicy(this.jobExecutionTerminalLambdaPolicy(topic))

    // SNS topic can only be published to by the job execution terminal almbda
    this.createSnsTopicPolicy(topic, jobExecutionTerminalLambda);

    this.createRule('CreateCertificate', createCertificateLambda, 
                    `SELECT *, topic(3) AS thingName, topic() as topic, clientid() AS clientId, principal() AS principal FROM 'awslabs/things/+/certificate/create'`)
    this.createRule('CommitCertificate', commitCertificateLambda, 
                    `SELECT *, topic(3) AS thingName, topic() as topic, clientid() AS clientId, principal() AS principal FROM 'awslabs/things/+/certificate/commit'`)
    this.createRule('JobExecutionTerminal', jobExecutionTerminalLambda, 
                    `SELECT * FROM '$aws/events/jobExecution/#' WHERE isUndefined(statusDetails.certificateRotationProgress) = false`)

    this.createJobExecutionEventsCustomResource()
  }

  private createSnsTopic(): sns.Topic {
    const topic = new sns.Topic(this, `${this.stackName}SNSTopic`, {
      topicName: `${this.stackName}Notification`,
      displayName: 'AWS Labs Certificate Rotator Notification',
      masterKey: kms.Alias.fromAliasName(this, `${this.stackName}SNSKey`, 'alias/aws/sns')
    });

    return topic;
  }

  private createSnsTopicPolicy(topic: sns.Topic, lambdaFunction: lambda.Function) {
    const topicPolicy = new sns.TopicPolicy(this, `${this.stackName}SNSTopicPolicy`, {
      topics: [topic],
    });
    
    topicPolicy.document.addStatements(new iam.PolicyStatement({
      actions: ['sns:Publish'],
      principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
      resources: [topic.topicArn],
      conditions: {
        'ArnLike': {
          'aws:SourceArn': lambdaFunction.functionArn
        }
      }
    }));
  }

  private createJobTemplate() {
    new iot.CfnJobTemplate(this, `${this.stackName}JobTemplate`, {
      description: 'Template for creating device certificate rotation jobs',
      jobTemplateId: `${this.stackName}`,
      document: JOB_DOCUMENT,
      jobExecutionsRolloutConfig: {
        // Set a value that should keep us well below API action limits for a large fleet
        MaximumPerMinute: 100,
        ExponentialRolloutRate: {
          BaseRatePerMinute: 100,
          IncrementFactor: 1.2,
          RateIncreaseCriteria: {
            NumberOfSucceededThings: 100
          }
        }
      },
      timeoutConfig: {
        InProgressTimeoutInMinutes: 5
      }
    });
  }

  private createCreateCertEnv(context: CertificateRotatorStackContext) {
    var pcaCaArn;

    // Setup the AWS Private CA certificate ARN if a CA certificate ID is defined
    if (context.pcaCaId !== '') {
      pcaCaArn = `arn:aws:acm-pca:${this.region}:${this.account}:certificate-authority/${context.pcaCaId}`;
    } else {
      pcaCaArn = '';
    }
  
    const env = {
      'JOB_DOCUMENT': JOB_DOCUMENT,
      'PCA_CA_ARN': pcaCaArn,
      'PCA_VALIDITY_IN_DAYS': context.pcaValidityInDays,
      'PCA_SIGNING_ALGORITHM': context.pcaSigningAlgorithm
    };
  
    return env;
  }

  private createCommitCertEnv() {
    return {
      'JOB_DOCUMENT': JOB_DOCUMENT
    }
  }

  private createJobTerminalEnv(topic: sns.Topic) {
    return {
      'JOB_DOCUMENT': JOB_DOCUMENT,
      'SNS_TOPIC_ARN': topic.topicArn
    }
  }

  private createLambdaBasicRole(lambdaFunctionName: string): iam.Role {
    const logGroupName = `/aws/lambda/${lambdaFunctionName}`

    // Create our own basic role so CDK nag doesn't nag about AWSLambdabasicExecutionRole
    const basicRole = new iam.Role(this, `${lambdaFunctionName}Role`, {
      roleName: `${lambdaFunctionName}Role`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      inlinePolicies: { 'cloudwatch': new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            actions: [
              'logs:CreateLogGroup',
              'logs:CreateLogStream'
            ],
            resources: [`arn:aws:logs:${this.region}:${this.account}:log-group:${logGroupName}:*`]
          }),
          new iam.PolicyStatement({
            actions: [
              'logs:PutLogEvents'
            ],
            resources: [`arn:aws:logs:${this.region}:${this.account}:log-group:${logGroupName}:log-stream:*`]
          })
        ]
      })}
    });

    NagSuppressions.addResourceSuppressions(basicRole, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'The wildcards used above are least privilege.'
      }
    ], true )

    return basicRole;
  }

  private createLambda(name: string, sourceName: string, timeout: number, environment: {} ): lambda.Function {
    const lambdaFunctionName = `${this.stackName}${name}`

    const basicRole = this.createLambdaBasicRole(lambdaFunctionName)

    const lambdaFunction = new lambda.Function(this, `${lambdaFunctionName}Lambda`, {
      functionName: lambdaFunctionName,
      description: `AWS Labs Certificate Rotator: ${name}`,
      runtime: lambda.Runtime.PYTHON_3_12,
      code: lambda.Code.fromAsset(`lambda/${sourceName}`),
      handler: `${sourceName}.handler`,
      retryAttempts: 0,
      maxEventAge: cdk.Duration.seconds(60),
      timeout: cdk.Duration.seconds(timeout),
      environment: environment,
      role: basicRole
    });

    NagSuppressions.addResourceSuppressions(lambdaFunction, [
      {
        id: 'AwsSolutions-L1',
        reason: 'Using latest runtime when coded. Do not let this block deployment when new runtimes get released.'
      }
    ], true )

    return lambdaFunction;
  }

  private createCertificateLambdaPolicy(): iam.Policy {
    const policy = new iam.Policy(this, `${this.stackName}CreateLambdaPolicy`, {
      statements: [
        // Wildcard resource is required for these actions
        // https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiot.html
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'iot:DescribeEndpoint', 'iot:CreateCertificateFromCsr',
            'iot:RegisterCertificateWithoutCA', 'iot:ListPrincipalPolicies',
            'iot:ListThingPrincipals', 'iot:AttachThingPrincipal'
          ],
          resources: ['*']
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'iot:AttachPolicy'
          ],
          resources: [`arn:aws:iot:${this.region}:${this.account}:cert/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'iotjobsdata:DescribeJobExecution', 'iotjobsdata:UpdateJobExecution'
          ],
          resources: [`arn:aws:iot:${this.region}:${this.account}:thing/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'acm-pca:IssueCertificate', 'acm-pca:GetCertificate'
          ],
          resources: [`arn:aws:acm-pca:${this.region}:${this.account}:certificate-authority/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:Publish'],
          resources: [
            `arn:aws:iot:${this.region}:${this.account}:topic/awslabs/things/*/certificate/create/accepted`,
            `arn:aws:iot:${this.region}:${this.account}:topic/awslabs/things/*/certificate/create/rejected`
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

  private commitCertificateLambdaPolicy(): iam.Policy {
    const policy = new iam.Policy(this, `${this.stackName}CommitLambdaPolicy`, {
      statements: [
        // Wildcard resource is required for these actions
        // https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiot.html
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'iot:DescribeEndpoint', 'iot:ListThingPrincipals'
          ],
          resources: ['*']
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'iotjobsdata:DescribeJobExecution', 'iotjobsdata:UpdateJobExecution'
          ],
          resources: [`arn:aws:iot:${this.region}:${this.account}:thing/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['iot:Publish'],
          resources: [
            `arn:aws:iot:${this.region}:${this.account}:topic/awslabs/things/*/certificate/commit/accepted`,
            `arn:aws:iot:${this.region}:${this.account}:topic/awslabs/things/*/certificate/commit/rejected`
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

  private jobExecutionTerminalLambdaPolicy(topic: sns.Topic): iam.Policy {
    const policy = new iam.Policy(this, `${this.stackName}JobTerminalLambdaPolicy`, {
      statements: [
        // Wildcard resource is required for these actions
        // https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiot.html
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'iot:ListPrincipalPolicies', 'iot:ListThingPrincipals',
            'iot:DetachThingPrincipal'
          ],
          resources: ['*']
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'iot:DescribeCertificate', 'iot:DeleteCertificate',
            'iot:DetachPolicy', 'iot:UpdateCertificate'
          ],
          resources: [`arn:aws:iot:${this.region}:${this.account}:cert/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'iot:GetJobDocument',
          ],
          resources: [`arn:aws:iot:${this.region}:${this.account}:job/*`]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'sns:Publish'
          ],
          resources: [`${topic.topicArn}`]
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

  private createRule(name: string, lambda: lambda.Function, sql: string) {
    // Create a rule that invokes a Lambda
    const rule = new iot.CfnTopicRule(this, `${this.stackName}${name}Rule`, {
      topicRulePayload: {
        description: `AWS Labs Certificate Rotator: ${name}`,
        sql: sql,
        awsIotSqlVersion: '2016-03-23',
        actions: [{
          lambda: {
            functionArn: lambda.functionArn,
          }
        }]      
      },
      ruleName: `${this.stackName}${name}`
    });

    // Give the rule permission to invoke the Lambda
    lambda.addPermission(`${name}IoTRulePermission`, {
      principal: new iam.ServicePrincipal('iot.amazonaws.com', {
        conditions: {
          ArnLike: {
            'aws:SourceArn': rule.attrArn,
          },
          StringEquals: {
            'aws:SourceAccount': this.account,
          }
        }
      })
    });
  }

  private createJobExecutionEventsCustomResource() {
    const lambdaFunctionName = `${this.stackName}CustomResourceJobExecutionEvents`

    const basicRole = this.createLambdaBasicRole(lambdaFunctionName)
    basicRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'iot:UpdateEventConfigurations'
      ],
      resources: ['*']
    }));

    new cr.AwsCustomResource(this, `${lambdaFunctionName}`, {
      functionName: `${lambdaFunctionName}`,
      // Update is also called on create
      onUpdate: {
        service: 'Iot',
        action: 'updateEventConfigurations',
        parameters: {
          eventConfigurations: {
            'JOB_EXECUTION': {
              Enabled: true
            }
          }
        },
        physicalResourceId: cr.PhysicalResourceId.of(`${lambdaFunctionName}Id`)
      },
      role: basicRole
    });

    NagSuppressions.addResourceSuppressions(this, [
      {
        id: 'AwsSolutions-L1',
        reason: 'Cannot control the runtime when using a custom resource in this way.'
      }
    ], true )
    NagSuppressions.addResourceSuppressions(basicRole, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'The wildcards in the role are least privilege.'
      }
    ], true )
  }

  private getContextVariable(name:string, desc:string): string {
    const contextVariable = this.node.tryGetContext(name);

    if (contextVariable === undefined) {
        throw new Error(`Context variable undefined: ${name}\n${desc}`);
    }

    return contextVariable;
  }

  private getContext(): CertificateRotatorStackContext {
    const pcaCaId             = this.getContextVariable('PcaCaId',             'ID of the AWS Private CA certificate to use for issuing device certificates');
    const pcaValidityInDays   = this.getContextVariable('PcaValidityInDays',   'Number of days the device certificates issued by AWS Private CA are valid for');
    const pcaSigningAlgorithm = this.getContextVariable('PcaSigningAlgorithm', 'SHA256WITHECDSA | SHA384WITHECDSA | SHA512WITHECDSA | SHA256WITHRSA | SHA384WITHRSA | SHA512WITHRSA');

    return {
        pcaCaId,
        pcaValidityInDays,
        pcaSigningAlgorithm
    }
  }
}
