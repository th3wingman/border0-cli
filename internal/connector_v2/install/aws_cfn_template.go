package install

// FIXME: this will go in S3... the source of truth is in
// https://github.com/borderzero/examples/blob/main/cloudformation-templates/aws_connector_installer/template.yaml
const awsCloudFormationTemplateBody = `
AWSTemplateFormatVersion: '2010-09-09'

####################################
##           PARAMETERS           ##
####################################
Parameters:

  VpcId:
    Type: AWS::EC2::VPC::Id
    Description: The ID of the VPC where to run the connector

  SubnetId:
    Type: AWS::EC2::Subnet::Id
    Description: The ID of the Subnet where to run the connector

  InstanceType:
    Type: String
    Description: The EC2 Instance Type for the connector instance
    Default: t4g.nano

  Border0TokenSsmParameter:
    Type: AWS::SSM::Parameter::Name
    Description: The name/path of the SSM parameter for the Border0 token (which the connector instance uses to authenticate against your Border0 organization)

  Border0LogLevel:
    Type: String
    Description: The minimum severity level of events to log
    Default: info

  Border0ConnectorServer:
    Type: String
    Description: The host and port of the Border0 connector control plane GRPC server.
    Default: capi.border0.com:443

  Border0TunnelServer:
    Type: String
    Description: The host and port of the Border0 connector data plane tunnel server.
    Default: tunnel.border0.com

####################################
##           RESOURCES            ##
####################################
Resources:

  ConnectorInstanceRole:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess'
        - 'arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess'
        - 'arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess'
      Policies:
        # There is no AWS-Managed ECS ReadOnly policy
        - PolicyName: AmazonECSReadOnlyAccess
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - 'ecs:DescribeClusters'
                  - 'ecs:DescribeContainerInstances'
                  - 'ecs:DescribeServices'
                  - 'ecs:DescribeTaskDefinition'
                  - 'ecs:DescribeTasks'
                  - 'ecs:ListClusters'
                  - 'ecs:ListContainerInstances'
                  - 'ecs:ListServices'
                  - 'ecs:ListTaskDefinitionFamilies'
                  - 'ecs:ListTaskDefinitions'
                  - 'ecs:ListTasks'
                Resource: '*'
        - PolicyName: AccessToBorder0TokenSsmParameter
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: 'ssm:DescribeParameters'
                Resource: !Sub 'arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter/*'
              - Effect: Allow
                Action:
                  - 'ssm:GetParameter'
                  - 'ssm:GetParameters'
                Resource: !Sub 'arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter/${Border0TokenSsmParameter}'

  ConnectorInstanceSecurityGroup:
    Type: 'AWS::EC2::SecurityGroup'
    Properties:
      GroupDescription: Security Group for instance with only egress allowed
      VpcId: !Ref VpcId
      SecurityGroupEgress:
        - CidrIp: 0.0.0.0/0
          IpProtocol: -1

  ConnectorInstanceProfile:
    Type: 'AWS::IAM::InstanceProfile'
    Properties:
      Roles:
        - !Ref ConnectorInstanceRole

  ConnectorInstanceLaunchConfiguration:
    Type: 'AWS::AutoScaling::LaunchConfiguration'
    Properties:
      IamInstanceProfile: !Ref ConnectorInstanceProfile
      ImageId: '{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-minimal-kernel-default-arm64}}'
      InstanceType: !Ref InstanceType
      SecurityGroups:
        - !Ref ConnectorInstanceSecurityGroup
      AssociatePublicIpAddress: true
      UserData:
        Fn::Base64:
          !Sub |
            #!/bin/bash -xe
            sudo curl https://download.border0.com/linux_arm64/border0 -o /usr/local/bin/border0
            sudo chmod +x /usr/local/bin/border0
            export AWS_REGION=${AWS::Region}
            export BORDER0_TOKEN=from:aws:ssm:${Border0TokenSsmParameter}
            export BORDER0_TUNNEL=${Border0TunnelServer}
            export BORDER0_CONNECTOR_SERVER=${Border0ConnectorServer}
            export BORDER0_LOG_LEVEL=${Border0LogLevel}
            border0 connector start --v2

  ConnectorInstanceAutoScalingGroup:
    Type: 'AWS::AutoScaling::AutoScalingGroup'
    Properties:
      MinSize: '1'
      MaxSize: '1'
      DesiredCapacity: '1'
      LaunchConfigurationName: !Ref ConnectorInstanceLaunchConfiguration
      VPCZoneIdentifier:
        - !Ref SubnetId
      MetricsCollection:
        - Granularity: '1Minute'
          Metrics:
            - GroupMinSize
            - GroupMaxSize
            - GroupDesiredCapacity
            - GroupInServiceInstances
            - GroupPendingInstances
            - GroupStandbyInstances
            - GroupTerminatingInstances
            - GroupTotalInstances

`
