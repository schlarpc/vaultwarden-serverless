import itertools
import json

from awacs import ec2, ecr, elasticfilesystem, logs, states, sts
from awacs.aws import (
    Allow,
    Bool,
    Condition,
    PolicyDocument,
    Principal,
    Statement,
    StringEqualsIfExists,
)
from troposphere import (
    AccountId,
    And,
    Cidr,
    Condition as ConditionFn,
    Equals,
    GetAtt,
    If,
    Join,
    Not,
    NoValue,
    Output,
    Parameter,
    Partition,
    Ref,
    Region,
    Select,
    Split,
    StackName,
    Tags,
    Template,
    URLSuffix,
)
from troposphere.apigatewayv2 import (
    Api,
    ApiMapping,
    DomainName,
    DomainNameConfiguration,
    Integration,
    Route,
    Stage,
)
from troposphere.awslambda import (
    Code,
    Environment,
    FileSystemConfig,
    Function,
    Permission,
    VPCConfig,
)
from troposphere.certificatemanager import Certificate, DomainValidationOption
from troposphere.ec2 import VPC, SecurityGroup, SecurityGroupEgress, Subnet
from troposphere.ecr import EncryptionConfiguration, LifecyclePolicy, Repository
from troposphere.efs import (
    AccessPoint,
    BackupPolicy,
    CreationInfo,
    FileSystem,
    MountTarget,
    PosixUser,
    RootDirectory,
)
from troposphere.events import Rule, Target
from troposphere.iam import Policy, PolicyType, Role
from troposphere.logs import LogGroup
from troposphere.route53 import AliasTarget, RecordSetType
from troposphere.stepfunctions import StateMachine
from troposphere.transfer import PosixProfile, Server, User

MAX_AVAILABILITY_ZONES = 8


class ListChecker:
    def __init__(self, template, name, items, *, delimiter=",", default_value=""):
        self._template = template
        self._name = name
        self._items = items
        self._delimiter = delimiter
        self._default_value = default_value

    def _extract_value(self, index):
        padding = self._delimiter.join([self._default_value] * (index + 1))
        joined = Join(self._delimiter, [Join(self._delimiter, self._items), padding])
        exploded = Split(self._delimiter, joined)
        return Select(index, exploded)

    def exists(self, index) -> str:
        condition_name = f"{self._name}ListIdx{index}Exists"
        return self._template.add_condition(
            condition_name, Not(Equals(self._extract_value(index), self._default_value))
        )


def create_inline_dependency(passthrough_data, dependencies):
    return Select(0, [passthrough_data] + dependencies)


def create_template():
    template = Template()

    availability_zones = template.add_parameter(
        Parameter(
            "AvailabilityZones",
            Type="List<AWS::EC2::AvailabilityZone::Name>",
            Description=f"Select from 1 to {MAX_AVAILABILITY_ZONES} availability zones",
        )
    )

    domain_name = template.add_parameter(
        Parameter(
            "DomainName",
            Type="String",
            Default="",
            Description="Custom domain name (optional, must also provide HostedZoneId)",
        )
    )

    hosted_zone_id = template.add_parameter(
        Parameter(
            "HostedZoneId",
            Type="String",
            Default="",
            AllowedPattern="^(Z[A-Z0-9]+|)$",
            Description="Route 53 hosted zone ID (e.g. ZZ148QEXAMPLE8V)",
        )
    )

    sftp_public_key = template.add_parameter(
        Parameter(
            "SftpPublicKey",
            Type="String",
            Default="",
            AllowedPattern="^(ssh-rsa .+|)$",
            Description=" ".join(
                (
                    "SSH public key (id_rsa.pub) used to provision an SFTP endpoint.",
                    "Can be used to directly interact with vaultwarden's data storage.",
                    "(optional, fixed cost of $0.30/hour)",
                )
            ),
        )
    )

    image_digest = template.add_parameter(
        Parameter(
            "ImageDigest",
            Type="String",
            Default="",
            Description=" ".join(
                (
                    "Container image digest",
                    "(provided by deployment script, do not modify)",
                )
            ),
        )
    )

    image_architecture = template.add_parameter(
        Parameter(
            "ImageArchitecture",
            Type="String",
            AllowedValues=["x86_64", "arm64"],
            Description=" ".join(
                (
                    "Container image architecture",
                    "(provided by deployment script, do not modify)",
                )
            ),
        )
    )

    availability_zones_checker = ListChecker(
        template, "AvailabilityZones", Ref(availability_zones)
    )

    using_domain_name = template.add_condition(
        "UsingDomainName",
        And(
            Not(Equals(Ref(domain_name), "")),
            Not(Equals(Ref(hosted_zone_id), "")),
        ),
    )

    have_sftp_public_key = template.add_condition(
        "HaveSftpPublicKey",
        Not(Equals(Ref(sftp_public_key), "")),
    )

    have_image_digest = template.add_condition(
        "HaveImageDigest",
        Not(Equals(Ref(image_digest), "")),
    )

    vpc = template.add_resource(
        VPC(
            "VPC",
            CidrBlock="10.0.0.0/16",
            EnableDnsHostnames=False,
            EnableDnsSupport=False,
            Tags=Tags(Name=StackName),
        )
    )

    subnets = []
    for idx in range(MAX_AVAILABILITY_ZONES):
        availability_zone = Select(idx, Ref(availability_zones))
        subnet = template.add_resource(
            Subnet(
                f"VPCSubnet{idx}",
                MapPublicIpOnLaunch=False,
                VpcId=Ref(vpc),
                CidrBlock=Select(
                    idx, Cidr(GetAtt(vpc, "CidrBlock"), MAX_AVAILABILITY_ZONES, 8)
                ),
                AvailabilityZone=availability_zone,
                Tags=Tags(Name=Join(" ", [StackName, availability_zone])),
                Condition=availability_zones_checker.exists(idx),
            )
        )
        subnets.append(subnet)

    function_role = template.add_resource(
        Role(
            "FunctionRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[sts.AssumeRole],
                        Principal=Principal("Service", "lambda.amazonaws.com"),
                    ),
                ],
            ),
            Policies=[
                Policy(
                    PolicyName="vpc-access",
                    PolicyDocument=PolicyDocument(
                        Version="2012-10-17",
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[
                                    ec2.DescribeNetworkInterfaces,
                                ],
                                Resource=["*"],
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[
                                    ec2.CreateNetworkInterface,
                                    ec2.DeleteNetworkInterface,
                                    ec2.AssignPrivateIpAddresses,
                                    ec2.UnassignPrivateIpAddresses,
                                ],
                                Resource=["*"],
                                Condition=Condition(
                                    StringEqualsIfExists(
                                        "ec2:Vpc",
                                        Join(
                                            ":",
                                            [
                                                "arn",
                                                Partition,
                                                "ec2",
                                                Region,
                                                AccountId,
                                                Join("/", ["vpc", Ref(vpc)]),
                                            ],
                                        ),
                                    ),
                                ),
                            ),
                        ],
                    ),
                ),
            ],
        )
    )

    transfer_user_role = template.add_resource(
        Role(
            "FileSystemTransferUserRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[sts.AssumeRole],
                        Principal=Principal("Service", "transfer.amazonaws.com"),
                    ),
                ],
            ),
            Condition=have_sftp_public_key,
        )
    )

    file_system = template.add_resource(
        FileSystem(
            "FileSystem",
            Encrypted=True,
            BackupPolicy=BackupPolicy(Status="ENABLED"),
            FileSystemPolicy=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[
                            elasticfilesystem.ClientMount,
                            elasticfilesystem.ClientWrite,
                        ],
                        Principal=Principal(
                            "AWS",
                            [
                                GetAtt(function_role, "Arn"),
                                If(
                                    have_sftp_public_key,
                                    GetAtt(transfer_user_role, "Arn"),
                                    NoValue,
                                ),
                            ],
                        ),
                        Condition=Condition(
                            [
                                Bool(
                                    {
                                        "aws:SecureTransport": True,
                                    }
                                )
                            ]
                        ),
                    ),
                    Statement(
                        Effect=Allow,
                        Action=[
                            elasticfilesystem.Backup,
                        ],
                        Principal=Principal("AWS", AccountId),
                    ),
                ],
            ).JSONrepr(),
            FileSystemTags=Tags(Name=StackName),
        )
    )

    function_security_group = template.add_resource(
        SecurityGroup(
            "FunctionSecurityGroup",
            GroupDescription=StackName,
            VpcId=Ref(vpc),
            SecurityGroupEgress=[{"CidrIp": "127.0.0.1/32", "IpProtocol": "-1"}],
        )
    )

    mount_target_security_group = template.add_resource(
        SecurityGroup(
            "FileSystemMountTargetSecurityGroup",
            GroupDescription=StackName,
            VpcId=Ref(vpc),
            SecurityGroupIngress=[
                {
                    "SourceSecurityGroupId": Ref(function_security_group),
                    "IpProtocol": "tcp",
                    "FromPort": "2049",
                    "ToPort": "2049",
                }
            ],
            SecurityGroupEgress=[{"CidrIp": "127.0.0.1/32", "IpProtocol": "-1"}],
        )
    )

    function_security_group_egress = template.add_resource(
        SecurityGroupEgress(
            "FunctionSecurityGroupEgress",
            GroupId=Ref(function_security_group),
            DestinationSecurityGroupId=Ref(mount_target_security_group),
            IpProtocol="tcp",
            FromPort="2049",
            ToPort="2049",
        )
    )

    mount_targets = []
    for idx, subnet in enumerate(subnets):
        mount_target = template.add_resource(
            MountTarget(
                f"FileSystemMountTarget{idx}",
                FileSystemId=Ref(file_system),
                SecurityGroups=[
                    Ref(mount_target_security_group),
                ],
                SubnetId=Ref(subnet),
                Condition=subnet.Condition,
            )
        )
        mount_targets.append(mount_target)

    access_point = template.add_resource(
        AccessPoint(
            "FileSystemAccessPoint",
            FileSystemId=Ref(file_system),
            PosixUser=PosixUser(
                Uid="1000",
                Gid="1000",
            ),
            RootDirectory=RootDirectory(
                Path="/data",
                CreationInfo=CreationInfo(
                    OwnerUid="1000",
                    OwnerGid="1000",
                    Permissions="0755",
                ),
            ),
        )
    )

    transfer_server_role = template.add_resource(
        Role(
            "FileSystemTransferServerRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[sts.AssumeRole],
                        Principal=Principal("Service", "transfer.amazonaws.com"),
                    ),
                ],
            ),
            Condition=have_sftp_public_key,
        )
    )

    transfer_server = template.add_resource(
        Server(
            "FileSystemTransferServer",
            Domain="EFS",
            EndpointType="PUBLIC",
            IdentityProviderType="SERVICE_MANAGED",
            LoggingRole=GetAtt(transfer_server_role, "Arn"),
            Protocols=["SFTP"],
            Tags=Tags(Name=StackName),
            Condition=have_sftp_public_key,
        )
    )

    transfer_server_log_group = template.add_resource(
        LogGroup(
            "FileSystemTransferServerLogGroup",
            LogGroupName=Join(
                "/", ["/aws/transfer", GetAtt(transfer_server, "ServerId")]
            ),
            RetentionInDays=30,
            Condition=have_sftp_public_key,
        )
    )

    transfer_server_log_group_policy = template.add_resource(
        PolicyType(
            "FileSystemTransferServerLogGroupPolicy",
            PolicyName="cloudwatch-logging",
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Resource=GetAtt(transfer_server_log_group, "Arn"),
                        Action=[logs.CreateLogStream, logs.PutLogEvents],
                    ),
                ],
            ),
            Roles=[Ref(transfer_server_role)],
            Condition=have_sftp_public_key,
        )
    )

    transfer_user = template.add_resource(
        User(
            "FileSystemTransferUser",
            HomeDirectory=Join("", ["/", Ref(file_system)]),
            HomeDirectoryType="PATH",
            PosixProfile=PosixProfile(
                Uid=1000,
                Gid=1000,
            ),
            Role=GetAtt(transfer_user_role, "Arn"),
            ServerId=GetAtt(transfer_server, "ServerId"),
            SshPublicKeys=[Ref(sftp_public_key)],
            UserName="vaultwarden",
            DependsOn=[transfer_server_log_group_policy],
            Condition=have_sftp_public_key,
        )
    )

    api = template.add_resource(
        Api(
            "API",
            Name=StackName,
            ProtocolType="HTTP",
            DisableExecuteApiEndpoint=If(using_domain_name, True, False),
        )
    )

    endpoint = Join(
        "",
        [
            "https://",
            If(
                using_domain_name,
                Ref(domain_name),
                Join(".", [Ref(api), "execute-api", Region, URLSuffix]),
            ),
        ],
    )

    function_image_repository = template.add_resource(
        Repository(
            "FunctionImageRepository",
            EncryptionConfiguration=EncryptionConfiguration(
                EncryptionType="KMS",
            ),
            LifecyclePolicy=LifecyclePolicy(
                LifecyclePolicyText=json.dumps(
                    {
                        "rules": [
                            {
                                "rulePriority": 1,
                                "selection": {
                                    "tagStatus": "untagged",
                                    "countType": "imageCountMoreThan",
                                    "countNumber": 1,
                                },
                                "action": {
                                    "type": "expire",
                                },
                            }
                        ]
                    },
                    indent=None,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            ),
        )
    )

    function = template.add_resource(
        Function(
            "Function",
            MemorySize=512,
            Role=GetAtt(function_role, "Arn"),
            VpcConfig=VPCConfig(
                SecurityGroupIds=[Ref(function_security_group)],
                SubnetIds=[
                    If(subnet.Condition, Ref(subnet), NoValue) for subnet in subnets
                ],
            ),
            FileSystemConfigs=[
                FileSystemConfig(
                    Arn=create_inline_dependency(
                        GetAtt(access_point, "Arn"),
                        [
                            If(
                                mount_target.Condition,
                                Ref(mount_target),
                                NoValue,
                            )
                            for mount_target in mount_targets
                        ],
                    ),
                    LocalMountPath="/mnt/data",
                ),
            ],
            Environment=Environment(
                Variables={
                    "DATA_FOLDER": "/mnt/data",
                    "DOMAIN": endpoint,
                }
            ),
            PackageType="Image",
            Code=Code(
                ImageUri=Join(
                    "@",
                    [
                        GetAtt(function_image_repository, "RepositoryUri"),
                        Ref(image_digest),
                    ],
                ),
            ),
            Architectures=[Ref(image_architecture)],
            Timeout=28,
            DependsOn=[function_security_group_egress],
        ),
    )

    function_image_tagger_role = template.add_resource(
        Role(
            "FunctionImageTaggerRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[sts.AssumeRole],
                        Principal=Principal("Service", "states.amazonaws.com"),
                    ),
                ],
            ),
            Policies=[
                Policy(
                    PolicyName="ecr-tagging",
                    PolicyDocument=PolicyDocument(
                        Version="2012-10-17",
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[ecr.BatchGetImage, ecr.PutImage],
                                Resource=[GetAtt(function_image_repository, "Arn")],
                            ),
                        ],
                    ),
                )
            ],
        )
    )

    function_image_tagger = template.add_resource(
        StateMachine(
            "FunctionImageTagger",
            RoleArn=GetAtt(function_image_tagger_role, "Arn"),
            StateMachineType="EXPRESS",
            Definition={
                "StartAt": "GetImageManifest",
                "States": {
                    "GetImageManifest": {
                        "Type": "Task",
                        "Resource": "arn:aws:states:::aws-sdk:ecr:batchGetImage",
                        "Parameters": {
                            "ImageIds": [{"ImageDigest": Ref(image_digest)}],
                            "RepositoryName": Ref(function_image_repository),
                        },
                        "ResultPath": "$",
                        "ResultSelector": {
                            "ImageManifest.$": "$.Images[0].ImageManifest"
                        },
                        "Next": "PutImageTag",
                    },
                    "PutImageTag": {
                        "Type": "Task",
                        "Resource": "arn:aws:states:::aws-sdk:ecr:putImage",
                        "Parameters": {
                            "ImageManifest.$": "$.ImageManifest",
                            "RepositoryName": Ref(function_image_repository),
                            "ImageTag": "cloudformation-current",
                        },
                        "Catch": [
                            {
                                "ErrorEquals": ["Ecr.ImageAlreadyExistsException"],
                                "Next": "Pass",
                            }
                        ],
                        "End": True,
                    },
                    "Pass": {"Type": "Pass", "End": True},
                },
            },
            DependsOn=[function],
        )
    )

    function_image_tagger_rule_role = template.add_resource(
        Role(
            "FunctionImageTaggerRuleRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[sts.AssumeRole],
                        Principal=Principal("Service", "events.amazonaws.com"),
                    ),
                ],
            ),
            Policies=[
                Policy(
                    PolicyName="state-machine-start",
                    PolicyDocument=PolicyDocument(
                        Version="2012-10-17",
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[states.StartExecution],
                                Resource=[GetAtt(function_image_tagger, "Arn")],
                            ),
                        ],
                    ),
                )
            ],
        )
    )

    function_image_tagger_rule = template.add_resource(
        Rule(
            "FunctionImageTaggerRule",
            ScheduleExpression="rate(1 hour)",
            Targets=[
                Target(
                    Id="state-machine",
                    Arn=Ref(function_image_tagger),
                    RoleArn=GetAtt(function_image_tagger_rule_role, "Arn"),
                )
            ],
        )
    )

    function_log_group = template.add_resource(
        LogGroup(
            "FunctionLogGroup",
            LogGroupName=Join("/", ["/aws/lambda", Ref(function)]),
            RetentionInDays=30,
        )
    )

    function_log_group_policy = template.add_resource(
        PolicyType(
            "FunctionLogGroupPolicy",
            PolicyName="cloudwatch-logging",
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Resource=GetAtt(function_log_group, "Arn"),
                        Action=[logs.CreateLogStream, logs.PutLogEvents],
                    ),
                ],
            ),
            Roles=[Ref(function_role)],
        )
    )

    function_api_permission = template.add_resource(
        Permission(
            "FunctionAPIPermission",
            Action="lambda:InvokeFunction",
            FunctionName=GetAtt(function, "Arn"),
            Principal="apigateway.amazonaws.com",
            SourceArn=Join(
                ":",
                [
                    "arn",
                    Partition,
                    "execute-api",
                    Region,
                    AccountId,
                    Join("/", [Ref(api), "*"]),
                ],
            ),
            DependsOn=[function_log_group_policy],
        )
    )

    api_integration = template.add_resource(
        Integration(
            "APIIntegration",
            ApiId=Ref(api),
            IntegrationType="AWS_PROXY",
            IntegrationMethod="POST",
            PayloadFormatVersion="1.0",
            IntegrationUri=Join(
                ":",
                [
                    "arn",
                    Partition,
                    "apigateway",
                    Region,
                    "lambda",
                    Join(
                        "/",
                        [
                            "path",
                            "2015-03-31",
                            "functions",
                            GetAtt(function, "Arn"),
                            "invocations",
                        ],
                    ),
                ],
            ),
            DependsOn=[function_api_permission],
        )
    )

    api_route = template.add_resource(
        Route(
            "APIRoute",
            ApiId=Ref(api),
            RouteKey="$default",
            Target=Join("/", ["integrations", Ref(api_integration)]),
        )
    )

    api_stage = template.add_resource(
        Stage(
            "APIStage",
            ApiId=Ref(api),
            StageName="$default",
            AutoDeploy=True,
        )
    )

    api_certificate = template.add_resource(
        Certificate(
            "APICertificate",
            DomainName=Ref(domain_name),
            ValidationMethod="DNS",
            DomainValidationOptions=[
                DomainValidationOption(
                    DomainName=Ref(domain_name),
                    HostedZoneId=Ref(hosted_zone_id),
                )
            ],
            Condition=using_domain_name,
        )
    )

    api_domain_name = template.add_resource(
        DomainName(
            "APIDomainName",
            DomainName=Ref(domain_name),
            DomainNameConfigurations=[
                DomainNameConfiguration(
                    CertificateArn=Ref(api_certificate),
                    EndpointType="REGIONAL",
                )
            ],
            Condition=using_domain_name,
        )
    )

    api_mapping = template.add_resource(
        ApiMapping(
            "APIMapping",
            ApiId=Ref(api),
            DomainName=Ref(api_domain_name),
            Stage=Ref(api_stage),
            Condition=using_domain_name,
        )
    )

    api_dns_record_set = template.add_resource(
        RecordSetType(
            "APIDNSRecordSet",
            HostedZoneId=Ref(hosted_zone_id),
            Name=Ref(domain_name),
            Type="A",
            AliasTarget=AliasTarget(
                DNSName=GetAtt(api_domain_name, "RegionalDomainName"),
                HostedZoneId=GetAtt(api_domain_name, "RegionalHostedZoneId"),
            ),
            Condition=using_domain_name,
        )
    )

    output_endpoint = template.add_output(
        Output(
            "Endpoint",
            Value=endpoint,
        )
    )

    output_sftp_endpoint = template.add_output(
        Output(
            "SftpEndpoint",
            Value=Join(
                "@",
                [
                    GetAtt(transfer_user, "UserName"),
                    Join(
                        ".",
                        [
                            GetAtt(transfer_server, "ServerId"),
                            "server",
                            "transfer",
                            Region,
                            URLSuffix,
                        ],
                    ),
                ],
            ),
            Condition=have_sftp_public_key,
        )
    )

    output_function_image_repository_uri = template.add_output(
        Output(
            "FunctionImageRepositoryUri",
            Value=GetAtt(function_image_repository, "RepositoryUri"),
        )
    )

    for element in itertools.chain(
        template.resources.values(), template.outputs.values()
    ):
        if element in {function_image_repository, output_function_image_repository_uri}:
            continue
        if hasattr(element, "Condition"):
            element.Condition = template.add_condition(
                f"{have_image_digest}And{element.Condition}",
                And(
                    ConditionFn(have_image_digest),
                    ConditionFn(element.Condition),
                ),
            )
        else:
            element.Condition = have_image_digest

    return template


if __name__ == "__main__":
    print(create_template().to_json(indent=None, separators=(",", ":")))
