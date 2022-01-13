# vaultwarden-serverless

`vaultwarden-serverless` allows you to run [vaultwarden](https://github.com/dani-garcia/vaultwarden)
on AWS in a "serverless" fashion, using Lambda, API Gateway, and Elastic File System.
Custom domain name support is also provided through integration with Route 53 and
Amazon Certificate Manager.

## Deployment

The `nix` package manager is required to build and deploy this project.
Using `nix` 2.4 or later with the [flakes feature](https://nixos.wiki/wiki/Flakes)
enabled is recommended, as the commands in this readme assume the use of flakes.

For a simple deployment that uses the default credentials in your `~/.aws/config` file,
run this command:

```
$ nix run github:schlarpc/vaultwarden-serverless -- --stack-name vaultwarden-serverless
```

This command will deploy a minimal bootstrap CloudFormation stack named `vaultwarden-serverless`,
build a container image and upload it to Elastic Container Registry, then
promote the bootstrap stack into a full deployment of the rest of the infrastructure.
Once fully deployed, the `Endpoint` output of the CloudFormation stack will
contain the URL for your new vaultwarden installation.

There are a few other arguments that can be passed to the deployment command, allowing
you to customize the availability zones used and to set up a custom domain name.
To use a custom domain name, its DNS must already be served through a Route 53 hosted zone.
Additionally, non-default AWS profiles or regions can be used by
setting the standard environment variables. Below is an example of these options:

```
$ env AWS_DEFAULT_REGION=us-west-2 AWS_PROFILE=some-other-profile \
  nix run github:schlarpc/vaultwarden-serverless -- \
  --stack-name vaultwarden-serverless --availability-zones us-west-2a,us-west-2b \
  --domain-name vaultwarden.example.com --hosted-zone-id Z148QEXAMPLE8V
```

Updates can be applied to the stack by running the deployment script again.
Optional arguments provided during a previous deployment are saved by CloudFormation
and automatically apply to future updates. Also, note that changing availability
zones after the initial deployment may not function correctly due to the design of
this project's CloudFormation template.

## Implementation details

### Network (VPC)

This project's CloudFormation stack creates a VPC with one subnet for each
availability zone specified at creation time. This VPC is isolated from direct internet
connectivity; there is no internet gateway and DNS resolution is disabled.

This isolation has both practical and idealistic motivations. Practically speaking,
allowing a VPC-attached Lambda to connect to the internet either requires expensive NAT
gateways or [unsupported hacks](https://github.com/glassechidna/lambdaeip).
At the same time, it's easy to show that this improves our security posture by
eliminating several classes of vulnerabilities (e.g. SSRF). This does come with
consequences though, as several features are unavailable: transactional
emails, website icon downloads, and several forms of 2-factor authentication
(Duo, Yubikey OTP, and email) are not usable.

Attached to the VPC are two resources - the Lambda function which runs vaultwarden
and Elastic File System mount targets. An explicit trust relationship is established
between these two resources using their attached security groups, allowing NFS traffic
to flow between them.

### Storage (Elastic File System)

The storage backend used in this project is Elastic File System, a managed NFS
service. Each concurrently executing Lambda accesses the same shared filesystem,
and can read and write to the SQLite database and other files used by vaultwarden.
SQLite's write-ahead logging mode is disabled due to its incompatibility with
network filesystems.

Automatic backup is enabled in Elastic File System, which will store daily
backups with a 35-day retention period to the AWS Backup service. Restoring
from one of these backups is a fairly manual process, but specifying the
`SftpPublicKey` stack parameter will help you out by provisioning an SFTP
endpoint for the filesystem.

### Web server (API Gateway)

The HTTPS endpoint for vaultwarden is provided by an API Gateway HTTP API.
This endpoint is configured to invoke the backend service Lambda function on any
incoming HTTP request.

API Gateway and Lambda integrations limit request and response sizes to around
5 MB, so it is recommended to avoid the use of large attachments or sends.

API Gateway does not offer unencrypted HTTP (port 80) endpoints, so only
HTTPS (port 443) access to vaultwarden is provided.

API Gateway HTTP APIs do not support WebSocket connections, and API Gateway
WebSocket APIs use a programming model unsuitable for unmodified vaultwarden.
Therefore, the "live sync" feature is not supported by this project.

### Service (Lambda)

The actual vaultwarden service is run within Lambda functions, with
concurrent processes launched on-demand to satisfy incoming requests. A small
Python script is used to manage the lifecycle of the vaultwarden process and
to translate requests between the API Gateway JSON format and vaultwarden's HTTP
listener.

You may want to access the vaultwarden admin page to change configuration options,
such as whether account registration is open. To do this, you must manually
add the `ADMIN_TOKEN` environment variable to the Lambda function's configuration.
In the future, this might be handled through an integration with
Systems Manager Parameter Store or Secrets Manager, but the isolated VPC makes
this challenging.

## Future improvements

* Handle admin token better, potentially with Parameter Store / Secrets Manager integration
* Cloaking domain name from certificate transparency logs by issuing a wildcard cert
* Add HTTP Strict Transport Security header
* Constrain CloudFormation to make sure domain name and hosted zone ID are always defined together

