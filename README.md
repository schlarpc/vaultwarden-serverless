# vaultwarden-serverless

* Planned improvements:
 * Handle admin token with SSM / Secrets Manager
 * WebAuthn 2FA broken (vaultwarden crashes with SIGILL)
 * Cloaking domain name from certificate transparency logs by issuing a wildcard cert
 * Add HSTS header
 * Constrain CloudFormation to make sure domain name and hosted zone ID are defined together
 * Add arg parsing to deploy script

* Known broken features, not planned to fix:
 * No HTTP endpoint that redirects to HTTPS (API Gateway limitation)
 * Service has no outbound internet access, meaning the following features do not function:
  * Email 2FA, account confirmations, etc
  * Yubikey 2FA
  * Duo 2FA
  * Website icon fetching

