# Security policy

DataSniper stores unusually sensitive household identity information. Treat every release as security-sensitive.

## Supported use

The supported deployment is a single household computer or a trusted home server bound to localhost. Do not expose port 8787 directly to the public internet. Remote access requires a private VPN and HTTPS termination configured by a competent administrator.

## Security controls

- Identity fields are encrypted at rest with a local Fernet key.
- The household interface is protected by an Argon2 password hash.
- Session cookies use SameSite=Strict and can be marked Secure behind HTTPS.
- State-changing requests reject foreign browser origins.
- Responses disable caching, framing, referrers, and unnecessary browser permissions.
- Login failures are rate limited.
- Automatic backups use consistent SQLite snapshots and SHA-256 checksums.
- The container runs as a non-root user with a read-only filesystem and no Linux capabilities.
- CI runs tests, compilation checks, and dependency vulnerability auditing.

## Known limits

- Local malware or an administrator account on the same computer may access the database and key.
- Backups include the encryption key so they can restore the vault. Protect backup media with full-disk encryption.
- Public-page disappearance cannot prove that a broker deleted all backend records.
- Broker pages and procedures change. Adapter behavior must be reviewed before release.
- The current household model uses one administrator login. Distinct delegated accounts and granular authorization are a future requirement before serving unrelated customers.

## Reporting a vulnerability

Do not open a public issue containing exploit details or personal data. Use GitHub private vulnerability reporting when enabled, or contact the repository owner privately. Include affected version, reproduction steps, impact, and a proposed mitigation when possible.

## Release gate

A commercial release must not ship unless CI passes, dependency audit findings are resolved or explicitly risk-accepted, backups have been restored in a clean environment, installer signatures are valid, and broker adapter URLs have been manually verified.
