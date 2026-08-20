# Security policy

## Supported versions

Only the latest published Preview release receives security fixes. DeepSeek
Harness compatibility is exact-version pinned; a fix that changes host or
KaleidoSphere compatibility is published as a new version rather than by
replacing an existing tag or asset.

| Version | Supported |
|---|---|
| `0.1.0-preview.x` latest | Yes |
| Older Preview builds | No |
| Unreleased branches | No guarantee |

## Reporting a vulnerability

Use **Report a vulnerability** on the repository's Security tab when GitHub
offers it. If that private form is unavailable, open a minimal issue requesting
a private contact channel. Do not put exploit details, credentials, connection
strings, customer data, or other secrets in a public issue.

Include, privately:

- affected plugin and DSH versions;
- source mode (`fixture`, live Microsoft SQL Server, or live Oracle);
- minimal reproduction steps and observed impact;
- whether credentials, filesystem data, network access, or source writes are
  involved;
- any proposed mitigation or safe disclosure timeline.

## Security boundary

The plugin owns its six registrations, its in-memory fixture/readback state,
and its temporary runtime directory. It removes those resources on HMR unload
and shutdown. Its live source surface uses allowlisted metadata `SELECT`
queries and requires a read-only database principal. Password values are read
from the configured environment-variable name and are not accepted in plugin
configuration or returned by tools.

This policy does not make the plugin responsible for host-wide DSH security,
other plugins, the operating-system account, network policy, database role
configuration, or misuse of a user-selected harness. It also does not claim a
security audit, malicious-plugin containment, production readiness, or live
customer-database evidence.

## Fix and disclosure process

Confirmed issues are repaired additively through a protected pull request with
focused regression evidence. Published tags and assets remain immutable. A
withdrawal or incompatible correction uses a new version and an explicit
advisory or release note; protected history is never rewritten.
