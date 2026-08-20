# KaleidoSphere for DeepSeek Harness

Native database analysis inside DeepSeek Harness — one plugin install, no separate KaleidoSphere checkout, service, endpoint, or startup step.

> Preview compatibility: DeepSeek Harness `dsh-v0.1.0-rc.8` / `@deepseek-ai/dsh@0.1.0-rc.8` at `141eb6fef83422698aef7a981029e843e8161534`. DSH is a Developer Preview and breaking updates may require a plugin release.

See the [evidence-backed compatibility matrix](COMPATIBILITY.md) for the exact
host, Node.js, operating-system, and database support boundaries.

## Install and try the fixture

Install DSH and pnpm, then add the immutable plugin release to a profile:

```sh
npm install --global @deepseek-ai/dsh@0.1.0-rc.8 pnpm@11.7.0
dsh plugin --profile kaleidosphere add github:JoFe2/kaleidosphere-dsh-plugin#v0.1.0-preview.1
dsh --profile kaleidosphere --dump-config
dsh --profile kaleidosphere
```

The default profile uses the bundled exact MSSQL synthetic fixture, so these six native tools are available immediately:

- `kaleidosphere_status`
- `kaleidosphere_discovery`
- `kaleidosphere_analyze`
- `kaleidosphere_plan`
- `kaleidosphere_preview`
- `kaleidosphere_readback`

A typical agent flow is `status` → `analyze` → `discovery`/`plan`/`preview` → `readback`. Every result is wrapped in the released KaleidoSphere External API v2 integrity envelope and a K1 evidence receipt. The intent set comes from the released K2 closed-intent contract.

Short demo:

```text
User: Analyze the configured database, propose a weekly order-value view, and show the readback.
Agent: kaleidosphere_status → kaleidosphere_analyze → kaleidosphere_plan
       → kaleidosphere_preview → kaleidosphere_readback
Result: deterministic fixture snapshot 293a896156d8f6269c4ad33e8d632da653ea180d35a4ea5f390b0be52ce3e44a
```

## Configure a real source

KaleidoSphere v0.16.0's supported main runtime paths are Microsoft SQL Server and Oracle. The plugin includes both required client paths (including the exact Oracle Thin driver), so no separate driver approval or KS install is required. It accepts the existing closed `chimpmaera.db/analyze-profile/v1` object directly; it does not invent a universal connection schema. Copy the relevant example into `$DSH_HOME/profiles/kaleidosphere/cordis.patch.yml` and adjust it:

- [`examples/live-mssql.patch.yml`](examples/live-mssql.patch.yml)
- [`examples/live-oracle.patch.yml`](examples/live-oracle.patch.yml)

Put the database password in the environment variable named by `adapter.passwordEnv`, then start DSH. Password values are neither accepted in plugin config nor returned by tools.

```sh
export KS_MSSQL_PASSWORD='...'
dsh --profile kaleidosphere
```

The configured principal must be read-only. The bundled KS query packs contain allowlisted metadata `SELECT` statements; raw rows, free SQL, credentials, source writes, and persistent Superset mutation are outside this plugin's tool surface. PostgreSQL remains the bounded v0.16.0 pilot and is not advertised here as a main live plugin path.

## Update, unload, and remove

DSH owns bundle composition and HMR. Disabling or reconfiguring the `kaleidosphere-dsh-plugin` row unloads its six registrations and deletes its private temporary profile directory. Normal shutdown does the same.

```sh
dsh plugin --profile kaleidosphere update kaleidosphere-dsh-plugin
dsh plugin --profile kaleidosphere remove kaleidosphere-dsh-plugin
```

Removal deletes both the profile dependency and the bundle layer. The plugin keeps fixture/readback/discovery state in memory and leaves no service, port, background process, database file, or plugin-owned state directory behind.

## Scope and provenance

This repository ships prebuilt ESM; GitHub installation needs no `prepare` script or build permission. It vendors the minimal analysis/API/K1/K2 runtime subset from KaleidoSphere v0.16.0 at exact commit `5a73ff8146afa0067d226cffa639efde959e8fde`. See [`NOTICE`](NOTICE) and the vendored Apache-2.0 license.

This Preview proves the deterministic fixture and exact rc.8 load/tool/unload/remove/reinstall lifecycle. It does not claim DSH stable ABI, host-wide DSH security, malicious third-party plugin containment, production readiness, live customer-database evidence, universal database support, Superset mutation, or upstream DeepSeek endorsement.

Report suspected vulnerabilities through the private path described in the
[security policy](SECURITY.md); never post credentials or exploit details in a
public issue.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for DCO, protected-PR, compatibility,
provenance, and evidence requirements.

```sh
npm test
npm run verify:package
npm run test:dsh
```

The exact DSH smoke installs a packed tarball into a fresh profile, checks the bundle layer and ACTIVE tool row, executes all six tools through `ctx.tools.execute`, exercises HMR unload/reload, removes/reinstalls the package, and proves scoped temporary cleanup.

`npm run verify:release -- <release.tgz> <release.tgz.sha256>` additionally
checks an immutable local or GitHub-hosted release asset and its sidecar before
running that same exact-host lifecycle against the downloaded bytes.
