# Compatibility

This Preview intentionally supports a narrow, evidence-backed matrix. A version
not listed as verified is not implied to work.

| Component | Supported or verified state | Evidence boundary |
|---|---|---|
| DeepSeek Harness | Exact `dsh-v0.1.0-rc.8` / `@deepseek-ai/dsh@0.1.0-rc.8` | Clean-profile install, six tool executions, HMR, removal, and reinstall are verified. |
| `@deepseek-ai/dsh-tools` | Exact peer `0.1.0-rc.8` | Loaded by the exact rc.8 host; it is not bundled as a second host runtime. |
| KaleidoSphere External API | Exact product `v0.16.0`, contract `2.0.0` | Advanced loopback-only binding verifies the complete capability attestation before registering tools. |
| KaleidoSphere | Embedded runtime subset from `v0.16.0` at `5a73ff8146afa0067d226cffa639efde959e8fde` | Provenance and vendored-file digests are checked. |
| Node.js | Declared `^22.19.0 || >=24.0.0`; CI uses `24.19.0` | Node 24 is the hosted-CI evidence lane; Node 22 is an engine contract, not a separate CI lane yet. |
| Operating system | Linux hosted runner | macOS and Windows are not yet claimed as verified. |
| Fixture source | Included deterministic Microsoft SQL Server-shaped fixture | Six results and their integrity/evidence digests are pinned. |
| Live Microsoft SQL Server | Existing KaleidoSphere v0.16.0 profile fields with a read-only principal | Profile contract is validated; no live customer database result is claimed. |
| Live Oracle | Existing KaleidoSphere v0.16.0 profile fields with a read-only principal and bundled Oracle Thin driver | Profile and driver contract are validated; no live customer database result is claimed. |
| PostgreSQL | Not a main Preview plugin path | The bounded KaleidoSphere pilot is deliberately not advertised as supported here. |

## Upgrade policy

DeepSeek Harness is a Developer Preview. Before changing the peer dependency
or compatibility statement, run the complete package audit and exact-host
lifecycle smoke against the proposed DSH version. Publish any compatibility
change as a new plugin version; never retag or replace an existing release.

If a future KaleidoSphere package export replaces the vendored runtime subset,
the six DSH tool contracts and mode selection remain the migration boundary.
The change still requires fresh fixture digests, provenance checks, lifecycle
evidence, and an additive protected release.
