# Changelog

All notable changes to this project are documented here. Versions follow
Semantic Versioning; Preview versions may change when the pinned DeepSeek
Harness Developer Preview ABI changes.

## [Unreleased]

- Compile parameterized tool authoring schemas through DSH rc.8 `defineTool`,
  producing object-rooted model schemas and enforcing required arguments before
  KaleidoSphere runtime dispatch.
- Add exact rc.8 schema snapshots plus discovery/plan/preview happy and negative
  Agent E2E coverage while retaining HMR, remove/reinstall, and zero-residue
  lifecycle evidence.

## [0.1.0-preview.2] - 2026-08-20

- Use DSH's shipped `headless` agent profile for the copy-paste fixture flow,
  so installation leads directly to a natural-language DSH request.
- Add a deterministic rc.8 agent-level probe covering model-visible discovery,
  KS tool execution, negative cases, restart cleanup, and removal against the
  immutable Preview release bytes.
- Add six advanced boolean intent-exposure switches while retaining all six as
  the one-click default.
- Add an advanced fail-closed loopback binding to an existing attested
  KaleidoSphere v0.16.0 External API v2 runtime; embedded remains the default.

## [0.1.0-preview.1] - 2026-08-20

- Add one prebuilt native DSH bundle pinned to `dsh-v0.1.0-rc.8`.
- Register six KaleidoSphere tools for status, discovery, analysis, plan,
  preview, and readback.
- Add the bundled deterministic fixture plus existing Microsoft SQL Server and
  Oracle live-profile semantics.
- Preserve KaleidoSphere External API v2, K1 evidence, and K2 closed-intent
  integrity contracts.
- Add HMR unload/reload, remove/reinstall, invalid-configuration, package,
  provenance, and exact-rc.8 lifecycle verification.

[Unreleased]: https://github.com/JoFe2/kaleidosphere-dsh-plugin/compare/v0.1.0-preview.2...HEAD
[0.1.0-preview.2]: https://github.com/JoFe2/kaleidosphere-dsh-plugin/releases/tag/v0.1.0-preview.2
[0.1.0-preview.1]: https://github.com/JoFe2/kaleidosphere-dsh-plugin/releases/tag/v0.1.0-preview.1
