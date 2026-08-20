# Contributing

Contributions are welcome when they preserve the plugin's narrow Preview
contract and evidence boundaries.

## Development setup

Use a supported Node.js version and install without running dependency install
scripts:

```sh
npm ci --ignore-scripts
npm test
npm run verify:package
npm run test:dsh
```

After publishing a release, verify the downloaded asset, sidecar, packaged
contract, and full exact-host lifecycle:

```sh
npm run verify:release -- \
  https://github.com/JoFe2/kaleidosphere-dsh-plugin/releases/download/v0.1.0-preview.1/kaleidosphere-dsh-plugin-0.1.0-preview.1.tgz \
  https://github.com/JoFe2/kaleidosphere-dsh-plugin/releases/download/v0.1.0-preview.1/kaleidosphere-dsh-plugin-0.1.0-preview.1.tgz.sha256
```

The exact-host smoke installs DeepSeek Harness `0.1.0-rc.8` in a temporary
profile, executes all six tools, exercises HMR unload/reload and removal, and
deletes its temporary directory. Set `DSH_TOOLS_ROOT` only to reuse a trusted
existing exact-rc.8 tool installation.

## Change rules

- Keep each commit coherent and add a Developer Certificate of Origin sign-off
  with `git commit --signoff`.
- Work on a feature branch and use the protected pull-request path. Do not
  force-push protected history, bypass required checks, retag a release, or
  replace published assets.
- Stage explicit paths only. Do not mix unrelated changes into a plugin PR.
- Add or update focused tests for behavior changes. Documentation claims must
  match code and current evidence.
- Do not hand-edit generated/vendor provenance. A KaleidoSphere or Oracle
  driver update requires exact-source reconciliation, licence review, digest
  regeneration, package audit, and full lifecycle evidence.
- Do not add a free-SQL surface, raw-row return path, credential values in
  configuration, source writes, or a background service without a separately
  reviewed product and security design.

## Compatibility changes

DSH is a Developer Preview. A peer dependency change is a compatibility change,
not routine dependency maintenance. Update `COMPATIBILITY.md`, run the complete
exact-host smoke against the proposed host version, and publish a new Preview
release if the change is accepted.

Changes to the six tool names, KaleidoSphere External API v2 envelopes, K1
evidence receipts, or K2 intent contracts are public contract changes and need
new deterministic fixtures/digests plus migration notes.

## Pull-request evidence

A release-quality pull request should state:

- exact base and head commits;
- focused tests and package/provenance checks run;
- exact DSH version and lifecycle-smoke result;
- behavior and compatibility claims added or removed;
- rollback path and any evidence not obtained.

Never include credentials, customer data, live connection strings, or private
test output. Follow `SECURITY.md` for sensitive vulnerability reports.
