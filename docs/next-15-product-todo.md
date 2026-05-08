# AstraGrid Next 15 Product Todo

This list keeps the next work honest: every item must either ship local working logic, a tested
operator flow, or a documented external dependency. No public-service, signing, installer, or
hardware claim is marked complete until real infrastructure exists.

## Wave 1: DevOps Blackbox Daily Use

- [x] Add a profile doctor shortcut for DevOps Blackbox workspaces.
- [x] Add a markdown DevOps report export.
- [x] Add a command gate mode that records failures and can fail the caller.
- [x] Add status counts by record kind and status.
- [x] Highlight the latest failed DevOps record.
- [x] Show project-work counts in the operator console summary.
- [x] Document the daily DevOps Blackbox workflow.
- [x] Add focused tests for parsing, report export, doctor, and status counts.

## Wave 2: Product Readiness Still To Build

- [x] Add a one-command local console launcher for DevOps profiles.
- [x] Add append-only task open/complete records for planned work.
- [x] Add report sections for attached artifact hashes.
- [x] Add backup and restore smoke commands scoped to DevOps profiles.
- [ ] Add a native operator console app shell.
- [ ] Add real public installer lanes: MSI, winget, and Scoop.
- [ ] Add real signed update channel and release signing operations.

## Final External Gates

The local Windows CLI package is ready to use. These public-product gates remain external and must
not be marked complete without real credentials, signing infrastructure, and distribution channels:

- Native operator console app shell.
- MSI, winget, and Scoop publication.
- Signed public binaries.
- Remote signed update channel.
