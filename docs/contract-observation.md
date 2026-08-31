# Guardian contract observation

At the observed `meta-ontology-go` PR #619 head, `.github/workflows/ci-guardian.yml` is a `pull_request_target` workflow with read-only contents, pull-request, and Actions permissions. It has no `workflow_dispatch` trigger and no `id-token: write` permission.

The current consumer validates `gooo/meta-foundation-authorization/v2` and `gooo/ci-governance-denominator-migration/v6`, but its live dispatch constants identify PR #609, branch `agent/dev-main-sync-20260831-rerun`, and the fixed v6 receipt lineage. Those exact values do not equal the issuer's verified PR #619 tuple.

The adapter therefore creates an observed-policy snapshot and a `PROPOSED_ONLY` input/patch. It does not dispatch to, edit, or merge `meta-ontology-go`, and it does not claim Guardian acceptance.
