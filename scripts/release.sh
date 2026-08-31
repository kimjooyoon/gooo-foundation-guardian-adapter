#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

repository=kimjooyoon/gooo-foundation-guardian-adapter
version=v0.1.0
base_sha=$(git rev-parse HEAD)
run_id=${GITHUB_RUN_ID:-local}
temp_root=${RUNNER_TEMP:-"$ROOT/.ci-tmp"}
conformance_dir="$temp_root/gooo-foundation-guardian-adapter-$run_id"
release_dir="$temp_root/gooo-foundation-guardian-adapter-release-$run_id"
rm -rf "$release_dir"
mkdir -p "$release_dir/bundle" "$release_dir/assets"

if gh api "repos/$repository/releases/tags/$version" >/dev/null 2>&1; then
  echo "release $version already exists; immutable release will not be rewritten" >&2
  exit 1
fi
if gh api "repos/$repository/git/ref/tags/$version" >/dev/null 2>&1; then
  echo "tag $version already exists; immutable tag will not be rewritten" >&2
  exit 1
fi

bash scripts/ci-conformance.sh

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$release_dir/assets/gooo-foundation-guardian-adapter-linux-amd64" ./cmd/gooo-foundation-guardian-adapter

cp "$conformance_dir/ci-report.json" "$release_dir/bundle/ci-report.json"
cp "$conformance_dir/issuer-release.json" "$release_dir/bundle/issuer-release.json"
cp "$conformance_dir/rotation-release.json" "$release_dir/bundle/rotation-release.json"
cp "$conformance_dir/guardian-policy.json" "$release_dir/bundle/observed-guardian-policy-source.json"
cp "$conformance_dir/guardian-workflow.yml" "$release_dir/bundle/observed-ci-guardian.yml"
cp "$conformance_dir/guardian-contract.js" "$release_dir/bundle/observed-foundation-authorization.js"
cp -R "$conformance_dir/adapter-output" "$release_dir/bundle/adapter-output"
cp -R "$conformance_dir/consumer-output" "$release_dir/bundle/consumer-output"
cp -R "$conformance_dir/issuer-evidence" "$release_dir/bundle/issuer-evidence"
cp -R "$conformance_dir/rotation-evidence" "$release_dir/bundle/rotation-evidence"
cp semantic/guardian-adapter.gooo "$release_dir/bundle/guardian-adapter.gooo"

cat > "$release_dir/bundle/durable-release-verification.json" <<EOF
{
  "schema": "gooo/foundation-guardian-adapter/durable-release-verification/v1",
  "repository": "$repository",
  "version": "$version",
  "tag_object_sha": "pending-before-release-publication",
  "target_commit": "$base_sha",
  "release_immutable_required": true,
  "asset_self_digest": "verified-after-publication-in-actions-artifact",
  "safety": "the published immutable release is never rewritten"
}
EOF
cat > "$release_dir/bundle/dossier.md" <<EOF
# gooo-foundation-guardian-adapter $version dossier

- source commit: $base_sha
- issuer: immutable gooo-foundation-issuer v0.1.1
- rotation: immutable gooo-foundation-rotation v0.1.2
- verified signature: true
- verified PR #619 tuple: true
- current Guardian input exact: false
- integration: UNKNOWN
- release evidence is caller-owned and was produced in GitHub Actions
EOF

tar -C "$release_dir/bundle" -czf "$release_dir/assets/gooo-foundation-guardian-adapter-evidence-v0.1.0.tar.gz" .

tag_object=$(gh api "repos/$repository/git/tags" -f tag="$version" -f message="gooo-foundation-guardian-adapter $version" -f object="$base_sha" -f type=commit --jq .sha)
gh api "repos/$repository/git/refs" -f ref="refs/tags/$version" -f sha="$tag_object" >/dev/null
release_json=$(gh api "repos/$repository/releases" -f tag_name="$version" -f target_commitish="$base_sha" -f name="gooo-foundation-guardian-adapter $version" -f body="Immutable Guardian adapter release; integration remains UNKNOWN when the observed consumer contract is not exact." -F draft=true)
release_id=$(jq -r .id <<<"$release_json")
gh release upload "$version" --repo "$repository" "$release_dir/assets/gooo-foundation-guardian-adapter-evidence-v0.1.0.tar.gz" "$release_dir/assets/gooo-foundation-guardian-adapter-linux-amd64"
gh api "repos/$repository/releases/$release_id" -X PATCH -f draft=false >/dev/null

release=$(gh api "repos/$repository/releases/tags/$version")
tag_ref=$(gh api "repos/$repository/git/ref/tags/$version")
tag_object_observed=$(jq -r '.object.sha' <<<"$tag_ref")
tag_target_observed=$(gh api "repos/$repository/git/tags/$tag_object_observed" --jq '.object.sha')
if [[ "$(jq -r '.immutable' <<<"$release")" != true || "$tag_object_observed" != "$tag_object" || "$tag_target_observed" != "$base_sha" ]]; then
  echo 'durable release identity verification failed' >&2
  exit 1
fi
asset_json=$(jq '[.assets[]|{id:.id,name:.name,size:.size,digest:.digest}]|sort_by(.name)' <<<"$release")
expected_json=$(jq -n --arg evidence "gooo-foundation-guardian-adapter-evidence-v0.1.0.tar.gz" --arg binary "gooo-foundation-guardian-adapter-linux-amd64" --argjson evidence_size "$(stat -c '%s' "$release_dir/assets/gooo-foundation-guardian-adapter-evidence-v0.1.0.tar.gz" 2>/dev/null || stat -f '%z' "$release_dir/assets/gooo-foundation-guardian-adapter-evidence-v0.1.0.tar.gz")" --argjson binary_size "$(stat -c '%s' "$release_dir/assets/gooo-foundation-guardian-adapter-linux-amd64" 2>/dev/null || stat -f '%z' "$release_dir/assets/gooo-foundation-guardian-adapter-linux-amd64")" --arg evidence_digest "sha256:$(shasum -a 256 "$release_dir/assets/gooo-foundation-guardian-adapter-evidence-v0.1.0.tar.gz" | awk '{print $1}')" --arg binary_digest "sha256:$(shasum -a 256 "$release_dir/assets/gooo-foundation-guardian-adapter-linux-amd64" | awk '{print $1}')" '[{name:$evidence,size:$evidence_size,digest:$evidence_digest},{name:$binary,size:$binary_size,digest:$binary_digest}]|sort_by(.name)')
if [[ "$(jq -c 'map({name,size,digest})' <<<"$asset_json")" != "$(jq -c . <<<"$expected_json")" ]]; then
  echo 'durable release asset verification failed' >&2
  exit 1
fi
jq -n --arg schema 'gooo/foundation-guardian-adapter/durable-release-verification/v1' --arg repository "$repository" --arg version "$version" --argjson release_id "$release_id" --arg tag_object_sha "$tag_object_observed" --arg target_commit "$tag_target_observed" --argjson assets "$asset_json" '{schema:$schema,repository:$repository,version:$version,release_id:$release_id,immutable:true,tag_object_sha:$tag_object_sha,target_commit:$target_commit,assets:$assets,asset_self_digest_verified_outside_archive:true}' > "$release_dir/durable-release-verification.json"
jq . "$release_dir/durable-release-verification.json"
echo "release-dir=$release_dir"
