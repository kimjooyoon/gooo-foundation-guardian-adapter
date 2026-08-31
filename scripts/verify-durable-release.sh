#!/usr/bin/env bash
set -euo pipefail

repository=kimjooyoon/gooo-foundation-guardian-adapter
version=${1:-v0.1.0}
run_id=${GITHUB_RUN_ID:-local}
temp_root=${RUNNER_TEMP:-"$(pwd)/.ci-tmp"}
out_dir="$temp_root/gooo-foundation-guardian-adapter-release-audit-$run_id"
rm -rf "$out_dir"
mkdir -p "$out_dir/assets"

release=$(gh api "repos/$repository/releases/tags/$version")
release_id=$(jq -r .id <<<"$release")
tag_ref=$(gh api "repos/$repository/git/ref/tags/$version")
tag_object=$(jq -r '.object.sha' <<<"$tag_ref")
tag_type=$(jq -r '.object.type' <<<"$tag_ref")
target=$(gh api "repos/$repository/git/tags/$tag_object" --jq '.object.sha')
if [[ "$(jq -r .immutable <<<"$release")" != true || "$tag_type" != tag ]]; then
  echo 'release is not an immutable annotated release' >&2
  exit 1
fi

mapfile -t asset_names < <(jq -r '.assets[].name' <<<"$release" | sort)
if [[ "${#asset_names[@]}" -ne 2 || "${asset_names[0]}" != gooo-foundation-guardian-adapter-evidence-v0.1.0.tar.gz || "${asset_names[1]}" != gooo-foundation-guardian-adapter-linux-amd64 ]]; then
  echo 'release asset inventory is not exact' >&2
  exit 1
fi
for name in "${asset_names[@]}"; do
  gh release download "$version" --repo "$repository" --pattern "$name" --dir "$out_dir/assets" --clobber
done

assets=$(jq '[.assets[]|{id:.id,name:.name,size:.size,digest:.digest}]|sort_by(.name)' <<<"$release")
verified_assets='[]'
for name in "${asset_names[@]}"; do
  path="$out_dir/assets/$name"
  size=$(stat -c '%s' "$path" 2>/dev/null || stat -f '%z' "$path")
  digest="sha256:$(shasum -a 256 "$path" | awk '{print $1}')"
  api_size=$(jq -r --arg name "$name" '.[]|select(.name==$name)|.size' <<<"$assets")
  api_digest=$(jq -r --arg name "$name" '.[]|select(.name==$name)|.digest' <<<"$assets")
  [[ "$size" == "$api_size" && "$digest" == "$api_digest" ]] || { echo "asset verification failed: $name" >&2; exit 1; }
  verified_assets=$(jq --argjson item "$(jq -c --arg name "$name" '.[]|select(.name==$name)' <<<"$assets")" '. + [$item]' <<<"$verified_assets")
done

jq -n --arg schema 'gooo/foundation-guardian-adapter/durable-release-verification/v1' --arg repository "$repository" --arg version "$version" --argjson release_id "$release_id" --arg tag_object_sha "$tag_object" --arg target_commit "$target" --argjson assets "$verified_assets" '{schema:$schema,repository:$repository,version:$version,release_id:$release_id,immutable:true,annotated_tag:true,tag_object_sha:$tag_object,target_commit:$target,assets:$assets,asset_digests_verified_after_download:true}' > "$out_dir/durable-release-verification.json"
jq . "$out_dir/durable-release-verification.json"
echo "audit-dir=$out_dir"
