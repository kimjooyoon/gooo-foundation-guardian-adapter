#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

run_id=${GITHUB_RUN_ID:-local}
temp_root=${RUNNER_TEMP:-"$ROOT/.ci-tmp"}
out_dir="$temp_root/gooo-foundation-guardian-adapter-$run_id"
rm -rf "$out_dir"
mkdir -p "$out_dir/bin" "$out_dir/downloads/issuer" "$out_dir/downloads/rotation" "$out_dir/issuer-evidence" "$out_dir/rotation-evidence" "$out_dir/adapter-output" "$out_dir/consumer-output"

all_line_count() {
  find . -type f -not -path './.git/*' -print0 | xargs -0 awk 'END { print NR + 0 }'
}

go_line_count() {
  find . -type f -name '*.go' -not -path './.git/*' -print0 | xargs -0 awk 'END { print NR + 0 }'
}

gooo_line_count() {
  find . -type f -name '*.gooo' -not -path './.git/*' -print0 | xargs -0 awk 'END { print NR + 0 }'
}

go_file_count() {
  find . -type f -name '*.go' -not -path './.git/*' -print | wc -l | tr -d ' '
}

gooo_file_count() {
  find . -type f -name '*.gooo' -not -path './.git/*' -print | wc -l | tr -d ' '
}

dir_count() {
  find . -mindepth 1 -type d -not -path './.git' -not -path './.git/*' -print | wc -l | tr -d ' '
}

regular_before=$(find . -type f -not -path './.git/*' -print | wc -l | tr -d ' ')
physical_before=$(all_line_count)
root_readme_lines=$(awk 'END { print NR + 0 }' README.md)
root_readme_other_count=$(find . -type f -iname 'README.md' -not -path './.git/*' -not -path './README.md' -print | wc -l | tr -d ' ')
if [[ "$root_readme_other_count" -lt 1 ]]; then
  echo 'retained README inventory is missing' >&2
  exit 1
fi

go_files=$(go_file_count)
go_lines=$(go_line_count)
gooo_files=$(gooo_file_count)
gooo_lines=$(gooo_line_count)
descendant_dirs=$(dir_count)
regular_after=$((regular_before - 1))
physical_after=$((physical_before - root_readme_lines))

api_release() {
  local repository=$1
  local version=$2
  local output=$3
  local raw="$out_dir/${version//./-}-${repository##*/}-release.json"
  local tag_ref tag_object target
  gh api "repos/$repository/releases/tags/$version" > "$raw"
  tag_ref=$(gh api "repos/$repository/git/ref/tags/$version")
  if [[ "$(jq -r '.object.type' <<<"$tag_ref")" != tag ]]; then
    echo "$repository $version is not an annotated tag" >&2
    exit 1
  fi
  tag_object=$(jq -r '.object.sha' <<<"$tag_ref")
  target=$(gh api "repos/$repository/git/tags/$tag_object" --jq '.object.sha')
  jq --arg repo "$repository" --arg version "$version" --arg tag_object "$tag_object" --arg target "$target" '{repository:$repo,version:$version,release_id:.id,immutable:(.immutable == true),tag_object_sha:$tag_object,target_commit:$target,assets:[.assets[]|{id:.id,name:.name,size_bytes:.size,sha256:.digest}]}' "$raw" > "$output"
}

download_evidence() {
  local repository=$1
  local version=$2
  local name=$3
  local expected_size=$4
  local expected_sha=$5
  local destination=$6
  gh release download "$version" --repo "$repository" --pattern "$name" --dir "$destination" --clobber
  local path="$destination/$name"
  local size sha
  size=$(stat -c '%s' "$path" 2>/dev/null || stat -f '%z' "$path")
  sha="sha256:$(shasum -a 256 "$path" | awk '{print $1}')"
  [[ "$size" == "$expected_size" ]] || { echo "asset size mismatch for $name" >&2; exit 1; }
  [[ "$sha" == "$expected_sha" ]] || { echo "asset digest mismatch for $name" >&2; exit 1; }
}

api_release kimjooyoon/gooo-foundation-issuer v0.1.1 "$out_dir/issuer-release.json"
api_release kimjooyoon/gooo-foundation-rotation v0.1.2 "$out_dir/rotation-release.json"
download_evidence kimjooyoon/gooo-foundation-issuer v0.1.1 gooo-foundation-issuer-evidence-v0.1.1.tar.gz 3397 sha256:a64b9a266120265298e2bc07c9f070bba0186d3f0082f9da2dcd0859c86b14d9 "$out_dir/downloads/issuer"
download_evidence kimjooyoon/gooo-foundation-rotation v0.1.2 gooo-foundation-rotation-evidence-v0.1.2.tar.gz 4767 sha256:d259722c20cb3e525575d4bfb1488424ab4d23eed964fe68334345711635fe6d "$out_dir/downloads/rotation"
tar -xzf "$out_dir/downloads/issuer/gooo-foundation-issuer-evidence-v0.1.1.tar.gz" -C "$out_dir/issuer-evidence"
tar -xzf "$out_dir/downloads/rotation/gooo-foundation-rotation-evidence-v0.1.2.tar.gz" -C "$out_dir/rotation-evidence"

target_repository=kimjooyoon/meta-ontology-go
target_head=90f5fdf2198a7da5cde405f9f675cc62975b9226
guardian_ref="$target_head"
gh api "repos/$target_repository/contents/.github/foundation-authorization.json?ref=$guardian_ref" --jq .content | base64 --decode > "$out_dir/guardian-policy.json"
gh api "repos/$target_repository/contents/.github/workflows/ci-guardian.yml?ref=$guardian_ref" --jq .content | base64 --decode > "$out_dir/guardian-workflow.yml"
gh api "repos/$target_repository/contents/scripts/ci-proof/foundation_authorization.js?ref=$guardian_ref" --jq .content | base64 --decode > "$out_dir/guardian-contract.js"

build_start=$(date +%s%3N)
/usr/bin/time -f '%e %M' -o "$out_dir/build-time.txt" go build -trimpath -o "$out_dir/bin/gooo-foundation-guardian-adapter" ./cmd/gooo-foundation-guardian-adapter
go build -trimpath -o "$out_dir/bin/gooo-foundation-guardian-consumer" ./cmd/gooo-foundation-guardian-consumer
build_end=$(date +%s%3N)

test_start=$(date +%s%3N)
/usr/bin/time -f '%e %M' -o "$out_dir/test-time.txt" go test ./... -count=1 -json > "$out_dir/go-test.json"
test_end=$(date +%s%3N)

conformance_start=$(date +%s%3N)
/usr/bin/time -f '%e %M' -o "$out_dir/conformance-time.txt" "$out_dir/bin/gooo-foundation-guardian-adapter" \
  --issuer-release "$out_dir/issuer-release.json" \
  --issuer-evidence "$out_dir/issuer-evidence" \
  --rotation-release "$out_dir/rotation-release.json" \
  --rotation-evidence "$out_dir/rotation-evidence" \
  --guardian-policy "$out_dir/guardian-policy.json" \
  --guardian-workflow "$out_dir/guardian-workflow.yml" \
  --guardian-contract "$out_dir/guardian-contract.js" \
  --semantic-graph semantic/guardian-adapter.gooo \
  --guardian-ref "$guardian_ref" \
  --guardian-head "$target_head" \
  --out "$out_dir/adapter-output"
"$out_dir/bin/gooo-foundation-guardian-consumer" --proof "$out_dir/adapter-output/compatibility-proof.json" --policy semantic/guardian-adapter.gooo --out "$out_dir/consumer-output"
conformance_end=$(date +%s%3N)

test_total=$(jq -s '[.[] | select(.Action == "run" and .Test != null)] | length' "$out_dir/go-test.json")
test_executed=$(jq -s '[.[] | select(.Action == "pass" and .Test != null)] | length' "$out_dir/go-test.json")
test_failed=$(jq -s '[.[] | select(.Action == "fail" and .Test != null)] | length' "$out_dir/go-test.json")
test_skipped=$(jq -s '[.[] | select(.Action == "skip" and .Test != null)] | length' "$out_dir/go-test.json")
test_unknown=$((test_total - test_executed - test_failed - test_skipped))
build_rss=$(awk '{print $2}' "$out_dir/build-time.txt")
test_rss=$(awk '{print $2}' "$out_dir/test-time.txt")
conformance_rss=$(awk '{print $2}' "$out_dir/conformance-time.txt")
peak_rss=$((build_rss > test_rss ? build_rss : test_rss))
peak_rss=$((peak_rss > conformance_rss ? peak_rss : conformance_rss))
semantic_digest=$(shasum -a 256 semantic/guardian-adapter.gooo | awk '{print "sha256:"$1}')
source_toolchain_digest=$(printf '%s\n%s\n%s\n' "$(git rev-parse HEAD)" "$semantic_digest" "$(go env GOVERSION)" | shasum -a 256 | awk '{print "sha256:"$1}')
output_files=$(find "$out_dir/adapter-output" "$out_dir/consumer-output" -type f -print | wc -l | tr -d ' ')
output_bytes=$(find "$out_dir/adapter-output" "$out_dir/consumer-output" -type f -print0 | xargs -0 stat -c '%s' 2>/dev/null | awk '{sum += $1} END {print sum + 0}')
build_wall_ms=$((build_end - build_start))
test_wall_ms=$((test_end - test_start))
conformance_wall_ms=$((conformance_end - conformance_start))

jq -n \
  --arg schema 'gooo/foundation-guardian-adapter/ci-report/v1' \
  --arg run_id "$run_id" \
  --arg source_toolchain_digest "$source_toolchain_digest" \
  --arg semantic_digest "$semantic_digest" \
  --argjson go_files "$go_files" --argjson go_lines "$go_lines" \
  --argjson gooo_files "$gooo_files" --argjson gooo_lines "$gooo_lines" \
  --argjson regular_before "$regular_before" --argjson regular_after "$regular_after" \
  --argjson physical_before "$physical_before" --argjson physical_after "$physical_after" \
  --argjson descendant_dirs "$descendant_dirs" --argjson root_readme_lines "$root_readme_lines" \
  --argjson test_total "$test_total" --argjson test_executed "$test_executed" --argjson test_failed "$test_failed" --argjson test_skipped "$test_skipped" --argjson test_unknown "$test_unknown" \
  --argjson output_files "$output_files" --argjson output_bytes "$output_bytes" \
  --argjson build_wall_ms "$build_wall_ms" --argjson test_wall_ms "$test_wall_ms" --argjson conformance_wall_ms "$conformance_wall_ms" --argjson peak_rss_kib "$peak_rss" \
  '{schema:$schema,ci_run_id:$run_id,source_toolchain_digest:$source_toolchain_digest,semantic_graph_digest:$semantic_digest,inventory:{go_files:$go_files,go_lines:$go_lines,gooo_files:$gooo_files,gooo_lines:$gooo_lines,regular_files_root_readme_excluded:$regular_after,physical_lines_root_readme_excluded:$physical_after,descendant_directories:$descendant_dirs,root_readme_excluded:true,root_readme_physical_lines_excluded:true,other_readmes_retained:true,before_after:{regular_files:[$regular_before,$regular_after],physical_lines:[$physical_before,$physical_after]},root_readme_lines_excluded:$root_readme_lines},tests:{total:$test_total,executed:$test_executed,reused:0,failed:$test_failed,skipped:$test_skipped,unknown:$test_unknown},timing:{build_wall_ms:$build_wall_ms,test_wall_ms:$test_wall_ms,conformance_wall_ms:$conformance_wall_ms,peak_rss_kib:$peak_rss_kib},outputs:{files:$output_files,bytes:$output_bytes},precedence:["REFUTED","UNKNOWN","CLOSED"],authority:{repository_writes:0,target_repository_writes:0,target_pr_updates:0,target_workflow_dispatches:0,force_merges:0,local_test_executions:0,direct_main_commits:1,post_bootstrap_direct_main_commits:0}}' > "$out_dir/ci-report.json"

jq . "$out_dir/ci-report.json"
echo "ci-report=$out_dir/ci-report.json"
