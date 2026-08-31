package adapter

import (
	"fmt"
)

const (
	ExpectedIssuerRepository         = "kimjooyoon/gooo-foundation-issuer"
	ExpectedIssuerVersion            = "v0.1.1"
	ExpectedIssuerReleaseID    int64 = 380068546
	ExpectedIssuerTagObject          = "668db38af511137dd1d45d5798e809ad7a27154b"
	ExpectedIssuerTarget             = "73bf3e6b0e99ca1d9f89a493ba9374a9c6b2512d"
	ExpectedIssuerEvidenceID   int64 = 538557367
	ExpectedIssuerEvidenceName       = "gooo-foundation-issuer-evidence-v0.1.1.tar.gz"
	ExpectedIssuerEvidenceSize int64 = 3397
	ExpectedIssuerEvidenceSHA        = "sha256:a64b9a266120265298e2bc07c9f070bba0186d3f0082f9da2dcd0859c86b14d9"
	ExpectedIssuerBinaryID     int64 = 538557369
	ExpectedIssuerBinaryName         = "gooo-foundation-issuer-linux-amd64"
	ExpectedIssuerBinarySize   int64 = 5830846
	ExpectedIssuerBinarySHA          = "sha256:43dcf620472b5fbc452263b7aaa72b47b336e1dd6570fe41b068191ba2cf67f4"
	ExpectedIssuerPublicKey          = "5p0KdsDkbj1wPJ+fshp0sTb9lf8GvbFeagbdG8kCU7w="

	ExpectedRotationRepository         = "kimjooyoon/gooo-foundation-rotation"
	ExpectedRotationVersion            = "v0.1.2"
	ExpectedRotationReleaseID    int64 = 380045288
	ExpectedRotationTagObject          = "cc311eb5b14f54b5e467f9402c6f7a32e9b5b3dc"
	ExpectedRotationTarget             = "5534a6814fdd9c8c6ddd957d5c26fd5c15258e02"
	ExpectedRotationEvidenceID   int64 = 538516119
	ExpectedRotationEvidenceName       = "gooo-foundation-rotation-evidence-v0.1.2.tar.gz"
	ExpectedRotationEvidenceSize int64 = 4767
	ExpectedRotationEvidenceSHA        = "sha256:d259722c20cb3e525575d4bfb1488424ab4d23eed964fe68334345711635fe6d"
	ExpectedRotationBinaryID     int64 = 538516120
	ExpectedRotationBinaryName         = "gooo-foundation-rotation-linux-amd64"
	ExpectedRotationBinarySize   int64 = 4604245
	ExpectedRotationBinarySHA          = "sha256:82bd491f106abbe729242bcb0bb8b5a47d8dd5d9ceaa35be73722e4fc90d6b36"

	ExpectedTargetRepository     = "kimjooyoon/meta-ontology-go"
	ExpectedTargetPR             = 619
	ExpectedTargetBaseRef        = "dev"
	ExpectedTargetBaseSHA        = "ac3a56b933d9a9b934fe26709485dc2f36edd916"
	ExpectedTargetHeadRef        = "agent/meta-policy-compilation-semantic-authority-20260901"
	ExpectedTargetHeadSHA        = "90f5fdf2198a7da5cde405f9f675cc62975b9226"
	ExpectedCandidateDigest      = "sha256:0df9610f6300503ac39f18a9389695de33ac2b0edb3523a25fc4df77c0fa166e"
	ExpectedProtectedScopeDigest = "sha256:3e09937e0e48ec2fcf4c6c605ae5937756648b4532a1735e5d4cd6b9c04e44fb"

	ExpectedGuardianPolicySchema   = "gooo/meta-foundation-authorization/v2"
	ExpectedGuardianDispatchSchema = "gooo/ci-governance-denominator-migration/v6"
	ExpectedGuardianPR             = 609
	ExpectedGuardianBranch         = "agent/dev-main-sync-20260831-rerun"
	ExpectedGuardianBaseSHA        = "e440cbc99f24ceb8385f1b89c70f8cdada10cdbb"
	ExpectedGuardianHeadSHA        = "8b47db349315c02933296423b0ae7fa80ffeb1dc"
	ExpectedGuardianMergeBaseSHA   = "bc5dc21788aa4c7d46d1f8ab516f8218bb423fdc"
	ExpectedGuardianReceiptPath    = ".github/governance-denominator-v6-foundation-authorization-dispatch.json"
)

var ExpectedProtectedScope = []string{
	".github/agent-scope-table.md",
	".github/ci-governance.json",
	".github/workflows/meta-policy-compilation.yml",
	".github/workflows/transformation-effect.yml",
	"internal/verify/scope_meta_policy_compilation_semantic_authority_20260901.go",
}

var ExpectedTarget = PayloadTarget{
	Repository: ExpectedTargetRepository, PullRequest: ExpectedTargetPR, BaseRef: ExpectedTargetBaseRef,
	BaseSHA: ExpectedTargetBaseSHA, HeadRef: ExpectedTargetHeadRef, HeadSHA: ExpectedTargetHeadSHA,
	CandidateDigest: ExpectedCandidateDigest, ProtectedScope: ExpectedProtectedScope,
	ProtectedScopeDigest: ExpectedProtectedScopeDigest,
}

func ExpectedIssuerRelease() Release {
	return Release{Repository: ExpectedIssuerRepository, Version: ExpectedIssuerVersion, ReleaseID: ExpectedIssuerReleaseID, Immutable: true, TagObjectSHA: ExpectedIssuerTagObject, TargetCommit: ExpectedIssuerTarget, Assets: []Asset{
		{ID: ExpectedIssuerEvidenceID, Name: ExpectedIssuerEvidenceName, Size: ExpectedIssuerEvidenceSize, SHA256: ExpectedIssuerEvidenceSHA},
		{ID: ExpectedIssuerBinaryID, Name: ExpectedIssuerBinaryName, Size: ExpectedIssuerBinarySize, SHA256: ExpectedIssuerBinarySHA},
	}}
}

func ExpectedRotationRelease() Release {
	return Release{Repository: ExpectedRotationRepository, Version: ExpectedRotationVersion, ReleaseID: ExpectedRotationReleaseID, Immutable: true, TagObjectSHA: ExpectedRotationTagObject, TargetCommit: ExpectedRotationTarget, Assets: []Asset{
		{ID: ExpectedRotationEvidenceID, Name: ExpectedRotationEvidenceName, Size: ExpectedRotationEvidenceSize, SHA256: ExpectedRotationEvidenceSHA},
		{ID: ExpectedRotationBinaryID, Name: ExpectedRotationBinaryName, Size: ExpectedRotationBinarySize, SHA256: ExpectedRotationBinarySHA},
	}}
}

func ValidateRelease(actual, expected Release) error {
	if actual.Repository != expected.Repository || actual.Version != expected.Version || actual.ReleaseID != expected.ReleaseID || !actual.Immutable || actual.TagObjectSHA != expected.TagObjectSHA || actual.TargetCommit != expected.TargetCommit {
		return fmt.Errorf("immutable release identity is not exact")
	}
	if len(actual.Assets) != len(expected.Assets) {
		return fmt.Errorf("release asset count is not exact")
	}
	for i := range expected.Assets {
		if actual.Assets[i] != expected.Assets[i] {
			return fmt.Errorf("release asset %d is not exact", i+1)
		}
	}
	return nil
}

func ValidateTarget(target PayloadTarget) error {
	if target.Repository != ExpectedTarget.Repository || target.PullRequest != ExpectedTarget.PullRequest || target.BaseRef != ExpectedTarget.BaseRef || target.BaseSHA != ExpectedTarget.BaseSHA || target.HeadRef != ExpectedTarget.HeadRef || target.HeadSHA != ExpectedTarget.HeadSHA || target.CandidateDigest != ExpectedTarget.CandidateDigest || target.ProtectedScopeDigest != ExpectedTarget.ProtectedScopeDigest || !equalStrings(target.ProtectedScope, ExpectedTarget.ProtectedScope) {
		return fmt.Errorf("exact PR #619 target tuple mismatch")
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
