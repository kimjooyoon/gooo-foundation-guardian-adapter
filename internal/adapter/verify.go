package adapter

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Inputs struct {
	IssuerReleasePath    string
	IssuerEvidenceDir    string
	RotationReleasePath  string
	RotationEvidenceDir  string
	GuardianPolicyPath   string
	GuardianWorkflowPath string
	GuardianContractPath string
	SemanticGraphPath    string
	GuardianRef          string
	GuardianHeadSHA      string
}

type issuerReport struct {
	Schema                 string `json:"schema"`
	Decision               State  `json:"decision"`
	SignatureValid         bool   `json:"signature_valid"`
	TupleExact             bool   `json:"tuple_exact"`
	RotationExact          bool   `json:"rotation_exact"`
	OIDCClaimsObserved     bool   `json:"oidc_claims_observed"`
	OIDCSignatureState     State  `json:"oidc_signature_state"`
	HumanIndependenceState State  `json:"human_independence_state"`
	IntegrationState       State  `json:"integration_state"`
}

type rotationVerification struct {
	Schema                 string `json:"schema"`
	CaseID                 string `json:"case_id"`
	Decision               State  `json:"decision"`
	RotationCount          int    `json:"rotation_count"`
	IssuerEvidenceObserved bool   `json:"issuer_evidence_observed"`
	ExternalAttestation    bool   `json:"external_attestation"`
}

type rotationCIReport struct {
	Schema      string `json:"schema"`
	Denominator struct {
		Cases int `json:"cases"`
		Cells int `json:"cells"`
	} `json:"denominator"`
}

type SemanticGraphObservation struct {
	Schema        string `json:"schema"`
	Path          string `json:"path"`
	Digest        string `json:"digest"`
	InventoryLine string `json:"inventory_line"`
}

func VerifyBundle(inputs Inputs, now time.Time) (CompatibilityProof, error) {
	var issuerRelease Release
	var rotationRelease Release
	if err := ReadJSON(inputs.IssuerReleasePath, &issuerRelease); err != nil {
		return CompatibilityProof{}, fmt.Errorf("read issuer release: %w", err)
	}
	if err := ReadJSON(inputs.RotationReleasePath, &rotationRelease); err != nil {
		return CompatibilityProof{}, fmt.Errorf("read rotation release: %w", err)
	}
	checks := make([]Check, 0, 14)
	if err := ValidateRelease(issuerRelease, ExpectedIssuerRelease()); err != nil {
		return CompatibilityProof{}, fmt.Errorf("issuer release: %w", err)
	}
	checks = append(checks, Check{Name: "issuer_release_immutable_exact", State: Closed, Reason: "release ID, immutable marker, annotated tag object, target, and both assets match"})
	if err := ValidateRelease(rotationRelease, ExpectedRotationRelease()); err != nil {
		return CompatibilityProof{}, fmt.Errorf("rotation release: %w", err)
	}
	checks = append(checks, Check{Name: "rotation_release_immutable_exact", State: Closed, Reason: "release ID, immutable marker, annotated tag object, target, and both assets match"})

	issuerEvidencePath := filepath.Join(inputs.IssuerEvidenceDir, "signed-receipt.json")
	var receipt Receipt
	if err := ReadJSON(issuerEvidencePath, &receipt); err != nil {
		return CompatibilityProof{}, fmt.Errorf("read signed receipt: %w", err)
	}
	keyBytes, err := ReadBytes(filepath.Join(inputs.IssuerEvidenceDir, "public-key.pub"))
	if err != nil {
		return CompatibilityProof{}, fmt.Errorf("read issuer public key: %w", err)
	}
	observedKey := strings.TrimSpace(string(keyBytes))
	if observedKey != ExpectedIssuerPublicKey || receipt.PublicKey != ExpectedIssuerPublicKey {
		return CompatibilityProof{}, fmt.Errorf("issuer public key is not the pinned Ed25519 key")
	}
	checks = append(checks, Check{Name: "issuer_public_key_pinned", State: Closed, Observed: observedKey})

	valid, err := VerifySignature(receipt)
	if err != nil {
		return CompatibilityProof{}, fmt.Errorf("issuer receipt signature: %w", err)
	}
	if !valid {
		return CompatibilityProof{}, fmt.Errorf("issuer receipt signature: Ed25519 verification returned false")
	}
	checks = append(checks, Check{Name: "issuer_ed25519_signature", State: Closed, Reason: "payload digest and Ed25519 signature verify with the pinned public key"})

	target := PayloadTarget{
		Repository: receipt.Payload.Repository, PullRequest: receipt.Payload.PullRequest,
		BaseRef: receipt.Payload.BaseRef, BaseSHA: receipt.Payload.BaseSHA,
		HeadRef: receipt.Payload.HeadRef, HeadSHA: receipt.Payload.HeadSHA,
		CandidateDigest:      receipt.Payload.CandidateDigest,
		ProtectedScope:       append([]string(nil), receipt.Payload.ProtectedScope...),
		ProtectedScopeDigest: receipt.Payload.ProtectedScopeDigest,
	}
	if err := ValidateTarget(target); err != nil {
		return CompatibilityProof{}, fmt.Errorf("issuer candidate tuple: %w", err)
	}
	checks = append(checks, Check{Name: "pr619_candidate_tuple_exact", State: Closed, Reason: "repository, PR, base/head tuple, candidate digest, and protected scope match"})

	var rotationInput RotationInput
	if err := ReadJSON(filepath.Join(inputs.IssuerEvidenceDir, "rotation-input.json"), &rotationInput); err != nil {
		return CompatibilityProof{}, fmt.Errorf("read issuer rotation input: %w", err)
	}
	if err := validateRotationInput(rotationInput); err != nil || !equalRotation(rotationInput, receipt.Payload.Rotation) {
		if err == nil {
			err = fmt.Errorf("receipt rotation binding differs from rotation input")
		}
		return CompatibilityProof{}, fmt.Errorf("issuer rotation input: %w", err)
	}
	checks = append(checks, Check{Name: "v012_rotation_input_exact", State: Closed, Reason: "receipt rotation and issuer rotation input match the immutable v0.1.2 release"})

	if err := verifyIssuerEvidence(inputs.IssuerEvidenceDir, receipt); err != nil {
		return CompatibilityProof{}, err
	}
	checks = append(checks, Check{Name: "issuer_regression_evidence", State: Closed, Reason: "issuer report is cryptographically CLOSED and replay/revocation evidence is fail-closed"})
	if err := verifyRotationEvidence(inputs.RotationEvidenceDir); err != nil {
		return CompatibilityProof{}, err
	}
	checks = append(checks, Check{Name: "rotation_regression_evidence", State: Closed, Reason: "v0.1.2 normal rotation evidence is CLOSED"})

	guardian, err := ObserveGuardian(inputs)
	if err != nil {
		return CompatibilityProof{}, err
	}
	guardianExact := guardian.TargetMatch
	if guardianExact {
		checks = append(checks, Check{Name: "guardian_consumer_contract_exact", State: Closed})
	} else {
		checks = append(checks, Check{Name: "legacy_guardian_input_mismatch", State: Unknown, Reason: "current Guardian's fixed PR609/v6 input does not accept the verified PR619 tuple"})
	}
	checks = append(checks,
		Check{Name: "external_human_independence", State: Unknown, Reason: "same-owner operation has no directly verified independent human approval"},
		Check{Name: "oidc_signature_verification", State: Unknown, Reason: "OIDC claims are observed in the issuer evidence; token signature verification is not established"},
	)

	temporal := "WITHIN_ISSUANCE_WINDOW"
	if receipt.Payload.Expired(now) {
		temporal = "EXPIRED_HISTORICAL_RECEIPT"
	}
	integration := Unknown
	if guardianExact {
		integration = Closed
	}
	proof := CompatibilityProof{
		Schema:     "gooo/foundation-guardian-adapter/compatibility-proof/v1",
		ObservedAt: now.UTC().Format(time.RFC3339), Decision: Combine(Closed, integration, Unknown, Unknown),
		CryptographicState: Closed, IntegrationState: integration,
		HumanIndependenceState: Unknown, OIDCSignatureState: Unknown,
		ReceiptTemporalState: temporal, IssuerRelease: issuerRelease, RotationRelease: rotationRelease,
		ReceiptDigest: receipt.PayloadDigest, SignatureValid: true, TupleExact: true, RotationExact: true,
		GuardianInputExact: guardianExact, AcceptedGuardianInput: nil, Target: target, Guardian: guardian,
		Inventory: observeInventory(inputs.SemanticGraphPath), Checks: checks,
		AuthorityBoundary: AuthorityBoundary{
			ExternalHumanIndependence: "UNKNOWN", OIDCVerification: "UNKNOWN", GuardianIntegration: string(integration),
			SameOwnerLimit: "same owner operates issuer, adapter, and target; independence is not inferred",
		},
	}
	return proof, nil
}

func VerifySignature(receipt Receipt) (bool, error) {
	if receipt.Schema != ReceiptSchema || receipt.PayloadType != PayloadType {
		return false, fmt.Errorf("receipt schema or payload type mismatch")
	}
	publicBytes, err := base64.StdEncoding.DecodeString(receipt.PublicKey)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("public key is malformed")
	}
	signature, err := base64.StdEncoding.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("signature is malformed")
	}
	payloadBytes, err := json.Marshal(receipt.Payload)
	if err != nil {
		return false, err
	}
	if Digest(payloadBytes) != receipt.PayloadDigest {
		return false, fmt.Errorf("payload digest mismatch")
	}
	return ed25519.Verify(ed25519.PublicKey(publicBytes), payloadBytes, signature), nil
}

func validateRotationInput(rotation RotationInput) error {
	expected := ExpectedRotationRelease()
	actual := Release{Repository: rotation.Repository, Version: rotation.Version, ReleaseID: rotation.ReleaseID, Immutable: rotation.Immutable, TagObjectSHA: rotation.TagObjectSHA, TargetCommit: rotation.TargetCommit, Assets: rotation.Assets}
	return ValidateRelease(actual, expected)
}

func equalRotation(left, right RotationInput) bool {
	return left.Repository == right.Repository && left.Version == right.Version && left.ReleaseID == right.ReleaseID && left.Immutable == right.Immutable && left.TagObjectSHA == right.TagObjectSHA && left.TargetCommit == right.TargetCommit && equalAssets(left.Assets, right.Assets)
}

func equalAssets(left, right []Asset) bool {
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

func verifyIssuerEvidence(dir string, receipt Receipt) error {
	var report issuerReport
	if err := ReadJSON(filepath.Join(dir, "issuer-verification-report.json"), &report); err != nil {
		return fmt.Errorf("read issuer verification report: %w", err)
	}
	if report.Schema != "gooo/foundation-authorization/verification-report/v1" || report.Decision != Unknown || !report.SignatureValid || !report.TupleExact || !report.RotationExact || report.OIDCSignatureState != Unknown || report.HumanIndependenceState != Unknown || report.IntegrationState != Unknown {
		return fmt.Errorf("issuer verification report is not the expected CLOSED/UNKNOWN boundary")
	}
	var replay ReplayEvidence
	if err := ReadJSON(filepath.Join(dir, "replay-revocation-evidence.json"), &replay); err != nil {
		return fmt.Errorf("read replay evidence: %w", err)
	}
	if replay.Schema != "gooo/foundation-authorization/replay-evidence/v1" || replay.ReceiptDigest != receipt.PayloadDigest || replay.FirstUse != Closed || replay.SecondUse != Refuted || replay.RevokedKeyUse != Refuted || replay.Decision != Refuted {
		return fmt.Errorf("issuer replay/revocation evidence is not exact")
	}
	return nil
}

func verifyRotationEvidence(dir string) error {
	var verification rotationVerification
	if err := ReadJSON(filepath.Join(dir, "evidence/cases/normal-rotation/verification.json"), &verification); err != nil {
		return fmt.Errorf("read rotation verification: %w", err)
	}
	if verification.Schema != "gooo/foundation-authorization/verification-result/v1" || verification.CaseID != "normal-rotation" || verification.Decision != Closed || verification.RotationCount != 1 || !verification.IssuerEvidenceObserved || !verification.ExternalAttestation {
		return fmt.Errorf("rotation normal evidence is not exact")
	}
	var report rotationCIReport
	if err := ReadJSON(filepath.Join(dir, "evidence/ci-report.json"), &report); err != nil {
		return fmt.Errorf("read rotation CI report: %w", err)
	}
	if report.Schema != "gooo/foundation-authorization/ci-report/v1" || report.Denominator.Cases != 12 || report.Denominator.Cells != 12 {
		return fmt.Errorf("rotation CI report denominator is not exact")
	}
	return nil
}

func ObserveGuardian(inputs Inputs) (GuardianObservation, error) {
	var policy GuardianPolicy
	if err := ReadJSON(inputs.GuardianPolicyPath, &policy); err != nil {
		return GuardianObservation{}, fmt.Errorf("read Guardian policy: %w", err)
	}
	workflowBytes, err := ReadBytes(inputs.GuardianWorkflowPath)
	if err != nil {
		return GuardianObservation{}, fmt.Errorf("read Guardian workflow: %w", err)
	}
	contractBytes, err := ReadBytes(inputs.GuardianContractPath)
	if err != nil {
		return GuardianObservation{}, fmt.Errorf("read Guardian contract: %w", err)
	}
	workflowText := string(workflowBytes)
	contractText := string(contractBytes)
	if policy.Schema != ExpectedGuardianPolicySchema || policy.Repository != ExpectedTargetRepository || policy.Candidate.PullRequest != ExpectedGuardianPR || policy.Candidate.Branch != ExpectedGuardianBranch || policy.Candidate.BaseSHA != ExpectedGuardianBaseSHA || policy.Candidate.HeadSHA != ExpectedGuardianHeadSHA || policy.Candidate.MergeBaseSHA != ExpectedGuardianMergeBaseSHA || policy.Dispatch.ReceiptPath != ExpectedGuardianReceiptPath {
		return GuardianObservation{}, fmt.Errorf("observed Guardian policy is not the exact current PR609/v6 policy")
	}
	if !strings.Contains(contractText, "const GUARDIAN_DISPATCH_SCHEMA = '"+ExpectedGuardianDispatchSchema+"'") || !strings.Contains(contractText, "const GUARDIAN_DISPATCH_PULL_REQUEST = "+fmt.Sprint(ExpectedGuardianPR)+";") || !strings.Contains(contractText, "const GUARDIAN_DISPATCH_HEAD_SHA = '"+ExpectedGuardianHeadSHA+"'") {
		return GuardianObservation{}, fmt.Errorf("observed Guardian contract constants are incomplete")
	}
	contractDigest, _, err := FileDigest(inputs.GuardianContractPath)
	if err != nil {
		return GuardianObservation{}, err
	}
	policyDigest, _, err := FileDigest(inputs.GuardianPolicyPath)
	if err != nil {
		return GuardianObservation{}, err
	}
	workflowDigest, _, err := FileDigest(inputs.GuardianWorkflowPath)
	if err != nil {
		return GuardianObservation{}, err
	}
	workflow := GuardianWorkflowObservation{
		Path: ".github/workflows/ci-guardian.yml", SHA256: workflowDigest,
		HasPullRequestTarget: strings.Contains(workflowText, "pull_request_target:"),
		HasWorkflowDispatch:  strings.Contains(workflowText, "workflow_dispatch:"),
		HasOIDCWrite:         strings.Contains(workflowText, "id-token: write"),
	}
	if !workflow.HasPullRequestTarget || workflow.HasWorkflowDispatch || workflow.HasOIDCWrite {
		return GuardianObservation{}, fmt.Errorf("Guardian workflow authority boundary changed unexpectedly")
	}
	reasons := []string{
		fmt.Sprintf("current consumer candidate is PR #%d, verified issuer candidate is PR #%d", policy.Candidate.PullRequest, ExpectedTargetPR),
		"current consumer validates the fixed v6 dispatch lineage rather than an issuer receipt for the verified candidate",
		"current workflow exposes no workflow_dispatch/id-token:write external issuer consumer path",
	}
	return GuardianObservation{
		Schema:      "gooo/foundation-guardian-adapter/guardian-observation/v1",
		Source:      SourceObservation{Repository: ExpectedTargetRepository, Ref: inputs.GuardianRef, HeadSHA: inputs.GuardianHeadSHA, PolicySHA256: policyDigest},
		Policy:      policy,
		Workflow:    workflow,
		Contract:    GuardianContractObservation{Path: "scripts/ci-proof/foundation_authorization.js", SHA256: contractDigest, PolicySchema: ExpectedGuardianPolicySchema, DispatchSchema: ExpectedGuardianDispatchSchema, DispatchPullRequest: ExpectedGuardianPR, DispatchBranch: ExpectedGuardianBranch, DispatchBaseSHA: ExpectedGuardianBaseSHA, DispatchHeadSHA: ExpectedGuardianHeadSHA, DispatchMergeBaseSHA: ExpectedGuardianMergeBaseSHA},
		TargetMatch: false, MismatchReasons: reasons,
	}, nil
}

func observeInventory(path string) InventoryObservation {
	bytes, err := ReadBytes(path)
	if err != nil {
		return InventoryObservation{}
	}
	line := "inventory root_readme=README.md files=excluded physical_lines=excluded other_readmes=retained"
	text := string(bytes)
	return InventoryObservation{RootReadmePath: "README.md", RootReadmeExcluded: strings.Contains(text, line), PhysicalLinesExcluded: strings.Contains(text, line), OtherReadmesRetained: strings.Contains(text, line), PolicyDigest: Digest(bytes)}
}

func WriteProposedArtifacts(outDir string, proof CompatibilityProof) error {
	proposal := ProposedDispatchInput{
		Schema: "gooo/foundation-guardian-adapter/proposed-guardian-dispatch-input/v1", Status: "PROPOSED_ONLY",
		Reason:          "current Guardian consumer contract is fixed to PR609/v6 and cannot accept this verified PR619 tuple without a consumer change",
		VerifiedReceipt: proof.ReceiptDigest, Candidate: proof.Target, Rotation: proof.RotationRelease, IssuerRelease: proof.IssuerRelease,
		GuardianContract: proof.Guardian, AcceptedByGuardian: nil, CompatibilityProof: "compatibility-proof.json",
	}
	if err := WriteJSON(filepath.Join(outDir, "proposed-guardian-dispatch-input.json"), proposal); err != nil {
		return err
	}
	patch := ProposedPatch{
		Schema: "gooo/foundation-guardian-adapter/proposed-guardian-patch/v1", Status: "PROPOSED_ONLY",
		Target: ExpectedTargetRepository, PullRequest: ExpectedTargetPR,
		Files: []string{".github/workflows/ci-guardian.yml", "scripts/ci-proof/foundation_authorization.js", ".github/foundation-authorization.json"},
		RequiredChanges: []string{
			"Add a trusted Guardian consumer path for this adapter's verified evidence bundle; do not treat adapter output as human independence.",
			"Validate the immutable issuer v0.1.1 release, pinned Ed25519 signature, exact PR #619 tuple, and immutable rotation v0.1.2 input.",
			"Preserve single-use replay and revoked-key refutations and keep OIDC signature state UNKNOWN unless independently verified.",
			"Replace the fixed PR609/v6 dispatch binding only through a reviewed consumer change that recomputes live candidate and protected-path evidence.",
		},
		SafetyInvariants: []string{"REFUTED > UNKNOWN > CLOSED", "no force merge", "no direct target repository write by this adapter", "external_human_independence remains UNKNOWN"},
		NoApplyReason:    "consumer code change and independent human approval are not observed; applying this proposal would bypass Guardian fail-closed behavior",
	}
	return WriteJSON(filepath.Join(outDir, "proposed-guardian-patch.json"), patch)
}

func HumanReport(proof CompatibilityProof) string {
	return fmt.Sprintf("# Foundation Guardian adapter report\n\n- decision: `%s`\n- cryptographic verification: `%s`\n- issuer receipt digest: `%s`\n- signature valid: `%t`\n- exact PR #619 tuple: `%t`\n- exact v0.1.2 rotation input: `%t`\n- current Guardian input exact: `%t`\n- integration: `%s`\n- external human independence: `%s`\n- OIDC signature verification: `%s`\n- receipt time: `%s`\n\nThe current Guardian consumer is fixed to PR #609/v6 and has no external adapter-consumer path at the observed head. The adapter therefore emits `PROPOSED_ONLY` artifacts and leaves integration `UNKNOWN`. No target repository write, PR update, workflow dispatch, or merge was performed.\n\nSame-owner operation remains an explicit authority limit.\n", proof.Decision, proof.CryptographicState, proof.ReceiptDigest, proof.SignatureValid, proof.TupleExact, proof.RotationExact, proof.GuardianInputExact, proof.IntegrationState, proof.HumanIndependenceState, proof.OIDCSignatureState, proof.ReceiptTemporalState)
}

func VerifyProofForConsumer(proof CompatibilityProof) error {
	if proof.Schema != "gooo/foundation-guardian-adapter/compatibility-proof/v1" || proof.CryptographicState != Closed || !proof.SignatureValid || !proof.TupleExact || !proof.RotationExact || proof.IntegrationState == Refuted || proof.AcceptedGuardianInput != nil {
		return fmt.Errorf("adapter proof is malformed or claims an unsafe Guardian acceptance")
	}
	if err := ValidateTarget(proof.Target); err != nil {
		return err
	}
	return nil
}

func WriteIndependentConsumerReport(outDir string, proof CompatibilityProof, proofBytes []byte) error {
	report := IndependentConsumerReport{
		Schema: "gooo/foundation-guardian-adapter/independent-consumer-report/v1", ConsumerIdentity: "independent-consumer:gooo-foundation-guardian-adapter",
		Decision: proof.Decision, ProofDigest: Digest(proofBytes), SignatureValid: proof.SignatureValid, TupleExact: proof.TupleExact, RotationExact: proof.RotationExact,
		GuardianInputExact: proof.GuardianInputExact, IntegrationState: proof.IntegrationState, HumanIndependenceState: proof.HumanIndependenceState,
		OIDCSignatureState: proof.OIDCSignatureState, InventoryRootReadmeExcluded: proof.Inventory.RootReadmeExcluded,
		InventoryPhysicalLinesExcluded: proof.Inventory.PhysicalLinesExcluded, InventoryOtherReadmesRetained: proof.Inventory.OtherReadmesRetained,
		InventoryPolicyDigest: proof.Inventory.PolicyDigest, Reason: "independently consumed verified adapter proof; PROPOSED_ONLY is not Guardian acceptance",
	}
	return WriteJSON(filepath.Join(outDir, "independent-consumer-report.json"), report)
}

func EnsureDir(path string) error { return os.MkdirAll(path, 0o700) }
