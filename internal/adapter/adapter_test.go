package adapter

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestStatePrecedence(t *testing.T) {
	if Combine(Closed, Unknown, Closed) != Unknown {
		t.Fatal("UNKNOWN must outrank CLOSED")
	}
	if Combine(Unknown, Refuted, Closed) != Refuted {
		t.Fatal("REFUTED must outrank UNKNOWN")
	}
}

func TestReceiptSignatureUsesIssuerPayloadContract(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := Payload{
		Schema: ReceiptSchema, Repository: ExpectedTargetRepository, PullRequest: ExpectedTargetPR,
		BaseRef: ExpectedTargetBaseRef, BaseSHA: ExpectedTargetBaseSHA, HeadRef: ExpectedTargetHeadRef, HeadSHA: ExpectedTargetHeadSHA,
		CandidateDigest: ExpectedCandidateDigest, ProtectedScope: ExpectedProtectedScope, ProtectedScopeDigest: ExpectedProtectedScopeDigest,
		ActorIdentity: "fixture", IssuerIdentity: ExpectedIssuerRepository, Nonce: "fixture-nonce", IssuedAt: "2026-09-01T00:00:00Z", ExpiresAt: "2026-09-01T00:15:00Z",
		Generation: 1, Decision: Unknown, IssuanceState: Closed, HumanIndependenceState: Unknown, IntegrationState: Unknown,
		ExternalAuthorityClaim: "OWNER_OPERATED_EXTERNAL_REPOSITORY_AUTHORITY_ONLY",
		Rotation:               RotationInput{Repository: ExpectedRotationRepository, Version: ExpectedRotationVersion, ReleaseID: ExpectedRotationReleaseID, Immutable: true, TagObjectSHA: ExpectedRotationTagObject, TargetCommit: ExpectedRotationTarget, Assets: ExpectedRotationRelease().Assets},
		OIDC:                   OIDCClaims{Issuer: "https://token.actions.githubusercontent.com", Subject: "fixture", Audience: "gooo-foundation-issuer", IssuedAt: 1, ExpiresAt: 2, RawObserved: true, SignatureState: Unknown},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{Schema: ReceiptSchema, PayloadType: PayloadType, Payload: payload, PayloadDigest: Digest(payloadBytes), PublicKey: base64.StdEncoding.EncodeToString(public), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payloadBytes))}
	valid, err := VerifySignature(receipt)
	if err != nil || !valid {
		t.Fatalf("signature must verify: valid=%t err=%v", valid, err)
	}
	receipt.Payload.HeadSHA = "tampered"
	valid, err = VerifySignature(receipt)
	if err == nil || valid {
		t.Fatal("tampered payload must be rejected")
	}
}

func TestExpectedContractsArePinned(t *testing.T) {
	if ExpectedIssuerRelease().Immutable != true || ExpectedRotationRelease().Immutable != true {
		t.Fatal("immutable release anchors must be true")
	}
	if err := ValidateTarget(ExpectedTarget); err != nil {
		t.Fatal(err)
	}
}
