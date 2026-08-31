package adapter

import "time"

type State string

const (
	Closed  State = "CLOSED"
	Unknown State = "UNKNOWN"
	Refuted State = "REFUTED"
)

func Combine(states ...State) State {
	for _, state := range states {
		if state == Refuted {
			return Refuted
		}
	}
	for _, state := range states {
		if state == Unknown {
			return Unknown
		}
	}
	return Closed
}

const (
	ReceiptSchema = "gooo/foundation-authorization/issuer-receipt/v1"
	PayloadType   = "application/vnd.gooo.foundation-authorization+json;version=1"
)

type Asset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}

type Release struct {
	Repository   string  `json:"repository"`
	Version      string  `json:"version"`
	ReleaseID    int64   `json:"release_id"`
	Immutable    bool    `json:"immutable"`
	TagObjectSHA string  `json:"tag_object_sha"`
	TargetCommit string  `json:"target_commit"`
	Assets       []Asset `json:"assets"`
}

type RotationInput struct {
	Repository   string  `json:"repository"`
	Version      string  `json:"version"`
	ReleaseID    int64   `json:"release_id"`
	Immutable    bool    `json:"immutable"`
	TagObjectSHA string  `json:"tag_object_sha"`
	TargetCommit string  `json:"target_commit"`
	Assets       []Asset `json:"assets"`
}

type OIDCClaims struct {
	Issuer          string `json:"iss"`
	Subject         string `json:"sub"`
	Audience        string `json:"aud"`
	IssuedAt        int64  `json:"iat"`
	ExpiresAt       int64  `json:"exp"`
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	Workflow        string `json:"workflow"`
	Ref             string `json:"ref"`
	SHA             string `json:"sha"`
	Actor           string `json:"actor"`
	RawObserved     bool   `json:"raw_observed"`
	SignatureState  State  `json:"signature_state"`
}

type Payload struct {
	Schema                 string        `json:"schema"`
	Repository             string        `json:"repository"`
	PullRequest            int           `json:"pull_request"`
	BaseRef                string        `json:"base_ref"`
	BaseSHA                string        `json:"base_sha"`
	HeadRef                string        `json:"head_ref"`
	HeadSHA                string        `json:"head_sha"`
	CandidateDigest        string        `json:"candidate_digest"`
	ProtectedScope         []string      `json:"protected_scope"`
	ProtectedScopeDigest   string        `json:"protected_scope_digest"`
	ActorIdentity          string        `json:"actor_identity"`
	IssuerIdentity         string        `json:"issuer_identity"`
	Nonce                  string        `json:"nonce"`
	IssuedAt               string        `json:"issued_at"`
	ExpiresAt              string        `json:"expires_at"`
	Generation             int           `json:"generation"`
	PriorReceiptDigest     string        `json:"prior_receipt_digest"`
	Decision               State         `json:"decision"`
	IssuanceState          State         `json:"issuance_state"`
	HumanIndependenceState State         `json:"human_independence_state"`
	IntegrationState       State         `json:"integration_state"`
	ExternalAuthorityClaim string        `json:"external_authority_claim"`
	Rotation               RotationInput `json:"rotation"`
	OIDC                   OIDCClaims    `json:"oidc"`
}

type Receipt struct {
	Schema        string  `json:"schema"`
	PayloadType   string  `json:"payload_type"`
	Payload       Payload `json:"payload"`
	PayloadDigest string  `json:"payload_digest"`
	PublicKey     string  `json:"public_key"`
	Signature     string  `json:"signature"`
}

type ReplayEvidence struct {
	Schema        string `json:"schema"`
	ReceiptDigest string `json:"receipt_digest"`
	FirstUse      State  `json:"first_use"`
	SecondUse     State  `json:"second_use"`
	RevokedKeyUse State  `json:"revoked_key_use"`
	Decision      State  `json:"decision"`
	Reason        string `json:"reason"`
}

type GuardianCandidate struct {
	PullRequest                 int    `json:"pull_request"`
	Branch                      string `json:"branch"`
	BaseBranch                  string `json:"base_branch"`
	BaseSHA                     string `json:"base_sha"`
	HeadSHA                     string `json:"head_sha"`
	MergeBaseSHA                string `json:"merge_base_sha"`
	ChangedFileCount            int    `json:"changed_file_count"`
	ChangedPathsSHA256          string `json:"changed_paths_sha256"`
	ProtectedIntersectionCount  int    `json:"protected_intersection_count"`
	ProtectedIntersectionSHA256 string `json:"protected_intersection_sha256"`
}

type GuardianDispatch struct {
	ReceiptPath    string `json:"receipt_path"`
	ReceiptSHA256  string `json:"receipt_sha256"`
	Mode           string `json:"mode"`
	Consumed       bool   `json:"consumed"`
	ReplayDecision State  `json:"replay_decision"`
}

type GuardianPolicy struct {
	Schema     string            `json:"schema"`
	Decision   string            `json:"decision"`
	Reason     string            `json:"reason"`
	Repository string            `json:"repository"`
	Candidate  GuardianCandidate `json:"candidate"`
	Dispatch   GuardianDispatch  `json:"dispatch"`
}

type GuardianWorkflowObservation struct {
	Path                 string `json:"path"`
	SHA256               string `json:"sha256"`
	HasPullRequestTarget bool   `json:"has_pull_request_target"`
	HasWorkflowDispatch  bool   `json:"has_workflow_dispatch"`
	HasOIDCWrite         bool   `json:"has_oidc_write"`
}

type GuardianContractObservation struct {
	Path                 string `json:"path"`
	SHA256               string `json:"sha256"`
	PolicySchema         string `json:"policy_schema"`
	DispatchSchema       string `json:"dispatch_schema"`
	DispatchPullRequest  int    `json:"dispatch_pull_request"`
	DispatchBranch       string `json:"dispatch_branch"`
	DispatchBaseSHA      string `json:"dispatch_base_sha"`
	DispatchHeadSHA      string `json:"dispatch_head_sha"`
	DispatchMergeBaseSHA string `json:"dispatch_merge_base_sha"`
}

type Check struct {
	Name     string `json:"name"`
	State    State  `json:"state"`
	Observed string `json:"observed,omitempty"`
	Expected string `json:"expected,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type CompatibilityProof struct {
	Schema                 string               `json:"schema"`
	ObservedAt             string               `json:"observed_at"`
	Decision               State                `json:"decision"`
	CryptographicState     State                `json:"cryptographic_state"`
	IntegrationState       State                `json:"integration_state"`
	HumanIndependenceState State                `json:"human_independence_state"`
	OIDCSignatureState     State                `json:"oidc_signature_state"`
	ReceiptTemporalState   string               `json:"receipt_temporal_state"`
	IssuerRelease          Release              `json:"issuer_release"`
	RotationRelease        Release              `json:"rotation_release"`
	ReceiptDigest          string               `json:"receipt_digest"`
	SignatureValid         bool                 `json:"signature_valid"`
	TupleExact             bool                 `json:"tuple_exact"`
	RotationExact          bool                 `json:"rotation_exact"`
	GuardianInputExact     bool                 `json:"guardian_input_exact"`
	AcceptedGuardianInput  any                  `json:"accepted_guardian_input"`
	Target                 PayloadTarget        `json:"target"`
	Guardian               GuardianObservation  `json:"guardian"`
	Inventory              InventoryObservation `json:"inventory"`
	Checks                 []Check              `json:"checks"`
	AuthorityBoundary      AuthorityBoundary    `json:"authority_boundary"`
}

type InventoryObservation struct {
	RootReadmePath        string `json:"root_readme_path"`
	RootReadmeExcluded    bool   `json:"root_readme_excluded"`
	PhysicalLinesExcluded bool   `json:"physical_lines_excluded"`
	OtherReadmesRetained  bool   `json:"other_readmes_retained"`
	PolicyDigest          string `json:"policy_digest"`
}

type PayloadTarget struct {
	Repository           string   `json:"repository"`
	PullRequest          int      `json:"pull_request"`
	BaseRef              string   `json:"base_ref"`
	BaseSHA              string   `json:"base_sha"`
	HeadRef              string   `json:"head_ref"`
	HeadSHA              string   `json:"head_sha"`
	CandidateDigest      string   `json:"candidate_digest"`
	ProtectedScope       []string `json:"protected_scope"`
	ProtectedScopeDigest string   `json:"protected_scope_digest"`
}

type AuthorityBoundary struct {
	ExternalHumanIndependence string `json:"external_human_independence"`
	OIDCVerification          string `json:"oidc_verification"`
	GuardianIntegration       string `json:"guardian_integration"`
	SameOwnerLimit            string `json:"same_owner_limit"`
	RepositoryWrites          int    `json:"repository_writes"`
	TargetRepositoryWrites    int    `json:"target_repository_writes"`
	TargetPRUpdates           int    `json:"target_pr_updates"`
	TargetWorkflowDispatches  int    `json:"target_workflow_dispatches"`
	ForceMerges               int    `json:"force_merges"`
}

type GuardianObservation struct {
	Schema          string                      `json:"schema"`
	Source          SourceObservation           `json:"source"`
	Policy          GuardianPolicy              `json:"policy"`
	Workflow        GuardianWorkflowObservation `json:"workflow"`
	Contract        GuardianContractObservation `json:"contract"`
	TargetMatch     bool                        `json:"target_match"`
	MismatchReasons []string                    `json:"mismatch_reasons"`
}

type SourceObservation struct {
	Repository   string `json:"repository"`
	Ref          string `json:"ref"`
	HeadSHA      string `json:"head_sha"`
	PolicySHA256 string `json:"policy_sha256"`
}

type ProposedDispatchInput struct {
	Schema             string              `json:"schema"`
	Status             string              `json:"status"`
	Reason             string              `json:"reason"`
	VerifiedReceipt    string              `json:"verified_receipt_digest"`
	Candidate          PayloadTarget       `json:"candidate"`
	Rotation           Release             `json:"rotation"`
	IssuerRelease      Release             `json:"issuer_release"`
	GuardianContract   GuardianObservation `json:"guardian_contract"`
	AcceptedByGuardian any                 `json:"accepted_by_guardian"`
	CompatibilityProof string              `json:"compatibility_proof"`
}

type ProposedPatch struct {
	Schema           string   `json:"schema"`
	Status           string   `json:"status"`
	Target           string   `json:"target"`
	PullRequest      int      `json:"pull_request"`
	Files            []string `json:"files"`
	RequiredChanges  []string `json:"required_changes"`
	SafetyInvariants []string `json:"safety_invariants"`
	NoApplyReason    string   `json:"no_apply_reason"`
}

type IndependentConsumerReport struct {
	Schema                         string `json:"schema"`
	ConsumerIdentity               string `json:"consumer_identity"`
	Decision                       State  `json:"decision"`
	ProofDigest                    string `json:"proof_digest"`
	SignatureValid                 bool   `json:"signature_valid"`
	TupleExact                     bool   `json:"tuple_exact"`
	RotationExact                  bool   `json:"rotation_exact"`
	GuardianInputExact             bool   `json:"guardian_input_exact"`
	IntegrationState               State  `json:"integration_state"`
	HumanIndependenceState         State  `json:"human_independence_state"`
	OIDCSignatureState             State  `json:"oidc_signature_state"`
	InventoryRootReadmeExcluded    bool   `json:"inventory_root_readme_excluded"`
	InventoryPhysicalLinesExcluded bool   `json:"inventory_physical_lines_excluded"`
	InventoryOtherReadmesRetained  bool   `json:"inventory_other_readmes_retained"`
	InventoryPolicyDigest          string `json:"inventory_policy_digest"`
	Reason                         string `json:"reason"`
}

func (p Payload) Expired(now time.Time) bool {
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	return err == nil && !now.Before(expires)
}
