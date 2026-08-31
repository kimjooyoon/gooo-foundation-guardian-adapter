package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kimjooyoon/gooo-foundation-guardian-adapter/internal/adapter"
)

func main() {
	inputs := adapter.Inputs{}
	flag.StringVar(&inputs.IssuerReleasePath, "issuer-release", "", "normalized issuer release JSON")
	flag.StringVar(&inputs.IssuerEvidenceDir, "issuer-evidence", "", "extracted issuer evidence directory")
	flag.StringVar(&inputs.RotationReleasePath, "rotation-release", "", "normalized rotation release JSON")
	flag.StringVar(&inputs.RotationEvidenceDir, "rotation-evidence", "", "extracted rotation evidence directory")
	flag.StringVar(&inputs.GuardianPolicyPath, "guardian-policy", "", "observed Guardian policy JSON")
	flag.StringVar(&inputs.GuardianWorkflowPath, "guardian-workflow", "", "observed Guardian workflow")
	flag.StringVar(&inputs.GuardianContractPath, "guardian-contract", "", "observed Guardian authorization contract")
	flag.StringVar(&inputs.SemanticGraphPath, "semantic-graph", "", ".gooo semantic graph")
	flag.StringVar(&inputs.GuardianRef, "guardian-ref", "", "observed Guardian source ref")
	flag.StringVar(&inputs.GuardianHeadSHA, "guardian-head", "", "observed Guardian source head SHA")
	outDir := flag.String("out", "", "caller-owned output directory")
	flag.Parse()
	if inputs.IssuerReleasePath == "" || inputs.IssuerEvidenceDir == "" || inputs.RotationReleasePath == "" || inputs.RotationEvidenceDir == "" || inputs.GuardianPolicyPath == "" || inputs.GuardianWorkflowPath == "" || inputs.GuardianContractPath == "" || inputs.SemanticGraphPath == "" || *outDir == "" {
		fatal("issuer/rotation evidence, Guardian observations, semantic graph, and out are required")
	}
	if err := adapter.EnsureDir(*outDir); err != nil {
		fatal("create output directory: %v", err)
	}
	proof, err := adapter.VerifyBundle(inputs, time.Now().UTC())
	if err != nil {
		fatal("verify Foundation bundle: %v", err)
	}
	if err := adapter.WriteJSON(filepath.Join(*outDir, "compatibility-proof.json"), proof); err != nil {
		fatal("write compatibility proof: %v", err)
	}
	if err := adapter.WriteProposedArtifacts(*outDir, proof); err != nil {
		fatal("write proposed Guardian artifacts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "human-report.md"), []byte(adapter.HumanReport(proof)), 0o600); err != nil {
		fatal("write human report: %v", err)
	}
	fmt.Printf("adapter decision=%s cryptographic=%s integration=%s signature_valid=%t tuple_exact=%t rotation_exact=%t guardian_input_exact=%t\n", proof.Decision, proof.CryptographicState, proof.IntegrationState, proof.SignatureValid, proof.TupleExact, proof.RotationExact, proof.GuardianInputExact)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
