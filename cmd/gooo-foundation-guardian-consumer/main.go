package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kimjooyoon/gooo-foundation-guardian-adapter/internal/adapter"
)

func main() {
	proofPath := flag.String("proof", "", "adapter compatibility-proof.json")
	outDir := flag.String("out", "", "caller-owned output directory")
	policyPath := flag.String("policy", "", "semantic graph used for inventory consumption")
	flag.Parse()
	if *proofPath == "" || *outDir == "" || *policyPath == "" {
		fatal("proof, out, and policy are required")
	}
	if err := adapter.EnsureDir(*outDir); err != nil {
		fatal("create output directory: %v", err)
	}
	proofBytes, err := adapter.ReadBytes(*proofPath)
	if err != nil {
		fatal("read compatibility proof: %v", err)
	}
	var proof adapter.CompatibilityProof
	if err := adapter.ReadJSON(*proofPath, &proof); err != nil {
		fatal("decode compatibility proof: %v", err)
	}
	if err := adapter.VerifyProofForConsumer(proof); err != nil {
		fatal("consumer rejected compatibility proof: %v", err)
	}
	policyBytes, err := adapter.ReadBytes(*policyPath)
	if err != nil {
		fatal("read semantic graph: %v", err)
	}
	if !containsInventoryAuthority(string(policyBytes)) {
		fatal("semantic graph inventory authority is not exact")
	}
	if err := adapter.WriteIndependentConsumerReport(*outDir, proof, proofBytes); err != nil {
		fatal("write independent consumer report: %v", err)
	}
	if err := adapter.WriteJSON(filepath.Join(*outDir, "inventory-consumer-report.json"), map[string]any{
		"schema":                  "gooo/foundation-guardian-adapter/inventory-consumer-report/v1",
		"consumer_identity":       "independent-consumer:gooo-foundation-guardian-adapter",
		"root_readme_excluded":    true,
		"physical_lines_excluded": true,
		"other_readmes_retained":  true,
		"policy_digest":           adapter.Digest(policyBytes),
	}); err != nil {
		fatal("write inventory consumer report: %v", err)
	}
	fmt.Printf("consumer decision=%s integration=%s root_readme_excluded=true other_readmes_retained=true\n", proof.Decision, proof.IntegrationState)
}

func containsInventoryAuthority(value string) bool {
	return len(value) > 0 && stringContains(value, "inventory root_readme=README.md files=excluded physical_lines=excluded other_readmes=retained")
}

func stringContains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
