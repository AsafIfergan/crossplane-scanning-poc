// Command wiz_eval_crossplane evaluates a Wiz Rego rule against a Crossplane
// YAML fixture and writes a PASSED/FAILED verdict as JSON. It is the local
// equivalent of wiz_eval_iac (which calls the Wiz portal's CloudFormation
// scanning API) for the Crossplane generator skill set, which must run before
// in-portal Crossplane parsing is available.
//
// Contract intentionally mirrors wiz_eval_iac:
//   - Exit 0 for both PASSED and FAILED (the verdict is a *result*, not an error).
//   - Non-zero only on file I/O, YAML parse, or Rego compile/eval errors.
//   - Output JSON: {"result": "PASSED"|"FAILED", "findings": [...], "parser_contract_version": "v1"}.
//
// The parse + OPA-eval logic is a direct port of evalCrossplanePolicy in
// parser/parser_test.go — keep them in sync.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/rego"
	"github.com/wiz-sec/crossplane-scanning-poc/parser"
)

// parserContractVersion is bumped whenever the input shape this binary
// produces for OPA changes in a way that committed rules need to react to
// (top-level key rename, doc envelope change, etc.). The test skill compares
// it against the version it was generated for; a mismatch surfaces as a clear
// error instead of a silent test pass/fail.
const parserContractVersion = "v1"

type envelope struct {
	Result                string `json:"result"`
	Findings              []any  `json:"findings"`
	ParserContractVersion string `json:"parser_contract_version"`
}

func main() {
	libDir := flag.String("lib-dir", "", "directory containing crossplane.rego and common.rego. Overrides $WIZ_CROSSPLANE_PARSER/rego and ./rego.")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: wiz_eval_crossplane [--lib-dir DIR] <query.rego> <fixture.yaml> <output.json>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Parses a Crossplane YAML fixture, runs the given Rego rule against it,")
		fmt.Fprintln(os.Stderr, "and writes a JSON verdict to <output.json> (use '-' for stdout).")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Helper-library lookup order: --lib-dir flag, $WIZ_CROSSPLANE_PARSER/rego, ./rego.")
		fmt.Fprintln(os.Stderr, "Exit 0 for both PASSED and FAILED; non-zero only on file/parse/compile errors.")
	}
	flag.Parse()

	if flag.NArg() != 3 {
		flag.Usage()
		os.Exit(2)
	}

	regoPath, yamlPath, outPath := flag.Arg(0), flag.Arg(1), flag.Arg(2)

	if err := run(regoPath, yamlPath, outPath, *libDir); err != nil {
		fmt.Fprintf(os.Stderr, "wiz_eval_crossplane: %v\n", err)
		os.Exit(1)
	}
}

func run(regoPath, yamlPath, outPath, libDirFlag string) error {
	libDir, err := resolveLibDir(libDirFlag)
	if err != nil {
		return err
	}

	parsed, err := parser.ParseFile(yamlPath)
	if err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}

	// Match parser_test.go's evalCrossplanePolicy exactly: assign a UUID id
	// and the source file path to every doc, then wrap as input.document[].
	// Rules rely on doc.id for the documentId field in WizPolicy results.
	docs := make([]any, 0, len(parsed.Documents))
	for _, d := range parsed.Documents {
		d["id"] = uuid.New().String()
		d["file"] = parsed.FilePath
		docs = append(docs, d)
	}
	input := map[string]any{"document": docs}

	policyData, err := os.ReadFile(regoPath)
	if err != nil {
		return fmt.Errorf("read rule: %w", err)
	}
	crossplaneLib, err := os.ReadFile(filepath.Join(libDir, "crossplane.rego"))
	if err != nil {
		return fmt.Errorf("read helper lib: %w", err)
	}
	commonLib, err := os.ReadFile(filepath.Join(libDir, "common.rego"))
	if err != nil {
		return fmt.Errorf("read helper lib: %w", err)
	}

	r := rego.New(
		rego.Query("data.wiz.WizPolicy"),
		rego.Module(regoPath, string(policyData)),
		rego.Module("crossplane.rego", string(crossplaneLib)),
		rego.Module("common.rego", string(commonLib)),
		rego.Input(input),
	)
	rs, err := r.Eval(context.Background())
	if err != nil {
		return fmt.Errorf("opa eval: %w", err)
	}

	findings := make([]any, 0)
	for _, result := range rs {
		for _, expr := range result.Expressions {
			if set, ok := expr.Value.([]any); ok {
				findings = append(findings, set...)
			}
		}
	}

	verdict := "PASSED"
	if len(findings) > 0 {
		verdict = "FAILED"
	}
	out, err := json.MarshalIndent(envelope{
		Result:                verdict,
		Findings:              findings,
		ParserContractVersion: parserContractVersion,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	out = append(out, '\n')

	if outPath == "-" {
		_, err = os.Stdout.Write(out)
	} else {
		err = os.WriteFile(outPath, out, 0o644)
	}
	if err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// resolveLibDir returns the directory holding crossplane.rego and common.rego,
// preferring an explicit --lib-dir flag, then $WIZ_CROSSPLANE_PARSER/rego, then
// ./rego (which works when running from the POC repo root).
func resolveLibDir(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if root := os.Getenv("WIZ_CROSSPLANE_PARSER"); root != "" {
		return filepath.Join(root, "rego"), nil
	}
	if _, err := os.Stat("rego/crossplane.rego"); err == nil {
		return "rego", nil
	}
	return "", fmt.Errorf("cannot locate crossplane.rego / common.rego: pass --lib-dir, set $WIZ_CROSSPLANE_PARSER to the POC repo root, or run from that directory")
}
