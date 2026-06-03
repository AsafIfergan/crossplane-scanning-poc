package parser

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Detection tests ---

func TestIsCrossplaneFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"crossplane.io provider", "apiVersion: database.aws.crossplane.io/v1beta1", true},
		{"upbound.io provider", "apiVersion: rds.aws.upbound.io/v1beta1", true},
		{"crossplane core", "apiVersion: apiextensions.crossplane.io/v1", true},
		{"pkg.crossplane.io", "apiVersion: pkg.crossplane.io/v1", true},
		{"JSON format", `"apiVersion": "rds.aws.upbound.io/v1beta1"`, true},
		{"kubernetes v1", "apiVersion: v1", false},
		{"kubernetes apps", "apiVersion: apps/v1", false},
		{"knative", "apiVersion: serving.knative.dev/v1", false},
		{"random yaml", "kind: something", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsCrossplaneFile([]byte(tt.content)))
		})
	}
}

// --- Parser shape tests ---
// The parser is a dumb YAML→JSON converter. Each YAML document is preserved
// exactly as written; multi-doc files (--- separated) are split into a list.

func TestParseStandaloneResources(t *testing.T) {
	result, err := ParseFile("../testdata/parser/multi-doc-standalone.yaml")
	require.NoError(t, err)
	require.Len(t, result.Documents, 5)

	byName := indexByName(t, result.Documents)
	require.Contains(t, byName, "sample-vpc")
	assert.Equal(t, "VPC", byName["sample-vpc"]["kind"])
	require.Contains(t, byName, "sample-subnet1")
	require.Contains(t, byName, "sample-subnet2")
	require.Contains(t, byName, "sample-cluster-sg")
	require.Contains(t, byName, "db-security-group")

	// Cross-resource reference preserved as written
	subnet1 := byName["sample-subnet1"]
	fp := subnet1["spec"].(map[string]any)["forProvider"].(map[string]any)
	assert.Equal(t, "sample-vpc", fp["vpcIdRef"].(map[string]any)["name"])
}

func TestParseComposition(t *testing.T) {
	result, err := ParseFile("../testdata/parser/composition.yaml")
	require.NoError(t, err)

	// One document: the Composition wrapper itself, with nested resources intact.
	require.Len(t, result.Documents, 1)
	comp := result.Documents[0]
	assert.Equal(t, "Composition", comp["kind"])
	assert.Equal(t, "parser-fixture-composition", comp["metadata"].(map[string]any)["name"])

	resources := comp["spec"].(map[string]any)["resources"].([]any)
	require.Len(t, resources, 2)

	first := resources[0].(map[string]any)
	assert.Equal(t, "rds-instance", first["name"])
	base := first["base"].(map[string]any)
	assert.Equal(t, "RDSInstance", base["kind"])
	assert.Equal(t, "parser-composed-rds", base["metadata"].(map[string]any)["name"])

	// patches must survive — they were dropped under the old restructuring.
	assert.NotEmpty(t, first["patches"].([]any))
}

func TestParseUpbound(t *testing.T) {
	data, err := os.ReadFile("../testdata/parser/upbound.yaml")
	require.NoError(t, err)
	assert.True(t, IsCrossplaneFile(data))

	result, err := ParseFile("../testdata/parser/upbound.yaml")
	require.NoError(t, err)
	require.Len(t, result.Documents, 1)

	doc := result.Documents[0]
	assert.Equal(t, "Instance", doc["kind"])
	assert.Equal(t, "upbound-rds", doc["metadata"].(map[string]any)["name"])
}

func TestParseMixed(t *testing.T) {
	result, err := ParseFile("../testdata/parser/mixed.yaml")
	require.NoError(t, err)
	require.Len(t, result.Documents, 2)

	standalone := result.Documents[0]
	assert.Equal(t, "RDSInstance", standalone["kind"])

	comp := result.Documents[1]
	assert.Equal(t, "Composition", comp["kind"])
	composed := comp["spec"].(map[string]any)["resources"].([]any)[0].(map[string]any)["base"].(map[string]any)
	assert.Equal(t, "RDSInstance", composed["kind"])
}

// --- End-to-end Rego policy tests ---
//
// Each rule has 8 cases: {pass, fail} × {standalone, composition} × {legacy, upbound}.
// Pass cases assert no findings; fail cases assert at least one finding with the
// required WizPolicy fields and the expected resourceType.

type policyCase struct {
	name         string
	yamlPath     string
	expectFail   bool
	resourceType string // expected on every finding (kind under inspection differs per family)
}

func TestRegoPolicy_RDSNotEncrypted(t *testing.T) {
	runPolicyCases(t, "../rego/rds_not_encrypted.rego", []policyCase{
		{"pass/legacy-standalone", "../testdata/rds_not_encrypted/pass/legacy-standalone.yaml", false, "RDSInstance"},
		{"pass/legacy-composition", "../testdata/rds_not_encrypted/pass/legacy-composition.yaml", false, "RDSInstance"},
		{"pass/upbound-standalone", "../testdata/rds_not_encrypted/pass/upbound-standalone.yaml", false, "Instance"},
		{"pass/upbound-composition", "../testdata/rds_not_encrypted/pass/upbound-composition.yaml", false, "Instance"},
		{"fail/legacy-standalone", "../testdata/rds_not_encrypted/fail/legacy-standalone.yaml", true, "RDSInstance"},
		{"fail/legacy-composition", "../testdata/rds_not_encrypted/fail/legacy-composition.yaml", true, "RDSInstance"},
		{"fail/upbound-standalone", "../testdata/rds_not_encrypted/fail/upbound-standalone.yaml", true, "Instance"},
		{"fail/upbound-composition", "../testdata/rds_not_encrypted/fail/upbound-composition.yaml", true, "Instance"},
	})
}

func TestRegoPolicy_SecurityGroupOpenIngress(t *testing.T) {
	// Legacy fails surface as SecurityGroup (inline ingress);
	// Upbound fails surface as SecurityGroupIngressRule (separate top-level resource).
	runPolicyCases(t, "../rego/security_group_open_ingress.rego", []policyCase{
		{"pass/legacy-standalone", "../testdata/security_group_open_ingress/pass/legacy-standalone.yaml", false, "SecurityGroup"},
		{"pass/legacy-composition", "../testdata/security_group_open_ingress/pass/legacy-composition.yaml", false, "SecurityGroup"},
		{"pass/upbound-standalone", "../testdata/security_group_open_ingress/pass/upbound-standalone.yaml", false, "SecurityGroupIngressRule"},
		{"pass/upbound-composition", "../testdata/security_group_open_ingress/pass/upbound-composition.yaml", false, "SecurityGroupIngressRule"},
		{"fail/legacy-standalone", "../testdata/security_group_open_ingress/fail/legacy-standalone.yaml", true, "SecurityGroup"},
		{"fail/legacy-composition", "../testdata/security_group_open_ingress/fail/legacy-composition.yaml", true, "SecurityGroup"},
		{"fail/upbound-standalone", "../testdata/security_group_open_ingress/fail/upbound-standalone.yaml", true, "SecurityGroupIngressRule"},
		{"fail/upbound-composition", "../testdata/security_group_open_ingress/fail/upbound-composition.yaml", true, "SecurityGroupIngressRule"},
	})
}

func TestRegoPolicy_SubnetWithoutVPCRef(t *testing.T) {
	runPolicyCases(t, "../rego/subnet_without_vpc_ref.rego", []policyCase{
		{"pass/legacy-standalone", "../testdata/subnet_without_vpc_ref/pass/legacy-standalone.yaml", false, "Subnet"},
		{"pass/legacy-composition", "../testdata/subnet_without_vpc_ref/pass/legacy-composition.yaml", false, "Subnet"},
		{"pass/upbound-standalone", "../testdata/subnet_without_vpc_ref/pass/upbound-standalone.yaml", false, "Subnet"},
		{"pass/upbound-composition", "../testdata/subnet_without_vpc_ref/pass/upbound-composition.yaml", false, "Subnet"},
		{"fail/legacy-standalone", "../testdata/subnet_without_vpc_ref/fail/legacy-standalone.yaml", true, "Subnet"},
		{"fail/legacy-composition", "../testdata/subnet_without_vpc_ref/fail/legacy-composition.yaml", true, "Subnet"},
		{"fail/upbound-standalone", "../testdata/subnet_without_vpc_ref/fail/upbound-standalone.yaml", true, "Subnet"},
		{"fail/upbound-composition", "../testdata/subnet_without_vpc_ref/fail/upbound-composition.yaml", true, "Subnet"},
	})
}

func runPolicyCases(t *testing.T, policyPath string, cases []policyCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := evalCrossplanePolicy(t, c.yamlPath, policyPath)
			if !c.expectFail {
				assert.Empty(t, findings, "expected no findings")
				return
			}
			require.NotEmpty(t, findings, "expected at least one finding")
			for _, f := range findings {
				finding := f.(map[string]any)
				assertWizPolicyFields(t, finding)
				assert.Equal(t, c.resourceType, finding["resourceType"])
			}
		})
	}
}

// --- Test helpers ---

// requiredWizPolicyFields are the fields every WizPolicy result must contain,
// matching the validation in iacscanlib/scanner/test/queries_content_test.go.
var requiredWizPolicyFields = []string{
	"documentId",
	"searchKey",
	"issueType",
	"keyExpectedValue",
	"keyActualValue",
	"resourceType",
	"resourceName",
}

// evalCrossplanePolicy simulates the full Wiz IaC scanning flow:
// 1. Read raw Crossplane YAML
// 2. Parse into raw documents
// 3. Wrap each doc as its own input.document[] entry, with id + file
// 4. Evaluate WizPolicy Rego rules via OPA
// 5. Return findings
func evalCrossplanePolicy(t *testing.T, yamlPath, policyPath string) []any {
	t.Helper()

	result, err := ParseFile(yamlPath)
	require.NoError(t, err)

	docs := make([]any, 0, len(result.Documents))
	for _, d := range result.Documents {
		d["id"] = uuid.New().String()
		d["file"] = result.FilePath
		docs = append(docs, d)
	}
	input := map[string]any{"document": docs}

	policyData, err := os.ReadFile(policyPath)
	require.NoError(t, err)
	crossplaneLib, err := os.ReadFile("../rego/crossplane.rego")
	require.NoError(t, err)
	commonLib, err := os.ReadFile("../rego/common.rego")
	require.NoError(t, err)

	r := rego.New(
		rego.Query("data.wiz.WizPolicy"),
		rego.Module(policyPath, string(policyData)),
		rego.Module("crossplane.rego", string(crossplaneLib)),
		rego.Module("common.rego", string(commonLib)),
		rego.Input(input),
	)

	rs, err := r.Eval(context.Background())
	require.NoError(t, err)

	var findings []any
	for _, result := range rs {
		for _, expr := range result.Expressions {
			if set, ok := expr.Value.([]any); ok {
				findings = append(findings, set...)
			}
		}
	}
	return findings
}

// indexByName returns a map keyed by metadata.name for quick lookup in tests.
func indexByName(t *testing.T, docs []Document) map[string]Document {
	t.Helper()
	out := make(map[string]Document, len(docs))
	for _, d := range docs {
		md, ok := d["metadata"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := md["name"].(string)
		if name == "" {
			continue
		}
		out[name] = d
	}
	return out
}

// assertWizPolicyFields validates that a finding contains all required fields
// that the Wiz scanner framework expects from WizPolicy results.
func assertWizPolicyFields(t *testing.T, finding map[string]any) {
	t.Helper()
	for _, field := range requiredWizPolicyFields {
		_, ok := finding[field]
		assert.True(t, ok, "WizPolicy result missing required field '%s': %v", field, finding)
	}
	if sl, ok := finding["searchLine"]; ok {
		_, isArr := sl.([]any)
		assert.True(t, isArr, "searchLine should be an array, got %T", sl)
	}
}
