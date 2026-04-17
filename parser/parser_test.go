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

// --- Parsing + restructuring tests ---

func TestParseStandaloneResources(t *testing.T) {
	result, err := ParseFile("../testdata/standalone/aws-network.yaml")
	require.NoError(t, err)

	resourceMap, ok := result.Document["resource"].(map[string]any)
	require.True(t, ok)

	vpcs := resourceMap["VPC"].(map[string]any)
	assert.Contains(t, vpcs, "sample-vpc")

	subnets := resourceMap["Subnet"].(map[string]any)
	assert.Contains(t, subnets, "sample-subnet1")
	assert.Contains(t, subnets, "sample-subnet2")
	assert.Len(t, subnets, 2)

	sgs := resourceMap["SecurityGroup"].(map[string]any)
	assert.Contains(t, sgs, "sample-cluster-sg")
	assert.Contains(t, sgs, "db-security-group")

	// Verify cross-resource reference preserved
	subnet1 := subnets["sample-subnet1"].(map[string]any)
	spec := subnet1["spec"].(map[string]any)
	fp := spec["forProvider"].(map[string]any)
	vpcRef := fp["vpcIdRef"].(map[string]any)
	assert.Equal(t, "sample-vpc", vpcRef["name"])
}

func TestParseComposition(t *testing.T) {
	result, err := ParseFile("../testdata/composition/rds-composition.yaml")
	require.NoError(t, err)

	resourceMap := result.Document["resource"].(map[string]any)

	rds := resourceMap["RDSInstance"].(map[string]any)
	assert.Contains(t, rds, "composed-rds")

	sg := resourceMap["DBSubnetGroup"].(map[string]any)
	assert.Contains(t, sg, "composed-subnet-group")

	_, hasComp := resourceMap["Composition"]
	assert.False(t, hasComp, "Composition itself should not be in resource map")
}

func TestParseUpbound(t *testing.T) {
	data, err := os.ReadFile("../testdata/upbound/aws-rds-upbound.yaml")
	require.NoError(t, err)
	assert.True(t, IsCrossplaneFile(data))

	result, err := ParseFile("../testdata/upbound/aws-rds-upbound.yaml")
	require.NoError(t, err)

	resourceMap := result.Document["resource"].(map[string]any)
	instances := resourceMap["Instance"].(map[string]any)
	assert.Contains(t, instances, "upbound-rds")
}

func TestParseMixed(t *testing.T) {
	result, err := ParseFile("../testdata/mixed/standalone-and-composition.yaml")
	require.NoError(t, err)

	resourceMap := result.Document["resource"].(map[string]any)
	rds := resourceMap["RDSInstance"].(map[string]any)

	assert.Contains(t, rds, "standalone-rds")
	assert.Contains(t, rds, "composed-app-db")
	assert.Len(t, rds, 2)
}

// --- End-to-end Rego policy tests (WizPolicy format) ---

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

func TestRegoPolicy_RDSNotEncrypted(t *testing.T) {
	findings := evalCrossplanePolicy(t,
		"../testdata/standalone/aws-rds.yaml",
		"../rego/rds_not_encrypted.rego",
	)
	require.NotEmpty(t, findings, "should detect unencrypted RDS instance")

	for _, f := range findings {
		finding := f.(map[string]any)
		assertWizPolicyFields(t, finding)
		assert.Equal(t, "RDSInstance", finding["resourceType"])
	}
}

func TestRegoPolicy_RDSNotEncrypted_Composition(t *testing.T) {
	findings := evalCrossplanePolicy(t,
		"../testdata/composition/rds-composition.yaml",
		"../rego/rds_not_encrypted.rego",
	)
	require.NotEmpty(t, findings, "should detect unencrypted RDS extracted from Composition")

	for _, f := range findings {
		finding := f.(map[string]any)
		assertWizPolicyFields(t, finding)
		assert.Equal(t, "composed-rds", finding["resourceName"])
	}
}

func TestRegoPolicy_SecurityGroupOpenIngress(t *testing.T) {
	findings := evalCrossplanePolicy(t,
		"../testdata/standalone/aws-network.yaml",
		"../rego/security_group_open_ingress.rego",
	)
	require.Len(t, findings, 1, "should detect one SG with 0.0.0.0/0 ingress")

	finding := findings[0].(map[string]any)
	assertWizPolicyFields(t, finding)
	assert.Equal(t, "SecurityGroup", finding["resourceType"])
	assert.Equal(t, "sample-cluster-sg", finding["resourceName"])
}

func TestRegoPolicy_SubnetVPCRef_NoFinding(t *testing.T) {
	findings := evalCrossplanePolicy(t,
		"../testdata/standalone/aws-network.yaml",
		"../rego/subnet_without_vpc_ref.rego",
	)
	assert.Empty(t, findings, "all subnets reference sample-vpc which exists — no findings expected")
}

func TestRegoPolicy_MixedStandaloneAndComposition(t *testing.T) {
	findings := evalCrossplanePolicy(t,
		"../testdata/mixed/standalone-and-composition.yaml",
		"../rego/rds_not_encrypted.rego",
	)
	// standalone-rds has storageEncrypted: true → no findings
	// composed-app-db has storageEncrypted: false → findings
	require.NotEmpty(t, findings)

	for _, f := range findings {
		finding := f.(map[string]any)
		assertWizPolicyFields(t, finding)
		assert.Equal(t, "composed-app-db", finding["resourceName"],
			"findings should only be for the unencrypted composed resource")
	}
}

// --- Test helpers ---

// evalCrossplanePolicy simulates the full Wiz IaC scanning flow:
// 1. Read raw Crossplane YAML file
// 2. Parse + restructure into Terraform-like document
// 3. Wrap in input.document[] (as the Wiz engine does via Combine())
// 4. Evaluate WizPolicy Rego rules via OPA
// 5. Return findings
func evalCrossplanePolicy(t *testing.T, yamlPath, policyPath string) []any {
	t.Helper()

	// Step 1-2: Parse and restructure
	result, err := ParseFile(yamlPath)
	require.NoError(t, err)

	// Step 3: Wrap in input.document[] — this is what the Wiz engine does
	// via FileMetadatas.Combine(). Each document gets an id and file path.
	result.Document["id"] = uuid.New().String()
	result.Document["file"] = result.FilePath
	input := map[string]any{
		"document": []any{result.Document},
	}

	// Step 4: Load Rego files
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

	// Step 5: Collect findings from result set
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

// assertWizPolicyFields validates that a finding contains all required fields
// that the Wiz scanner framework expects from WizPolicy results.
func assertWizPolicyFields(t *testing.T, finding map[string]any) {
	t.Helper()
	for _, field := range requiredWizPolicyFields {
		_, ok := finding[field]
		assert.True(t, ok, "WizPolicy result missing required field '%s': %v", field, finding)
	}

	// searchLine should be an array (used for line detection)
	if sl, ok := finding["searchLine"]; ok {
		_, isArr := sl.([]any)
		assert.True(t, isArr, "searchLine should be an array, got %T", sl)
	}
}
