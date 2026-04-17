package parser

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestParseStandaloneResources(t *testing.T) {
	result, err := ParseFile("../testdata/standalone/aws-network.yaml")
	require.NoError(t, err)

	resourceMap, ok := result.Document["resource"].(map[string]any)
	require.True(t, ok)

	// VPC
	vpcs, ok := resourceMap["VPC"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, vpcs, "sample-vpc")

	// Subnets
	subnets, ok := resourceMap["Subnet"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, subnets, "sample-subnet1")
	assert.Contains(t, subnets, "sample-subnet2")
	assert.Len(t, subnets, 2)

	// SecurityGroups
	sgs, ok := resourceMap["SecurityGroup"].(map[string]any)
	require.True(t, ok)
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

	// RDSInstance extracted from composition
	rds, ok := resourceMap["RDSInstance"].(map[string]any)
	require.True(t, ok, "RDSInstance should be extracted from Composition")
	assert.Contains(t, rds, "composed-rds")

	// DBSubnetGroup extracted from composition
	sg, ok := resourceMap["DBSubnetGroup"].(map[string]any)
	require.True(t, ok, "DBSubnetGroup should be extracted from Composition")
	assert.Contains(t, sg, "composed-subnet-group")

	// Composition itself should NOT be in the resource map
	_, hasComp := resourceMap["Composition"]
	assert.False(t, hasComp)
}

func TestParseUpbound(t *testing.T) {
	data, err := os.ReadFile("../testdata/upbound/aws-rds-upbound.yaml")
	require.NoError(t, err)
	assert.True(t, IsCrossplaneFile(data), "should detect upbound.io as Crossplane")

	result, err := ParseFile("../testdata/upbound/aws-rds-upbound.yaml")
	require.NoError(t, err)

	resourceMap := result.Document["resource"].(map[string]any)
	instances, ok := resourceMap["Instance"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, instances, "upbound-rds")
}

func TestParseMixed(t *testing.T) {
	result, err := ParseFile("../testdata/mixed/standalone-and-composition.yaml")
	require.NoError(t, err)

	resourceMap := result.Document["resource"].(map[string]any)
	rds := resourceMap["RDSInstance"].(map[string]any)

	assert.Contains(t, rds, "standalone-rds", "standalone resource should be in map")
	assert.Contains(t, rds, "composed-app-db", "composition-extracted resource should be in map")
	assert.Len(t, rds, 2)
}

// TestRegoPolicy runs actual Rego policies against parsed Crossplane documents
// to verify the end-to-end flow: YAML file → parse → restructure → Rego evaluation → findings.
func TestRegoPolicy_RDSNotEncrypted(t *testing.T) {
	result, err := ParseFile("../testdata/standalone/aws-rds.yaml")
	require.NoError(t, err)

	findings := evalRego(t, "../rego/rds_not_encrypted.rego", result.Document)
	assert.NotEmpty(t, findings, "should detect unencrypted RDS instance")

	finding := findings[0].(map[string]any)
	assert.Equal(t, "RDSInstance", finding["resourceType"])
	assert.Equal(t, "HIGH", finding["severity"])
}

func TestRegoPolicy_RDSNotEncrypted_Composition(t *testing.T) {
	result, err := ParseFile("../testdata/composition/rds-composition.yaml")
	require.NoError(t, err)

	findings := evalRego(t, "../rego/rds_not_encrypted.rego", result.Document)
	assert.NotEmpty(t, findings, "should detect unencrypted RDS from composition")
}

func TestRegoPolicy_SecurityGroupOpenIngress(t *testing.T) {
	result, err := ParseFile("../testdata/standalone/aws-network.yaml")
	require.NoError(t, err)

	findings := evalRego(t, "../rego/security_group_open_ingress.rego", result.Document)
	assert.Len(t, findings, 1, "should detect one SG with 0.0.0.0/0 ingress")

	finding := findings[0].(map[string]any)
	assert.Equal(t, "SecurityGroup", finding["resourceType"])
}

func TestRegoPolicy_SubnetVPCRef(t *testing.T) {
	result, err := ParseFile("../testdata/standalone/aws-network.yaml")
	require.NoError(t, err)

	findings := evalRego(t, "../rego/subnet_without_vpc_ref.rego", result.Document)
	assert.Empty(t, findings, "all subnets reference sample-vpc which exists in the document")
}

func TestRegoPolicy_MixedStandaloneAndComposition(t *testing.T) {
	result, err := ParseFile("../testdata/mixed/standalone-and-composition.yaml")
	require.NoError(t, err)

	findings := evalRego(t, "../rego/rds_not_encrypted.rego", result.Document)
	// standalone-rds has storageEncrypted: true → no findings
	// composed-app-db has storageEncrypted: false → findings from both deny rules
	require.NotEmpty(t, findings, "should detect the unencrypted composed RDS")

	for _, f := range findings {
		finding := f.(map[string]any)
		assert.Equal(t, "composed-app-db", finding["resourceName"], "findings should only be for the unencrypted composed resource")
	}
}

// evalRego is a test helper that evaluates a Rego policy against an input document.
func evalRego(t *testing.T, policyPath string, input Document) []any {
	t.Helper()

	policyData, err := os.ReadFile(policyPath)
	require.NoError(t, err)

	libraryData, err := os.ReadFile("../rego/crossplane.rego")
	require.NoError(t, err)

	// Find all .rego files for the query
	policyDir := filepath.Dir(policyPath)
	policyFiles, _ := filepath.Glob(filepath.Join(policyDir, "*.rego"))
	_ = policyFiles

	// Use a wildcard query that finds all deny rules across crossplane packages
	r := rego.New(
		rego.Query("data.crossplane[provider][rule].deny"),
		rego.Module(policyPath, string(policyData)),
		rego.Module("crossplane.rego", string(libraryData)),
		rego.Input(input),
	)

	rs, err := r.Eval(context.Background())
	require.NoError(t, err)

	var findings []any
	for _, result := range rs {
		for _, expr := range result.Expressions {
			switch v := expr.Value.(type) {
			case []any:
				findings = append(findings, v...)
			case map[string]any:
				for _, val := range v {
					if set, ok := val.([]any); ok {
						findings = append(findings, set...)
					}
				}
			}
		}
	}

	return findings
}
