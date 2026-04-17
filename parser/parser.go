// Package parser provides Crossplane YAML parsing and document restructuring.
//
// Crossplane manifests are Kubernetes YAML files that provision cloud infrastructure.
// The parser reads YAML files (which may contain multiple documents separated by ---),
// and restructures them into a Terraform-like format keyed by Kind + metadata.name:
//
//	{
//	  "resource": {
//	    "VPC":    { "my-vpc": { ... } },
//	    "Subnet": { "subnet-a": { ... }, "subnet-b": { ... } }
//	  }
//	}
//
// This structure enables efficient Rego policy evaluation without expensive
// input.document[_] scans — policies access resources via document.resource.<Kind>[name],
// matching the pattern used by Terraform and CloudFormation.
//
// For Compositions (traditional mode with spec.resources[].base), nested managed
// resources are extracted into the flat resource map alongside standalone resources.
package parser

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// CrossPlaneRegex matches Crossplane and Upbound provider apiVersion patterns.
// Covers both legacy crossplane.io providers and modern upbound.io providers.
var CrossPlaneRegex = regexp.MustCompile(`"?apiVersion"?\s*:\s*"?(\w+\.)+(?:crossplane|upbound)\.io/v\w+"?\s*`)

// Document is the parsed representation of a YAML document.
type Document = map[string]any

// ParseResult holds the restructured output from parsing a Crossplane YAML file.
type ParseResult struct {
	FilePath string
	Document Document // The restructured document with "resource" key
}

// ParseFile reads a YAML file and restructures its contents into a Terraform-like document.
func ParseFile(path string) (*ParseResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}
	return Parse(path, data)
}

// Parse restructures raw YAML bytes into a Terraform-like document.
func Parse(filePath string, data []byte) (*ParseResult, error) {
	docs, err := splitYAMLDocuments(data)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML in %s: %w", filePath, err)
	}

	restructured := restructureDocs(docs)

	return &ParseResult{
		FilePath: filePath,
		Document: restructured,
	}, nil
}

// splitYAMLDocuments splits a multi-document YAML file (--- separated) into individual documents.
func splitYAMLDocuments(data []byte) ([]Document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []Document

	for {
		var doc Document
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}

	return docs, nil
}

// restructureDocs groups YAML documents into a single Terraform-like document
// keyed by Kind + metadata.name. Composition nested resources are extracted
// into the flat resource map.
func restructureDocs(docs []Document) Document {
	resourceMap := make(map[string]any)

	for _, doc := range docs {
		kind, _ := doc["kind"].(string)
		if kind == "" {
			continue
		}

		if kind == "Composition" {
			extractCompositionResources(doc, resourceMap)
			continue
		}

		metadata, _ := doc["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if name == "" {
			continue
		}

		addToResourceMap(resourceMap, kind, name, doc)
	}

	return Document{
		"resource": resourceMap,
	}
}

// extractCompositionResources extracts managed resources nested under
// spec.resources[].base in a traditional Composition.
func extractCompositionResources(compositionDoc Document, resourceMap map[string]any) {
	spec, ok := compositionDoc["spec"].(map[string]any)
	if !ok {
		return
	}

	resources, ok := spec["resources"].([]any)
	if !ok {
		return
	}

	for _, res := range resources {
		resMap, ok := res.(map[string]any)
		if !ok {
			continue
		}

		base, ok := resMap["base"].(map[string]any)
		if !ok {
			continue
		}

		kind, _ := base["kind"].(string)
		if kind == "" {
			continue
		}

		metadata, _ := base["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)

		// Fall back to composition resource name if metadata.name is absent
		if name == "" {
			name, _ = resMap["name"].(string)
		}
		if name == "" {
			continue
		}

		addToResourceMap(resourceMap, kind, name, base)
	}
}

func addToResourceMap(resourceMap map[string]any, kind, name string, doc Document) {
	kindMap, ok := resourceMap[kind].(map[string]any)
	if !ok {
		kindMap = make(map[string]any)
		resourceMap[kind] = kindMap
	}
	kindMap[name] = doc
}

// IsCrossplaneFile checks if file content matches Crossplane/Upbound apiVersion patterns.
func IsCrossplaneFile(content []byte) bool {
	return CrossPlaneRegex.Match(content)
}
