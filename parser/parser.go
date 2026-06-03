// Package parser reads Crossplane YAML files and returns their documents
// as JSON-compatible maps.
//
// It is intentionally dumb: each YAML document is preserved as written, with
// only one transformation — multi-document files (separated by ---) are split
// into a list. Compositions are not flattened; their nested resources stay
// under spec.resources[].base. Rego policies walk into them via the
// managedResourcesOf helper in rego/crossplane.rego.
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
var CrossPlaneRegex = regexp.MustCompile(`"?apiVersion"?\s*:\s*"?(\w+\.)+(?:crossplane|upbound)\.io/v\w+"?\s*`)

// Document is the parsed representation of a single YAML document.
type Document = map[string]any

// ParseResult holds the list of documents parsed from a single YAML file.
type ParseResult struct {
	FilePath  string
	Documents []Document
}

// ParseFile reads a YAML file and returns its documents.
func ParseFile(path string) (*ParseResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}
	return Parse(path, data)
}

// Parse splits a multi-document YAML byte slice into JSON-compatible maps.
func Parse(filePath string, data []byte) (*ParseResult, error) {
	docs, err := splitYAMLDocuments(data)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML in %s: %w", filePath, err)
	}
	return &ParseResult{
		FilePath:  filePath,
		Documents: docs,
	}, nil
}

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

// IsCrossplaneFile checks if file content matches Crossplane/Upbound apiVersion patterns.
func IsCrossplaneFile(content []byte) bool {
	return CrossPlaneRegex.Match(content)
}
