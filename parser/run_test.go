package parser

import (
	"encoding/json"
	"os"
	"testing"
)

// TestRunOnFile parses a single file and prints its raw documents.
// Override the target with: CROSSPLANE_FILE=<path> go test -v -run TestRunOnFile ./parser/
func TestRunOnFile(t *testing.T) {
	path := os.Getenv("CROSSPLANE_FILE")
	if path == "" {
		path = "../testdata/parser/composition.yaml"
	}

	res, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile(%s): %v", path, err)
	}

	out, err := json.MarshalIndent(res.Documents, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	t.Logf("FilePath: %s\nDocuments:\n%s", res.FilePath, out)
}
