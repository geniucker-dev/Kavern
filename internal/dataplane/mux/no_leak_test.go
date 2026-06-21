package mux_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThirdPartyMuxTypesDoNotLeakOutsideMuxPackage(t *testing.T) {
	root := repoRoot(t)
	allowed := filepath.Join(root, "internal", "dataplane", "mux")
	checked := []string{
		filepath.Join(root, "internal", "domain"),
		filepath.Join(root, "internal", "session"),
		filepath.Join(root, "internal", "router"),
		filepath.Join(root, "internal", "gateway", "agent_v1"),
		filepath.Join(root, "internal", "dataplane", "carrier"),
	}
	for _, dir := range checked {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range file.Imports {
				importPath := strings.Trim(imp.Path.Value, `"`)
				if strings.Contains(importPath, "xtaci/smux") || strings.Contains(importPath, "hashicorp/yamux") {
					t.Fatalf("%s imports third-party mux package %q", path, importPath)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	err := filepath.WalkDir(allowed, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(importPath, "hashicorp/yamux") {
				t.Fatalf("%s imports yamux in Gate 3", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
