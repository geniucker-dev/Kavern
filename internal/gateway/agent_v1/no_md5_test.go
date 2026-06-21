package agent_v1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func TestAgentV1NonTestFilesDoNotUseMD5(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	for _, file := range files {
		if filepath.Ext(file) != ".go" || len(file) >= 8 && file[len(file)-8:] == "_test.go" {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", file, err)
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", file, err)
		}
		for _, imp := range parsed.Imports {
			if imp.Path.Value == `"crypto/md5"` {
				t.Fatalf("%s imports crypto/md5", file)
			}
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "md5" {
				t.Fatalf("%s references md5.%s", file, sel.Sel.Name)
			}
			return true
		})
	}
}
