//go:build legacy_npc_integration

package legacy_npc

import (
	"os"
	"testing"
)

func TestNPCBinRequired(t *testing.T) {
	npcBin := os.Getenv("NPC_BIN")
	if npcBin == "" {
		t.Fatalf("NPC_BIN is required when running with -tags=legacy_npc_integration; real stock npc compatibility is deferred to Gate 5/Gate 6")
	}
	info, err := os.Stat(npcBin)
	if err != nil {
		t.Fatalf("NPC_BIN %q is not accessible: %v", npcBin, err)
	}
	if info.IsDir() {
		t.Fatalf("NPC_BIN %q is a directory, want executable file", npcBin)
	}
	if info.Mode()&0111 == 0 {
		t.Fatalf("NPC_BIN %q is not executable", npcBin)
	}
	t.Logf("NPC_BIN is present; real stock npc protocol acceptance is not implemented until Gate 5/Gate 6")
}
