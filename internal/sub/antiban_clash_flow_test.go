package sub

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/dbtest"
)

// AntiBan Clash flow tests.
//
// The Clash/Mihomo export is the second way a client reaches the tunnel. A
// proxy without the Vision flow keeps the TLS-in-TLS signature that the
// Russian TSPU looks for, so AntiBan has to enforce the same profile there
// that it enforces on the direct share links.

func TestAntiBanClashProxyForcesVisionFlow(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	antiBanSetToggle(t, true)

	proxy := antiBanClashRealityProxy(t)
	if got := proxy["flow"]; got != "xtls-rprx-vision" {
		t.Fatalf("flow = %v, want xtls-rprx-vision with the toggle on", got)
	}
}

func TestAntiBanClashProxyKeepsNoFlowWhenToggleOff(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	antiBanSetToggle(t, false)

	proxy := antiBanClashRealityProxy(t)
	if got, ok := proxy["flow"]; ok {
		t.Fatalf("flow = %v, want no flow while the toggle is off", got)
	}
}
