package sub

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/dbtest"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// AntiBan ML-KEM tests.
//
// TSPU drops the post-quantum X25519MLKEM768 key share, so a client that
// offers it may never reach the server at all. Dropping it is only safe when
// the serving core predates 26.9.8: newer cores reject a REALITY handshake
// that arrives without an ML-KEM key share. AntiBan therefore drops the key
// share only when the toggle is on AND the local core is older than 26.9.8;
// a modern core keeps the hybrid key share so the tunnel keeps working.

// antiBanStubCoreVersion replaces the detected Xray core version for one test.
func antiBanStubCoreVersion(t *testing.T, version string) {
	t.Helper()
	previous := antiBanCoreVersion
	antiBanCoreVersion = func() string { return version }
	t.Cleanup(func() { antiBanCoreVersion = previous })
}

// antiBanClashRealityProxy builds the Clash proxy of a REALITY inbound.
func antiBanClashRealityProxy(t *testing.T) map[string]any {
	t.Helper()
	svc := &SubClashService{SubService: &SubService{}}
	inbound := antiBanTestInbound(antiBanRealityStream)
	client := model.Client{ID: "11111111-2222-4333-8444-555555555555"}
	stream := map[string]any{
		"network":         "tcp",
		"security":        "reality",
		"tcpSettings":     map[string]any{"header": map[string]any{"type": "none"}},
		"realitySettings": map[string]any{"serverName": "reality.example.com", "publicKey": "PBKvalue", "shortId": "ab12", "fingerprint": "chrome"},
	}
	proxy := svc.buildProxy(svc.SubService, inbound, client, stream, nil)
	if proxy == nil {
		t.Fatal("buildProxy returned nil for a valid reality stream")
	}
	return proxy
}

// An old core plus the toggle on: the client must not offer the key share
// that TSPU blackholes.
func TestAntiBanClashDropsMLKEMOnOldCore(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	antiBanSetToggle(t, true)
	antiBanStubCoreVersion(t, "26.9.7")

	proxy := antiBanClashRealityProxy(t)
	opts, _ := proxy["reality-opts"].(map[string]any)
	if opts == nil {
		t.Fatalf("reality-opts missing: %#v", proxy)
	}
	if opts["support-x25519mlkem768"] != false {
		t.Fatalf("ML-KEM support = %v, want false on a core older than 26.9.8", opts["support-x25519mlkem768"])
	}
}

// A modern core rejects a handshake without the key share, so the hybrid
// key share must stay even with the toggle on.
func TestAntiBanClashKeepsMLKEMOnModernCore(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	antiBanSetToggle(t, true)
	antiBanStubCoreVersion(t, "26.10.21")

	proxy := antiBanClashRealityProxy(t)
	opts, _ := proxy["reality-opts"].(map[string]any)
	if opts == nil {
		t.Fatalf("reality-opts missing: %#v", proxy)
	}
	if opts["support-x25519mlkem768"] != true {
		t.Fatalf("ML-KEM support = %v, want true on a modern core", opts["support-x25519mlkem768"])
	}
}

// The toggle off keeps the upstream behaviour untouched.
func TestAntiBanClashKeepsMLKEMWhenToggleOff(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	antiBanSetToggle(t, false)
	antiBanStubCoreVersion(t, "26.9.7")

	proxy := antiBanClashRealityProxy(t)
	opts, _ := proxy["reality-opts"].(map[string]any)
	if opts == nil {
		t.Fatalf("reality-opts missing: %#v", proxy)
	}
	if opts["support-x25519mlkem768"] != true {
		t.Fatalf("ML-KEM support = %v, want true while the toggle is off", opts["support-x25519mlkem768"])
	}
}

// The share link carries the same hint, so an Xray based client (Happ,
// Incy) can be told to skip the key share as well.
func TestAntiBanVlessLinkDropsMLKEMParamOnOldCore(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	antiBanSetToggle(t, true)
	antiBanStubCoreVersion(t, "26.9.7")

	s := &SubService{}
	got := s.genVlessLink(antiBanTestInbound(antiBanRealityStream), "user")
	if strings.Contains(got, "support-x25519mlkem768") {
		t.Fatalf("expected no ML-KEM hint in %q", got)
	}
}

// A modern core keeps the hint, otherwise the tunnel would break.
func TestAntiBanVlessLinkKeepsMLKEMParamOnModernCore(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	antiBanSetToggle(t, true)
	antiBanStubCoreVersion(t, "26.10.21")

	s := &SubService{}
	got := s.genVlessLink(antiBanTestInbound(antiBanRealityStream), "user")
	if !strings.Contains(got, "support-x25519mlkem768=true") {
		t.Fatalf("expected the ML-KEM hint in %q", got)
	}
}
